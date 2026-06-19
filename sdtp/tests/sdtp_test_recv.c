#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdtp_test_tls.h"

#define SDTP_CMSG_TYPE		1

#define SDTP_MAX_MESSAGE_LENGTH 1000000
#define SDTP_BPAGE_SHIFT	16
#define SDTP_BPAGE_SIZE		(1 << SDTP_BPAGE_SHIFT)
#define SDTP_MAX_BPAGES \
	((SDTP_MAX_MESSAGE_LENGTH + SDTP_BPAGE_SIZE - 1) >> SDTP_BPAGE_SHIFT)

#define SDTP_RECVMSG_REQUEST	 0x01
#define SDTP_RECVMSG_RESPONSE	 0x02
#define SDTP_RECVMSG_NONBLOCKING 0x04
#define SDTP_RECVMSG_VALID_FLAGS 0x07

struct sdtp_recvmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
	int flags;
	uint32_t num_bpages;
	uint32_t _pad[2];
	uint32_t bpage_offsets[SDTP_MAX_BPAGES];
};

struct sdtp_sendmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
};

union sdtp_send_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct sdtp_sendmsg_args))];
};

union sdtp_recv_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct sdtp_recvmsg_args))];
};

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "Usage: %s -a <bind_ip> -p <port> [-n count] [-q] [-T]\n"
	    "  -a bind IPv4 address\n"
	    "  -p bind port\n"
	    "  -n number of request/response exchanges (default 1)\n"
	    "  -q quiet (do not print payloads)\n"
	    "  -T enable TLS encryption using test keys\n",
	    prog);
}

static int
parse_u16(const char *s, uint16_t *value)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v > 65535)
		return (-1);

	*value = (uint16_t)v;
	return (0);
}

static int
parse_int(const char *s, int *value)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < 1 || v > 1000000)
		return (-1);

	*value = (int)v;
	return (0);
}

static int
extract_recv_args(struct msghdr *msg, struct sdtp_recvmsg_args *out)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_SDTP &&
		    cmsg->cmsg_type == SDTP_CMSG_TYPE &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(*out))) {
			memcpy(out, CMSG_DATA(cmsg), sizeof(*out));
			return (0);
		}
	}

	return (-1);
}

int
main(int argc, char **argv)
{
	int ch;
	int fd;
	int exchanges;
	int quiet;
	int tls;
	uint16_t port;
	char *bind_ip;
	struct sockaddr_in local;

	fd = -1;
	exchanges = 1;
	quiet = 0;
	tls = 0;
	port = 0;
	bind_ip = NULL;

	while ((ch = getopt(argc, argv, "a:p:n:qT")) != -1) {
		switch (ch) {
		case 'a':
			bind_ip = optarg;
			break;
		case 'p':
			if (parse_u16(optarg, &port) != 0) {
				fprintf(stderr, "invalid port: %s\n", optarg);
				return (2);
			}
			break;
		case 'n':
			if (parse_int(optarg, &exchanges) != 0) {
				fprintf(stderr, "invalid count: %s\n", optarg);
				return (2);
			}
			break;
		case 'q':
			quiet = 1;
			break;
		case 'T':
			tls = 1;
			break;
		default:
			usage(argv[0]);
			return (2);
		}
	}

	if (bind_ip == NULL || port == 0) {
		usage(argv[0]);
		return (2);
	}

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_SDTP);
	if (fd < 0) {
		perror("socket");
		return (1);
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	if (inet_pton(AF_INET, bind_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", bind_ip);
		close(fd);
		return (2);
	}

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		perror("bind");
		close(fd);
		return (1);
	}
	if (tls && sdtp_enable_test_tls(fd, true) != 0) {
		close(fd);
		return (1);
	}

	for (int i = 0; i < exchanges; i++) {
		char data_buf[SDTP_MAX_MESSAGE_LENGTH];
		union sdtp_recv_cmsgbuf recv_control;
		struct iovec iov;
		struct sockaddr_in peer;
		struct msghdr msg;
		struct sdtp_recvmsg_args recv_args;
		ssize_t n;

		memset(&peer, 0, sizeof(peer));
		memset(&msg, 0, sizeof(msg));
		memset(&recv_control, 0, sizeof(recv_control));
		memset(&recv_args, 0, sizeof(recv_args));

		iov.iov_base = data_buf;
		iov.iov_len = sizeof(data_buf);

		msg.msg_name = &peer;
		msg.msg_namelen = sizeof(peer);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = recv_control.buf;
		msg.msg_controllen = sizeof(recv_control.buf);

		n = recvmsg(fd, &msg, SDTP_RECVMSG_REQUEST);
		if (n < 0) {
			perror("recvmsg(request)");
			close(fd);
			return (1);
		}

		if (extract_recv_args(&msg, &recv_args) != 0) {
			fprintf(stderr,
			    "missing SDTP control message in request\n");
			close(fd);
			return (1);
		}

		if (!quiet) {
			fwrite(data_buf, 1, (size_t)n, stdout);
			fputc('\n', stdout);
			fflush(stdout);
		}

		{
			union sdtp_send_cmsgbuf send_control;
			struct sdtp_sendmsg_args send_args;
			struct iovec send_iov;
			struct msghdr reply;
			struct cmsghdr *cmsg;
			ssize_t sent;

			memset(&send_control, 0, sizeof(send_control));
			memset(&send_args, 0, sizeof(send_args));
			memset(&reply, 0, sizeof(reply));

			send_args.id = recv_args.id;
			send_args.completion_cookie =
			    recv_args.completion_cookie;

			send_iov.iov_base = data_buf;
			send_iov.iov_len = (size_t)n;

			reply.msg_name = &peer;
			reply.msg_namelen = sizeof(peer);
			reply.msg_iov = &send_iov;
			reply.msg_iovlen = 1;
			reply.msg_control = send_control.buf;
			reply.msg_controllen = sizeof(send_control.buf);

			cmsg = &send_control.hdr;
			cmsg->cmsg_level = IPPROTO_SDTP;
			cmsg->cmsg_type = SDTP_CMSG_TYPE;
			cmsg->cmsg_len = CMSG_LEN(sizeof(send_args));

			memcpy(CMSG_DATA(cmsg), &send_args, sizeof(send_args));

			sent = sendmsg(fd, &reply, 0);
			if (sent < 0) {
				perror("sendmsg(response)");
				close(fd);
				return (1);
			}
			if (sent != n) {
				fprintf(stderr,
				    "short send: sent=%zd expected=%zd\n", sent,
				    n);
				close(fd);
				return (1);
			}
		}
	}

	close(fd);
	return (0);
}
