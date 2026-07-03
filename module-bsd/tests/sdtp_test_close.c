#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IPPROTO_SDTP	146
#define TEST_ITERATIONS 1000
#define TEST_PORT	9001

static int
open_sdtp_socket(void)
{
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_SDTP);
	if (fd < 0)
		perror("socket");
	return (fd);
}

static int
bind_port(int fd)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(TEST_PORT);

	return (bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
}

static int
test_unbound_close(void)
{
	int fd;

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		fd = open_sdtp_socket();
		if (fd < 0)
			return (-1);
		if (close(fd) < 0) {
			perror("close(unbound socket)");
			return (-1);
		}
	}

	return (0);
}

static int
test_bound_close(void)
{
	int bind_error, competing_fd, fd;

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		fd = open_sdtp_socket();
		if (fd < 0)
			return (-1);
		if (bind_port(fd) < 0) {
			perror("bind(first socket)");
			close(fd);
			return (-1);
		}

		competing_fd = open_sdtp_socket();
		if (competing_fd < 0) {
			close(fd);
			return (-1);
		}
		if (bind_port(competing_fd) == 0) {
			fprintf(stderr,
			    "bind(competing socket) unexpectedly succeeded\n");
			close(competing_fd);
			close(fd);
			return (-1);
		}
		bind_error = errno;
		if (bind_error != EADDRINUSE) {
			fprintf(stderr,
			    "bind(competing socket) failed with %s, "
			    "expected %s\n",
			    strerror(bind_error), strerror(EADDRINUSE));
			close(competing_fd);
			close(fd);
			return (-1);
		}

		if (close(fd) < 0) {
			perror("close(bound socket)");
			close(competing_fd);
			return (-1);
		}
		if (bind_port(competing_fd) < 0) {
			perror("bind(after close)");
			close(competing_fd);
			return (-1);
		}
		if (close(competing_fd) < 0) {
			perror("close(rebound socket)");
			return (-1);
		}
	}

	return (0);
}

int
main(void)
{
	if (test_unbound_close() != 0)
		return (1);
	if (test_bound_close() != 0)
		return (1);

	return (0);
}
