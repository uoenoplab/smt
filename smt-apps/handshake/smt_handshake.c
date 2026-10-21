/* smt_handshake: SMT keys from a TLS 1.3 handshake.
 *
 * The client connects to the server's TLS port over TCP and runs a TLS 1.3
 * handshake (OpenSSL). Both ends then derive the SMT keys with the TLS
 * exporter (RFC 8446 section 7.5): 56 bytes labelled "EXPORTER-SMT-NG keys",
 * the client's AES-128 key and 12-byte IV followed by the server's. Each end
 * installs them on its Homa socket for the other end only, with
 * setsockopt(SOL_TLS, TLS_TX / TLS_RX). The client first sends its Homa port
 * and the TLS version of the SMT records (12 or 13) over the TLS connection,
 * and waits for the server's go-ahead before its first request.
 *
 * Any TLS library with the exporter derives the same keys: Go crypto/tls
 * (ConnectionState.ExportKeyingMaterial), rustls (export_keying_material).
 *
 * usage: smt_handshake server [-p homa_port] [-t tls_port]
 *        smt_handshake client -a server_ip [-p homa_port] [-t tls_port]
 *                             [-3] [-l bytes] [-n rpcs]
 * The server reads cert.pem and key.pem (make cert); the client trusts
 * cert.pem. -3 selects TLS 1.3 records (default 1.2). Set
 * net.homa.smt_fixed_key to 0 on both hosts, so that keys come only from here.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "homa.h"
#include "smt_uapi.h"

#define LABEL "EXPORTER-SMT-NG keys"
#define KEY_LEN TLS_CIPHER_AES_GCM_128_KEY_SIZE
#define IV_LEN 12
#define KEYS_LEN (2 * (KEY_LEN + IV_LEN))
/* Receive region: Homa wants a bpage per possible CPU plus two maximum-size
 * messages; untouched pages cost nothing.
 */
#define BUF_PAGES 1000

static int homa_port = 2000, tls_port = 4433;
static int homa_fd;
static uint8_t *rbuf;

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	ERR_print_errors_fp(stderr);
	exit(1);
}

/* A Homa socket, bound to @port unless 0, with its receive buffer region. */
static int homa_open(int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET,
				 .sin_port = htons(port) };
	struct homa_rcvbuf_args buf;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);

	if (fd < 0)
		die("homa socket");
	if (port && bind(fd, (struct sockaddr *)&a, sizeof(a)))
		die("homa bind");
	rbuf = mmap(NULL, BUF_PAGES * HOMA_BPAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rbuf == MAP_FAILED)
		die("mmap");
	buf.start = (uintptr_t)rbuf;
	buf.length = BUF_PAGES * HOMA_BPAGE_SIZE;
	if (setsockopt(fd, IPPROTO_HOMA, SO_HOMA_RCVBUF, &buf, sizeof(buf)))
		die("SO_HOMA_RCVBUF");
	return fd;
}

/* The client's key and IV, then the server's. */
static void derive(SSL *ssl, uint8_t keys[KEYS_LEN])
{
	if (SSL_export_keying_material(ssl, keys, KEYS_LEN, LABEL,
				       strlen(LABEL), NULL, 0, 0) != 1)
		die("SSL_export_keying_material");
}

/* Install @tx and @rx (each a key followed by its IV) on the Homa socket
 * for the peer at @addr:@port (network order).
 */
static void set_keys(uint32_t addr, uint16_t port, int tls13,
		     const uint8_t *tx, const uint8_t *rx)
{
	const uint8_t *k[2] = { tx, rx };
	const int opt[2] = { TLS_TX, TLS_RX };

	for (int i = 0; i < 2; i++) {
		struct smt_aes_gcm_128_info info = { 0 };
		struct tls12_crypto_info_aes_gcm_128 *c = &info.aes_gcm_128;

		info.smt.peer_addr = addr;
		info.smt.peer_port = port;
		c->info.version = tls13 ? TLS_1_3_VERSION : TLS_1_2_VERSION;
		c->info.cipher_type = TLS_CIPHER_AES_GCM_128;
		memcpy(c->key, k[i], KEY_LEN);
		memcpy(c->salt, k[i] + KEY_LEN, sizeof(c->salt));
		/* TLS 1.3 nonces use the whole IV; TLS 1.2 records carry an
		 * explicit nonce, which must start out equal to rec_seq (0).
		 */
		if (tls13)
			memcpy(c->iv, k[i] + KEY_LEN + sizeof(c->salt),
			       sizeof(c->iv));
		if (setsockopt(homa_fd, SOL_TLS, opt[i], &info, sizeof(info)))
			die("setsockopt(SOL_TLS)");
	}
}

/* Server: one TLS handshake per client, on its own thread. */
static void *handshakes(void *unused)
{
	struct sockaddr_in a = { .sin_family = AF_INET,
				 .sin_port = htons(tls_port) };
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	int lfd = socket(AF_INET, SOCK_STREAM, 0), one = 1;

	(void)unused;
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) != 1)
		die("cert.pem / key.pem");
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) || listen(lfd, 16))
		die("TLS listen");
	for (;;) {
		struct sockaddr_in peer;
		socklen_t len = sizeof(peer);
		uint8_t hello[3], keys[KEYS_LEN], go = 1;
		uint16_t port;
		SSL *ssl;
		int fd = accept(lfd, (struct sockaddr *)&peer, &len);

		if (fd < 0)
			continue;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, fd);
		if (SSL_accept(ssl) == 1 && SSL_read(ssl, hello, 3) == 3) {
			memcpy(&port, hello, 2);
			derive(ssl, keys);
			set_keys(peer.sin_addr.s_addr, port, hello[2] == 13,
				 keys + KEY_LEN + IV_LEN, keys);
			SSL_write(ssl, &go, 1);
			printf("keys for %s:%d, TLS 1.%d records\n",
			       inet_ntoa(peer.sin_addr), ntohs(port),
			       hello[2] == 13 ? 3 : 2);
		} else {
			ERR_print_errors_fp(stderr);
		}
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(fd);
	}
	return NULL;
}

/* Server: echo every request. */
static void serve(void)
{
	struct homa_recvmsg_args rc = { 0 };
	pthread_t t;

	homa_fd = homa_open(homa_port);
	if (pthread_create(&t, NULL, handshakes, NULL))
		die("pthread_create");
	printf("echoing on Homa port %d, handshakes on TCP port %d\n",
	       homa_port, tls_port);
	for (;;) {
		struct sockaddr_in src;
		struct msghdr m = { .msg_name = &src,
				    .msg_namelen = sizeof(src),
				    .msg_control = &rc,
				    .msg_controllen = sizeof(rc) };
		struct homa_sendmsg_args sc = { 0 };
		struct iovec v[HOMA_MAX_BPAGES];
		int len;

		/* rc still lists the last message's bpages: they go back. */
		rc.id = 0;
		len = recvmsg(homa_fd, &m, 0);
		if (len < 0) {
			perror("recvmsg");
			continue;
		}
		for (uint32_t i = 0; i < rc.num_bpages; i++) {
			v[i].iov_base = rbuf + rc.bpage_offsets[i];
			v[i].iov_len = len - i * HOMA_BPAGE_SIZE;
			if (v[i].iov_len > HOMA_BPAGE_SIZE)
				v[i].iov_len = HOMA_BPAGE_SIZE;
		}
		sc.id = rc.id;
		m.msg_iov = v;
		m.msg_iovlen = rc.num_bpages;
		m.msg_control = &sc;
		m.msg_controllen = 0;
		if (sendmsg(homa_fd, &m, 0) < 0)
			perror("sendmsg");
	}
}

/* Client: handshake, then @n echoes of @size bytes, each one checked. */
static void client(const char *server, int tls13, int size, int n)
{
	struct sockaddr_in s = { .sin_family = AF_INET,
				 .sin_port = htons(tls_port) };
	struct homa_recvmsg_args rc = { 0 };
	struct sockaddr_in me;
	socklen_t len = sizeof(me);
	uint8_t hello[3], keys[KEYS_LEN], go;
	uint8_t *req = malloc(size);
	double total_us = 0;
	SSL_CTX *ctx;
	SSL *ssl;
	int fd;

	if (inet_pton(AF_INET, server, &s.sin_addr) != 1)
		die("server address");
	homa_fd = homa_open(0);
	if (getsockname(homa_fd, (struct sockaddr *)&me, &len))
		die("getsockname");

	ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	if (SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL) != 1)
		die("cert.pem");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *)&s, sizeof(s)))
		die("TLS connect");
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) != 1)
		die("TLS handshake");
	memcpy(hello, &me.sin_port, 2);
	hello[2] = tls13 ? 13 : 12;
	if (SSL_write(ssl, hello, 3) != 3)
		die("TLS write");
	derive(ssl, keys);
	s.sin_port = htons(homa_port);
	set_keys(s.sin_addr.s_addr, s.sin_port, tls13, keys,
		 keys + KEY_LEN + IV_LEN);
	if (SSL_read(ssl, &go, 1) != 1)
		die("no go-ahead from the server");
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(fd);

	for (int i = 0; i < n; i++) {
		struct iovec v = { .iov_base = req, .iov_len = size };
		struct homa_sendmsg_args sc = { 0 };
		struct msghdr m = { .msg_name = &s, .msg_namelen = sizeof(s),
				    .msg_iov = &v, .msg_iovlen = 1,
				    .msg_control = &sc };
		struct timespec t0, t1;
		int got, off = 0;

		for (int j = 0; j < size; j++)
			req[j] = i + j;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		if (sendmsg(homa_fd, &m, 0) < 0)
			die("sendmsg");
		rc.id = 0;
		m = (struct msghdr){ .msg_control = &rc,
				     .msg_controllen = sizeof(rc) };
		got = recvmsg(homa_fd, &m, 0);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		if (got != size)
			die("recvmsg");
		for (uint32_t b = 0; b < rc.num_bpages; off += HOMA_BPAGE_SIZE, b++) {
			int part = size - off < HOMA_BPAGE_SIZE ? size - off :
								  HOMA_BPAGE_SIZE;

			if (memcmp(rbuf + rc.bpage_offsets[b], req + off, part)) {
				fprintf(stderr, "echo %d differs\n", i);
				exit(1);
			}
		}
		total_us += (t1.tv_sec - t0.tv_sec) * 1e6 +
			    (t1.tv_nsec - t0.tv_nsec) / 1e3;
	}
	printf("%d echoes of %d B checked over SMT (TLS 1.%d records), mean RTT %.1f us\n",
	       n, size, tls13 ? 3 : 2, total_us / n);
}

int main(int argc, char **argv)
{
	const char *server = NULL;
	int tls13 = 0, size = 1500, n = 1000, opt;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2)
		goto usage;
	optind = 2;
	while ((opt = getopt(argc, argv, "a:p:t:3l:n:")) != -1) {
		switch (opt) {
		case 'a': server = optarg; break;
		case 'p': homa_port = atoi(optarg); break;
		case 't': tls_port = atoi(optarg); break;
		case '3': tls13 = 1; break;
		case 'l': size = atoi(optarg); break;
		case 'n': n = atoi(optarg); break;
		default: goto usage;
		}
	}
	if (!strcmp(argv[1], "server")) {
		serve();
		return 0;
	}
	if (!strcmp(argv[1], "client") && server && size > 0 && n > 0) {
		client(server, tls13, size, n);
		return 0;
	}
usage:
	fprintf(stderr, "usage: %s server [-p homa_port] [-t tls_port]\n"
		"       %s client -a server_ip [-p homa_port] [-t tls_port] [-3] [-l bytes] [-n rpcs]\n",
		argv[0], argv[0]);
	return 2;
}
