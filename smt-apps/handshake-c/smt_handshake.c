/* smt_handshake: SMT keys from a TLS 1.3 handshake over Homa.
 *
 * The client carries its TLS records in Homa RPCs to the server's handshake
 * port, which has no keys, and gets the server's in the replies: one RPC for
 * the ClientHello, one for the client's Certificate, CertificateVerify and
 * Finished plus its Homa port as TLS application data. The client checks
 * the server's certificate against ca.pem, and the server the client's if
 * it presents one (mutual TLS: the client has client.pem). Both take 56
 * bytes from the TLS exporter (RFC 8446 section 7.5, label "EXPORTER-SMT-NG
 * keys"): the client's AES-128 key and IV, then the server's. Each installs
 * them on its data socket for the other end only, with setsockopt(SOL_TLS),
 * and the client checks one echo over SMT with TLS 1.3 records.
 *
 * The server installs the keys for the address the RPCs come from and the
 * port the client names. The --handshake option of ../unloaded-golang (Go
 * crypto/tls) and ../unloaded-rust (rustls) speaks the same protocol.
 *
 * usage: smt_handshake server | smt_handshake client <server_ip>
 * Files (make cert): ca.pem, server.pem, server-key.pem and, for mutual
 * TLS, client.pem, client-key.pem.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
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
#define KEY_LEN 16
#define IV_LEN 12
#define DATA_PORT 2000
#define HS_PORT 4433
#define BUF_PAGES 1000 /* a bpage per possible CPU and then some */
#define MAX_PENDING 16
#define HS_SECS 10

/* A Homa socket and the bpages of its last message, which the next recvmsg
 * returns.
 */
struct hsock {
	int fd;
	uint8_t *buf;
	struct homa_recvmsg_args rc;
};

/* A server handshake between its two RPCs. */
struct pending {
	struct sockaddr_in peer;
	SSL *ssl;
	time_t start;
};

static struct hsock data;

static void die(const char *what)
{
	perror(what);
	ERR_print_errors_fp(stderr);
	exit(1);
}

static struct hsock homa_open(int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
	struct hsock s = { .fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA) };
	struct homa_rcvbuf_args b = { .length = BUF_PAGES * HOMA_BPAGE_SIZE };

	s.buf = mmap(NULL, b.length, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	b.start = (uintptr_t)s.buf;
	if (s.fd < 0 || s.buf == MAP_FAILED ||
	    (port && bind(s.fd, (struct sockaddr *)&a, sizeof(a))) ||
	    setsockopt(s.fd, IPPROTO_HOMA, SO_HOMA_RCVBUF, &b, sizeof(b)))
		die("homa socket");
	return s;
}

/* The next message (any request on a server socket), or NULL. Messages
 * here fit in one bpage.
 */
static uint8_t *homa_recv(struct hsock *s, struct sockaddr_in *src, int *len)
{
	struct msghdr m = { .msg_name = src, .msg_namelen = sizeof(*src),
			    .msg_control = &s->rc, .msg_controllen = sizeof(s->rc) };

	s->rc.id = 0;
	*len = recvmsg(s->fd, &m, 0);
	if (*len < 0 || *len > HOMA_BPAGE_SIZE)
		return NULL;
	return s->buf + s->rc.bpage_offsets[0];
}

/* A request when @id is 0, else the reply to RPC @id. */
static int homa_send(struct hsock *s, struct sockaddr_in *to, __u64 id,
		     void *buf, size_t len)
{
	struct homa_sendmsg_args sc = { .id = id };
	struct iovec v = { buf, len };
	struct msghdr m = { .msg_name = to, .msg_namelen = sizeof(*to),
			    .msg_iov = &v, .msg_iovlen = 1, .msg_control = &sc };

	return sendmsg(s->fd, &m, 0);
}

/* Send what TLS has written; Homa can't send an empty message. */
static void send_tls(struct hsock *s, struct sockaddr_in *to, __u64 id,
		     SSL *ssl)
{
	char *out;
	long n = BIO_get_mem_data(SSL_get_wbio(ssl), &out);

	if (homa_send(s, to, id, out, n) < 0)
		perror("handshake sendmsg");
	BIO_reset(SSL_get_wbio(ssl));
}

/* TLS 1.3 over memory BIOs: this end's certificate (the client's only if
 * it has one), and ca.pem to check the peer's.
 */
static SSL *tls_new(int server)
{
	static SSL_CTX *ctx;
	SSL *ssl;

	if (!ctx) {
		ctx = SSL_CTX_new(server ? TLS_server_method() :
					   TLS_client_method());
		SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
		SSL_CTX_set_num_tickets(ctx, 0);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		if (((server || !access("client.pem", R_OK)) &&
		     (SSL_CTX_use_certificate_file(ctx, server ? "server.pem" :
					"client.pem", SSL_FILETYPE_PEM) != 1 ||
		      SSL_CTX_use_PrivateKey_file(ctx, server ? "server-key.pem" :
					"client-key.pem", SSL_FILETYPE_PEM) != 1)) ||
		    SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL) != 1)
			die("certificates (make cert)");
	}
	ssl = SSL_new(ctx);
	SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
	return ssl;
}

/* Take the keys from the exporter and install them for the peer at
 * @addr:@port (network order); the client's come first.
 */
static int set_keys(SSL *ssl, uint32_t addr, uint16_t port, int client)
{
	uint8_t k[2][KEY_LEN + IV_LEN];

	if (SSL_export_keying_material(ssl, &k[0][0], sizeof(k), LABEL,
				       strlen(LABEL), NULL, 0, 0) != 1)
		return -1;
	for (int i = 0; i < 2; i++) {
		struct smt_aes_gcm_128_info info = { .smt = { addr, port } };
		struct tls12_crypto_info_aes_gcm_128 c = {
			.info = { TLS_1_3_VERSION, TLS_CIPHER_AES_GCM_128 } };
		const uint8_t *key = k[i ^ !client]; /* TX: our own */

		memcpy(c.key, key, KEY_LEN);
		memcpy(c.salt, key + KEY_LEN, sizeof(c.salt));
		memcpy(c.iv, key + KEY_LEN + sizeof(c.salt), sizeof(c.iv));
		info.aes_gcm_128 = c; /* packed: assigned, not addressed */
		if (setsockopt(data.fd, SOL_TLS, i ? TLS_RX : TLS_TX, &info,
			       sizeof(info)))
			return -1;
	}
	return 0;
}

/* Feed a server handshake one request. Returns 0 while it waits for more,
 * 1 once it is over, keys installed or not.
 */
static int handshake_step(struct pending *e, uint8_t *msg, int len)
{
	uint16_t port = 0;
	uint8_t go = 1;
	int r;

	BIO_write(SSL_get_rbio(e->ssl), msg, len);
	r = SSL_do_handshake(e->ssl);
	if (r == 1)
		r = SSL_read(e->ssl, &port, sizeof(port));
	if (r <= 0 && SSL_get_error(e->ssl, r) == SSL_ERROR_WANT_READ)
		return 0;
	if (r == sizeof(port) && port &&
	    !set_keys(e->ssl, e->peer.sin_addr.s_addr, port, 0)) {
		SSL_write(e->ssl, &go, 1);
		printf("keys for %s:%d, client %sauthenticated\n",
		       inet_ntoa(e->peer.sin_addr), ntohs(port),
		       SSL_get0_peer_certificate(e->ssl) ? "" : "not ");
		return 1;
	}
	fprintf(stderr, "handshake with %s failed\n",
		inet_ntoa(e->peer.sin_addr));
	ERR_print_errors_fp(stderr);
	if (r > 0)
		SSL_shutdown(e->ssl); /* else TLS has written its alert */
	return 1;
}

/* Server: handshakes, each kept between its two RPCs for up to HS_SECS. */
static void *handshakes(void *unused)
{
	static struct pending p[MAX_PENDING];
	struct hsock hs = homa_open(HS_PORT);

	for (;;) {
		struct sockaddr_in src;
		struct pending *e = NULL;
		int len, i;
		uint8_t *msg = homa_recv(&hs, &src, &len);

		if (!msg)
			continue;
		for (i = 0; i < MAX_PENDING; i++) {
			if (p[i].ssl && time(NULL) - p[i].start > HS_SECS) {
				SSL_free(p[i].ssl);
				p[i].ssl = NULL;
			}
			if (p[i].ssl && p[i].peer.sin_port == src.sin_port &&
			    p[i].peer.sin_addr.s_addr == src.sin_addr.s_addr)
				e = &p[i];
			else if (!p[i].ssl && !e)
				e = &p[i];
		}
		if (!e) { /* all busy: take the first */
			e = &p[0];
			SSL_free(e->ssl);
			e->ssl = NULL;
		}
		if (!e->ssl) {
			*e = (struct pending){ src, tls_new(1), time(NULL) };
			SSL_set_accept_state(e->ssl);
		}
		i = handshake_step(e, msg, len);
		send_tls(&hs, &src, hs.rc.id, e->ssl);
		if (i) {
			SSL_free(e->ssl);
			e->ssl = NULL;
		}
	}
	return unused;
}

/* Server: echo every request on the data port. */
static void serve(void)
{
	pthread_t t;

	data = homa_open(DATA_PORT);
	pthread_create(&t, NULL, handshakes, NULL);
	for (;;) {
		struct sockaddr_in src;
		int len;
		uint8_t *msg = homa_recv(&data, &src, &len);

		if (msg && homa_send(&data, &src, data.rc.id, msg, len) < 0)
			perror("sendmsg");
	}
}

/* One handshake RPC: our records out, the server's back. */
static void exchange(struct hsock *hs, struct sockaddr_in *srv, SSL *ssl)
{
	int len;
	uint8_t *msg;

	send_tls(hs, srv, 0, ssl);
	msg = homa_recv(hs, srv, &len);
	if (!msg)
		die("handshake recvmsg");
	BIO_write(SSL_get_rbio(ssl), msg, len);
}

/* Client: the handshake, then one echo over SMT. */
static void client(const char *server)
{
	struct sockaddr_in srv = { .sin_family = AF_INET,
				   .sin_port = htons(HS_PORT) }, me;
	socklen_t alen = sizeof(me);
	struct hsock hs = homa_open(0);
	SSL *ssl = tls_new(0);
	char req[] = "hello over SMT";
	uint8_t go, *echo;
	int len;

	data = homa_open(0);
	if (inet_pton(AF_INET, server, &srv.sin_addr) != 1 ||
	    getsockname(data.fd, (struct sockaddr *)&me, &alen))
		die("server address");
	SSL_set1_host(ssl, "smt-server");
	SSL_set_connect_state(ssl);
	SSL_do_handshake(ssl); /* writes the ClientHello */
	exchange(&hs, &srv, ssl);
	if (SSL_do_handshake(ssl) != 1)
		die("TLS handshake");
	SSL_write(ssl, &me.sin_port, sizeof(me.sin_port));
	if (set_keys(ssl, srv.sin_addr.s_addr, htons(DATA_PORT), 1))
		die("keys");
	exchange(&hs, &srv, ssl);
	if (SSL_read(ssl, &go, 1) != 1)
		die("no go-ahead from the server");

	srv.sin_port = htons(DATA_PORT);
	if (homa_send(&data, &srv, 0, req, sizeof(req)) < 0)
		die("sendmsg");
	echo = homa_recv(&data, &srv, &len);
	if (!echo || len != sizeof(req) || memcmp(echo, req, len))
		die("echo");
	printf("echo checked over SMT (TLS 1.3 records)\n");
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc == 2 && !strcmp(argv[1], "server"))
		serve();
	if (argc != 3 || strcmp(argv[1], "client")) {
		fprintf(stderr, "usage: %s server | %s client <server_ip>\n",
			argv[0], argv[0]);
		return 2;
	}
	client(argv[2]);
	return 0;
}
