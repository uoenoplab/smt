/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SDTP_LOADED_H_
#define _SDTP_LOADED_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define SDTP_BENCH_CMSG_TYPE	      1
#define SDTP_BENCH_MAX_MESSAGE_LENGTH 1000000
#define SDTP_BENCH_BPAGE_SHIFT	      16
#define SDTP_BENCH_BPAGE_SIZE	      (1U << SDTP_BENCH_BPAGE_SHIFT)
#define SDTP_BENCH_MAX_BPAGES                                          \
	((SDTP_BENCH_MAX_MESSAGE_LENGTH + SDTP_BENCH_BPAGE_SIZE - 1) / \
	    SDTP_BENCH_BPAGE_SIZE)

#define SDTP_BENCH_RECV_REQUEST	     0x01
#define SDTP_BENCH_RECV_RESPONSE     0x02
#define SDTP_BENCH_RECV_NONBLOCKING  0x04
#define SDTP_BENCH_PREHEAT_RPCS	     2
#define SDTP_BENCH_RESPONSE_LEN_SIZE sizeof(uint32_t)

#define SDTP_BENCH_HIST_BIN_WIDTH_US 0.1
#define SDTP_BENCH_HIST_MAX_US	     10000.0
#define SDTP_BENCH_HIST_BINS \
	((size_t)(SDTP_BENCH_HIST_MAX_US / SDTP_BENCH_HIST_BIN_WIDTH_US) + 1)

#ifndef IPPROTO_SDTP
#define IPPROTO_SDTP 146
#endif

enum sdtp_bench_protocol {
	SDTP_BENCH_PROTO_UNSET,
	SDTP_BENCH_PROTO_HOMA,
	SDTP_BENCH_PROTO_SMT,
};

struct sdtp_bench_sendmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
};

struct sdtp_bench_recvmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
	int flags;
	uint32_t num_bpages;
	uint32_t _pad[2];
	uint32_t bpage_offsets[SDTP_BENCH_MAX_BPAGES];
};

union sdtp_bench_send_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct sdtp_bench_sendmsg_args))];
};

union sdtp_bench_recv_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct sdtp_bench_recvmsg_args))];
};

struct sdtp_bench_histogram {
	uint64_t *bins;
	double *overflow;
	size_t overflow_count;
	size_t overflow_capacity;
	uint64_t count;
	double sum_us;
	double sum_squares_us;
	uint64_t total_request_bytes;
	uint64_t total_response_bytes;
};

struct sdtp_bench_rate_limit {
	struct timespec last_time;
	double rate;
	double budget;
};

extern volatile sig_atomic_t sdtp_bench_stop;

int sdtp_bench_parse_int(const char *, int, int, int *);
int sdtp_bench_parse_u16(const char *, uint16_t *);
int sdtp_bench_parse_ports(const char *, uint16_t *, int *);
int sdtp_bench_parse_sizes(char *, uint32_t *, uint32_t *);
int sdtp_bench_parse_protocol(const char *, enum sdtp_bench_protocol *);
const char *sdtp_bench_protocol_name(enum sdtp_bench_protocol);
const char *sdtp_bench_verbose_name(int);

void sdtp_bench_setup_signals(void);
int sdtp_bench_now(struct timespec *);
double sdtp_bench_elapsed_seconds(const struct timespec *,
    const struct timespec *);
double sdtp_bench_elapsed_us(const struct timespec *, const struct timespec *);
int sdtp_bench_pin_thread(int, int);
int sdtp_bench_resolve_ipv4(const char *, uint16_t, struct sockaddr_in *,
    char *, size_t);
int sdtp_bench_fill_payload(void *, size_t);

int sdtp_bench_hist_init(struct sdtp_bench_histogram *);
void sdtp_bench_hist_destroy(struct sdtp_bench_histogram *);
int sdtp_bench_hist_add(struct sdtp_bench_histogram *, double, uint32_t,
    uint32_t);
int sdtp_bench_hist_merge(struct sdtp_bench_histogram *,
    const struct sdtp_bench_histogram *);
double sdtp_bench_hist_average(const struct sdtp_bench_histogram *);
double sdtp_bench_hist_stddev(const struct sdtp_bench_histogram *);
double sdtp_bench_hist_percentile(struct sdtp_bench_histogram *, double);

void sdtp_bench_rate_init(struct sdtp_bench_rate_limit *, double);
double sdtp_bench_rate_try_send(struct sdtp_bench_rate_limit *, uint32_t);

int sdtp_bench_bind_socket(int, const char *, uint16_t);
int sdtp_bench_enable_tls(int, bool);
ssize_t sdtp_bench_read_full(int, void *, size_t);
ssize_t sdtp_bench_write_full(int, const void *, size_t);
ssize_t sdtp_bench_send_request(int, const struct sockaddr_in *, const void *,
    size_t, uint64_t);
ssize_t sdtp_bench_send_response(int, const struct sockaddr_in *, const void *,
    size_t, uint64_t);
ssize_t sdtp_bench_recv(int, int, void *, size_t, struct sockaddr_in *,
    struct sdtp_bench_recvmsg_args *);

#endif
