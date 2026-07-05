/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SMT_LOADED_H_
#define _SMT_LOADED_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define SMT_BENCH_CMSG_TYPE	      1
#define SMT_BENCH_MAX_MESSAGE_LENGTH 1000000
#define SMT_BENCH_BPAGE_SHIFT	      16
#define SMT_BENCH_BPAGE_SIZE	      (1U << SMT_BENCH_BPAGE_SHIFT)
#define SMT_BENCH_MAX_BPAGES                                          \
	((SMT_BENCH_MAX_MESSAGE_LENGTH + SMT_BENCH_BPAGE_SIZE - 1) / \
	    SMT_BENCH_BPAGE_SIZE)

#define SMT_BENCH_RECV_REQUEST	     0x01
#define SMT_BENCH_RECV_RESPONSE     0x02
#define SMT_BENCH_RECV_NONBLOCKING  0x04
#define SMT_BENCH_PREHEAT_RPCS	     2
#define SMT_BENCH_RESPONSE_LEN_SIZE sizeof(uint32_t)

#define SMT_BENCH_HIST_BIN_WIDTH_US 0.1
#define SMT_BENCH_HIST_MAX_US	     10000.0
#define SMT_BENCH_HIST_BINS \
	((size_t)(SMT_BENCH_HIST_MAX_US / SMT_BENCH_HIST_BIN_WIDTH_US) + 1)

#ifndef IPPROTO_SMT
#define IPPROTO_SMT 146
#endif

enum smt_bench_protocol {
	SMT_BENCH_PROTO_UNSET,
	SMT_BENCH_PROTO_HOMA,
	SMT_BENCH_PROTO_SMT,
};

struct smt_bench_sendmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
};

struct smt_bench_recvmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
	int flags;
	uint32_t num_bpages;
	uint32_t _pad[2];
	uint32_t bpage_offsets[SMT_BENCH_MAX_BPAGES];
};

union smt_bench_send_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct smt_bench_sendmsg_args))];
};

union smt_bench_recv_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct smt_bench_recvmsg_args))];
};

struct smt_bench_histogram {
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

struct smt_bench_rate_limit {
	struct timespec last_time;
	double rate;
	double budget;
};

extern volatile sig_atomic_t smt_bench_stop;

int smt_bench_parse_int(const char *, int, int, int *);
int smt_bench_parse_u16(const char *, uint16_t *);
int smt_bench_parse_ports(const char *, uint16_t *, int *);
int smt_bench_parse_sizes(char *, uint32_t *, uint32_t *);
int smt_bench_parse_protocol(const char *, enum smt_bench_protocol *);
const char *smt_bench_protocol_name(enum smt_bench_protocol);
const char *smt_bench_verbose_name(int);

void smt_bench_setup_signals(void);
int smt_bench_now(struct timespec *);
double smt_bench_elapsed_seconds(const struct timespec *,
    const struct timespec *);
double smt_bench_elapsed_us(const struct timespec *, const struct timespec *);
int smt_bench_pin_thread(int, int);
int smt_bench_resolve_ipv4(const char *, uint16_t, struct sockaddr_in *,
    char *, size_t);
int smt_bench_fill_payload(void *, size_t);

int smt_bench_hist_init(struct smt_bench_histogram *);
void smt_bench_hist_destroy(struct smt_bench_histogram *);
int smt_bench_hist_add(struct smt_bench_histogram *, double, uint32_t,
    uint32_t);
int smt_bench_hist_merge(struct smt_bench_histogram *,
    const struct smt_bench_histogram *);
double smt_bench_hist_average(const struct smt_bench_histogram *);
double smt_bench_hist_stddev(const struct smt_bench_histogram *);
double smt_bench_hist_percentile(struct smt_bench_histogram *, double);

void smt_bench_rate_init(struct smt_bench_rate_limit *, double);
double smt_bench_rate_try_send(struct smt_bench_rate_limit *, uint32_t);

int smt_bench_bind_socket(int, const char *, uint16_t);
int smt_bench_enable_tls(int, bool);
ssize_t smt_bench_read_full(int, void *, size_t);
ssize_t smt_bench_write_full(int, const void *, size_t);
ssize_t smt_bench_send_request(int, const struct sockaddr_in *, const void *,
    size_t, uint64_t);
ssize_t smt_bench_send_response(int, const struct sockaddr_in *, const void *,
    size_t, uint64_t);
ssize_t smt_bench_recv(int, int, void *, size_t, struct sockaddr_in *,
    struct smt_bench_recvmsg_args *);

#endif
