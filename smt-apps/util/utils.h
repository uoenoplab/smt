#ifndef _UTIL_H
#define _UTIL_H

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "log_c/log.h"
#include "../../homa.h"
#include "../../smt_uapi.h"

extern int verbose_level; // -1 for quiet, 0 for normal, 1 for debug, 2 for trace, 3 for hexdump
extern volatile sig_atomic_t sigint_received;

// protocols //

enum Protocol {
  ECHO_HOMA,
  ECHO_SMT,
  ECHO_TCP,
  ECHO_TCP_KTLS,
  ECHO_PROTO_NUM,
};

extern const char *const protocol_names[ECHO_PROTO_NUM];

int  parse_protocol(const char *protocol_name);
void print_protocol_names(void);

// protocols //

// common utils //

static inline long int parse_int(const char *str) {
  char *endptr;
  errno = 0;
  long val = strtol(str, &endptr, 10);
  if (errno != 0 || *endptr != '\0') {
    fprintf(stderr, "Invalid integer value: %s\n", str);
    exit(EXIT_FAILURE);
  }
  return val;
}

static inline double parse_double(const char *str) {
  char *endptr;
  errno = 0;
  double val = strtod(str, &endptr);
  if (errno != 0 || *endptr != '\0' || isinf(val) || isnan(val)) {
    fprintf(stderr, "Invalid double value : %s\n", str);
    exit(EXIT_FAILURE);
  }
  return val;
}

#define malloc_check(ptr) do { \
  if ((ptr) == NULL) { \
    log_fatal("%s: malloc failed in file %s at line %d\n", __func__, __FILE__, __LINE__); \
    exit(EXIT_FAILURE); \
  } \
} while(0)

// Install signal handlers on the calling thread:
// 1. ignore SIGPIPE (https://web.archive.org/web/20240325025853/https://rigtorp.se/sockets/)
// 2. set SIGINT (Ctrl-C) to sigint_handler for main thread to join child threads
// 3. set SIGUSR1 to sigusr1_handler, child threads will use this sigusr1_handler
//    with `shutdown_thread` function
void setup_sigaction(void);

void hexdump(const char *title, void *buf, size_t len);
void hexdump_iov(const char *title, struct iovec *vecs, size_t vecs_len);

// Fill buf[0..len) based on HOMA_ECHO_PAYLOAD env (fixed/mod/random).
void setup_payload_buffer(uint8_t *buf, size_t len);

static inline const char *get_verbose_level_str(int level) {
  switch (level) {
    case -1: return "\"quiet\"";
    case 0:  return "\"info\"";
    case 1:  return "\"debug\"";
    case 2:  return "\"trace\"";
    case 3:  return "\"trace with hexdump\"";
    default: return "\"invalid\"";
  }
}

static inline void set_log_c_verbose_level(int verbose_level) {
  switch (verbose_level) {
    case 3:
    case 2:
      log_set_level(LOG_TRACE);
      break;
    case 1:
      log_set_level(LOG_DEBUG);
      break;
    case 0:
      log_set_level(LOG_INFO);
      break;
    case -1:
      log_set_level(LOG_WARN);
      break;
    default:
      log_fatal("invalid verbose_level %d", verbose_level);
      exit(EXIT_FAILURE);
      break;
  }
}

static inline double calculate_time_delta_us(struct timespec a, struct timespec b) {
  return fabs((a.tv_sec - b.tv_sec) * 1000000.0 + (a.tv_nsec - b.tv_nsec) / 1000.0);
}

static inline double calculate_time_delta_s(struct timespec a, struct timespec b) {
  return fabs((a.tv_sec - b.tv_sec) * 1.0 + (a.tv_nsec - b.tv_nsec) / 1000000000.0);
}

void pin_core(int core, pthread_attr_t *attr, pthread_t thread);

static inline void pin_core_attr(int core, pthread_attr_t *attr) {
  pin_core(core, attr, 0);
}

static inline void pin_core_thread(int core, pthread_t thread) {
  pin_core(core, NULL, thread);
}

static inline void set_socket_nonblocking(int socket_fd) {
  int flags = fcntl(socket_fd, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }

  flags |= O_NONBLOCK;
  if (fcntl(socket_fd, F_SETFL, flags) == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }
}

// common utils //

// google workload //

extern void get_google_workload_rpc_size(uint32_t* reqlen, uint32_t* resplen);
extern void get_google_workload_avg_rpc_size(uint32_t* reqlen, uint32_t* resplen);
extern void get_google_workload_max_rpc_size(uint32_t* reqlen, uint32_t* resplen);

// google workload //

// homa smt uapi utils //

ssize_t homa_recv_build_iov(
    struct iovec *vecs, uint8_t *recv_buf_region, const ssize_t msg_length,
    const uint32_t num_bpages, const uint32_t bpage_offsets[HOMA_MAX_BPAGES]);

ssize_t homa_init_recv_buffer(int sockfd, size_t *recv_buf_size,
                              uint8_t **recv_buf_region,
                              int homa_bpage_num);

static inline int smt_setsockopt_wrapper(int sockfd, uint32_t addr, uint16_t port,
					 int server, int tls13)
{
  return smt_aes_gcm_128_setsockopt_hardcodekey_helper(sockfd, tls13, addr,
                                                       port, 0, server);
}

static inline int tcpktls_setsockopt_wrapper(int sockfd, int server, int tls13)
{
  return tcpktls_aes_gcm_128_setsockopt_hardcodekey_helper(sockfd, server,
                                                           tls13);
}

#ifdef BUILD_HOMA_CSUM
uint16_t homa_iovec_checksum(struct iovec *iov, int iovcnt);
#endif

// homa smt uapi utils //

#endif /* _UTIL_H */
