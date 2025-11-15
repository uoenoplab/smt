#ifndef _UTIL_H
#define _UTIL_H

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "log_c/log.h"
#include "../../module/homa.h"
#include "../../module/smt.h"

// -1 for quiet, 0 for normal, 1 for debug, 2 for trace, 3 for hexdump
extern int verbose_level;
extern volatile sig_atomic_t sigint_received;

// NOTE: DISABLE_UTIL_PROTOCOL must be defined to avoid macro divergence
//       between utils.o and protocol-dependent executables
#ifndef DISABLE_UTIL_PROTOCOL
// protocols //

enum Protocol {
  ECHO_HOMA,
#ifdef BUILD_HOMA_CSUM
  ECHO_HOMA_CSUM,
#endif
  ECHO_SMT,
  ECHO_TCP,
  ECHO_TCP_KTLS,
#ifdef BUILD_TCPLS
  ECHO_TCPLS,
#endif
  ECHO_PROTO_NUM,
};

static const char *protocol_names[] = {
  [ECHO_HOMA] = "homa",
#ifdef BUILD_HOMA_CSUM
  [ECHO_HOMA_CSUM] = "homacsum",
#endif
  [ECHO_SMT] = "smt",
  [ECHO_TCP] = "tcp",
  [ECHO_TCP_KTLS] = "tcp_ktls",
#ifdef BUILD_TCPLS
  [ECHO_TCPLS] = "tcpls",
#endif
};

_Static_assert(ECHO_PROTO_NUM ==
                   sizeof(protocol_names) / sizeof(protocol_names[0]),
               "protocol_names[] and Protocol enum must match");

static inline int parse_protocol(char const *protocol_name) {
  for (int i = 0; i < ECHO_PROTO_NUM; i++) {
    if (strcmp(protocol_name, protocol_names[i]) == 0) return i;
  }
  return -1;
}

static inline void print_protocol_names(void) {
  fprintf(stderr, "Unsupported protocol! (Choose from ");
  for (int i = 0; i < ECHO_PROTO_NUM; i++) {
    fprintf(stderr, "%s", protocol_names[i]);
    if (i != ECHO_PROTO_NUM - 1) fprintf(stderr, ", ");
  }
  fprintf(stderr, ")\n");
}

// protocols //
#endif

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

// main thread receive SIGINT and start join threads
static inline void sigint_handler(int signum __attribute__((unused)))
{
  sigint_received = 1;
}

// threads receive USR1 and exit, SIGINT will be masked out
static inline void sigusr1_handler(int signum __attribute__((unused)))
{
  pthread_exit(EXIT_SUCCESS);
}

// Steup three things
// 1. ignore SIGPIPE (https://web.archive.org/web/20240325025853/https://rigtorp.se/sockets/)
// 2. set SIGINT (Ctrl-C) to sigint_handler for main thread to join child threads
// 3. set SIGUSR1 to sigusr1_handler, child threads will use this sigusr1_handler
//    with `shutdown_thread` function
static inline void setup_sigaction(void) {
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    fprintf(stderr, "Could not SIG_IGN for SIGPIPE (error %s)\n", strerror(errno));
  }

  struct sigaction sa_sigint = { 0 };
  sa_sigint.sa_handler = sigint_handler;
  sa_sigint.sa_flags = 0;
  if (sigaction(SIGINT, &sa_sigint, NULL)) {
    fprintf(stderr, "Could not setup signal handler for SIGINT (error %s)\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct sigaction sa_sigusr1 = { 0 };
  sa_sigusr1.sa_handler = sigusr1_handler;
  sa_sigusr1.sa_flags = 0;
  if (sigaction(SIGUSR1, &sa_sigusr1, NULL)) {
    fprintf(stderr, "Could not setup signal handler for SIGUSR1 (error %s)\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static inline void check_pending_signals() {
  sigset_t pending;
  if (sigpending(&pending) == 0) {
    for (int sig = 1; sig < NSIG; sig++) {
      if (sigismember(&pending, sig)) {
        printf("Signal %d is pending\n", sig);
      }
    }
  }
}

static inline void hexdump(const char *title, void *buf, size_t len) {
  if (verbose_level != 3) return;
  printf("%s (%lu bytes) :\n", title, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02hhX ", ((uint8_t *)buf)[i]);
    if (i % 16 == 15) printf("\n");
  }
  printf("\n");
}

static inline void hexdump_iov(const char *title, struct iovec *vecs, size_t vecs_len) {
  if (verbose_level != 3) return;
  printf("%s (%lu vecs):\n", title, vecs_len);
  for (size_t i = 0; i < vecs_len; i++) {
    char subtitle[20];
    sprintf(subtitle, "vec[%ld]", i);
    hexdump(subtitle, vecs[i].iov_base, vecs[i].iov_len);
  }
}

static inline void setup_payload_buffer(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = '?'; //i % 256;
    // reqmsg[i] = i % 256;
  }
  // FILE *fp = fopen("/dev/urandom", "r");
  // if (fp) {
  //     int reqlen_random = fread(reqmsg, 1, reqlen, fp);
  //     fclose(fp);
  //     if (reqlen_random == reqlen) {
  //         return 1;
  //     } else {
  //         return -1;
  //     }
  // }
}

static inline void set_log_c_verbose_level(int verbose_level) {
  switch (verbose_level)
  {
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

static inline void pin_core(int core, pthread_attr_t *attr, pthread_t thread) {
  bool core_valid;

  if (core == 0) {
    core_valid = true;
  } else {
    char path[40];
    FILE *fp;
    char status[2] = {0};
    sprintf(path, "/sys/devices/system/cpu/cpu%d/online", core);
    fp = fopen(path, "r");
    if (fp == NULL) {
      core_valid = false;
    } else {
      if (fread(status, 1, 1, fp) < 1) {
        core_valid = false;
      } else {
        if (status[0] == '1') {
          core_valid = true;
        } else {
          core_valid = false;
        }
      }
      fclose(fp);
    }
  }

  if (!core_valid) {
    log_fatal("core (%d) to pin doesn't exist or offline", core);
    exit(EXIT_FAILURE);
  }

  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(core, &cpus);

  if (attr != NULL) {
    if (pthread_attr_setaffinity_np(attr, sizeof(cpu_set_t), &cpus) != 0) {
      log_fatal("pthread_attr_setaffinity_np failed (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }
  } else {
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpus) != 0) {
      log_fatal("pthread_setaffinity_np failed (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
}

static inline void pin_core_attr(int core, pthread_attr_t *attr) {
  pin_core(core, attr, 0);
}

static inline void pin_core_thread(int core, pthread_t thread) {
  pin_core(core, NULL, thread);
}

static inline void set_socket_nonblocking(int socket_fd)
{
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

// homa utils //
extern ssize_t homa_recv_build_iov(
    struct iovec *vecs, uint8_t *recv_buf_region, const ssize_t msg_length,
    const uint32_t num_bpages, const uint32_t bpage_offsets[HOMA_MAX_BPAGES]);

extern ssize_t homa_init_recv_buffer(int sockfd, size_t *recv_buf_size,
                              uint8_t **recv_buf_region, int homa_bpage_num);

#ifdef BUILD_HOMA_CSUM
uint16_t homa_iovec_checksum(struct iovec *iov, int iovcnt);
#endif

// homa utils //

#endif /* _UTIL_H */
