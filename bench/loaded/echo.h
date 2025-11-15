#ifndef _ECHO_H
#define _ECHO_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <liburing.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>

#include "../util/utils.h"

#ifdef BUILD_TCPLS
#include "tcpls/tcpls.h"
#endif

// variables and structs //

// common
#define DEFAULT_SERVER_BIND "0.0.0.0"
#define TCP_RECV_BUF_SIZE 8192
#define HOMA_BPAGE_NUM 4000 // 64KB * 4000 -> 256MB
#define RTT_PREHEAT 2

extern int protocol;
extern int num_threads;
extern int num_server_ports; // homa only
extern int num_server_ips; // homa client only
extern struct sockaddr_in saddr_alter; // homa client only
extern struct sockaddr_in saddr;
extern uint32_t req_size;
extern uint32_t resp_size;
extern bool use_google_workload;

// client
extern int num_rpcs;
extern int num_sockets;
extern double net_mbps;
extern _Atomic uint64_t rpc_id_counter;
extern int client_tcp_send_batch;

// server
extern int max_conns;

// variables and structs //

// rpc //

#define MAGIC_NUMBER 0x7467616f

struct rpc_header {
  uint32_t magic_number;
  uint64_t id;
  uint32_t reqlen;
  uint32_t resplen;
};

// rpc //

// echo_iouring common utils //

void print_help(const char *prog_name, bool is_server);
void parse_args(int argc, char *argv[], bool is_server);

void launch_threads(void* args_list, int num_threads, size_t arg_size, void* (*thread_func)(void*));
int shutdown_thread(pthread_t thread, long tv_nsec);

// echo_iouring common utils //

#ifdef MAKE_IOURING

// iouring helper functions //

extern ssize_t add_connect_request(struct io_uring *ring, int fd, void *data,
  bool submit);
extern ssize_t add_send_request(struct io_uring *ring, int fd, void *buf,
  size_t len, void *data, bool submit);
extern ssize_t add_recv_request(struct io_uring *ring, int fd, void *buf,
  size_t len, void *data, bool submit);
extern ssize_t add_sendmsg_request(struct io_uring *ring, int fd,
  const struct msghdr *msg, unsigned int flags, void *data, bool submit);
extern ssize_t add_recvmsg_request(struct io_uring *ring, int fd,
  struct msghdr *msg, unsigned int flags, void *data, bool submit);

// iouring helper functions //

#endif // MAKE_IOURING

#ifdef MAKE_EPOLL

// epoll helper functions //

extern int epoll_wait_timeout;

extern void add_event(const int epoll_fd, const int sockfd, uint32_t events, void *data_ptr);
extern void modify_event(const int epoll_fd, const int sockfd, uint32_t events, void *data_ptr);

// epoll helper functions //

#endif // MAKE_EPOLL

#endif /* _ECHO_H */
