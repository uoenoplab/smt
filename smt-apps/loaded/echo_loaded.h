#ifndef _ECHO_LOADED_H
#define _ECHO_LOADED_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdatomic.h>

#include "../util/utils.h"

// variables and structs //

#define HOMA_BPAGE_NUM    4000 // 64 KB * 4000 -> 256 MB
#define RTT_PREHEAT       2

// common
extern int protocol;
extern int num_threads;
extern int num_server_ports;          // server listen ports or client per-ip
extern int num_server_ips;            // client: 1 or 2
extern struct sockaddr_in saddr;
extern struct sockaddr_in saddr_alter; // client optional second IP
extern uint32_t req_size;
extern uint32_t resp_size;
extern bool use_google_workload;
// client
extern int num_rpcs;
extern int num_sockets;               // sockets per client thread
extern double net_mbps;                // 0 means uncapped
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

// echo_loaded common utils //

void print_help(const char *prog_name, bool is_server);
void parse_args(int argc, char *argv[], bool is_server);

void launch_threads(void *args_list, int num_threads, size_t arg_size,
                    void *(*thread_func)(void *));
int  shutdown_thread(pthread_t thread, long tv_nsec);

// echo_loaded common utils //

// rate limit //

struct rate_limit_context {
  struct timespec last_time;
  double rate;   // bytes per second
  double budget;
};

void   rate_limit_init(double rate, struct rate_limit_context *rl);
double rate_limit_try_send(struct rate_limit_context *rl, uint32_t bytes);
void   rate_limit_sleep(double wait_time);

// rate limit //

// epoll helpers //

extern int epoll_wait_timeout;

void add_epoll_event(int epoll_fd, int sockfd, uint32_t events,
                     void *data_ptr);
void mod_epoll_event(int epoll_fd, int sockfd, uint32_t events,
                     void *data_ptr);

// epoll helpers //

#endif // _ECHO_LOADED_H
