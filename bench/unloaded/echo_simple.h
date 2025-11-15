#ifndef _ECHO_SIMPLE_H
#define _ECHO_SIMPLE_H

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

#include "../util/utils.h"

// variables and structs //

#define DEFAULT_SERVER_BIND "0.0.0.0"
#define HOMA_BPAGE_NUM 4000 // 64KB * 4000 -> 256MB
#define RTT_PREHEAT 2

extern int protocol;
extern struct sockaddr_in saddr;
extern uint32_t req_size;
extern uint32_t resp_size;

// server - len is resp_size - req_size
// client - len is req_size
extern uint8_t *send_buf;

// server - len is req_size
// client - len is resp_size
extern uint8_t *tcp_recv_buf;

extern size_t homa_recv_buf_size;
extern uint8_t *homa_recv_buf_region;
extern struct homa_recvmsg_args homa_recv_control;
extern struct msghdr homa_recv_msghdr;

// variables and structs //

// echo_simple common utils //

void print_help(char *prog_name, bool is_server);
void parse_args(int argc, char *argv[], bool is_server);

// echo_simple common utils //

#endif /* _ECHO_SIMPLE_H */
