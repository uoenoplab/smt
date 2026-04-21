// Multi-threaded loaded benchmark server (port of ~/repos/smt/bench/loaded).
// - Homa/SMT: one socket per listen port, one thread per port, blocking
//   recvmsg.
// - TCP: one listen socket; accept loop dispatches fds to worker threads
//   via a num_conns_pending slot; workers drive an epoll state machine
//   (TCP_RPC_RECV / TCP_RPC_SEND) per connection.
#include "echo_loaded.h"

#include <sys/epoll.h>
#include <limits.h>

// tcp path //

enum TCP_RPC_STATES {
  TCP_RPC_RECV,
  TCP_RPC_SEND,
  TCP_RPC_STATES_NUM,
};

// rpc is equivalent to conn for tcp here
struct tcp_rpc {
  struct sockaddr_in client_addr;
  char client_addr_ip[INET_ADDRSTRLEN];
  int conn_sockfd;
  enum TCP_RPC_STATES state;
  uint8_t *recv_buf;
  uint32_t recv_buflen;
  uint32_t recv_len;
  uint32_t recv_offset;
  int recv_next_rpc_bytes;
  int recv_next_rpc_offset;
  struct msghdr send_msg;
  struct iovec send_vecs[2];
  uint8_t *send_buf;
  uint32_t send_buflen;
  uint32_t send_remain;
};

struct tcp_thread_args {
  pthread_t thread;
  pthread_mutex_t lock;
  int num_conns;
  int num_conns_pending;
  struct tcp_rpc **rpcs;
};

// Don't reset recv_next_rpc_bytes / recv_next_rpc_offset / recv_buf for the
// next rpc whose bytes may already be in recv_buf.
static void tcp_reset_rpc(struct tcp_rpc *rpc) {
  rpc->state = TCP_RPC_RECV;
  rpc->recv_len = 0;
  rpc->recv_offset = 0;
  rpc->send_remain = 0;
  rpc->send_msg.msg_iovlen = 0;
  rpc->send_msg.msg_iov = rpc->send_vecs;
  rpc->send_vecs[0].iov_base = rpc->recv_buf;
  rpc->send_vecs[1].iov_base = rpc->send_buf;
}

static struct tcp_rpc *tcp_init_rpc(void) {
  struct tcp_rpc *rpc = calloc(1, sizeof(struct tcp_rpc));
  malloc_check(rpc);

  if (use_google_workload) {
    get_google_workload_max_rpc_size(&rpc->recv_buflen, &rpc->send_buflen);
  } else {
    rpc->recv_buflen = req_size;
    rpc->send_buflen = resp_size;
  }

  rpc->recv_buflen += sizeof(struct rpc_header);
  rpc->recv_buf = malloc(rpc->recv_buflen);
  malloc_check(rpc->recv_buf);

  rpc->send_buf = malloc(rpc->send_buflen);
  malloc_check(rpc->send_buf);
  setup_payload_buffer(rpc->send_buf, rpc->send_buflen);

  tcp_reset_rpc(rpc);
  return rpc;
}

static void tcp_release_rpc(struct tcp_rpc *rpc) {
  close(rpc->conn_sockfd);
  tcp_reset_rpc(rpc);
  free(rpc->recv_buf);
  free(rpc->send_buf);
  free(rpc);
}

static void tcp_disconnect_rpc(struct tcp_thread_args *targs,
                               struct tcp_rpc *rpc) {
  log_info("Disconnecting rpc %p with fd %d", rpc, rpc->conn_sockfd);
  pthread_mutex_lock(&targs->lock);
  int i = 0;
  for (; i < targs->num_conns; i++) {
    if (targs->rpcs[i] == rpc) break;
  }
  targs->num_conns--;
  targs->rpcs[i] = targs->rpcs[targs->num_conns];
  targs->rpcs[targs->num_conns] = NULL;
  tcp_release_rpc(rpc);
  pthread_mutex_unlock(&targs->lock);
}

// Returns bytes received on success, 0 on EAGAIN, -1 on error or EOF.
static ssize_t tcp_issue_recv(struct tcp_rpc *rpc) {
  int bytes_received = recv(rpc->conn_sockfd, rpc->recv_buf + rpc->recv_offset,
                            rpc->recv_buflen - rpc->recv_offset, 0);
  log_debug("recv returned %d", bytes_received);
  if ((bytes_received == 0) ||
      (bytes_received == -1 && errno != EAGAIN)) {
    log_warn("recv fail (ret %d, error %s)", bytes_received, strerror(errno));
    return -1;
  }
  if (bytes_received == -1 && errno == EAGAIN)
    return 0;
  return bytes_received;
}

static ssize_t tcp_parse_rpc_header(struct tcp_rpc *rpc) {
  struct rpc_header *hdr = (struct rpc_header *)rpc->recv_buf;

  if (hdr->magic_number != MAGIC_NUMBER) {
    log_error("received a RPC with invalid magicnumber header");
    return -1;
  }
  if (hdr->reqlen > 0 &&
      hdr->reqlen <= rpc->recv_buflen - sizeof(struct rpc_header)) {
    rpc->recv_len = hdr->reqlen + sizeof(struct rpc_header);
  } else {
    log_error("invalid (too long or zero) req len %d (recv_buflen %d)",
              hdr->reqlen, rpc->recv_buflen);
    return -1;
  }
  if (hdr->resplen > 0 && hdr->resplen <= rpc->send_buflen) {
    rpc->send_remain = hdr->resplen + sizeof(struct rpc_header);
  } else {
    log_error("invalid (too long or zero) resp len %d (send_buflen %d)",
              hdr->resplen, rpc->send_buflen);
    return -1;
  }
  return 0;
}

static ssize_t tcp_handle_recv(struct tcp_rpc *rpc, ssize_t bytes_received) {
  log_debug("bytes_received %ld (fd %d)", bytes_received, rpc->conn_sockfd);
  if (bytes_received == 0) {
    log_warn("no bytes received, drop conn %d", rpc->conn_sockfd);
    return -1;
  }
  rpc->recv_offset += bytes_received;

  if (!rpc->recv_len && rpc->recv_offset >= sizeof(struct rpc_header)) {
    if (tcp_parse_rpc_header(rpc) == -1) {
      log_warn("RPC header parsing failed");
      return -1;
    }
  }
  if (rpc->recv_offset >= rpc->recv_len)
    rpc->state = TCP_RPC_SEND;
  if (rpc->recv_offset > rpc->recv_len) {
    rpc->recv_next_rpc_bytes = rpc->recv_offset - rpc->recv_len;
    rpc->recv_next_rpc_offset = rpc->recv_len;
  }
  return 0;
}

// Returns 0 when the reply is fully flushed or sendmsg returned EAGAIN,
// bytes_sent (>0) on partial send, -1 on error. INT_MAX is a sentinel used
// by the main loop to mean "resume from stored iov state".
static ssize_t tcp_reply(struct tcp_rpc *rpc, int bytes_sent) {
  if (rpc->send_msg.msg_iovlen == 0) {
    if (bytes_sent != 0 && bytes_sent != INT_MAX) {
      log_fatal("msg_iovlen is zero, no bytes_sent can be handled");
      exit(EXIT_FAILURE);
    }
    if (rpc->send_remain <= rpc->recv_len) {
      rpc->send_msg.msg_iovlen = 1;
      rpc->send_vecs[0].iov_len = rpc->send_remain;
      log_trace("msg_iovlen 1 vec[0].iov_len %zu", rpc->send_vecs[0].iov_len);
    } else {
      rpc->send_msg.msg_iovlen = 2;
      rpc->send_vecs[0].iov_len = rpc->recv_len;
      rpc->send_vecs[1].iov_len = rpc->send_remain - rpc->recv_len;
      log_trace("msg_iovlen 2 vec[0].iov_len %zu vec[1].iov_len %zu",
                rpc->send_vecs[0].iov_len, rpc->send_vecs[1].iov_len);
    }
  } else {
    if (bytes_sent == INT_MAX) {
      log_debug("resume send");
    } else {
      if (bytes_sent <= 0) {
        log_warn("invalid bytes_sent %d", bytes_sent);
        return -1;
      }
      rpc->send_remain -= bytes_sent;
      log_trace("rpc->send_remain %u bytes_sent %d",
                rpc->send_remain, bytes_sent);
      if (rpc->send_remain == 0) {
        tcp_reset_rpc(rpc);
        return 0;
      }
      while (bytes_sent > 0 && rpc->send_msg.msg_iovlen > 0) {
        if ((size_t)bytes_sent < rpc->send_msg.msg_iov->iov_len) {
          rpc->send_msg.msg_iov->iov_base =
              (char *)rpc->send_msg.msg_iov->iov_base + bytes_sent;
          rpc->send_msg.msg_iov->iov_len -= bytes_sent;
          bytes_sent = 0;
        } else {
          bytes_sent -= rpc->send_msg.msg_iov->iov_len;
          rpc->send_msg.msg_iov++;
          rpc->send_msg.msg_iovlen--;
        }
      }
      if (bytes_sent != 0) {
        log_fatal("bytes_sent (%d) > 0 but iov is empty", bytes_sent);
        exit(EXIT_FAILURE);
      }
    }
  }

  bytes_sent = sendmsg(rpc->conn_sockfd, &rpc->send_msg, 0);
  log_debug("sendmsg returned %d", bytes_sent);
  if ((bytes_sent == 0) ||
      (bytes_sent == -1 && errno != EAGAIN)) {
    log_warn("sendmsg fail (ret %d, error %s)", bytes_sent, strerror(errno));
    return -1;
  }
  if (bytes_sent == -1 && errno == EAGAIN)
    return 0;
  return bytes_sent;
}

static void *thread_tcp(void *arg) {
  struct tcp_thread_args *targs = arg;
  int ret = 0;
  struct epoll_event events[max_conns + 1];
  memset(events, 0, sizeof(struct epoll_event) * (max_conns + 1));
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    log_fatal("epoll_create1 (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }

  while (!sigint_received) {
    if (targs->num_conns_pending > 0 || targs->num_conns == 0) {
      pthread_mutex_lock(&targs->lock);
      if (targs->num_conns_pending > 0) {
        log_trace("num_conns %d num_conns_pending %d",
                  targs->num_conns, targs->num_conns_pending);
        struct tcp_rpc *rpc =
            targs->rpcs[max_conns - targs->num_conns_pending];
        targs->rpcs[max_conns - targs->num_conns_pending] = NULL;
        targs->rpcs[targs->num_conns] = rpc;
        set_socket_nonblocking(rpc->conn_sockfd);
        add_epoll_event(epoll_fd, rpc->conn_sockfd, EPOLLIN | EPOLLRDHUP, rpc);
        targs->num_conns++;
        targs->num_conns_pending--;
      }
      pthread_mutex_unlock(&targs->lock);
      continue;
    }

    int event_count = epoll_wait(epoll_fd, events, max_conns + 1, epoll_wait_timeout);
    if (event_count == -1) {
      if (errno == EAGAIN) continue;
      if (errno == EINTR) goto threadloop_end;
      log_fatal("epoll_wait (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    for (int i = 0; i < event_count; i++) {
      struct tcp_rpc *rpc = events[i].data.ptr;
      if (!(events[i].events & (EPOLLIN | EPOLLOUT))) {
        log_warn("unhandled event (fd %d events %d)", rpc->conn_sockfd,
                 events[i].events);
        tcp_disconnect_rpc(targs, rpc);
        continue;
      }
      if (events[i].events & EPOLLIN) {
        while (true) {
          ret = tcp_issue_recv(rpc);
          if (ret == -1 || ret == 0) break;
process_recv_buf:
          ret = tcp_handle_recv(rpc, ret);
          if (ret == -1 || rpc->state == TCP_RPC_SEND) break;
        }
        if (ret == -1) {
          log_warn("tcp_issue_recv trigger disconnect");
          tcp_disconnect_rpc(targs, rpc);
          continue;
        }
      }
      if (rpc->state == TCP_RPC_SEND) {
        ret = INT_MAX;
        while (true) {
          ret = tcp_reply(rpc, ret);
          if (ret == 0 || ret == -1) break;
        }
        if (ret == -1) {
          log_warn("tcp_reply trigger disconnect");
          tcp_disconnect_rpc(targs, rpc);
          continue;
        }
        if (rpc->state == TCP_RPC_RECV && rpc->recv_next_rpc_bytes) {
          memmove(rpc->recv_buf,
                  rpc->recv_buf + rpc->recv_next_rpc_offset,
                  rpc->recv_next_rpc_bytes);
          ret = rpc->recv_next_rpc_bytes;
          rpc->recv_next_rpc_bytes = 0;
          rpc->recv_next_rpc_offset = 0;
          goto process_recv_buf;
        }
      }
      if (rpc->state == TCP_RPC_RECV && (events[i].events & EPOLLOUT))
        mod_epoll_event(epoll_fd, rpc->conn_sockfd, EPOLLIN | EPOLLRDHUP, rpc);
      if (rpc->state == TCP_RPC_SEND && (events[i].events & EPOLLIN))
        mod_epoll_event(epoll_fd, rpc->conn_sockfd, EPOLLOUT | EPOLLRDHUP, rpc);
    }
  }

threadloop_end:
  pthread_mutex_lock(&targs->lock);
  for (int i = 0; i < max_conns; i++) {
    if (targs->rpcs[i]) tcp_release_rpc(targs->rpcs[i]);
  }
  targs->num_conns = max_conns;
  targs->num_conns_pending = 0;
  pthread_mutex_unlock(&targs->lock);

  close(epoll_fd);
  return NULL;
}

static int main_tcp(void) {
  int listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (listen_sockfd < 0) {
    log_fatal("tcp listen socket: %s", strerror(errno));
    return 1;
  }
  setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  if (bind(listen_sockfd, (const struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
    log_fatal("tcp bind: %s", strerror(errno));
    return 1;
  }
  if (listen(listen_sockfd, SOMAXCONN) < 0) {
    log_fatal("tcp listen: %s", strerror(errno));
    return 1;
  }

  struct tcp_thread_args args[num_threads];

  for (int i = 0; i < num_threads; i++) {
    args[i].rpcs = calloc(max_conns, sizeof(struct tcp_rpc *));
    malloc_check(args[i].rpcs);
    args[i].num_conns = 0;
    args[i].num_conns_pending = 0;
    pthread_mutex_init(&args[i].lock, NULL);
  }
  launch_threads(args, num_threads, sizeof(args[0]), thread_tcp);
  log_info("TCP server ready on port %d", ntohs(saddr.sin_port));
  log_info("All threads launched, Press Ctrl+C to stop...");

  size_t last_dispatch_thread = 0;

  while (!sigint_received) {
    struct sockaddr_in client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    int sockfd = accept(listen_sockfd, (struct sockaddr *)&client_addr,
                        (socklen_t *)&client_addrlen);

    if (sockfd < 0) {
      if (errno == EINTR) {
        log_info("Server received SIGINT, exiting...");
        break;
      }
      log_warn("accept: %s", strerror(errno));
      continue;
    }
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));
    setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int));
    if (protocol == ECHO_TCP_KTLS &&
        tcpktls_setsockopt_wrapper(sockfd, 1, 0) < 0) {
      log_warn("tcp_ktls setkey: %s", strerror(errno));
      close(sockfd);
      continue;
    }
    struct tcp_rpc *rpc = tcp_init_rpc();
    rpc->client_addr = client_addr;
    rpc->conn_sockfd = sockfd;
    if (inet_ntop(AF_INET, &client_addr.sin_addr, rpc->client_addr_ip,
                  INET_ADDRSTRLEN) == NULL) {
      log_fatal("Couldn't convert client_addr to string (error %s)",
                strerror(errno));
      exit(EXIT_FAILURE);
    }
    log_info("Accepted %s:%d (rpc %p, fd %d)", rpc->client_addr_ip,
             ntohs(rpc->client_addr.sin_port), rpc, rpc->conn_sockfd);

    for (int i = 0; i < num_threads; i++) {
      int cur_thread = (last_dispatch_thread + i) % num_threads;
      struct tcp_thread_args *targs = &args[cur_thread];
      pthread_mutex_lock(&targs->lock);
      if (targs->num_conns + targs->num_conns_pending < max_conns) {
        targs->rpcs[max_conns - targs->num_conns_pending - 1] = rpc;
        log_info("Dispatched rpc %p to thread %d slot %d", rpc, cur_thread,
                 max_conns - targs->num_conns_pending - 1);
        targs->num_conns_pending++;
        last_dispatch_thread = cur_thread + 1;
        rpc = NULL;
      }
      pthread_mutex_unlock(&targs->lock);
      if (rpc == NULL) break;
    }
    if (rpc != NULL) {
      log_warn("All threads currently full, have to drop %s:%d (rpc %p, fd %d)",
               rpc->client_addr_ip, ntohs(rpc->client_addr.sin_port),
               rpc, rpc->conn_sockfd);
      tcp_release_rpc(rpc);
    }
  }

  for (int i = 0; i < num_threads; i++)
    shutdown_thread(args[i].thread, 10 * (long)1e6);
  for (int i = 0; i < num_threads; i++)
    free(args[i].rpcs);
  close(listen_sockfd);
  return 0;
}

// tcp path //

// homa / smt path //

struct homa_thread_args {
  pthread_t thread;
  int sockfd;
  int port;
  uint8_t *recv_buf_region;
  uint8_t *send_buf;
  uint32_t send_buflen;
};

static void *thread_homa(void *arg) {
  struct homa_thread_args *targs = arg;
  struct iovec vecs[HOMA_MAX_BPAGES + 1];
  struct homa_recvmsg_args control = { 0 };

  while (!sigint_received) {
    struct sockaddr_in client_addr = { 0 };
    struct msghdr recv_hdr = {
      .msg_name = &client_addr,
      .msg_namelen = sizeof(client_addr),
      .msg_control = &control,
      .msg_controllen = sizeof(control),
    };

    control.id = 0;
    control.completion_cookie = 0;
    ssize_t reqlen = recvmsg(targs->sockfd, &recv_hdr, 0);

    if (reqlen == 0) {
      log_fatal("A zero-length Homa msg was received which is abnormal");
      exit(EXIT_FAILURE);
    }
    if (reqlen < 0) {
      if (errno == EINTR) {
        log_info("Server received SIGINT, exiting...");
        break;
      }
      log_fatal("Couldn't receive Homa msg: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    int recv_vecs_len = homa_recv_build_iov(vecs, targs->recv_buf_region, reqlen,
               control.num_bpages, control.bpage_offsets);

    if (verbose_level > 0) {
      char client_ip[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
                    INET_ADDRSTRLEN) == NULL) {
        log_fatal("Couldn't convert client address to string: %s",
                  strerror(errno));
        exit(EXIT_FAILURE);
      }
      log_info("Server recv (ip %s, port %hu, reqlen %ld, rpcid %llu, serverport %d)",
               client_ip, ntohs(client_addr.sin_port), reqlen,
               (unsigned long long)control.id, targs->port);
      hexdump_iov(__func__, vecs, recv_vecs_len);
    }

    if (reqlen <= (ssize_t)sizeof(uint32_t)) {
      log_fatal("received buffer length <= resplen header size (reqlen %ld)",
                reqlen);
      exit(EXIT_FAILURE);
    }
    uint32_t resplen = *(uint32_t *)vecs[0].iov_base;

    if (resplen == 0) {
      log_fatal("invalid resp len (%u)", resplen);
      exit(EXIT_FAILURE);
    }
    if (resplen > targs->send_buflen) {
      log_fatal("resplen (%u) exceeds send_buflen (%u)",
                resplen, targs->send_buflen);
      exit(EXIT_FAILURE);
    }

    // Build response iov: first the received bytes, then pad from
    // send_buf up to resplen.
    vecs[recv_vecs_len].iov_base = targs->send_buf;
    vecs[recv_vecs_len].iov_len = targs->send_buflen;
    int total = recv_vecs_len + 1;
    uint32_t need = resplen;
    int kept = 0;

    for (int i = 0; i < total; i++) {
      if (need < vecs[i].iov_len) {
        vecs[i].iov_len = need;
        need = 0;
        kept = i + 1;
        break;
      }
      need -= vecs[i].iov_len;
      kept = i + 1;
    }
    if (need > 0) {
      log_fatal("iovecs received + send_buf can not accommedate resp_size"
                " (bytes_to_send %u, send_buflen %u)",
                need, targs->send_buflen);
      exit(EXIT_FAILURE);
    }

    struct homa_sendmsg_args send_control = {
      .id = control.id,
    };
    struct msghdr send_hdr = {
      .msg_name = &client_addr,
      .msg_namelen = sizeof(client_addr),
      .msg_iov = vecs,
      .msg_iovlen = kept,
      .msg_control = &send_control,
      .msg_controllen = 0,
    };
    if (sendmsg(targs->sockfd, &send_hdr, 0) < 0) {
      if (errno == EINTR)
        break;
      log_fatal("homa sendmsg: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  return NULL;
}

static int main_homa(void) {
  int sockfds[num_server_ports];
  size_t bufsz[num_server_ports];
  uint8_t *bufs[num_server_ports];
  uint32_t max_resp;

  if (use_google_workload) {
    uint32_t tmp;
    get_google_workload_max_rpc_size(&tmp, &max_resp);
  } else {
    max_resp = resp_size;
  }

  short base = ntohs(saddr.sin_port);

  for (int i = 0; i < num_server_ports; i++) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);

    if (fd < 0) {
      log_fatal("homa socket: %s", strerror(errno));
      return 1;
    }
    struct sockaddr_in a = saddr;

    a.sin_port = htons(base + i);
    if (bind(fd, (const struct sockaddr *)&a, sizeof(a)) < 0) {
      log_fatal("homa bind %d: %s", base + i,
          strerror(errno));
      return 1;
    }
    if (homa_init_recv_buffer(fd, &bufsz[i], &bufs[i],
            HOMA_BPAGE_NUM) == -1) {
      log_fatal("homa_init_recv_buffer: %s",
          strerror(errno));
      return 1;
    }
    if (protocol == ECHO_SMT &&
        smt_setsockopt_wrapper(fd, 0, 0, 1, 0) < 0) {
      log_fatal("smt setkey: %s", strerror(errno));
      return 1;
    }
    sockfds[i] = fd;
  }

  struct homa_thread_args args[num_threads];

  for (int i = 0; i < num_threads; i++) {
    int idx = i % num_server_ports;

    args[i].sockfd = sockfds[idx];
    args[i].port = base + idx;
    args[i].recv_buf_region = bufs[idx];
    args[i].send_buflen = max_resp;
    args[i].send_buf = malloc(max_resp);
    malloc_check(args[i].send_buf);
    setup_payload_buffer(args[i].send_buf, max_resp);
    log_info("Homa: thread %d is assigned to port %d", i, args[i].port);
  }
  launch_threads(args, num_threads, sizeof(args[0]), thread_homa);
  log_info("All threads launched, Press Ctrl+C to stop...");

  pause();
  log_info("Server received SIGINT, exiting...");
  for (int i = 0; i < num_threads; i++)
    shutdown_thread(args[i].thread, 10 * (long)1e6);
  for (int i = 0; i < num_server_ports; i++) {
    close(sockfds[i]);
    munmap(bufs[i], bufsz[i]);
  }
  for (int i = 0; i < num_threads; i++)
    free(args[i].send_buf);
  return 0;
}

// homa / smt path //

// main //

int main(int argc, char *argv[]) {
  setup_sigaction();
  parse_args(argc, argv, true);

  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;

  if (protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS)
    return main_tcp();
  if (protocol == ECHO_HOMA || protocol == ECHO_SMT)
    return main_homa();
  log_fatal("unsupported protocol %d", protocol);
  return 1;
}

// main //
