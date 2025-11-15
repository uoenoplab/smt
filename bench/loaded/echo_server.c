#include "echo.h"

struct tcp_thread_args {
  pthread_t thread;
  pthread_mutex_t lock;
  int num_conns;
  int num_conns_pending;
  struct tcp_rpc **rpcs;
};

enum TCP_RPC_STATES {
  TCP_RPC_RECV,
  TCP_RPC_SEND,
  TCP_RPC_STATES_NUM
};

// rpc is equavilent to conn for tcp here
struct tcp_rpc {
  struct sockaddr_in client_addr;
  char client_addr_ip[INET_ADDRSTRLEN];
  int sockfd;
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

// we don't reset recv_next_rpc_bytes and recv_next_rpc_bytes and recv_buf for
// next rpc which already potentially in recv_buf
void tcp_reset_rpc(struct tcp_rpc *rpc) {
  rpc->state = TCP_RPC_RECV;
  rpc->recv_len = 0;
  rpc->recv_offset = 0;
  rpc->send_remain = 0;
  rpc->send_msg.msg_iovlen = 0;
  rpc->send_msg.msg_iov = rpc->send_vecs;
  rpc->send_vecs[0].iov_base = rpc->recv_buf;
  rpc->send_vecs[1].iov_base = rpc->send_buf;
}

struct tcp_rpc *tcp_init_rpc(void) {
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

void tcp_release_rpc(struct tcp_rpc *rpc) {
  close(rpc->sockfd);
  tcp_reset_rpc(rpc);
  if (rpc->recv_buf)
    free(rpc->recv_buf);
  if (rpc->send_buf)
    free(rpc->send_buf);
  free(rpc);
}

void tcp_disconnect_rpc(struct tcp_thread_args *targs, struct tcp_rpc *rpc) {
  log_info("Disconnecting rpc %p with fd %d", rpc, rpc->sockfd);
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

#if defined MAKE_IOURING
void tcp_issue_recv(struct io_uring *ring, struct tcp_rpc *rpc) {
  int ret = add_recv_request(ring, rpc->sockfd, rpc->recv_buf + rpc->recv_offset,
    rpc->recv_buflen - rpc->recv_offset, rpc, true);
  if (ret != 0) {
    log_fatal("add_recv_request failed");
    exit(EXIT_FAILURE);
  }
}
#elif defined MAKE_EPOLL
// return 0 if EAGAIN, -1 if error or no bytes received, bytes_received if success
ssize_t tcp_issue_recv(struct tcp_rpc *rpc) {
  int bytes_received = recv(rpc->sockfd, rpc->recv_buf + rpc->recv_offset,
    rpc->recv_buflen - rpc->recv_offset, 0);
  log_debug("recv returned %d", bytes_received);
  if ((bytes_received == 0) || (bytes_received == -1 && errno != EAGAIN)) {
    log_fatal("recv fail (ret %d, error %s)", bytes_received, strerror(errno));
    return -1;
  }
  if (bytes_received == -1 && errno == EAGAIN) {
    return 0;
  }
  return bytes_received;
}
#endif

ssize_t tcp_parse_rpc_header(struct tcp_rpc *rpc) {
  struct rpc_header *rpc_recvhdr = (struct rpc_header *)rpc->recv_buf;

  if (rpc_recvhdr->magic_number != MAGIC_NUMBER) {
    log_error("received a RPC with invalid magicnumber header");
    return -1;
  }

  if (rpc_recvhdr->reqlen > 0 && rpc_recvhdr->reqlen <= rpc->recv_buflen - sizeof(struct rpc_header)) {
    rpc->recv_len = rpc_recvhdr->reqlen + sizeof(struct rpc_header);
  } else {
    log_error("invalid (too long or zero) req len %d (rpc->recv_buflen %d)",
      rpc_recvhdr->reqlen, rpc->recv_buflen);
    return -1;
  }

  if (rpc_recvhdr->resplen > 0 && (rpc_recvhdr->resplen - rpc_recvhdr->reqlen) <= rpc->send_buflen) {
    rpc->send_remain = rpc_recvhdr->resplen + sizeof(struct rpc_header);
  } else {
    log_error("invalid (too long or zero) resp len %d (rpc->send_buflen %d)",
      rpc_recvhdr->resplen, rpc->recv_buflen);
    return -1;
  }

  return 0;
}

ssize_t tcp_handle_recv(struct tcp_rpc *rpc, ssize_t bytes_received) {
  log_debug("bytes_received %ld (fd %d)", bytes_received, rpc->sockfd);
  if (bytes_received == 0) {
    log_warn("no bytes received, drop conn %d", rpc->sockfd);
    return -1;
  }

  rpc->recv_offset += bytes_received;

  if (!rpc->recv_len && (rpc->recv_offset >= sizeof(struct rpc_header))) {
    if (tcp_parse_rpc_header(rpc) == -1) {
      log_warn("RPC header parsing failed");
      return -1;
    }
  }

  if (rpc->recv_offset >= rpc->recv_len) {
    rpc->state = TCP_RPC_SEND;
  }

  if (rpc->recv_offset > rpc->recv_len) {
    rpc->recv_next_rpc_bytes = rpc->recv_offset - rpc->recv_len;
    rpc->recv_next_rpc_offset = rpc->recv_len;
  }

  return 0;
}

// return 0 if 1. reply done 2. (iouring) add_sendmsg_request done 3. (epoll) sendmsg return EAGAIN
// return bytes_sent (>0) if sendmsg success
// return -1 if error
#if defined MAKE_IOURING
ssize_t tcp_reply(struct io_uring *ring, struct tcp_rpc *rpc, int bytes_sent) {
#elif defined MAKE_EPOLL
ssize_t tcp_reply(struct tcp_rpc *rpc, int bytes_sent) {
#endif
  if (rpc->send_msg.msg_iovlen == 0) {
    // if msg_iovlen == 0, it means this rpc is under clean state and
    // we need to initialize send iovec
    if ((bytes_sent != 0) && (bytes_sent != INT_MAX)) {
      log_fatal("msg_iovlen is zero, no bytes_sent can be handled");
      exit(EXIT_FAILURE);
    }
    if (rpc->send_remain <= rpc->recv_len) {
      rpc->send_msg.msg_iovlen = 1;
      rpc->send_vecs[0].iov_len = rpc->send_remain;
      log_trace("msg_iovlen 1 vec[0].iov_len %d", rpc->send_remain);
    } else {
      rpc->send_msg.msg_iovlen = 2;
      rpc->send_vecs[0].iov_len = rpc->recv_len;
      rpc->send_vecs[1].iov_len = rpc->send_remain - rpc->recv_len;
      log_trace("msg_iovlen 2 vec[0].iov_len %d vec[1].iov_len %d",
        rpc->recv_len, rpc->send_remain - rpc->recv_len);
    }
  } else {
    if (bytes_sent == INT_MAX) {
      log_debug("resume send");
    } else {
      // if msg_iovlen > 0, it means we have already initialized send buffer and
      // sent some bytes
      log_trace("rpc->send_remain %d bytes_sent %d", rpc->send_remain, bytes_sent);

      if (bytes_sent <= 0) {
        log_warn("invalid bytes_sent %d", bytes_sent);
        return -1;
      }

      rpc->send_remain -= bytes_sent;

      if (rpc->send_remain == 0) {
        tcp_reset_rpc(rpc);
        return 0;
      }

      while (bytes_sent > 0 && rpc->send_msg.msg_iovlen > 0) {
        if ((size_t)bytes_sent < rpc->send_msg.msg_iov->iov_len) {
          rpc->send_msg.msg_iov->iov_base = (char *)rpc->send_msg.msg_iov->iov_base + bytes_sent;
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

#if defined MAKE_IOURING
  if (add_sendmsg_request(ring, rpc->sockfd, &rpc->send_msg, 0, rpc, true) != 0) {
    log_fatal("add_sendmsg_request failed");
    exit(EXIT_FAILURE);
  }

  return 0;
#elif defined MAKE_EPOLL
  bytes_sent = sendmsg(rpc->sockfd, &rpc->send_msg, 0);
  log_debug("sendmsg returned %d", bytes_sent);
  if ((bytes_sent == 0) || (bytes_sent == -1 && errno != EAGAIN)) {
    log_fatal("sendmsg fail (ret %d, error %s)", bytes_sent, strerror(errno));
    return -1;
  }
  if (bytes_sent == -1 && errno == EAGAIN) {
    return 0;
  }
  return bytes_sent;
#endif
}

void *thread_tcp(void *args) {
  int ret = 0;
  struct tcp_thread_args *targs = (struct tcp_thread_args *)args;

#if defined MAKE_IOURING
  struct io_uring ring;
  io_uring_queue_init(max_conns * 2, &ring, 0);
#elif defined MAKE_EPOLL
  struct epoll_event events[max_conns + 1];
  memset(events, 0, sizeof(struct epoll_event) * (max_conns + 1));
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    log_fatal("epoll_create1 (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
#endif

  while (!sigint_received) {
    if ((targs->num_conns_pending > 0) || (targs->num_conns == 0)) {
      pthread_mutex_lock(&targs->lock);
      if (targs->num_conns_pending > 0) {
        log_trace("num_conns %d num_conns_pending %d",
          targs->num_conns, targs->num_conns_pending);
        struct tcp_rpc *rpc = targs->rpcs[max_conns - targs->num_conns_pending];
        targs->rpcs[max_conns - targs->num_conns_pending] = NULL;
        targs->rpcs[targs->num_conns] = rpc;
#if defined MAKE_IOURING
        tcp_issue_recv(&ring, targs->rpcs[targs->num_conns]);
#elif defined MAKE_EPOLL
        set_socket_nonblocking(rpc->sockfd);
        add_event(epoll_fd, rpc->sockfd, EPOLLIN | EPOLLRDHUP, rpc);
#endif
        targs->num_conns++;
        targs->num_conns_pending--;
      }
      pthread_mutex_unlock(&targs->lock);
      continue;
    }

#if defined MAKE_IOURING

    struct io_uring_cqe *cqe = NULL;
#ifdef MAKE_IOURING_NONBLOCK
    struct __kernel_timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
    ret = io_uring_wait_cqe_timeout(&ring, &cqe, &timeout);
#else
    ret = io_uring_wait_cqe(&ring, &cqe);
#endif
    if (ret == -EAGAIN || ret == -ETIME) {
      log_debug("io_uring_wait_cqe (errno %d error %s)", -ret, strerror(-ret));
      continue;
    } else if (ret != 0) {
      log_fatal("io_uring_wait_cqe (errno %d error %s)", -ret, strerror(-ret));
      exit(EXIT_FAILURE);
    }

    struct tcp_rpc *rpc = io_uring_cqe_get_data(cqe);
    if (!rpc) {
      log_error("received a CQE with no associated data");
      io_uring_cqe_seen(&ring, cqe);
      continue;
    }

    log_debug("cqe->res %d", cqe->res);
    if (cqe->res < 0) {
      log_warn("syscall failed (rpc %p, state %d, error %s)\n",
        rpc, rpc->state, strerror(-cqe->res));
      io_uring_cqe_seen(&ring, cqe);
      tcp_disconnect_rpc(targs, rpc);
      continue;
    }

process_rpc:

    switch (rpc->state) {
      case TCP_RPC_RECV:
        if (tcp_handle_recv(rpc, cqe->res) != 0) {
          tcp_disconnect_rpc(targs, rpc);
        } else {
          if (rpc->state == TCP_RPC_SEND) {
            tcp_reply(&ring, rpc, 0);
          } else {
            tcp_issue_recv(&ring, rpc);
          }
        }
        break;
      case TCP_RPC_SEND:
        if (tcp_reply(&ring, rpc, cqe->res) != 0) {
          tcp_disconnect_rpc(targs, rpc);
        } else {
          if (rpc->state == TCP_RPC_RECV) {
            if (rpc->recv_next_rpc_bytes) {
              memmove(rpc->recv_buf, rpc->recv_buf + rpc->recv_next_rpc_offset, rpc->recv_next_rpc_bytes);
              cqe->res = rpc->recv_next_rpc_bytes;
              rpc->recv_next_rpc_bytes = 0;
              rpc->recv_next_rpc_offset = 0;
              goto process_rpc;
            } else {
              tcp_issue_recv(&ring, rpc);
            }
          }
        }
        break;
      default:
        log_fatal("RPC state is invalid (%d)", rpc->state);
        exit(EXIT_FAILURE);
        break;
    }

    io_uring_cqe_seen(&ring, cqe);

#elif defined MAKE_EPOLL
    int event_count = epoll_wait(epoll_fd, events, max_conns + 1, epoll_wait_timeout);
    if (event_count == -1) {
      if (errno == EAGAIN) {
        continue;
      } else if (errno == EINTR) {
        goto threadloop_end;
      } else {
        log_fatal("epoll_wait (error %s)", strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

    for (int i = 0; i < event_count; i++)
    {
      struct tcp_rpc *rpc = events[i].data.ptr;
      if (events[i].events & EPOLLIN || events[i].events & EPOLLOUT) {
        // call recv until a complete RPC is ready to send or EAGAIN occurs
        // try to reply the rpc right after a complete rpc is received
        if (events[i].events & EPOLLIN) {
          while (true) {
            ret = tcp_issue_recv(rpc);
            if (ret == -1 || ret == 0) {
              break;
            }
process_recv_buf:
            ret = tcp_handle_recv(rpc, ret);
            if (ret == -1 || rpc->state == TCP_RPC_SEND) {
              break;
            }
          }
          if (ret == -1) {
            log_warn("tcp_issue_recv trigger disconnect");
            tcp_disconnect_rpc(targs, rpc);
            continue;
          }
        }
        if (rpc->state == TCP_RPC_SEND) {
          // call send until send return EAGIN or whole rpc sent out
          ret = INT_MAX;
          while (true) {
            ret = tcp_reply(rpc, ret);
            if (ret == 0 || ret == -1) {
              break;
            }
          }
          if (ret == -1) {
            log_warn("tcp_reply trigger disconnect");
            tcp_disconnect_rpc(targs, rpc);
            continue;
          }
          if (rpc->state == TCP_RPC_RECV && rpc->recv_next_rpc_bytes) {
            memmove(rpc->recv_buf, rpc->recv_buf + rpc->recv_next_rpc_offset, rpc->recv_next_rpc_bytes);
            ret = rpc->recv_next_rpc_bytes;
            rpc->recv_next_rpc_bytes = 0;
            rpc->recv_next_rpc_offset = 0;
            goto process_recv_buf;
          }
        }
        if (rpc->state == TCP_RPC_RECV && events[i].events & EPOLLOUT) {
          modify_event(epoll_fd, rpc->sockfd, EPOLLIN | EPOLLRDHUP, rpc);
        }
        if (rpc->state == TCP_RPC_SEND && events[i].events & EPOLLIN) {
          modify_event(epoll_fd, rpc->sockfd, EPOLLOUT | EPOLLRDHUP, rpc);
        }
      } else {
        log_warn("unhandled event (fd %d events %d)\n", rpc->sockfd, events[i].events);
        tcp_disconnect_rpc(targs, rpc);
        continue;
      }
    }
#endif
  }

#ifdef MAKE_EPOLL
threadloop_end:
#endif

  pthread_mutex_lock(&targs->lock);
  for (int i = 0; i < max_conns; i++)
  {
    if (targs->rpcs[i]) {
      tcp_release_rpc(targs->rpcs[i]);
    }
  }
  // Set num_conns to max_conns so main thread is unable to fill more rpc
  targs->num_conns = max_conns;
  targs->num_conns_pending = 0;
  pthread_mutex_unlock(&targs->lock);

#if defined MAKE_IOURING
  io_uring_queue_exit(&ring);
#elif defined MAKE_EPOLL
  close(epoll_fd);
#endif

  return NULL;
}

int main_tcp(void) {
  int enable = 1;

  int listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sockfd < 0) {
    perror("Couldn't open socket");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable,
                 sizeof(int)) < 0) {
    perror("setsockopt SO_REUSEADDR failed");
    exit(EXIT_FAILURE);
  }

  if (bind(listen_sockfd, (struct sockaddr *)&saddr,
           sizeof(struct sockaddr_in)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(listen_sockfd, SOMAXCONN) < 0) {
    perror("listen failed");
    exit(EXIT_FAILURE);
  }

  struct tcp_thread_args args_list[num_threads];
  for (int i = 0; i < num_threads; i++) {
    args_list[i].rpcs = calloc(sizeof(struct tcp_rpc *), max_conns);
    malloc_check(args_list[i].rpcs);
    args_list[i].num_conns = 0;
    args_list[i].num_conns_pending = 0;
    pthread_mutex_init(&args_list[i].lock, NULL);
  }

  launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_tcp);

  log_info("All threads launched, Press Ctrl+C to stop...");

  size_t last_dispatch_thread = 0;
  while (!sigint_received) {
    struct sockaddr_in client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    int sockfd = accept(listen_sockfd, (struct sockaddr *)&client_addr,
      (socklen_t *)&client_addrlen);

    if (sockfd > 0) {
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt TCP_QUICKACK");
        exit(EXIT_FAILURE);
      }
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt TCP_QUICKACK");
        exit(EXIT_FAILURE);
      }

      if (protocol == ECHO_TCP_KTLS) {
        if (tcpktls_setsockopt_wrapper(sockfd, 1, 0) < 0) {
          log_fatal("Couldn't set KTLS to the socket: %s", strerror(errno));
          exit(EXIT_FAILURE);
        }
      }

      struct tcp_rpc *rpc = tcp_init_rpc();
      rpc->client_addr = client_addr;
      rpc->sockfd = sockfd;

      if (inet_ntop(AF_INET, &client_addr.sin_addr, rpc->client_addr_ip, INET_ADDRSTRLEN) == NULL) {
        log_fatal("Couldn't convert client_addr to string (error %s)", strerror(errno));
        exit(EXIT_FAILURE);
      }

      log_info("Accepted %s:%d (rpc %p, fd %d)", rpc->client_addr_ip,
        ntohs(rpc->client_addr.sin_port), rpc, rpc->sockfd);

      for (int i = 0; i < num_threads; i++) {
        int cur_thread = (last_dispatch_thread + i) % num_threads;
        struct tcp_thread_args *targs = &args_list[cur_thread];
        pthread_mutex_lock(&targs->lock);
        log_trace("num_conns %d num_conns_pending %d",
          targs->num_conns, targs->num_conns_pending);
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
          rpc->client_addr_ip, ntohs(rpc->client_addr.sin_port), rpc, rpc->sockfd);
        tcp_release_rpc(rpc);
      }
    } else if (errno == EINTR) {
      printf("\n");
      log_info("Server received SIGINT, exiting...\n");
      break;
    } else {
      log_fatal("Listen socekt accept failed (ret %d, error %s)",
        sockfd, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  for (int i = 0; i < num_threads; i++) {
    shutdown_thread(args_list[i].thread, 10 * 1e6);
    free(args_list[i].rpcs);
  }

  close(listen_sockfd);

  return 0;
}

struct homa_thread_args {
  pthread_t thread;
  int port;
  int sockfd;
  uint8_t *recv_buf_region;
};

void *thread_homa(void *args) {
  struct homa_thread_args *targs = (struct homa_thread_args *)args;

  int sockfd = targs->sockfd;
  uint8_t *recv_buf_region = targs->recv_buf_region;
  struct iovec vecs[HOMA_MAX_BPAGES + 1];
  struct sockaddr_in client_addr;
  uint8_t *send_buf = NULL;
  uint32_t send_buflen = 0;

  if (use_google_workload) {
    uint32_t tmp;
    get_google_workload_max_rpc_size(&tmp, &send_buflen);
  } else {
    send_buflen = resp_size;
  }
  send_buf = malloc(send_buflen);
  malloc_check(send_buf);
  setup_payload_buffer(send_buf, send_buflen);

  // Keep num_bpages and bpage_offsets so can return the buffer to Homa
  struct homa_recvmsg_args control = { 0 };
  control.flags = HOMA_RECVMSG_REQUEST;
#ifdef MAKE_ONESOCK_NONBLOCK
  control.flags = HOMA_RECVMSG_REQUEST | HOMA_RECVMSG_NONBLOCKING;
#endif

  while (!sigint_received) {
    control.id = 0;
    control.completion_cookie = 0;

    struct msghdr hdr = { 0 };
    memset(&client_addr, 0, sizeof(client_addr));
    hdr.msg_name = &client_addr;
    hdr.msg_namelen = sizeof(client_addr);
    hdr.msg_control = &control;
    hdr.msg_controllen = sizeof(control);

    ssize_t reqlen = recvmsg(sockfd, &hdr, 0);
    if (reqlen == 0) {
      log_fatal("A zero-length Homa msg was received which is abnormal");
      exit(EXIT_FAILURE);
    } else if (reqlen < 0) {
      if (errno == EAGAIN) {
        control.num_bpages = 0;
        continue;
      }
      if (errno == EINTR) {
        log_info("Server received SIGINT, exiting...");
        break;
      }
      log_fatal("Couldn't receive Homa msg: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    int recv_vecs_len = homa_recv_build_iov(vecs, recv_buf_region, reqlen,
      control.num_bpages, control.bpage_offsets);

#ifdef BUILD_HOMA_CSUM
    volatile uint16_t csum;
    // not real compare
    if (protocol == ECHO_HOMA_CSUM) {
      csum = homa_iovec_checksum(vecs, recv_vecs_len);
      memcpy((void *)&csum, vecs[0].iov_base, sizeof(csum));
    }
#endif

    if (verbose_level > 0) {
      char client_ip[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
                    INET_ADDRSTRLEN) == NULL) {
        log_fatal("Couldn't convert client address to string (inet_ntop): %s\n",
               strerror(errno));
        exit(EXIT_FAILURE);
      }
      log_info("Server recv (ip %s, port %hu, reqlen %ld, rpcid %ld, serverport %d)",
        client_ip, ntohs(client_addr.sin_port), reqlen, control.id, targs->port);
      hexdump_iov(__func__, vecs, recv_vecs_len);
    }

#ifdef BUILD_HOMA_CSUM
    // not real compare
    if (protocol == ECHO_HOMA_CSUM) {
      int send_csum = homa_iovec_checksum(vecs, recv_vecs_len);
      memcpy((void *)&csum, vecs[0].iov_base, sizeof(csum));
      if (send_csum != csum) {
        csum = send_csum;
      }
    }
#endif

    uint32_t resplen;
    if (reqlen <= (uint32_t)sizeof(resplen)) {
      log_fatal("received buffer length <= resplen header size (reqlen %ld)", reqlen);
      exit(EXIT_FAILURE);
    }

    resplen = *(uint32_t *)(vecs[0].iov_base);
    if (resplen == 0) {
      log_fatal("invalid resp len (%d)", resplen);
      exit(EXIT_FAILURE);
    }

    int send_vecs_len = recv_vecs_len + 1;
    vecs[recv_vecs_len].iov_base = send_buf;
    vecs[recv_vecs_len].iov_len = send_buflen;

    int i = 0;
    uint32_t bytes_to_send = resplen;
    for (; i < send_vecs_len; i++)
    {
      if (bytes_to_send < vecs[i].iov_len) {
        vecs[i].iov_len = bytes_to_send;
        bytes_to_send = 0;
        i++;
        break;
      } else {
        bytes_to_send -= vecs[i].iov_len;
      }
    }
    if (bytes_to_send > 0) {
      log_fatal("iovecs received + send_buf can not accommedate resp_size"
        " (bytes_to_send %d, send_buflen %d)", bytes_to_send, send_buflen);
      exit(EXIT_FAILURE);
    }
    send_vecs_len = i;

    if (homa_replyv(sockfd, vecs, send_vecs_len, (const sockaddr_in_union *)&client_addr, control.id) == -1) {
      log_fatal("Couldn't send Homa msg: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  if (send_buf)
    free(send_buf);

  return NULL;
}

int main_homa(void) {
  int sockfds[num_server_ports];
  size_t recv_buf_sizes[num_server_ports];
  uint8_t *recv_buf_regions[num_server_ports];
  short base_port = ntohs(saddr.sin_port);

  // Open Homa sockets and init recv buffers
  for (int i = 0; i < num_server_ports; i++) {
    int sockfd;
    size_t recv_buf_size;
    uint8_t *recv_buf_region;
    struct sockaddr_in saddr_cur = saddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
    if (sockfd < 0) {
      printf("Couldn't open Homa socket: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    saddr_cur.sin_port = htons(base_port + i);
    if (bind(sockfd, (struct sockaddr *)&saddr_cur, sizeof(saddr_cur)) == -1) {
      printf("Couldn't bind Homa: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (homa_init_recv_buffer(sockfd, &recv_buf_size, &recv_buf_region, HOMA_BPAGE_NUM) == -1) {
      printf("Couldn't init recv buffer: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (protocol == ECHO_SMT) {
      if (smt_setsockopt_wrapper(sockfd, 0, 0, 1, 0) < 0) {
        printf("Couldn't set SMT key to the socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

    sockfds[i] = sockfd;
    recv_buf_sizes[i] = recv_buf_size;
    recv_buf_regions[i] = recv_buf_region;
  }

  // Assign threads to ports in round-robin fashion
  struct homa_thread_args args_list[num_threads];
  for (int i = 0; i < num_threads; i++) {
    int sockfd_idx = i % num_server_ports;
    args_list[i].port = base_port + sockfd_idx;
    args_list[i].sockfd = sockfds[sockfd_idx];
    args_list[i].recv_buf_region = recv_buf_regions[i];
    log_info("Homa: thread %ld is assigned to port %ld", i, args_list[i].port);
  }

  launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_homa);

  log_info("All threads launched, Press Ctrl+C to stop...");
  pause();
  log_info("Server received SIGINT, exiting...");

  for (int i = 0; i < num_threads; i++) {
    shutdown_thread(args_list[i].thread, 10 * 1e6);
  }

  for (int i = 0; i < num_server_ports; i++) {
    close(sockfds[i]);
    munmap(recv_buf_regions[i], recv_buf_sizes[i]);
  }

  return 0;
}

#ifdef BUILD_TCPLS

struct tcpls_thread_args {
  pthread_t thread;
  int listen_sockfd;
};

struct tcpls_bench {
  tcpls_t *tcpls;
  int sockfd;
  streamid_t sid;
  tcpls_buffer_t *recvbufs;
};

static int tcpls_handle_conn_event(tcpls_t *tcpls, tcpls_event_t ev, int
                             socket, int transportid, void *cbdata) {
  switch (ev) {
  case CONN_CLOSED:
  case CONN_FAILED:
    // it is normal exit since we can not handle it anyway
    fprintf(stdout, "%s: connection closed or failed\n", __func__);
    exit(0);
    break;
  case CONN_OPENED:
    break;
  default:
    break;
  }
  return 0;
}

int tcpls_accept_new_conn(struct tcpls_bench *tbench, struct pollfd *pfd,
  ptls_context_t *ctx, int listen_sockfd) {

  int new_sockfd = accept(listen_sockfd, NULL, NULL);
  if (new_sockfd == -1) {
    return -1;
  }

  tbench->sockfd = new_sockfd;
  struct sockaddr_in our_addr = { 0 };
  socklen_t slen = sizeof(our_addr);
  getsockname(tbench->sockfd, (struct sockaddr *)&our_addr, &slen);

  tbench->tcpls = tcpls_new(ctx, 1);
  tcpls_add_v4(tbench->tcpls->tls, &our_addr, 1, 1, 1);
  int ret = tcpls_accept(tbench->tcpls, tbench->sockfd, NULL, 0);
  if (ret < 0) {
    fprintf(stderr, "failed tcpls_accept\n");
    exit(EXIT_FAILURE);
  }

  ptls_handshake_properties_t hsprop = {{{{NULL}}}};
  hsprop.socket = tbench->sockfd;

  pfd->fd = tbench->sockfd;
  pfd->events = POLLIN;

  tcpls_set_user_timeout(tbench->tcpls, 0, 250, 0, 1, 1);

  ret = tcpls_handshake(tbench->tcpls->tls, &hsprop);
  if (ret != 0) {
    fprintf(stderr, "handshake failed: %d\n", ret);
    exit(EXIT_FAILURE);
  }

  tbench->recvbufs = tcpls_stream_buffers_new(tbench->tcpls, 1);
  return 0;
}

void *thread_tcpls(void *args) {
  struct tcpls_thread_args *targs = (struct tcpls_thread_args *) args;
  ptls_key_exchange_algorithm_t *key_exchanges[1] = {&ptls_openssl_secp256r1};
  ptls_cipher_suite_t *cipher_suites[1] = {&ptls_openssl_aes128gcmsha256};
  ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges,
    cipher_suites};
  static ptls_openssl_sign_certificate_t sc;
  FILE *fp;
  EVP_PKEY *pkey;
  struct tcpls_bench tbenchs[max_conns];
  struct pollfd pfds[max_conns];

  memset(tbenchs, 0, sizeof(tbenchs));
  memset(pfds, 0, sizeof(pfds));

  ctx.support_tcpls_options = 1;
  ctx.connection_event_cb = &tcpls_handle_conn_event;

  char bin_path[PATH_MAX] = { 0 };
  char path[PATH_MAX] = { 0 };
  int bin_path_len = readlink("/proc/self/exe", bin_path, sizeof(bin_path) - 1);
  if (bin_path_len == -1) {
      perror("readlink");
      exit(EXIT_FAILURE);
  }
  for (int i = strlen(bin_path) - 1; i >= 0; i--) {
    if (bin_path[i] == '/') {
      bin_path[i+1] = '\0'; // Terminate the string right after the last '/'
      break;
    }
  }

  strcpy(path, bin_path);
  strcat(path, "tcpls/server.cert");
  if (ptls_load_certificates(&ctx, path) != 0) {
    fprintf(stderr, "failed to load certificate:%s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  strcpy(path, bin_path);
  strcat(path, "tcpls/server.key");
  fp = fopen(path, "rb");
  if (fp == NULL) {
    fprintf(stderr, "failed to load key\n");
    exit(EXIT_FAILURE);
  }

  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if (pkey == NULL) {
    fprintf(stderr, "failed to read private key\n");
    exit(EXIT_FAILURE);
  }

  ptls_openssl_init_sign_certificate(&sc, pkey);
  EVP_PKEY_free(pkey);

  ctx.sign_certificate = &sc.super;

  int num_conns = 0;
  struct timeval timeout = { 0 };
  while (!sigint_received) {
    int ret = 0;
    /* if it is possible, we want to accept more than one connection */
    while (num_conns < max_conns && ret == 0) {
      ret = tcpls_accept_new_conn(&tbenchs[num_conns], &pfds[num_conns], &ctx,
        targs->listen_sockfd);
      if (ret == 0) {
        log_info("new conn accepted");
        num_conns++;
      }
    }

    if (num_conns == 0) {
      continue;
    }

    int nfds_ready = poll(pfds, (nfds_t)num_conns, 1);
    if (nfds_ready == -1) {
      fprintf(stderr, "poll() failed\n");
      exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_conns && nfds_ready > 0; i++) {
      if ((pfds[i].revents & POLLIN) == 0) {
        continue;
      } else {
        nfds_ready--;
      }

      ret = -1;
      while (ret != TCPLS_OK) {
        ret = tcpls_receive(tbenchs[i].tcpls->tls, tbenchs[i].recvbufs, &timeout);
        if (ret == -1) {
          fprintf(stderr, "tcpls_receive() failed\n");
          exit(EXIT_FAILURE);
        }
      }

      for (int j = 0; j < tbenchs[i].recvbufs->wtr_streams->size; j++) {
        streamid_t *sid_ptr = list_get(tbenchs[i].recvbufs->wtr_streams, j);
        ptls_buffer_t *buf = tcpls_get_stream_buffer(tbenchs[i].recvbufs, *sid_ptr);

        if (buf) {
          while (tcpls_send(tbenchs[i].tcpls->tls, *sid_ptr, buf->base, buf->off) == TCPLS_HOLD_DATA_TO_SEND);
          buf->off = 0;
        }
      }
    }

    if (nfds_ready != 0) {
      fprintf(stderr, "nfds_ready (%d) should be 0 after traverse all connetions\n"
        , nfds_ready);
      exit(EXIT_FAILURE);
    }
  }

  for (int i = 0; i < num_conns; ++i) {
    close(tbenchs[i].sockfd);
    tcpls_free(tbenchs[i].tcpls);
  }

  return 0;
}

int main_tcpls(void) {
  int qlen = 5, on = 1;

  int listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sockfd == -1) {
    fprintf(stderr, "socket(2) failed\n");
    return 1;
  }

  if (setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
    fprintf(stderr, "setsockopt(SOL_REUSEADDR) failed\n");
    return 1;
  }

  if (setsockopt(listen_sockfd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) != 0) {
    fprintf(stderr, "setsockopt(SOL_FASTOPEN) failed\n");
    return 1;
  }

  if (bind(listen_sockfd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in)) != 0) {
    fprintf(stderr, "bind(2) failed: %s\n", strerror(errno));
    return 1;
  }

  if (listen(listen_sockfd, SOMAXCONN) != 0) {
    fprintf(stderr, "listen(2) failed\n");
    return 1;
  }

  fcntl(listen_sockfd, F_SETFL, O_NONBLOCK);

  struct tcpls_thread_args args_list[num_threads];

  for (size_t i = 0; i < num_threads; i++) {
    args_list[i].listen_sockfd = listen_sockfd;
  }

  launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_tcpls);

  printf("All threads launched, Press Ctrl+C to stop...\n");
  pause();
  printf("Server received SIGINT, exiting...\n");

  for (size_t i = 0; i < num_threads; i++) {
    shutdown_thread(args_list[i].thread, 10 * 1e6);
  }

  close(listen_sockfd);

  return 0;
}
#endif

int main(int argc, char *argv[]) {
  setup_sigaction();

  parse_args(argc, argv, true);

  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;

  if (protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS) {
    return main_tcp();
  } else if (protocol == ECHO_HOMA || protocol == ECHO_SMT
#ifdef BUILD_HOMA_CSUM
    || protocol == ECHO_HOMA_CSUM
#endif
  ) {
    return main_homa();
#ifdef BUILD_TCPLS
  } else if (protocol == ECHO_TCPLS) {
    return main_tcpls();
#endif
  }
}
