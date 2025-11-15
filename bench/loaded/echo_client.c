#include "echo.h"
#include "../util/rtts.h"

struct rate_limit_context {
  struct timespec last_time;
  double rate; // bytes per second
  double budget;
};

void rate_limit_init(double rate, struct rate_limit_context *rate_limit) {
  rate_limit->rate = rate;
  rate_limit->budget = 0.0;
  memset(&rate_limit->last_time, 0, sizeof(rate_limit->last_time));
}

void rate_limit_sleep(double wait_time) {
  // sleep if more than 1us
  if (wait_time > 0.000001) {
    struct timespec ts;
    ts.tv_sec = (time_t)wait_time;
    ts.tv_nsec = (long)((wait_time - ts.tv_sec) * 1e9);
    log_debug("sleeping for %ld.%09ld seconds", ts.tv_sec, ts.tv_nsec);
    nanosleep(&ts, NULL);
  }
}

// return time need to wait
double rate_limit_try_send(struct rate_limit_context *rate_limit, uint32_t bytes_to_send) {
  if (net_mbps == 0.0) {
    log_debug("no rate limit");
    return 0.0;
  }

  struct timespec current_time;
  clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);

  // always allow first send go out
  if (rate_limit->last_time.tv_nsec == 0 && rate_limit->last_time.tv_sec == 0) {
    rate_limit->last_time = current_time;
    rate_limit->budget += bytes_to_send;
  }

  double time_elapsed = calculate_time_delta_s(current_time, rate_limit->last_time);
  rate_limit->last_time = current_time;
  rate_limit->budget += time_elapsed * rate_limit->rate;
  if (rate_limit->budget >= (double)bytes_to_send) {
    rate_limit->budget -= (double)bytes_to_send;
    if (rate_limit->budget > rate_limit->rate) {
      rate_limit->budget = rate_limit->rate;
    }
    log_debug("can send (budget %f rate %f time_elapsed %f)", rate_limit->budget, rate_limit->rate, time_elapsed);
    return 0.0;
  } else {
    log_debug("cannot send (budget %f rate %f time_elapsed %f)", rate_limit->budget, rate_limit->rate, time_elapsed);
    return ((double)bytes_to_send - rate_limit->budget) / rate_limit->rate;
  }
}

struct thread_args {
  pthread_t thread;
  int thread_id;
  int num_rpcs;
  struct sockaddr_in *saddrs;
  int saddrs_offset;
  struct rate_limit_context rate_limit;
  struct histogram rtt_hist;
  struct timespec bench_start;
  struct timespec bench_end;
};

void stats_bench(struct thread_args *args_list) {
  struct histogram rtt_hists[num_threads];
  size_t max_rtt_count = 0, min_rtt_count = SIZE_MAX;
  double kops_per_sec = 0.0;

  for (int i = 0; i < num_threads; i++) {
    rtt_hists[i] = args_list[i].rtt_hist;

    if (args_list[i].bench_start.tv_sec == 0 && args_list[i].bench_start.tv_nsec == 0) {
      log_warn("thread_id %d bench_start is zero", args_list[i].thread_id);
      continue;
    }

    if (args_list[i].bench_end.tv_sec == 0 && args_list[i].bench_end.tv_nsec == 0) {
      log_warn("thread_id %d bench_end is zero", args_list[i].thread_id);
      continue;
    }

    size_t rtt_count = rtt_hists[i].total_data_points;

    if (rtt_count == 0)
      continue;

    if (rtt_count > max_rtt_count) max_rtt_count = rtt_count;
    if (rtt_count < min_rtt_count) min_rtt_count = rtt_count;

    double thread_time = calculate_time_delta_s(args_list[i].bench_start,
                                                args_list[i].bench_end);

    log_debug("thread_id %d saddrs_offset %d rtt_count %ld thread_time %lf\n",
      args_list[i].thread_id, args_list[i].saddrs_offset, rtt_count, thread_time);

    kops_per_sec += ((double)rtt_count / thread_time) / 1000.0;
  }

  struct histogram combined_hist = create_histogram();
  merge_histograms(&combined_hist, rtt_hists, num_threads);

  size_t total_rtt_count = combined_hist.total_data_points;
  double avg_req_size = combined_hist.total_req_size / combined_hist.total_data_points;
  double avg_resp_size = combined_hist.total_resp_size / combined_hist.total_data_points;
  double throughput_mbps_tx = (kops_per_sec * 1000.0) * avg_req_size * 8.0 / (1000.0 * 1000.0);
  double throughput_mbps_rx = (kops_per_sec * 1000.0) * avg_resp_size * 8.0 / (1000.0 * 1000.0);
  double avg = calculate_average(&combined_hist);
  double avg_stddev = calculate_stddev(&combined_hist, &avg);
  double percentiles[] = {50.0, 95.0, 99.0};
  double percentile_results[3];
  calculate_percentiles(&combined_hist, percentiles, percentile_results, 3);

  free_histogram(&combined_hist);

  printf("\n--- RESULT ---\n");
  printf("{\n");
  printf("  \"total_rpcs\": %ld,\n", total_rtt_count);
  printf("  \"max_per_thread\": %ld,\n", max_rtt_count);
  printf("  \"min_per_thread\": %ld,\n", min_rtt_count);
  printf("  \"avg_per_thread\": %.2lf,\n", (double)total_rtt_count / (double)num_threads);
  printf("  \"kops_per_second\": %.2lf,\n", kops_per_sec);
  printf("  \"tx_throughput_mbps\": %.2lf,\n", throughput_mbps_tx);
  if (net_mbps != 0.0)
    printf("  \"tx_throughput_mbps_relative_error_percentage\": %.2lf,\n",
      100 * fabs(throughput_mbps_tx - net_mbps) / net_mbps);
  printf("  \"rx_throughput_mbps\": %.2lf,\n", throughput_mbps_rx);
  printf("  \"average_rtt_us\": %.2lf,\n", avg);
  printf("  \"average_stddev_rtt_us\": %.2lf,\n", avg_stddev);
  printf("  \"p50_median_rtt_us\": %.2lf,\n", percentile_results[0]);
  printf("  \"p95_rtt_us\": %.2lf,\n", percentile_results[1]);
  printf("  \"p99_rtt_us\": %.2lf\n", percentile_results[2]);
  printf("}\n");
  printf("--- RESULT ---\n");
}

struct tcp_conn;

enum TCP_RPC_STATES {
  TCP_RPC_INIT,
  TCP_RPC_SEND,
  TCP_RPC_RECV,
  TCP_RPC_DONE,
  TCP_RPC_STATES_NUM
};

struct tcp_rpc {
  enum TCP_RPC_STATES state;
  struct tcp_conn *conn;
  struct rpc_header hdr;
  // send
  struct timespec send_time;
  uint8_t *send_buf;
  // recv
  struct timespec recv_time;
  uint32_t recv_remain;
};

enum TCP_CONN_EVENTS {
  TCP_CONN_CONNECT,
  TCP_CONN_SEND,
  TCP_CONN_RECV,
  TCP_CONN_EVENTS_NUM
};

struct tcp_sock_event {
  enum TCP_CONN_EVENTS event;
  struct tcp_conn *conn;
};

struct tcp_conn {
  int sockfd;
  bool connected;
  int num_rpcs;
  int events;
  struct tcp_rpc *rpcs;
  struct rate_limit_context* rate_limit;
  struct tcp_sock_event evs[TCP_CONN_EVENTS_NUM];
  // send
  int rpc_send_pending; // already added to send queue but not sent out with send()
  struct iovec *send_iovecs;
  int *send_iovecs_rpc_index;
  struct msghdr send_msghdr;
  // recv
  int rpc_recv_pending; // already sent out, waiting for recv
  int rpc_receving; // the rpc currently receiving
  char recv_buf[TCP_RECV_BUF_SIZE];
  int recv_buf_offset;
};

void tcp_reset_rpc(struct tcp_rpc *rpc) {
  rpc->state = TCP_RPC_INIT;
  rpc->recv_remain = 0;
  rpc->send_time.tv_nsec = 0;
  rpc->send_time.tv_sec = 0;
  rpc->recv_time.tv_nsec = 0;
  rpc->recv_time.tv_sec = 0;
}

void tcp_free_rpc(struct tcp_rpc *rpc) {
  tcp_reset_rpc(rpc);
  if (rpc->send_buf)
    free(rpc->send_buf);
}

static void tcp_setup_rpc_header(struct tcp_rpc *rpc) {
  rpc->hdr.magic_number = MAGIC_NUMBER;
  if (use_google_workload) {
    get_google_workload_rpc_size(&(rpc->hdr.reqlen), &(rpc->hdr.resplen));
  } else {
    rpc->hdr.reqlen = req_size;
    rpc->hdr.resplen = resp_size;
  }
  rpc->hdr.id = ++rpc_id_counter;
  *(struct rpc_header *)(rpc->send_buf) = rpc->hdr;
}

static void tcp_init_rpc_sendbuf(struct tcp_rpc *rpc, uint32_t payload_size) {
  rpc->send_buf = malloc(payload_size + sizeof(struct rpc_header));
  malloc_check(rpc->send_buf);
  setup_payload_buffer(rpc->send_buf + sizeof(struct rpc_header), payload_size);
}

// in client, only need to malloc send buffer
static void tcp_init_rpc(struct tcp_rpc *rpc, struct tcp_conn *conn) {
  memset(rpc, 0, sizeof(*rpc));
  rpc->state = TCP_RPC_INIT;
  rpc->conn = conn;
  if (use_google_workload) {
    // set a biggest possible send buffer
    get_google_workload_max_rpc_size(&(rpc->hdr.reqlen), &(rpc->hdr.resplen));
    tcp_init_rpc_sendbuf(rpc, rpc->hdr.reqlen);
  } else {
    tcp_init_rpc_sendbuf(rpc, req_size);
  }
}

static void tcp_init_conn(struct tcp_conn *conn, int num_rpcs,
  struct tcp_rpc *rpcs, struct thread_args *targs)
{
  memset(conn, 0, sizeof(*conn));

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
      log_fatal("Couldn't open TCP socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
  }

  if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) != 0) {
    perror("setsockopt TCP_NODELAY");
    exit(EXIT_FAILURE);
  }
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) != 0) {
    perror("setsockopt TCP_QUICKACK");
    exit(EXIT_FAILURE);
  }

  conn->connected = false;

#if defined MAKE_EPOLL || (defined MAKE_ONESOCK && defined MAKE_ONESOCK_NONBLOCK)
  set_socket_nonblocking(sockfd);
#endif

  conn->sockfd = sockfd;
  conn->connected = false;
  conn->num_rpcs = num_rpcs;
  conn->rpcs = rpcs;
  conn->rate_limit = &targs->rate_limit;
  for (size_t i = 0; i < TCP_CONN_EVENTS_NUM; i++) {
    conn->evs[i].conn = conn;
    conn->evs[i].event = i;
  }

  conn->rpc_send_pending = 0;
  conn->send_iovecs = calloc(sizeof(struct iovec), num_rpcs);
  malloc_check(conn->send_iovecs);
  conn->send_iovecs_rpc_index = calloc(sizeof(int), num_rpcs);
  malloc_check(conn->send_iovecs_rpc_index);
  conn->send_msghdr.msg_iov = conn->send_iovecs;
  conn->send_msghdr.msg_iovlen = 0;

  conn->rpc_recv_pending = 0;
  conn->rpc_receving = -1;
}

// add rpcs into send queue
// call sendmsg (epoll/onesock) or submit send job (io_uring)
//
// for iouring, return value is ignored / always 0
#ifdef MAKE_IOURING
int tcp_issue_send_conn(struct io_uring *ring, struct tcp_conn *conn) {
#else
// return 0 if send is not called due to no rpc to send or rate limit is not satisfied
// return bytes_sent (>0) or -1 for EAGAIN
int tcp_issue_send_conn(struct tcp_conn *conn) {
#endif

  for (int i = 0; i < conn->num_rpcs; i++) {
    if (!client_tcp_send_batch && (conn->rpc_send_pending > 0)) {
      break;
    }

    struct tcp_rpc *rpc = &conn->rpcs[i];
    if (rpc->state != TCP_RPC_INIT) {
      continue;
    }

    // we need size first to determine rate limit
    tcp_setup_rpc_header(rpc);

    // add rate limit here, we have to busy loop until something to send as least
    double rate_limit_wait_time = rate_limit_try_send(conn->rate_limit, rpc->hdr.reqlen);
    while (rate_limit_wait_time != 0.0 && conn->rpc_send_pending == 0 && conn->rpc_recv_pending == 0)
    {
      rate_limit_wait_time = rate_limit_try_send(conn->rate_limit, rpc->hdr.reqlen);
      rate_limit_sleep(rate_limit_wait_time);
    }
    if (rate_limit_wait_time != 0.0) break;

    clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->send_time);

    // add to send queue
    rpc->state = TCP_RPC_SEND;
    conn->send_iovecs[conn->rpc_send_pending].iov_base = rpc->send_buf;
    conn->send_iovecs[conn->rpc_send_pending].iov_len = sizeof(struct rpc_header) + rpc->hdr.reqlen;
    conn->send_iovecs_rpc_index[conn->rpc_send_pending] = i;
    log_debug("conn->rpc_send_pending %d rpc_idx %d iov_len %ld",
      conn->rpc_send_pending, i, conn->send_iovecs[conn->rpc_send_pending].iov_len);

    conn->rpc_send_pending++;
  }

  if (conn->rpc_send_pending == 0)
    return 0;

  conn->send_msghdr.msg_iovlen = conn->rpc_send_pending;

  log_debug("conn->rpc_send_pending %d conn->send_msghdr.msg_iovlen %d",
    conn->rpc_send_pending, conn->send_msghdr.msg_iovlen);

#if defined MAKE_IOURING
  if (add_sendmsg_request(ring, conn->sockfd, &conn->send_msghdr, 0,
    &conn->evs[1], true) != 0) {
    log_fatal("add_sendmsg_request failed");
    exit(EXIT_FAILURE);
  }
  return 0;
#elif defined MAKE_EPOLL || defined MAKE_ONESOCK
  ssize_t bytes_sent = sendmsg(conn->sockfd, &conn->send_msghdr, 0);
  if ((bytes_sent == 0) || (bytes_sent == -1 && errno != EAGAIN)) {
    log_fatal("sendmsg fail (ret %d, error %s)", bytes_sent, strerror(errno));
    exit(EXIT_FAILURE);
  }
  return bytes_sent;
#endif
}

// handle send queue, mark rpcs as done if all bytes sent
// return number of rpcs sent
int tcp_handle_send_conn(struct tcp_conn *conn, int bytes_sent) {
  int rpcs_send_done = 0;

  while (bytes_sent != 0) {
    log_debug("bytes_sent %d rpcs_send_done %d rpc_send_pending %d",
      bytes_sent, rpcs_send_done, conn->rpc_send_pending, conn->send_iovecs_rpc_index[rpcs_send_done]);
    int rpc_index = conn->send_iovecs_rpc_index[rpcs_send_done];
    struct iovec *cur_iovec = &conn->send_iovecs[rpcs_send_done];
    struct tcp_rpc* cur_rpc = &conn->rpcs[rpc_index];
    if (bytes_sent >= (int)cur_iovec->iov_len) {
      log_debug("rpc %d sent %ld remain 0 total %ld",
        rpc_index, cur_rpc->hdr.reqlen + sizeof(struct rpc_header),
        cur_rpc->hdr.reqlen + sizeof(struct rpc_header));
      bytes_sent -= cur_iovec->iov_len;
      cur_rpc->state = TCP_RPC_RECV;
      rpcs_send_done++;
      conn->rpc_send_pending--;
    } else {
      cur_iovec->iov_len -= bytes_sent;
      cur_iovec->iov_base = (uint8_t *)cur_iovec->iov_base + bytes_sent;
      log_debug("rpc %d sent %ld remain %ld total %ld",
        rpc_index, (uint8_t *)cur_iovec->iov_base - cur_rpc->send_buf,
        cur_iovec->iov_len, cur_rpc->hdr.reqlen + sizeof(struct rpc_header));
      bytes_sent = 0;
    }
  }

  if (rpcs_send_done > 0) {
    log_debug("rpcs_send_done %d rpc_send_pending %d rpc_recv_pending %d",
      rpcs_send_done, conn->rpc_send_pending, conn->rpc_recv_pending);
    memmove(&conn->send_iovecs[0], &conn->send_iovecs[rpcs_send_done],
      conn->rpc_send_pending * sizeof(struct iovec));
  }

  return rpcs_send_done;
}

#if defined MAKE_IOURING
void tcp_issue_recv_conn(struct io_uring *ring, struct tcp_conn *conn) {
  if (conn->rpc_recv_pending > 0) {
    if (add_recv_request(ring, conn->sockfd, conn->recv_buf + conn->recv_buf_offset,
      sizeof(conn->recv_buf) - conn->recv_buf_offset, &conn->evs[2], true) != 0) {
      log_fatal("add_recv_request failed");
      exit(EXIT_FAILURE);
    }
  }
}
#elif defined MAKE_EPOLL || defined MAKE_ONESOCK
// return bytes_received (>0) or -1 for EAGAIN
int tcp_issue_recv_conn(struct tcp_conn *conn) {
  int bytes_received = recv(conn->sockfd, conn->recv_buf + conn->recv_buf_offset,
    sizeof(conn->recv_buf) - conn->recv_buf_offset, 0);
  if ((bytes_received == 0) || (bytes_received == -1 && errno != EAGAIN)) {
    log_fatal("recv fail (ret %d, error %s)", bytes_received, strerror(errno));
    exit(EXIT_FAILURE);
  }
  return bytes_received;
}
#endif

// return number of rpcs received or 0 if no rpcs received
// -1 for error including invalid rpc header, unknown rpc id, and invalid response size
int tcp_handle_recv_conn(struct tcp_conn *conn, int bytes_received, struct histogram *rtt_hist) {
  int bytes_processed = 0;
  struct tcp_rpc *rpcs = conn->rpcs;
  int rpcs_recv_done = 0;

  if (bytes_received <= 0) {
    log_error("no bytes received, assume connection is failed");
    return -1;
  }

  while (bytes_received != 0) {
    log_debug("bytes_received %ld conn->rpc_receving %d\n", bytes_received, conn->rpc_receving);

    // waiting for a header
    if (conn->rpc_receving == -1) {
      // not enough bytes for a header
      if (conn->recv_buf_offset + bytes_received < (int)sizeof(struct rpc_header)) {
        memmove(conn->recv_buf, conn->recv_buf + bytes_processed, bytes_received);
        conn->recv_buf_offset += bytes_received;
        return rpcs_recv_done;
      }

      log_debug("get header (bytes_processed %ld, bytes_received %ld, recv_buf_offset %d)",
        bytes_processed, bytes_received, conn->recv_buf_offset);
      struct rpc_header *rpc_recvhdr = (struct rpc_header *)(conn->recv_buf + bytes_processed);
      bytes_received -= sizeof(struct rpc_header) - conn->recv_buf_offset;
      bytes_processed += sizeof(struct rpc_header);
      conn->recv_buf_offset = 0;

      // parse rpc, locate rpc
      if (rpc_recvhdr->magic_number != MAGIC_NUMBER) {
        log_error("received a RPC with invalid magicnumber header");
        hexdump(__func__, conn->recv_buf, sizeof(conn->recv_buf));
        return -1;
      }

      // find rpc with matched id
      for (int i = 0; i < conn->num_rpcs; i++) {
        if (rpc_recvhdr->id == rpcs[i].hdr.id) {
          conn->rpc_receving = i;
          break;
        }
      }
      if (conn->rpc_receving == -1) {
        log_error("received a RPC with unkown id");
        return -1;
      }

      if (rpc_recvhdr->resplen != rpcs[conn->rpc_receving].hdr.resplen) {
        log_error("mismatched resplen (%d != %d)", rpc_recvhdr->resplen,
          rpcs[conn->rpc_receving].hdr.resplen);
        return -1;
      }

      if (rpc_recvhdr->reqlen != rpcs[conn->rpc_receving].hdr.reqlen) {
        log_error("mismatched reqlen (%d != %d)", rpc_recvhdr->reqlen,
          rpcs[conn->rpc_receving].hdr.reqlen);
        return -1;
      }

      rpcs[conn->rpc_receving].recv_remain = rpc_recvhdr->resplen;
    }

    struct tcp_rpc *rpc = &rpcs[conn->rpc_receving];
    log_debug("rpc %d recv_remain %d bytes_received %ld", conn->rpc_receving, rpc->recv_remain, bytes_received);
    if ((uint32_t)bytes_received >= rpc->recv_remain) {
      bytes_received -= rpc->recv_remain;
      bytes_processed += rpc->recv_remain;
      rpcs_recv_done++;
      conn->rpc_receving = -1;
      clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->recv_time);
      add_rtt(rtt_hist, rpc->send_time, rpc->recv_time, rpc->hdr.reqlen, rpc->hdr.resplen);
      tcp_reset_rpc(rpc);
    } else {
      rpc->recv_remain -= bytes_received;
      break;
    }
  }

  return rpcs_recv_done;
}

#if defined MAKE_IOURING
void tcp_connect(struct io_uring *ring, struct tcp_conn *conn) {
#else
void tcp_connect(struct tcp_conn *conn) {
#endif
  if (!conn->connected) {
#if defined MAKE_IOURING
    add_connect_request(ring, conn->sockfd, &conn->evs[TCP_CONN_CONNECT], true);
    return;
#else
    if (connect(conn->sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
      if (errno != EINPROGRESS) {
        log_fatal("connect failed (error %s)", strerror(errno));
        exit(EXIT_FAILURE);
      }
      return;
    }
    conn->connected = true;
#endif
  }

  if (protocol == ECHO_TCP_KTLS) {
    if (tcpktls_setsockopt_wrapper(conn->sockfd, 0, 0) < 0) {
      log_fatal("Couldn't set KTLS to the socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
}

void *thread_tcp(void *args)
{
  int ret = 0;
  struct thread_args *targs = (struct thread_args *)args;
  int num_sockets_cur_thread = (targs->num_rpcs < num_sockets)
    ? targs->num_rpcs : num_sockets;
  struct tcp_conn conns[num_sockets];

  if (num_sockets_cur_thread == 0) {
    log_warn("no rpc or socket this thread");
    pthread_exit(EXIT_SUCCESS);
  }
  struct tcp_rpc rpcs[num_sockets][targs->num_rpcs / num_sockets + 1];

  int num_rpcs_per_socket = targs->num_rpcs / num_sockets_cur_thread;
  int extra_rpcs = targs->num_rpcs % num_sockets_cur_thread;

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    int num_rpcs_this_socket = num_rpcs_per_socket;
    if (i < extra_rpcs)
      num_rpcs_this_socket++;

    tcp_init_conn(&conns[i], num_rpcs_this_socket, rpcs[i], targs);

    for (int j = 0; j < num_rpcs_this_socket; j++) {
      tcp_init_rpc(&rpcs[i][j], &conns[i]);
    }
  }

#if defined MAKE_IOURING
  struct io_uring ring;
  io_uring_queue_init(num_sockets_cur_thread * 2, &ring, 0);
#elif defined MAKE_EPOLL
  struct epoll_event events[num_sockets_cur_thread + 1];
  memset(events, 0, sizeof(struct epoll_event) * (num_sockets_cur_thread + 1));
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    log_fatal("epoll_create1 (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
#endif

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_start);

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    log_debug("sockfd %d s_addr %x port %d", conns[i].sockfd, saddr.sin_addr.s_addr, ntohs(saddr.sin_port));
#if defined MAKE_IOURING
    add_connect_request(&ring, conns[i].sockfd, &conns[i].evs[TCP_CONN_CONNECT], true);
#elif defined MAKE_EPOLL
    tcp_connect(&conns[i]);
    conns[i].events = EPOLLOUT | EPOLLHUP;
    add_event(epoll_fd, conns[i].sockfd, conns[i].events, &conns[i]);
#endif
  }

#ifdef MAKE_ONESOCK
  struct tcp_conn *conn = &conns[0];
  tcp_connect(conn);
#endif

  while (!sigint_received) {
#ifdef MAKE_IOURING
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

    struct tcp_sock_event *ev = io_uring_cqe_get_data(cqe);
    if (!ev) {
      log_error("received a CQE with no associated data");
      io_uring_cqe_seen(&ring, cqe);
      continue;
    }

    struct tcp_conn *conn = ev->conn;

    log_debug("cqe->res %d", cqe->res);
    if (cqe->res < 0) {
      struct sockaddr_in client_addr;
      socklen_t len = sizeof(client_addr);
      if (getsockname(conn->sockfd, (struct sockaddr *)&client_addr, &len) == -1) {
        log_fatal("getsockname failed (error %s)", strerror(errno));
        exit(EXIT_FAILURE);
      }
      log_fatal("syscall failed (event %d, port %d, error %s)", ev->event,
        ntohs(client_addr.sin_port), strerror(-cqe->res));
      exit(EXIT_FAILURE);
    }

    int rpcs_send_done = 0, rpcs_recv_done = 0;
    switch (ev->event)
    {
    case TCP_CONN_CONNECT:
      log_trace("TCP_CONN_CONNECT");
      conn->connected = true;
      tcp_connect(&ring, conn);
      tcp_issue_send_conn(&ring, conn);
      break;
    case TCP_CONN_SEND:
      log_trace("TCP_CONN_SEND");
      // check head of send queue according to the syscall return value
      rpcs_send_done = tcp_handle_send_conn(conn, cqe->res);
      // add more rpcs into send queue
      tcp_issue_send_conn(&ring, conn);
      // activate recv event if not
      conn->rpc_recv_pending += rpcs_send_done;
      if (conn->rpc_recv_pending == rpcs_send_done) {
        tcp_issue_recv_conn(&ring, conn);
      }
      break;
    case TCP_CONN_RECV:
      rpcs_recv_done = tcp_handle_recv_conn(conn, cqe->res, &targs->rtt_hist);
      if (rpcs_recv_done == -1) {
        log_fatal("tcp_handle_recv_conn returned -1, exiting");
        exit(EXIT_FAILURE);
        break;
      }
      conn->rpc_recv_pending -= rpcs_recv_done;
      tcp_issue_recv_conn(&ring, conn);
      if (rpcs_recv_done > 0 && conn->rpc_send_pending == 0) {
        tcp_issue_send_conn(&ring, conn);
      }
      break;
    default:
      log_fatal("conn event is invalid (%d), exiting", ev->event);
      exit(EXIT_FAILURE);
      break;
    }

    io_uring_cqe_seen(&ring, cqe);
#elif defined MAKE_EPOLL
    int event_count = epoll_wait(epoll_fd, events, num_sockets_cur_thread + 1, epoll_wait_timeout);
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

    for (int i = 0; i < event_count; i++) {
      struct tcp_conn *conn = events[i].data.ptr;
      if (events[i].events & EPOLLOUT || events[i].events & EPOLLIN) {
        if (events[i].events & EPOLLOUT) {
          if (conn->connected == false) {
            tcp_connect(conn);
            if (conn->connected == false) {
              continue;
            }
          }
          while (conn->rpc_recv_pending < conn->num_rpcs) {
            ret = tcp_issue_send_conn(conn);
            if (ret <= 0) {
              break;
            }
            conn->rpc_recv_pending += tcp_handle_send_conn(conn, ret);
          }
        }
        if (events[i].events & EPOLLIN) {
          int num_rpcs_handled = 0;
          while (conn->rpc_recv_pending > 0 && num_rpcs_handled < conn->num_rpcs) {
            ret = tcp_issue_recv_conn(conn);
            log_debug("tcp_issue_recv_conn return (ret %d)", ret);
            if (ret == -1) {
              break; // EAGAIN
            }
            ret = tcp_handle_recv_conn(conn, ret, &targs->rtt_hist);
            if (ret == -1) {
              log_fatal("tcp_handle_recv_conn returned -1, exiting");
              exit(EXIT_FAILURE);
            }
            conn->rpc_recv_pending -= ret;
            num_rpcs_handled += ret;
            while (conn->rpc_recv_pending < conn->num_rpcs) {
              ret = tcp_issue_send_conn(conn);
              if (ret <= 0) {
                break;
              }
              conn->rpc_recv_pending += tcp_handle_send_conn(conn, ret);
            }
          }
        }
        int new_events = EPOLLHUP;
        new_events |= EPOLLOUT ? (conn->rpc_send_pending > 0) : 0;
        new_events |= EPOLLIN ? (conn->rpc_recv_pending > 0) : 0;
        if (conn->events != new_events) {
          conn->events = new_events;
          modify_event(epoll_fd, conn->sockfd, conn->events, conn);
        }
      } else {
        log_fatal("unhandled event (fd %d events %d)\n", conn->sockfd, events[i].events);
        exit(EXIT_FAILURE);
      }
    }
#elif defined MAKE_ONESOCK
    while (conn->rpc_recv_pending < conn->num_rpcs) {
      ret = tcp_issue_send_conn(conn);
      if (ret <= 0) {
        break;
      }
      conn->rpc_recv_pending += tcp_handle_send_conn(conn, ret);
    }
    if (conn->rpc_recv_pending > 0) {
      ret = tcp_issue_recv_conn(conn);
      if (ret == -1) {
        continue;
      }
      ret = tcp_handle_recv_conn(conn, ret, &targs->rtt_hist);
      if (ret == -1) {
        log_fatal("tcp_handle_recv_conn returned -1, exiting");
        exit(EXIT_FAILURE);
      }
      conn->rpc_recv_pending -= ret;
    }
#endif
  }

#ifdef MAKE_EPOLL
threadloop_end:
#endif

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_end);

#if defined MAKE_IOURING
  io_uring_queue_exit(&ring);
#elif defined MAKE_EPOLL
  close(epoll_fd);
#endif

  for (int i = 0; i < num_sockets_cur_thread; i++)
  {
    struct tcp_conn *conn = &conns[i];
    close(conn->sockfd);
    for (int j = 0; j < conn->num_rpcs; j++)
    {
      tcp_free_rpc(&conn->rpcs[j]);
    }
    free(conn->send_iovecs);
    free(conn->send_iovecs_rpc_index);
  }

  return NULL;
}

struct homa_rpc {
  struct homa_sock *sock;
  struct rpc_header hdr;
  struct msghdr send_msghdr;
  struct homa_sendmsg_args send_control;
  struct timespec send_time;
  struct iovec send_vec;
  struct timespec recv_time;
  struct msghdr recv_msghdr;
  struct homa_recvmsg_args recv_control;
  struct sockaddr_in recv_saddr;
#ifdef BUILD_HOMA_CSUM
  volatile uint16_t csum;
#endif
};

struct homa_sock {
  int sockfd;
  struct rate_limit_context *rate_limit;
  struct homa_rpc *rpcs;
  int num_rpcs;
  size_t recv_buf_size;
  uint8_t *recv_buf_region;
};

void homa_setup_rpc_header(struct homa_rpc *rpc) {
  if (use_google_workload) {
    get_google_workload_rpc_size(&(rpc->hdr.reqlen), &(rpc->hdr.resplen));
  } else {
    rpc->hdr.reqlen = req_size;
    rpc->hdr.resplen = resp_size;
  }
  *(uint32_t *)(rpc->send_vec.iov_base) = rpc->hdr.resplen;
  rpc->send_vec.iov_len = rpc->hdr.reqlen + sizeof(rpc->hdr.resplen);
}

void homa_reset_rpc(struct homa_rpc *rpc) {
  memset(&rpc->hdr, 0, sizeof(rpc->hdr));
  rpc->send_control.id = 0;
  rpc->send_control.completion_cookie = 0;
  rpc->send_time.tv_nsec = 0;
  rpc->send_time.tv_sec = 0;
  rpc->recv_control.id = 0;
  rpc->recv_control.completion_cookie = 0;
  rpc->recv_time.tv_nsec = 0;
  rpc->recv_time.tv_sec = 0;
}

void homa_send_rpc(__attribute__((unused)) struct io_uring *ring, struct homa_rpc *rpc) {
  // we need size first to determine rate limit
  homa_setup_rpc_header(rpc);
  while (rate_limit_try_send(rpc->sock->rate_limit, rpc->hdr.reqlen) != 0.0) {
    // busy wait until rate limit is satisfied
    rate_limit_sleep(rate_limit_try_send(rpc->sock->rate_limit, rpc->hdr.reqlen));
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->send_time);

#ifdef BUILD_HOMA_CSUM
  if (protocol == ECHO_HOMA_CSUM) rpc->csum = homa_iovec_checksum(&rpc->send_vec, 1);
#endif

#if defined MAKE_IOURING
  if (add_sendmsg_request(ring, rpc->sock->sockfd, &rpc->send_msghdr, 0, rpc,
    true) != 0) {
    log_fatal("add_sendmsg_request failed");
    exit(EXIT_FAILURE);
  }
#elif defined MAKE_EPOLL || defined MAKE_ONESOCK
  if (sendmsg(rpc->sock->sockfd, &rpc->send_msghdr, 0) == -1) {
    // homa sendmsg will not return EAGAIN
    if (errno != EINTR) {
      log_fatal("sendmsg returned -1 (error %s)",strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
#endif
}

void homa_send_all_rpcs(struct io_uring *ring, struct homa_sock *ctx) {
  for (int i = 0; i < ctx->num_rpcs; i++) {
    homa_reset_rpc(&(ctx->rpcs[i]));
    homa_send_rpc(ring, &(ctx->rpcs[i]));
  }
}

// handle recv then resend
void homa_recvdone_rpc(struct homa_rpc *rpc, int reqlen, struct io_uring *ring, struct histogram *rtt_hist) {
  struct iovec vecs[HOMA_MAX_BPAGES];
  int vecs_len =
      homa_recv_build_iov(vecs, rpc->sock->recv_buf_region, reqlen, rpc->recv_control.num_bpages,
                          rpc->recv_control.bpage_offsets);
#ifdef BUILD_HOMA_CSUM
    if (protocol == ECHO_HOMA_CSUM) {
      int recv_csum = homa_iovec_checksum(vecs, vecs_len);
      // not real compare
      if (recv_csum != rpc->csum) {
        rpc->csum = recv_csum;
      }
    }
#endif
    add_rtt(rtt_hist, rpc->send_time, rpc->recv_time, rpc->hdr.reqlen, rpc->hdr.resplen);
    log_debug("client recv (reslen %d, rpcid %ld)\n", reqlen, rpc->recv_control.id);
    hexdump_iov("homa client recv buf", vecs, vecs_len);
    homa_reset_rpc(rpc);
    homa_send_rpc(ring, rpc);
}

void homa_init_sock(struct homa_sock *ctx, struct homa_rpc *rpcs,
 struct rate_limit_context *rate_limit, int num_rpcs_this_socket, bool ktls)
{
  memset(ctx, 0, sizeof(*ctx));

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);

  if (sockfd < 0) {
    log_fatal("Couldn't open Homa socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (homa_init_recv_buffer(sockfd, &ctx->recv_buf_size,
                            &ctx->recv_buf_region, HOMA_BPAGE_NUM) == -1) {
    log_fatal("Couldn't init recv buffer: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (ktls) {
    if (smt_setsockopt_wrapper(sockfd, 0, 0, 0, 0) < 0) {
      log_fatal("Couldn't set SMT key: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  ctx->sockfd = sockfd;

  ctx->num_rpcs = num_rpcs_this_socket;
  ctx->rpcs = rpcs;
  ctx->rate_limit = rate_limit;
}

void homa_init_rpc(struct homa_rpc *rpc, struct homa_sock *ctx,
  struct sockaddr_in *saddr_rpc)
{
  log_info("rpc %p server %d port %d", rpc, saddr_rpc->sin_addr.s_addr, ntohs(saddr_rpc->sin_port));

  memset(rpc, 0, sizeof(*rpc));
  rpc->sock = ctx;
  rpc->send_msghdr.msg_iov = &rpc->send_vec;
  rpc->send_msghdr.msg_iovlen = 1;
  rpc->send_control.id = 0;
  rpc->send_control.completion_cookie = 0;
  rpc->send_msghdr.msg_control = &rpc->send_control;
  rpc->send_msghdr.msg_controllen = 0;
  rpc->send_msghdr.msg_name = saddr_rpc;
  rpc->send_msghdr.msg_namelen = sizeof(*saddr_rpc);

  if (use_google_workload) {
    get_google_workload_max_rpc_size(&rpc->hdr.reqlen, &rpc->hdr.resplen);
  } else {
    rpc->hdr.reqlen = req_size;
    rpc->hdr.resplen = resp_size;
  }
  rpc->send_vec.iov_base = malloc(rpc->hdr.reqlen + sizeof(rpc->hdr.resplen));
  malloc_check(rpc->send_vec.iov_base);
  setup_payload_buffer(rpc->send_vec.iov_base + sizeof(rpc->hdr.resplen), rpc->hdr.reqlen);

  rpc->recv_control.flags = 0;
  rpc->recv_msghdr.msg_name = &rpc->recv_saddr;
  rpc->recv_msghdr.msg_namelen = sizeof(rpc->recv_saddr);
  rpc->recv_msghdr.msg_control = &rpc->recv_control;
}

void *thread_homa(void *args)
{
  struct thread_args *targs = (struct thread_args *)args;
  int ret = 0;
  struct io_uring ring;

  int num_sockets_cur_thread = (targs->num_rpcs < num_sockets) ? targs->num_rpcs : num_sockets;
  if (targs->num_rpcs == 0) pthread_exit(EXIT_SUCCESS);

  struct homa_sock socks[num_sockets];
  struct homa_rpc rpcs[num_sockets][targs->num_rpcs / num_sockets + 1];

  int saddrs_idx = targs->saddrs_offset;
  for (int i = 0; i < num_sockets_cur_thread; i++) {
    int num_rpcs_cur_socket = targs->num_rpcs / num_sockets_cur_thread;
    if (i < targs->num_rpcs % num_sockets_cur_thread)
      num_rpcs_cur_socket++;

    log_info("thread_id %d socket_idx %d num_rpcs_cur_socket %d", targs->thread_id, i, num_rpcs_cur_socket);

    homa_init_sock(&socks[i], rpcs[i], &targs->rate_limit, num_rpcs_cur_socket, protocol == ECHO_SMT);
    for (int j = 0; j < num_rpcs_cur_socket; j++) {
      homa_init_rpc(&rpcs[i][j], &socks[i], &targs->saddrs[saddrs_idx]);
      saddrs_idx = (saddrs_idx + 1) % (num_server_ips * num_server_ports);
    }
  }

#if defined MAKE_EPOLL || defined MAKE_ONESOCK
  // for dummy recv
  struct homa_rpc rpc_dummy_recv = { 0 };
#if defined MAKE_EPOLL || defined MAKE_ONESOCK_NONBLOCK
  rpc_dummy_recv.recv_control.flags = HOMA_RECVMSG_RESPONSE | HOMA_RECVMSG_NONBLOCKING;
#else
  rpc_dummy_recv.recv_control.flags = HOMA_RECVMSG_RESPONSE;
#endif
  rpc_dummy_recv.recv_msghdr.msg_control = &rpc_dummy_recv.recv_control;
  rpc_dummy_recv.recv_msghdr.msg_name = &rpc_dummy_recv.recv_saddr;
  rpc_dummy_recv.recv_msghdr.msg_namelen = sizeof(rpc_dummy_recv.recv_saddr);
#endif

#if defined MAKE_IOURING
  io_uring_queue_init(targs->num_rpcs * 2, &ring, 0);
#elif defined MAKE_EPOLL
  struct epoll_event events[num_sockets_cur_thread + 1];
  memset(events, 0, sizeof(struct epoll_event) * (num_sockets_cur_thread + 1));
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    log_fatal("epoll_create1 (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    log_trace("register sockfd %d to epoll", socks[i].sockfd);
    add_event(epoll_fd, socks[i].sockfd, EPOLLIN, &socks[i]);
  }
#elif defined MAKE_ONESOCK
  struct homa_sock *sock = &socks[0];
#endif

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_start);

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    homa_send_all_rpcs(&ring, &socks[i]);
  }

  while (!sigint_received) {
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

    struct homa_rpc *rpc = io_uring_cqe_get_data(cqe);
    if (!rpc) {
      log_warn("Received a CQE with no associated RPC context");
      io_uring_cqe_seen(&ring, cqe);
      continue;
    }

    log_debug("cqe->res %d rpc %p", cqe->res, rpc);
    if (cqe->res < 0) {
      log_fatal("syscall failed (error %s, rpc->send_control.id %ld, "
              "rpc->recv_control.id %ld",
              strerror(-cqe->res), rpc->send_control.id,
              rpc->recv_control.id);
      exit(EXIT_FAILURE);
    }

    if (rpc->send_control.id != 0) {
      // homa_send done
      rpc->recv_control.id = rpc->send_control.id;
      rpc->send_control.id = 0;
      rpc->recv_msghdr.msg_controllen = sizeof(rpc->recv_control);
      if (add_recvmsg_request(&ring, rpc->sock->sockfd, &rpc->recv_msghdr, 0, rpc, true) != 0) {
        log_fatal("add_recvmsg_request failed");
        exit(EXIT_FAILURE);
      }
    } else {
      // homa_recv done
      clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->recv_time);
      homa_recvdone_rpc(rpc, cqe->res, &ring, &targs->rtt_hist);
    }
    io_uring_cqe_seen(&ring, cqe);
#elif defined MAKE_EPOLL
    int event_count = epoll_wait(epoll_fd, events, num_sockets_cur_thread + 1, epoll_wait_timeout);
    log_trace("epoll_wait returned %d errno %d", event_count, errno);
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
    for (int i = 0; i < event_count; i++) {
      struct homa_sock *sock = events[i].data.ptr;
      if (!(events[i].events & EPOLLIN)) {
        log_fatal("unhandled event (fd %d events %d)\n", sock->sockfd, events[i].events);
        exit(EXIT_FAILURE);
      }
      int num_rpcs_handled = 0;
      while (num_rpcs_handled < sock->num_rpcs) { // we can't allow one socket recv then resend forever
        rpc_dummy_recv.recv_msghdr.msg_controllen = sizeof(rpc_dummy_recv.recv_control);
        rpc_dummy_recv.recv_control.id = 0;
        rpc_dummy_recv.recv_control.completion_cookie = 0;
        ret = recvmsg(sock->sockfd, &rpc_dummy_recv.recv_msghdr, 0);
        log_trace("recvmsg returned (ret %d, errno %d)", ret, errno);
        if (ret <= 0) {
          if (errno == EAGAIN) {
            break;
          }
          if (errno == EINTR) {
            goto threadloop_end;
          }
          if (ret < 0)
            log_fatal("Couldn't receive Homa msg: %s", strerror(errno));
          if (ret == 0)
            log_fatal("A zero-length Homa msg was received which is abnormal");
          exit(EXIT_FAILURE);
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &rpc_dummy_recv.recv_time);
        for (int j = 0; j < sock->num_rpcs; j++) {
          if (rpc_dummy_recv.recv_control.id == sock->rpcs[j].send_control.id) {
            sock->rpcs[j].recv_time = rpc_dummy_recv.recv_time;
            homa_recvdone_rpc(&sock->rpcs[j], ret, &ring, &targs->rtt_hist);
            num_rpcs_handled++;
          }
        }
      }
    }
#elif defined MAKE_ONESOCK
    rpc_dummy_recv.recv_msghdr.msg_controllen = sizeof(rpc_dummy_recv.recv_control);
    rpc_dummy_recv.recv_control.id = 0;
    rpc_dummy_recv.recv_control.completion_cookie = 0;
    ret = recvmsg(sock->sockfd, &rpc_dummy_recv.recv_msghdr, 0);
    log_debug("recvmsg returned (ret %d, errno %d)", ret, errno);
    if (ret <= 0) {
      if (errno == EAGAIN) {
        continue;
      }
      if (errno == EINTR) {
        goto threadloop_end;
      }
      if (ret < 0)
        log_fatal("Couldn't receive Homa msg: %s", strerror(errno));
      if (ret == 0)
        log_fatal("A zero-length Homa msg was received which is abnormal");
      exit(EXIT_FAILURE);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &rpc_dummy_recv.recv_time);
    for (int j = 0; j < sock->num_rpcs; j++) {
      if (rpc_dummy_recv.recv_control.id == sock->rpcs[j].send_control.id) {
        sock->rpcs[j].recv_time = rpc_dummy_recv.recv_time;
        homa_recvdone_rpc(&sock->rpcs[j], ret, &ring, &targs->rtt_hist);
      }
    }
#endif
  }

#if defined MAKE_EPOLL || defined MAKE_ONESOCK
threadloop_end:
#endif

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_end);

#if defined MAKE_IOURING
  io_uring_queue_exit(&ring);
#elif defined MAKE_EPOLL
  close(epoll_fd);
#endif

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    for (int j = 0; j < socks[i].num_rpcs; j++) {
      free(rpcs[i][j].send_vec.iov_base);
    }
    close(socks[i].sockfd);
    munmap(socks[i].recv_buf_region, socks[i].recv_buf_size);
  }

  return NULL;
}

#ifdef BUILD_TCPLS
void *thread_tcpls(void *args) {
  int ret = 0;
  struct thread_args *targs = (struct thread_args *)args;
  int num_tcpls_streams = targs->num_rpcs;
  ptls_key_exchange_algorithm_t *key_exchanges[1] = {&ptls_openssl_secp256r1};
  ptls_cipher_suite_t *cipher_suites[1] = {&ptls_openssl_aes128gcmsha256};
  ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, cipher_suites};
  ptls_handshake_properties_t hsprop = {NULL};
  struct tcpls_bench {
    tcpls_t *tcpls;
    int fd;
    streamid_t sid;
    tcpls_buffer_t *recvbufs;
    struct timespec rtt_start;
    struct timespec rtt_end;
    bool rpc_sent;
    uint8_t *rpc_buffer;
    size_t sum;
  } tbenchs[num_tcpls_streams];
  struct pollfd pfds[num_tcpls_streams];

  memset(tbenchs, 0, sizeof(tbenchs));
  memset(pfds, 0, sizeof(pfds));

  ctx.support_tcpls_options = 1;

  for (int i = 0; i < num_tcpls_streams; i++) {
    tbenchs[i].tcpls = tcpls_new(&ctx, 0);
    tcpls_t *tcpls = tbenchs[i].tcpls;
    tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&saddr, 1, 0, 0);

    ret = tcpls_connect(tcpls->tls, NULL, NULL, NULL);
    if (ret) {
      fprintf(stderr, "tcpls_connect failed with err %d\n", ret);
      exit(EXIT_FAILURE);
    }
    log_info("connect done (fd %d, stream id %d)", tcpls->socket_primary, i);

    tbenchs[i].fd = tcpls->socket_primary;

    pfds[i].fd = tcpls->socket_primary;
    pfds[i].events = POLLIN;

    hsprop.client.dest = (struct sockaddr_storage *) &tcpls->v4_addr_llist->addr;
    ret = tcpls_handshake(tcpls->tls, &hsprop);
    if (ret != 0) {
      fprintf(stderr, "handshake failed: %d\n", ret);
      exit(EXIT_FAILURE);
    }

    tbenchs[i].sid = tcpls_stream_new(tcpls->tls, NULL, (struct sockaddr *) &tcpls->v4_addr_llist->addr);
    if (tbenchs[i].sid == 0) {
      fprintf(stderr, "stream creation failed: %d\n", tbenchs[i].sid);
      exit(EXIT_FAILURE);
    }

    if (tcpls_streams_attach(tcpls->tls, 0, 1) < 0) {
      fprintf(stderr, "stream failed attach\n");
      exit(EXIT_FAILURE);
    }

    tbenchs[i].recvbufs = tcpls_stream_buffers_new(tcpls, 1);


    tbenchs[i].rpc_buffer = malloc(req_size);
    malloc_check(tbenchs[i].rpc_buffer);
    setup_payload_buffer(tbenchs[i].rpc_buffer, req_size);
  }

  struct timeval timeout = { 0 };
  int idx = 0;

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_start);

  while (!sigint_received) {
    int nfds_ready = 0;

    for (int i = 0; i < num_tcpls_streams; i++) {
      idx = (idx + 1) % num_tcpls_streams;
      if (tbenchs[idx].rpc_sent == false) {
        tbenchs[idx].rpc_sent = true;
        clock_gettime(CLOCK_MONOTONIC_RAW, &(tbenchs[idx].rtt_start));

        while (tcpls_send(tbenchs[idx].tcpls->tls, tbenchs[idx].sid,
          tbenchs[idx].rpc_buffer, req_size) == TCPLS_HOLD_DATA_TO_SEND);

      }

      nfds_ready = poll(pfds, (nfds_t)num_tcpls_streams, 0);
      if (nfds_ready == -1) {
        fprintf(stderr, "poll() failed\n");
        exit(EXIT_FAILURE);
      }

      if (nfds_ready > 0) {
        break;
      }
    }

    if (nfds_ready == 0) {
      nfds_ready = poll(pfds, (nfds_t)num_tcpls_streams, -1);
      if (nfds_ready == -1) {
        fprintf(stderr, "poll() failed\n");
        exit(EXIT_FAILURE);
      }
    }

    for (int i = 0; i < num_tcpls_streams && nfds_ready > 0; ++i) {
      if ((pfds[i].revents & POLLIN) == 0) {
        continue;
      }

      nfds_ready--;

      ret = -1;
      while (ret != TCPLS_OK) {
        ret = tcpls_receive(tbenchs[i].tcpls->tls, tbenchs[i].recvbufs, &timeout);
        if (ret == -1) {
          fprintf(stderr, "tcpls_receive() failed\n");
          exit(EXIT_FAILURE);
        }
      }

      ptls_buffer_t *buf = tcpls_get_stream_buffer(tbenchs[i].recvbufs, tbenchs[i].sid);
      tbenchs[i].sum += buf->off;
      buf->off = 0;

      if (tbenchs[i].sum >= req_size) {
        log_trace("rpc %d done", i);
        clock_gettime(CLOCK_MONOTONIC_RAW, &(tbenchs[i].rtt_end));
        add_rtt(&targs->rtt_hist, tbenchs[i].rtt_start, tbenchs[i].rtt_end, req_size, resp_size);
  tbenchs[i].rpc_sent = false;
        tbenchs[i].sum = 0;
      }
    }

    if (nfds_ready != 0) {
      fprintf(stderr, "nfds_ready (%d) should be 0 after traverse all connetions\n", nfds_ready);
      exit(EXIT_FAILURE);
    }
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_end);

  for (int i = 0; i < num_tcpls_streams; ++i) {
    tcpls_stream_close(tbenchs[i].tcpls->tls, tbenchs[i].sid, 0);
    tcpls_free(tbenchs[i].tcpls);
    free(tbenchs[i].rpc_buffer);
  }

  return 0;
}
#endif

int main(int argc, char *argv[]) {
  setup_sigaction();

  parse_args(argc, argv, false);

  struct sockaddr_in saddrs[num_server_ips * num_server_ports];
  short port = ntohs(saddr.sin_port);
  // interleave multiple servers
  for (int i = 0; i < num_server_ips * num_server_ports; i += num_server_ips, port++) {
    saddrs[i] = saddr;
    saddrs[i].sin_port = htons(port);
    for (int j = 1; j < num_server_ips; j++) {
      saddrs[i+j] = saddr_alter;
      saddrs[i+j].sin_port = saddrs[i].sin_port;
    }
  }
  // // massed multiple servers
  // for (int i = 0; i < num_server_ports; i ++, port++) {
  //   saddrs[i] = saddr;
  //   saddrs[i].sin_port = htons(port);
  //   for (int j = 1; j < num_server_ips; j++) {
  //       saddrs[i + num_server_ports * j] = saddr_alter;
  //       saddrs[i + num_server_ports * j].sin_port = saddrs[i].sin_port;
  //   }
  // }


  double net_bps_per_thread = (1000.0*1000.0*net_mbps/8.0)/num_threads;
  log_info("rate net_bps_per_thread %.2f", net_bps_per_thread);

  struct thread_args args_list[num_threads];
  memset(args_list, 0, sizeof(args_list));

  int num_rpcs_per_thread = num_rpcs / num_threads;
  int extra_rpcs = num_rpcs % num_threads;
  for (int i = 0; i < num_threads; i++) {
    args_list[i].thread_id = i;
    args_list[i].rtt_hist = create_histogram_with_preheat(RTT_PREHEAT);
    args_list[i].num_rpcs = num_rpcs_per_thread;
    if (extra_rpcs > 0) {
      args_list[i].num_rpcs = num_rpcs_per_thread + 1;
      extra_rpcs--;
    }
    rate_limit_init(net_bps_per_thread, &args_list[i].rate_limit);
  }

  if (protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS) {
    if (num_server_ports != 1) {
      log_fatal("tcp: server port must be a single port");
      exit(EXIT_FAILURE);
    }
    if (num_server_ips != 1) {
      log_fatal("tcp: alter server address is not supported");
      exit(EXIT_FAILURE);
    }
    launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_tcp);
  } else if (protocol == ECHO_HOMA || protocol == ECHO_SMT
#ifdef BUILD_HOMA_CSUM
    || protocol == ECHO_HOMA_CSUM
#endif
  ) {
    int saddr_offset = 0;
    for (int i = 0; i < num_threads; i++) {
      args_list[i].saddrs = saddrs;
      args_list[i].saddrs_offset = saddr_offset;
      saddr_offset = (saddr_offset + args_list[i].num_rpcs) % (num_server_ips * num_server_ports);
    }
    launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_homa);
#ifdef BUILD_TCPLS
  } else if (protocol == ECHO_TCPLS) {
    launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_tcpls);
#endif
  }

  log_info("All threads launched, Press Ctrl+C to stop...");
  pause();
  printf("\n");
  log_info("Client received SIGINT, exiting...\n");

  bool thread_killed = false;
  for (int i = 0; i < num_threads; i++) {
    // we use 1s to let client exit itself as much as possible
    // as long as the thread is joined it is considered as success
    if (shutdown_thread(args_list[i].thread, (long)1e9) == -1) {
      thread_killed = true;
      log_fatal("thread_id %d is force killed", i);
    }
  }

  if (thread_killed == false) stats_bench(args_list);

  for (int i = 0; i < num_threads; i++) {
    free_histogram(&args_list[i].rtt_hist);
  }

  if (thread_killed) return EXIT_FAILURE;
  return EXIT_SUCCESS;
}
