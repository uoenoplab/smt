// Multi-threaded loaded benchmark client (port of ~/repos/smt/bench/loaded).
// Homa/SMT: each thread opens num_sockets sockets, nonblocking, registered
// to one epoll_fd; drains every ready socket's recvmsg until EAGAIN and
// re-sends the matching RPC slot. TCP: one blocking connection per thread,
// rate-limited send/recv loop.
#include "echo_loaded.h"
#include "../util/rtts.h"

#include <sys/epoll.h>

// variables and structs //

struct thread_args {
  pthread_t thread;
  int thread_id;
  int num_rpcs;     // RPCs this thread must complete
  struct sockaddr_in *saddrs; // interleaved ip/port list
  int saddrs_offset;
  struct rate_limit_context rate_limit;
  struct histogram rtt_hist;
  struct timespec bench_start;
  struct timespec bench_end;
};

// variables and structs //

// stats //

static void stats_bench(struct thread_args *args_list) {
  struct histogram rtt_hists[num_threads];
  size_t max_rtt_count = 0, min_rtt_count = SIZE_MAX;
  double kops_per_sec = 0.0;

  for (int i = 0; i < num_threads; i++) {
    rtt_hists[i] = args_list[i].rtt_hist;

    if (args_list[i].bench_start.tv_sec == 0 &&
        args_list[i].bench_start.tv_nsec == 0) {
      log_warn("thread_id %d bench_start is zero", args_list[i].thread_id);
      continue;
    }
    if (args_list[i].bench_end.tv_sec == 0 &&
        args_list[i].bench_end.tv_nsec == 0) {
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
              args_list[i].thread_id, args_list[i].saddrs_offset, rtt_count,
              thread_time);
    kops_per_sec += ((double)rtt_count / thread_time) / 1000.0;
  }
  struct histogram combined_hist = create_histogram();
  merge_histograms(&combined_hist, rtt_hists, num_threads);
  size_t total_rtt_count = combined_hist.total_data_points;

  if (total_rtt_count == 0) {
    log_error("no RPCs completed");
    free_histogram(&combined_hist);
    return;
  }
  double avg_req_size = combined_hist.total_req_size / (double)total_rtt_count;
  double avg_resp_size = combined_hist.total_resp_size / (double)total_rtt_count;
  double throughput_mbps_tx = (kops_per_sec * 1000.0) * avg_req_size * 8.0 / (1000.0 * 1000.0);
  double throughput_mbps_rx = (kops_per_sec * 1000.0) * avg_resp_size * 8.0 / (1000.0 * 1000.0);
  double avg = calculate_average(&combined_hist);
  double avg_stddev = calculate_stddev(&combined_hist, &avg);
  double percentiles[3] = { 50.0, 95.0, 99.0 };
  double percentile_results[3];

  calculate_percentiles(&combined_hist, percentiles, percentile_results, 3);

  printf("\n--- RESULT ---\n");
  printf("{\n");
  printf("  \"total_rpcs\": %ld,\n", total_rtt_count);
  printf("  \"max_per_thread\": %ld,\n", max_rtt_count);
  printf("  \"min_per_thread\": %ld,\n", min_rtt_count);
  printf("  \"avg_per_thread\": %.2lf,\n", (double)total_rtt_count / num_threads);
  printf("  \"kops_per_second\": %.2lf,\n", kops_per_sec);
  printf("  \"tx_throughput_mbps\": %.2lf,\n", throughput_mbps_tx);
  if (net_mbps != 0.0)
    printf("  \"tx_throughput_mbps_relative_error_percentage\": %.2lf,\n",
           100.0 * fabs(throughput_mbps_tx - net_mbps) / net_mbps);
  printf("  \"rx_throughput_mbps\": %.2lf,\n", throughput_mbps_rx);
  printf("  \"average_rtt_us\": %.2lf,\n", avg);
  printf("  \"average_stddev_rtt_us\": %.2lf,\n", avg_stddev);
  printf("  \"p50_median_rtt_us\": %.2lf,\n", percentile_results[0]);
  printf("  \"p95_rtt_us\": %.2lf,\n", percentile_results[1]);
  printf("  \"p99_rtt_us\": %.2lf\n", percentile_results[2]);
  printf("}\n");
  printf("--- RESULT ---\n");

  free_histogram(&combined_hist);
}

// stats //

// tcp path //

#define TCP_RECV_BUF_SIZE 8192

struct tcp_conn;

enum TCP_RPC_STATES {
  TCP_RPC_INIT,
  TCP_RPC_SEND,
  TCP_RPC_RECV,
  TCP_RPC_DONE,
  TCP_RPC_STATES_NUM,
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
  TCP_CONN_EVENTS_NUM,
};

struct tcp_sock_event {
  enum TCP_CONN_EVENTS event;
  struct tcp_conn *conn;
};

struct tcp_conn {
  int sockfd;
  bool connected;
  int num_rpcs;
  uint32_t events;
  struct tcp_rpc *rpcs;
  struct rate_limit_context *rate_limit;
  struct tcp_sock_event evs[TCP_CONN_EVENTS_NUM];
  // send
  int rpc_send_pending;
  struct iovec *send_iovecs;
  int *send_iovecs_rpc_index;
  struct msghdr send_msghdr;
  // recv
  int rpc_recv_pending;
  int rpc_receving;
  char recv_buf[TCP_RECV_BUF_SIZE];
  int recv_buf_offset;
};

static void tcp_reset_rpc(struct tcp_rpc *rpc) {
  rpc->state = TCP_RPC_INIT;
  rpc->recv_remain = 0;
  rpc->send_time.tv_nsec = 0;
  rpc->send_time.tv_sec = 0;
  rpc->recv_time.tv_nsec = 0;
  rpc->recv_time.tv_sec = 0;
}

static void tcp_free_rpc(struct tcp_rpc *rpc) {
  tcp_reset_rpc(rpc);
  if (rpc->send_buf)
    free(rpc->send_buf);
}

static void tcp_setup_rpc_header(struct tcp_rpc *rpc) {
  rpc->hdr.magic_number = MAGIC_NUMBER;
  if (use_google_workload) {
    get_google_workload_rpc_size(&rpc->hdr.reqlen, &rpc->hdr.resplen);
  } else {
    rpc->hdr.reqlen = req_size;
    rpc->hdr.resplen = resp_size;
  }
  rpc->hdr.id = atomic_fetch_add(&rpc_id_counter, 1) + 1;
  *(struct rpc_header *)(rpc->send_buf) = rpc->hdr;
}

static void tcp_init_rpc_sendbuf(struct tcp_rpc *rpc, uint32_t payload_size) {
  rpc->send_buf = malloc(payload_size + sizeof(struct rpc_header));
  malloc_check(rpc->send_buf);
  setup_payload_buffer(rpc->send_buf + sizeof(struct rpc_header), payload_size);
}

static void tcp_init_rpc(struct tcp_rpc *rpc, struct tcp_conn *conn) {
  memset(rpc, 0, sizeof(*rpc));
  rpc->state = TCP_RPC_INIT;
  rpc->conn = conn;
  if (use_google_workload) {
    get_google_workload_max_rpc_size(&rpc->hdr.reqlen, &rpc->hdr.resplen);
    tcp_init_rpc_sendbuf(rpc, rpc->hdr.reqlen);
  } else {
    tcp_init_rpc_sendbuf(rpc, req_size);
  }
}

static void tcp_init_conn(struct tcp_conn *conn, int num_rpcs,
                          struct tcp_rpc *rpcs, struct thread_args *targs) {
  memset(conn, 0, sizeof(*conn));

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    log_fatal("Couldn't open TCP socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) != 0) {
    log_fatal("setsockopt TCP_NODELAY: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) != 0) {
    log_fatal("setsockopt TCP_QUICKACK: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  set_socket_nonblocking(sockfd);

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
  conn->send_iovecs = calloc(num_rpcs, sizeof(struct iovec));
  malloc_check(conn->send_iovecs);
  conn->send_iovecs_rpc_index = calloc(num_rpcs, sizeof(int));
  malloc_check(conn->send_iovecs_rpc_index);
  conn->send_msghdr.msg_iov = conn->send_iovecs;
  conn->send_msghdr.msg_iovlen = 0;

  conn->rpc_recv_pending = 0;
  conn->rpc_receving = -1;
}

// add INIT rpcs to send queue (honoring rate limit), then call sendmsg.
// returns bytes_sent (>0) or -1 for EAGAIN, or 0 if nothing to send.
static int tcp_issue_send_conn(struct tcp_conn *conn,
                               const struct sockaddr_in *dst) {
  for (int i = 0; i < conn->num_rpcs; i++) {
    if (!client_tcp_send_batch && (conn->rpc_send_pending > 0)) {
      break;
    }
    struct tcp_rpc *rpc = &conn->rpcs[i];
    if (rpc->state != TCP_RPC_INIT)
      continue;

    tcp_setup_rpc_header(rpc);

    // busy-wait on rate limit only while this conn has no other inflight
    double wait = rate_limit_try_send(conn->rate_limit, rpc->hdr.reqlen);
    while (wait != 0.0 && conn->rpc_send_pending == 0 &&
           conn->rpc_recv_pending == 0) {
      wait = rate_limit_try_send(conn->rate_limit, rpc->hdr.reqlen);
      rate_limit_sleep(wait);
    }
    if (wait != 0.0) break;

    clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->send_time);
    rpc->state = TCP_RPC_SEND;
    conn->send_iovecs[conn->rpc_send_pending].iov_base = rpc->send_buf;
    conn->send_iovecs[conn->rpc_send_pending].iov_len =
        sizeof(struct rpc_header) + rpc->hdr.reqlen;
    conn->send_iovecs_rpc_index[conn->rpc_send_pending] = i;
    log_debug("conn->rpc_send_pending %d rpc_idx %d iov_len %ld",
              conn->rpc_send_pending, i,
              conn->send_iovecs[conn->rpc_send_pending].iov_len);
    conn->rpc_send_pending++;
  }

  if (conn->rpc_send_pending == 0)
    return 0;

  conn->send_msghdr.msg_iovlen = conn->rpc_send_pending;
  conn->send_msghdr.msg_name = (void *)dst;
  conn->send_msghdr.msg_namelen = sizeof(*dst);

  log_debug("conn->rpc_send_pending %d conn->send_msghdr.msg_iovlen %zu",
            conn->rpc_send_pending, conn->send_msghdr.msg_iovlen);

  ssize_t bytes_sent = sendmsg(conn->sockfd, &conn->send_msghdr, 0);
  if ((bytes_sent == 0) || (bytes_sent == -1 && errno != EAGAIN)) {
    log_fatal("sendmsg fail (ret %zd, error %s)", bytes_sent, strerror(errno));
    exit(EXIT_FAILURE);
  }
  return (int)bytes_sent;
}

// walk iovec queue, mark fully-sent rpcs as RECV, return rpcs_send_done.
static int tcp_handle_send_conn(struct tcp_conn *conn, int bytes_sent) {
  int rpcs_send_done = 0;

  while (bytes_sent != 0) {
    log_debug("bytes_sent %d rpcs_send_done %d rpc_send_pending %d",
              bytes_sent, rpcs_send_done, conn->rpc_send_pending,
              conn->send_iovecs_rpc_index[rpcs_send_done]);
    int rpc_index = conn->send_iovecs_rpc_index[rpcs_send_done];
    struct iovec *cur_iovec = &conn->send_iovecs[rpcs_send_done];
    struct tcp_rpc *cur_rpc = &conn->rpcs[rpc_index];

    if (bytes_sent >= (int)cur_iovec->iov_len) {
      log_debug("rpc %d sent %zu remain 0 total %zu",
                rpc_index, cur_rpc->hdr.reqlen + sizeof(struct rpc_header),
                cur_rpc->hdr.reqlen + sizeof(struct rpc_header));
      bytes_sent -= cur_iovec->iov_len;
      cur_rpc->state = TCP_RPC_RECV;
      rpcs_send_done++;
      conn->rpc_send_pending--;
    } else {
      cur_iovec->iov_len -= bytes_sent;
      cur_iovec->iov_base = (uint8_t *)cur_iovec->iov_base + bytes_sent;
      log_debug("rpc %d sent %ld remain %zu total %zu",
                rpc_index,
                (uint8_t *)cur_iovec->iov_base - cur_rpc->send_buf,
                cur_iovec->iov_len,
                cur_rpc->hdr.reqlen + sizeof(struct rpc_header));
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

// return bytes_received (>0), -1 for EAGAIN, -2 for fatal/EOF.
static int tcp_issue_recv_conn(struct tcp_conn *conn) {
  int bytes_received = recv(conn->sockfd,
                            conn->recv_buf + conn->recv_buf_offset,
                            sizeof(conn->recv_buf) - conn->recv_buf_offset, 0);
  if ((bytes_received == 0) ||
      (bytes_received == -1 && errno != EAGAIN)) {
    log_fatal("recv fail (ret %d, error %s)", bytes_received, strerror(errno));
    exit(EXIT_FAILURE);
  }
  return bytes_received;
}

// return number of rpcs completed (>=0), or -1 on protocol error.
static int tcp_handle_recv_conn(struct tcp_conn *conn, int bytes_received,
                                struct histogram *rtt_hist) {
  int bytes_processed = 0;
  struct tcp_rpc *rpcs = conn->rpcs;
  int rpcs_recv_done = 0;

  if (bytes_received <= 0) {
    log_error("no bytes received, assume connection is failed");
    return -1;
  }

  while (bytes_received != 0) {
    log_debug("bytes_received %d conn->rpc_receving %d\n",
              bytes_received, conn->rpc_receving);

    if (conn->rpc_receving == -1) {
      if (conn->recv_buf_offset + bytes_received < (int)sizeof(struct rpc_header)) {
        memmove(conn->recv_buf, conn->recv_buf + bytes_processed, bytes_received);
        conn->recv_buf_offset += bytes_received;
        return rpcs_recv_done;
      }
      log_debug("get header (bytes_processed %d, bytes_received %d, recv_buf_offset %d)",
                bytes_processed, bytes_received, conn->recv_buf_offset);
      struct rpc_header *rpc_recvhdr =
          (struct rpc_header *)(conn->recv_buf + bytes_processed);
      bytes_received -= sizeof(struct rpc_header) - conn->recv_buf_offset;
      bytes_processed += sizeof(struct rpc_header);
      conn->recv_buf_offset = 0;

      if (rpc_recvhdr->magic_number != MAGIC_NUMBER) {
        log_error("received a RPC with invalid magicnumber header");
        hexdump(__func__, conn->recv_buf, sizeof(conn->recv_buf));
        return -1;
      }
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
        log_error("mismatched resplen (%u != %u)", rpc_recvhdr->resplen,
                  rpcs[conn->rpc_receving].hdr.resplen);
        return -1;
      }
      if (rpc_recvhdr->reqlen != rpcs[conn->rpc_receving].hdr.reqlen) {
        log_error("mismatched reqlen (%u != %u)", rpc_recvhdr->reqlen,
                  rpcs[conn->rpc_receving].hdr.reqlen);
        return -1;
      }
      rpcs[conn->rpc_receving].recv_remain = rpc_recvhdr->resplen;
    }

    struct tcp_rpc *rpc = &rpcs[conn->rpc_receving];
    log_debug("rpc %d recv_remain %u bytes_received %d",
              conn->rpc_receving, rpc->recv_remain, bytes_received);
    if ((uint32_t)bytes_received >= rpc->recv_remain) {
      bytes_received -= rpc->recv_remain;
      bytes_processed += rpc->recv_remain;
      rpcs_recv_done++;
      conn->rpc_receving = -1;
      clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->recv_time);
      add_rtt(rtt_hist, rpc->send_time, rpc->recv_time, rpc->hdr.reqlen,
              rpc->hdr.resplen);
      tcp_reset_rpc(rpc);
    } else {
      rpc->recv_remain -= bytes_received;
      break;
    }
  }
  return rpcs_recv_done;
}

static void tcp_connect(struct tcp_conn *conn, const struct sockaddr_in *dst) {
  if (!conn->connected) {
    if (connect(conn->sockfd, (const struct sockaddr *)dst, sizeof(*dst)) == -1) {
      if (errno != EINPROGRESS) {
        log_fatal("connect failed (error %s)", strerror(errno));
        exit(EXIT_FAILURE);
      }
      return;
    }
    conn->connected = true;
  }
  if (protocol == ECHO_TCP_KTLS) {
    if (tcpktls_setsockopt_wrapper(conn->sockfd, 0, 0) < 0) {
      log_fatal("Couldn't set KTLS to the socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
}

static void *thread_tcp(void *arg) {
  int ret = 0;
  struct thread_args *targs = arg;
  int num_sockets_cur_thread = (targs->num_rpcs < num_sockets)
                                 ? targs->num_rpcs : num_sockets;

  if (num_sockets_cur_thread == 0) {
    log_warn("no rpc or socket this thread");
    pthread_exit(EXIT_SUCCESS);
  }
  struct tcp_conn conns[num_sockets_cur_thread];
  struct tcp_rpc rpcs[num_sockets_cur_thread]
                     [targs->num_rpcs / num_sockets_cur_thread + 1];
  const struct sockaddr_in *dst = &targs->saddrs[targs->saddrs_offset];

  int num_rpcs_per_socket = targs->num_rpcs / num_sockets_cur_thread;
  int extra_rpcs = targs->num_rpcs % num_sockets_cur_thread;

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    int num_rpcs_this_socket = num_rpcs_per_socket + (i < extra_rpcs ? 1 : 0);

    tcp_init_conn(&conns[i], num_rpcs_this_socket, rpcs[i], targs);
    for (int j = 0; j < num_rpcs_this_socket; j++)
      tcp_init_rpc(&rpcs[i][j], &conns[i]);
  }

  struct epoll_event events[num_sockets_cur_thread + 1];
  memset(events, 0, sizeof(events));
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    log_fatal("epoll_create1 (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_start);

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    log_debug("sockfd %d s_addr %x port %d", conns[i].sockfd,
              dst->sin_addr.s_addr, ntohs(dst->sin_port));
    tcp_connect(&conns[i], dst);
    conns[i].events = EPOLLOUT | EPOLLHUP;
    add_epoll_event(epoll_fd, conns[i].sockfd, conns[i].events, &conns[i]);
  }

  while (!sigint_received) {
    int event_count = epoll_wait(epoll_fd, events,
                                 num_sockets_cur_thread + 1, epoll_wait_timeout);
    if (event_count == -1) {
      if (errno == EAGAIN) continue;
      if (errno == EINTR) goto threadloop_end;
      log_fatal("epoll_wait (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    for (int i = 0; i < event_count; i++) {
      struct tcp_conn *conn = events[i].data.ptr;

      if (!(events[i].events & (EPOLLOUT | EPOLLIN))) {
        log_fatal("unhandled event (fd %d events %d)", conn->sockfd,
                  events[i].events);
        exit(EXIT_FAILURE);
      }
      if (events[i].events & EPOLLOUT) {
        if (!conn->connected) {
          tcp_connect(conn, dst);
          if (!conn->connected) continue;
        }
        while (conn->rpc_recv_pending < conn->num_rpcs) {
          ret = tcp_issue_send_conn(conn, dst);
          if (ret <= 0) break;
          conn->rpc_recv_pending += tcp_handle_send_conn(conn, ret);
        }
      }
      if (events[i].events & EPOLLIN) {
        int num_rpcs_handled = 0;
        while (conn->rpc_recv_pending > 0 &&
               num_rpcs_handled < conn->num_rpcs) {
          ret = tcp_issue_recv_conn(conn);
          log_debug("tcp_issue_recv_conn return (ret %d)", ret);
          if (ret == -1) break; // EAGAIN
          ret = tcp_handle_recv_conn(conn, ret, &targs->rtt_hist);
          if (ret == -1) {
            log_fatal("tcp_handle_recv_conn returned -1, exiting");
            exit(EXIT_FAILURE);
          }
          conn->rpc_recv_pending -= ret;
          num_rpcs_handled += ret;
          while (conn->rpc_recv_pending < conn->num_rpcs) {
            ret = tcp_issue_send_conn(conn, dst);
            if (ret <= 0) break;
            conn->rpc_recv_pending += tcp_handle_send_conn(conn, ret);
          }
        }
      }
      uint32_t new_events = EPOLLHUP;
      if (conn->rpc_send_pending > 0) new_events |= EPOLLOUT;
      if (conn->rpc_recv_pending > 0) new_events |= EPOLLIN;
      if (conn->events != new_events) {
        conn->events = new_events;
        mod_epoll_event(epoll_fd, conn->sockfd, conn->events, conn);
      }
    }
  }

threadloop_end:
  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_end);
  close(epoll_fd);
  for (int i = 0; i < num_sockets_cur_thread; i++) {
    struct tcp_conn *conn = &conns[i];

    close(conn->sockfd);
    for (int j = 0; j < conn->num_rpcs; j++)
      tcp_free_rpc(&conn->rpcs[j]);
    free(conn->send_iovecs);
    free(conn->send_iovecs_rpc_index);
  }
  return NULL;
}

// tcp path //

// homa / smt path //

struct homa_sock;

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
};

struct homa_sock {
  int sockfd;
  struct rate_limit_context *rate_limit;
  struct homa_rpc *rpcs;
  int num_rpcs;
  size_t recv_buf_size;
  uint8_t *recv_buf_region;
  // per-socket dummy recv: holds this socket's outstanding bpages so the
  // next recvmsg on THIS socket recycles them to THIS socket's pool. Must
  // not be shared across sockets (different pools, different bpage index
  // spaces).
  struct homa_rpc rpc_dummy_recv;
};

static void homa_setup_rpc_header(struct homa_rpc *rpc) {
  if (use_google_workload) {
    get_google_workload_rpc_size(&rpc->hdr.reqlen, &rpc->hdr.resplen);
  } else {
    rpc->hdr.reqlen = req_size;
    rpc->hdr.resplen = resp_size;
  }
  *(uint32_t *)(rpc->send_vec.iov_base) = rpc->hdr.resplen;
  rpc->send_vec.iov_len = rpc->hdr.reqlen + sizeof(rpc->hdr.resplen);
}

static void homa_reset_rpc(struct homa_rpc *rpc) {
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

static void homa_send_rpc(struct homa_rpc *rpc) {
  homa_setup_rpc_header(rpc);
  while (rate_limit_try_send(rpc->sock->rate_limit, rpc->hdr.reqlen) != 0.0) {
    rate_limit_sleep(
        rate_limit_try_send(rpc->sock->rate_limit, rpc->hdr.reqlen));
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &rpc->send_time);

  if (sendmsg(rpc->sock->sockfd, &rpc->send_msghdr, 0) < 0) {
    if (errno == EINTR)
      return;
    log_fatal("homa sendmsg: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void homa_send_all_rpcs(struct homa_sock *ctx) {
  for (int i = 0; i < ctx->num_rpcs; i++) {
    homa_reset_rpc(&ctx->rpcs[i]);
    homa_send_rpc(&ctx->rpcs[i]);
  }
}

static void homa_init_sock(struct homa_sock *ctx, struct homa_rpc *rpcs,
                           struct rate_limit_context *rate_limit,
                           int num_rpcs_this_socket, bool smt) {
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
  if (smt) {
    if (smt_setsockopt_wrapper(sockfd, 0, 0, 0, 0) < 0) {
      log_fatal("Couldn't set SMT key: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  ctx->sockfd = sockfd;
  ctx->num_rpcs = num_rpcs_this_socket;
  ctx->rpcs = rpcs;
  ctx->rate_limit = rate_limit;

  ctx->rpc_dummy_recv.recv_msghdr.msg_control =
      &ctx->rpc_dummy_recv.recv_control;
  ctx->rpc_dummy_recv.recv_msghdr.msg_name = &ctx->rpc_dummy_recv.recv_saddr;
  ctx->rpc_dummy_recv.recv_msghdr.msg_namelen =
      sizeof(ctx->rpc_dummy_recv.recv_saddr);
}

static void homa_init_rpc(struct homa_rpc *rpc, struct homa_sock *ctx,
                          struct sockaddr_in *saddr_rpc) {
  log_info("rpc %p server %d port %d", rpc, saddr_rpc->sin_addr.s_addr,
           ntohs(saddr_rpc->sin_port));

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
  setup_payload_buffer(rpc->send_vec.iov_base + sizeof(rpc->hdr.resplen),
                       rpc->hdr.reqlen);

  rpc->recv_msghdr.msg_name = &rpc->recv_saddr;
  rpc->recv_msghdr.msg_namelen = sizeof(rpc->recv_saddr);
  rpc->recv_msghdr.msg_control = &rpc->recv_control;
}

static void homa_recvdone_rpc(struct homa_rpc *rpc, int reqlen,
                              struct histogram *rtt_hist) {
  struct iovec vecs[HOMA_MAX_BPAGES];
  int vecs_len = homa_recv_build_iov(vecs, rpc->sock->recv_buf_region, reqlen,
                                     rpc->recv_control.num_bpages,
                                     rpc->recv_control.bpage_offsets);

  add_rtt(rtt_hist, rpc->send_time, rpc->recv_time, rpc->hdr.reqlen,
          rpc->hdr.resplen);
  log_debug("client recv (reslen %d, rpcid %llu)\n", reqlen,
            (unsigned long long)rpc->recv_control.id);
  hexdump_iov("homa client recv buf", vecs, vecs_len);
  homa_reset_rpc(rpc);
  homa_send_rpc(rpc);
}

static void *thread_homa(void *args) {
  struct thread_args *targs = (struct thread_args *)args;
  int ret = 0;

  int num_sockets_cur_thread = (targs->num_rpcs < num_sockets)
                                 ? targs->num_rpcs : num_sockets;
  if (targs->num_rpcs == 0) pthread_exit(EXIT_SUCCESS);

  struct homa_sock socks[num_sockets_cur_thread];
  struct homa_rpc rpcs[num_sockets_cur_thread]
                      [targs->num_rpcs / num_sockets_cur_thread + 1];

  int saddrs_idx = targs->saddrs_offset;

  for (int i = 0; i < num_sockets_cur_thread; i++) {
    int num_rpcs_cur_socket = targs->num_rpcs / num_sockets_cur_thread +
        (i < targs->num_rpcs % num_sockets_cur_thread ? 1 : 0);

    log_info("thread_id %d socket_idx %d num_rpcs_cur_socket %d",
             targs->thread_id, i, num_rpcs_cur_socket);

    homa_init_sock(&socks[i], rpcs[i], &targs->rate_limit,
                   num_rpcs_cur_socket, protocol == ECHO_SMT);
    for (int j = 0; j < num_rpcs_cur_socket; j++) {
      homa_init_rpc(&rpcs[i][j], &socks[i], &targs->saddrs[saddrs_idx]);
      saddrs_idx = (saddrs_idx + 1) % (num_server_ips * num_server_ports);
    }
  }

  struct epoll_event events[num_sockets_cur_thread + 1];

  memset(events, 0, sizeof(events));
  int epoll_fd = epoll_create1(0);

  if (epoll_fd == -1) {
    log_fatal("epoll_create1 (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < num_sockets_cur_thread; i++) {
    log_trace("register sockfd %d to epoll", socks[i].sockfd);
    add_epoll_event(epoll_fd, socks[i].sockfd, EPOLLIN, &socks[i]);
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_start);

  for (int i = 0; i < num_sockets_cur_thread; i++)
    homa_send_all_rpcs(&socks[i]);

  while (!sigint_received) {
    int event_count = epoll_wait(epoll_fd, events,
                                 num_sockets_cur_thread + 1, epoll_wait_timeout);

    log_trace("epoll_wait returned %d errno %d", event_count, errno);
    if (event_count == -1) {
      if (errno == EAGAIN) continue;
      if (errno == EINTR) goto threadloop_end;
      log_fatal("epoll_wait (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }
    for (int i = 0; i < event_count; i++) {
      struct homa_sock *sock = events[i].data.ptr;
      struct homa_rpc *dummy = &sock->rpc_dummy_recv;

      if (!(events[i].events & EPOLLIN)) {
        log_fatal("unhandled event (fd %d events %d)", sock->sockfd,
                  events[i].events);
        exit(EXIT_FAILURE);
      }
      int num_rpcs_handled = 0;
      while (num_rpcs_handled < sock->num_rpcs) {
        dummy->recv_msghdr.msg_controllen = sizeof(dummy->recv_control);
        dummy->recv_control.id = 0;
        dummy->recv_control.completion_cookie = 0;
        ret = recvmsg(sock->sockfd, &dummy->recv_msghdr, MSG_DONTWAIT);
        log_trace("recvmsg returned (ret %d, errno %d)", ret, errno);
        if (ret <= 0) {
          if (errno == EAGAIN) break;
          if (errno == EINTR) goto threadloop_end;
          if (ret < 0)
            log_fatal("Couldn't receive Homa msg: %s", strerror(errno));
          if (ret == 0)
            log_fatal("A zero-length Homa msg was received which is abnormal");
          exit(EXIT_FAILURE);
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &dummy->recv_time);
        for (int j = 0; j < sock->num_rpcs; j++) {
          if (dummy->recv_control.id == sock->rpcs[j].send_control.id) {
            sock->rpcs[j].recv_time = dummy->recv_time;
            sock->rpcs[j].recv_control = dummy->recv_control;
            homa_recvdone_rpc(&sock->rpcs[j], ret, &targs->rtt_hist);
            num_rpcs_handled++;
            break;
          }
        }
      }
    }
  }

threadloop_end:
  clock_gettime(CLOCK_MONOTONIC_RAW, &targs->bench_end);
  close(epoll_fd);
  for (int i = 0; i < num_sockets_cur_thread; i++) {
    for (int j = 0; j < socks[i].num_rpcs; j++)
      free(rpcs[i][j].send_vec.iov_base);
    close(socks[i].sockfd);
    munmap(socks[i].recv_buf_region, socks[i].recv_buf_size);
  }
  return NULL;
}

// homa / smt path //

// main //

int main(int argc, char *argv[]) {
  setup_sigaction();
  parse_args(argc, argv, false);

  int num_saddrs = num_server_ips * num_server_ports;
  struct sockaddr_in saddrs[num_saddrs];
  short port = ntohs(saddr.sin_port);

  // interleave multiple servers
  for (int i = 0; i < num_saddrs; i += num_server_ips, port++) {
    saddrs[i] = saddr;
    saddrs[i].sin_port = htons(port);
    for (int j = 1; j < num_server_ips; j++) {
      saddrs[i + j] = saddr_alter;
      saddrs[i + j].sin_port = saddrs[i].sin_port;
    }
  }

  double net_bps_per_thread = (1000.0 * 1000.0 * net_mbps / 8.0) / num_threads;

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
    args_list[i].saddrs = saddrs;
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
  } else if (protocol == ECHO_HOMA || protocol == ECHO_SMT) {
    int saddr_offset = 0;
    for (int i = 0; i < num_threads; i++) {
      args_list[i].saddrs_offset = saddr_offset;
      saddr_offset = (saddr_offset + args_list[i].num_rpcs) % num_saddrs;
    }
    launch_threads(args_list, num_threads, sizeof(args_list[0]), thread_homa);
  }

  log_info("All threads launched, Press Ctrl+C to stop...");
  pause();
  printf("\n");
  log_info("Client received SIGINT, exiting...\n");

  bool thread_killed = false;
  for (int i = 0; i < num_threads; i++) {
    if (shutdown_thread(args_list[i].thread, (long)1e9) == -1) {
      thread_killed = true;
      log_fatal("thread_id %d is force killed", i);
    }
  }

  if (!thread_killed) stats_bench(args_list);

  for (int i = 0; i < num_threads; i++)
    free_histogram(&args_list[i].rtt_hist);

  return thread_killed ? EXIT_FAILURE : EXIT_SUCCESS;
}

// main //
