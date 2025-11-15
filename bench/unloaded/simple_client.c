#include "echo_simple.h"
#include "../util/rtts.h"

struct timespec send_time = { 0 }, recv_time = { 0 };
int sockfd = 0, ret = 0;

void homa_send_recv(int sockfd, struct histogram *rtt_hist) {
  log_debug("client send (len: %d)", req_size);
  hexdump("request", (void *)send_buf, req_size);

  clock_gettime(CLOCK_MONOTONIC_RAW, &send_time);
  ret = homa_send(sockfd, send_buf, req_size, (sockaddr_in_union *)&saddr, &homa_recv_control.id, 0);
  if (ret < 0) {
    if (errno == EINTR)
      return;
    log_fatal("couldn't send Homa msg (ret %d, error %s)", ret, strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in saddr_recv;
  homa_recv_msghdr.msg_name = &saddr_recv;
  homa_recv_msghdr.msg_namelen = sizeof(saddr_recv);
  homa_recv_msghdr.msg_controllen = sizeof(homa_recv_control);

  ret = recvmsg(sockfd, &homa_recv_msghdr, 0);
  if (ret <= 0) {
    if (errno == EINTR) {
      return;
    }
    log_fatal("couldn't receive Homa msg (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }
  if ((uint32_t)ret != resp_size) {
    log_fatal("received incorrect response size (ret %d, resp_size %d)", ret, resp_size);
    exit(EXIT_FAILURE);
  }

  struct iovec vecs[HOMA_MAX_BPAGES];
  int vecs_len = homa_recv_build_iov(vecs, homa_recv_buf_region, ret,
    homa_recv_control.num_bpages, homa_recv_control.bpage_offsets);

  clock_gettime(CLOCK_MONOTONIC_RAW, &recv_time);
  add_rtt(rtt_hist, send_time, recv_time, req_size, resp_size);

  if (verbose_level > 0) {
    char saddr_recv_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &saddr_recv.sin_addr, saddr_recv_ip, INET_ADDRSTRLEN) == NULL) {
      log_fatal("Couldn't convert saddr_recv to string (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }
    log_debug("client recv (ip %s, ret %d, rpcid %ld, rtt_us %.2lf)",
      saddr_recv_ip, ret, homa_recv_control.id, calculate_time_delta_us(send_time, recv_time));
    hexdump_iov("homa client recv buf", vecs, vecs_len);
  }
}

void tcp_send_recv(int sockfd, struct histogram *rtt_hist) {
  log_debug("client send (len %d)", req_size);
  hexdump("request", (void *)send_buf, req_size);

  clock_gettime(CLOCK_MONOTONIC_RAW, &send_time);

  uint32_t bytes_sent = 0;
  while (bytes_sent < req_size) {
    ret = send(sockfd, send_buf + bytes_sent, req_size - bytes_sent, 0);
    if (ret <= 0) {
      if (errno == EINTR) {
        return;
      }
      log_fatal("Couldn't send TCP msg (ret %d, error %s)", ret, strerror(errno));
      exit(EXIT_FAILURE);
    }
    bytes_sent += ret;
  }

  uint32_t bytes_recv = 0;
  while (bytes_recv < resp_size) {
    ret = recv(sockfd, tcp_recv_buf + bytes_recv, resp_size - bytes_recv, 0);
    if (ret <= 0) {
      if (errno == EINTR) {
        return;
      }
      log_fatal("Couldn't recv TCP msg (ret %d, error %s)", ret, strerror(errno));
      exit(EXIT_FAILURE);
    }
    bytes_recv += ret;
  }

  clock_gettime(CLOCK_MONOTONIC_RAW, &recv_time);
  add_rtt(rtt_hist, send_time, recv_time, req_size, resp_size);
  log_debug("client recv (rtt_us %.2lf)", calculate_time_delta_us(send_time, recv_time));
  hexdump("recv_buf", tcp_recv_buf, resp_size);
}

int main(int argc, char *argv[]) {
  pin_core_thread(1, pthread_self());
  setup_sigaction();

  parse_args(argc, argv, false);

  struct timespec bench_start, bench_end;
  struct histogram rtt_hist = create_histogram_with_preheat(RTT_PREHEAT);

  send_buf = malloc(req_size);
  malloc_check(send_buf);
  setup_payload_buffer(send_buf, req_size);

  clock_gettime(CLOCK_MONOTONIC_RAW, &bench_start);
  if (protocol == ECHO_HOMA || protocol == ECHO_SMT) {
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
    if (sockfd < 0) {
      log_fatal("Couldn't open Homa socket (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (homa_init_recv_buffer(sockfd, &homa_recv_buf_size, &homa_recv_buf_region, HOMA_BPAGE_NUM) == -1) {
      log_fatal("Couldn't init recv buffer: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (protocol == ECHO_SMT) {
      if (smt_setsockopt_wrapper(sockfd, 0, 0, 0, 0) < 0) {
        log_fatal("Couldn't set smt key: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

    homa_recv_msghdr.msg_iov = NULL;
    homa_recv_msghdr.msg_iovlen = 0;
    homa_recv_msghdr.msg_control = &homa_recv_control;
    homa_recv_msghdr.msg_controllen = sizeof(homa_recv_control);
    homa_recv_control.flags = 0;

    log_info("Start sending RPC, Press Ctrl+C to stop...");
    while (!sigint_received) {
      homa_send_recv(sockfd, &rtt_hist);
    }
  } else if (protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS) {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
      log_fatal("Couldn't open TCP socket: %s\n", strerror(errno));
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

    if (connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      log_fatal("Couldn't connect TCP server: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (protocol == ECHO_TCP_KTLS) {
      if (tcpktls_setsockopt_wrapper(sockfd, 0, 0) < 0) {
        log_fatal("Couldn't set tcp ktls (error %s)", strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

    tcp_recv_buf = malloc(resp_size);
    malloc_check(tcp_recv_buf);

    log_info("Start sending RPC, Press Ctrl+C to stop...");
    while (!sigint_received) {
      tcp_send_recv(sockfd, &rtt_hist);
    }

    free(tcp_recv_buf);
  }
  clock_gettime(CLOCK_MONOTONIC_RAW, &bench_end);

  double bench_time = calculate_time_delta_s(bench_start, bench_end);
  double kops_per_sec = ((double)rtt_hist.total_data_points / bench_time) / 1000.0;
  double avg_req_size = rtt_hist.total_req_size / rtt_hist.total_data_points;
  double avg_resp_size = rtt_hist.total_resp_size / rtt_hist.total_data_points;
  double throughput_mbps_tx = (kops_per_sec * 1000.0) * avg_req_size * 8.0 / (1024.0 * 1024.0);
  double throughput_mbps_rx = (kops_per_sec * 1000.0) * avg_resp_size * 8.0 / (1024.0 * 1024.0);
  double avg = calculate_average(&rtt_hist);
  double avg_stddev = calculate_stddev(&rtt_hist, &avg);
  double percentiles[] = {50.0, 95.0, 99.0};
  double percentile_results[3];
  calculate_percentiles(&rtt_hist, percentiles, percentile_results, 3);

  printf("\n--- RESULT ---\n");
  printf("{\n");
  printf("  \"bench_time\": %lf,\n", bench_time);
  printf("  \"total_rpcs\": %ld,\n", rtt_hist.total_data_points);
  printf("  \"kops_per_second\": %.2lf,\n", kops_per_sec);
  printf("  \"tx_throughput_mbps\": %.2lf,\n", throughput_mbps_tx);
  printf("  \"rx_throughput_mbps\": %.2lf,\n", throughput_mbps_rx);
  printf("  \"average_rtt_us\": %.2lf,\n", avg);
  printf("  \"average_stddev_rtt_us\": %.2lf,\n", avg_stddev);
  printf("  \"p50_median_rtt_us\": %.2lf,\n", percentile_results[0]);
  printf("  \"p95_rtt_us\": %.2lf,\n", percentile_results[1]);
  printf("  \"p99_rtt_us\": %.2lf\n", percentile_results[2]);
  printf("}\n");
  printf("--- RESULT ---\n");

  free_histogram(&rtt_hist);

  close(sockfd);
  free(send_buf);

  return 0;
}
