#include "echo_simple.h"

int sockfd_listen = 0, ret = 0;

char caddr_ip[INET_ADDRSTRLEN] = { 0 };
struct sockaddr_in caddr = { 0 };
socklen_t caddr_slen = sizeof(caddr);

static inline void homa_recv_reply() {
  memset(&caddr, 0, sizeof(caddr));
  struct msghdr recv_msghdr = {
    .msg_name = &caddr,
    .msg_namelen = sizeof(caddr),
    .msg_iov = NULL,
    .msg_iovlen = 0,
    .msg_control = &homa_recv_control,
    .msg_controllen = sizeof(homa_recv_control),
    .msg_flags = 0
  };

  homa_recv_control.id = 0;

  ret = recvmsg(sockfd_listen, &recv_msghdr, 0);
  if (ret < 0) {
    if (errno == EINTR)
      return;
    log_error("couldn't receive Homa msg (error %s)", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if ((uint32_t)ret != req_size) {
    log_error("received incorrect req size (ret %d, req_size %d)", ret, req_size);
    exit(EXIT_FAILURE);
  }

  int recv_vecs_len = homa_recv_build_iov(homa_vecs, homa_recv_buf_region, ret,
    homa_recv_control.num_bpages, homa_recv_control.bpage_offsets);
  if (recv_vecs_len <= 0) {
    log_error("homa_recv_build_iov failed");
    exit(EXIT_FAILURE);
  }

  if (verbose_level > 0) {
    if (inet_ntop(AF_INET, &caddr.sin_addr, caddr_ip,
                  INET_ADDRSTRLEN) == NULL) {
      log_fatal("couldn't convert client address to string (inet_ntop): %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
    log_info("server recv (ip %s, port %hu, ret %d, recv_vecs_len %d, rpcid %ld)",
      caddr_ip, ntohs(caddr.sin_port), ret, recv_vecs_len, homa_recv_control.id);
    hexdump_iov(__func__, homa_vecs, recv_vecs_len);
  }

  int send_vecs_len = recv_vecs_len;
  if (send_buf) {
    homa_vecs[recv_vecs_len].iov_base = send_buf;
    homa_vecs[recv_vecs_len].iov_len = resp_size - req_size;
    send_vecs_len++;
  }

  int i = 0;
  uint32_t bytes_to_send = resp_size;
  for (; i < send_vecs_len; i++)
  {
    if (bytes_to_send < homa_vecs[i].iov_len) {
      homa_vecs[i].iov_len = bytes_to_send;
      bytes_to_send = 0;
      i++;
      break;
    } else {
      bytes_to_send -= homa_vecs[i].iov_len;
    }
  }
  if (bytes_to_send > 0) {
    log_fatal("iovecs received + send_buf can not accommedate resp_size (bytes_to_send %d)", bytes_to_send);
    exit(EXIT_FAILURE);
  }
  send_vecs_len = i;

  struct homa_sendmsg_args send_control = {
    .id = homa_recv_control.id,
    .completion_cookie = 0,
    .flags = 0,
    .reserved = 0,
  };
  struct msghdr send_msghdr = {
    .msg_name = (struct sockaddr *)&caddr,
    .msg_namelen = sizeof(caddr),
    .msg_iov = (struct iovec *)homa_vecs,
    .msg_iovlen = (size_t)send_vecs_len,
    .msg_control = &send_control,
    .msg_controllen = 0,
  };

  ret = sendmsg(sockfd_listen, &send_msghdr, 0);
  log_debug("server replied (send_vecs_len %d, ret %d)", send_vecs_len, ret);
  if (ret < 0) {
    if (errno == EINTR)
      return;
    log_fatal("couldn't send Homa msg (ret %d error %s)", ret, strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static inline int tcp_recv_send(int sockfd) {
  uint32_t bytes_recv = 0;
  while (bytes_recv < req_size) {
    ret = recv(sockfd, tcp_recv_buf + bytes_recv, req_size - bytes_recv, 0);
    if (ret <= 0) {
      log_error("couldn't receive TCP (ret %d, error %s)", ret, strerror(errno));
      return -1;
    }
    bytes_recv += ret;
    log_debug("server recv %d/%d bytes", bytes_recv, req_size);
  }

  int vecs_len;
  homa_vecs[0].iov_base = tcp_recv_buf;
  if (send_buf) {
    vecs_len = 2;
    homa_vecs[0].iov_len = req_size;
    homa_vecs[1].iov_base = send_buf;
    homa_vecs[1].iov_len = resp_size - req_size;
  } else {
    vecs_len = 1;
    homa_vecs[0].iov_len = resp_size;
  }

  struct msghdr msg = { 0 };
  msg.msg_iov = homa_vecs;
  msg.msg_iovlen = vecs_len;

  uint32_t bytes_sent = 0;
  ret = 0;
  while (bytes_sent < resp_size) {
    while (ret > 0 && msg.msg_iovlen > 0) {
      if ((size_t)ret < msg.msg_iov->iov_len) {
        msg.msg_iov->iov_base = (char*)msg.msg_iov->iov_base + ret;
        msg.msg_iov->iov_len -= ret;
        ret = 0;
      } else {
        ret -= msg.msg_iov->iov_len;
        msg.msg_iov++;
        msg.msg_iovlen--;
      }
    }
    ret = sendmsg(sockfd, &msg, 0);
    if (ret <= 0) {
      log_error("Failed to send TCP message (ret %d, error %s)", ret, strerror(errno));
      return -1;
    }
    bytes_sent += ret;
    log_debug("server sent %d/%d bytes", bytes_sent, resp_size);
  }

  return 0;
}

int main(int argc, char *argv[]) {
  pin_core_thread(1, pthread_self());
  setup_sigaction();

  parse_args(argc, argv, true);
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;

  if (resp_size > req_size) {
    send_buf = malloc(resp_size - req_size);
    malloc_check(send_buf);
    setup_payload_buffer(send_buf, resp_size - req_size);
  }

  if (protocol == ECHO_HOMA || protocol == ECHO_SMT) {
    sockfd_listen = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
    if (sockfd_listen < 0) {
      log_fatal("Couldn't open Homa socket (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (homa_init_recv_buffer(sockfd_listen, &homa_recv_buf_size, &homa_recv_buf_region, HOMA_BPAGE_NUM) == -1) {
      log_fatal("Couldn't init recv buffer: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (bind(sockfd_listen, (struct sockaddr *)&saddr, sizeof(saddr)) != 0) {
      log_fatal("Couldn't bind Homa (eror %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (protocol == ECHO_SMT) {
      if (smt_setsockopt_wrapper(sockfd_listen, 0, 0, 1, 0) < 0) {
        log_fatal("Couldn't init recv buffer: %s", strerror(errno));
        exit(EXIT_FAILURE);
      }
    }

    while (!sigint_received) {
      homa_recv_reply();
    }

  } else if (protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS) {
    tcp_recv_buf = malloc(req_size);
    malloc_check(tcp_recv_buf);

    sockfd_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_listen < 0) {
      log_fatal("Couldn't open TCP socket (error %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd_listen, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0) {
      perror("setsockopt SO_REUSEADDR");
      exit(EXIT_FAILURE);
    }

    if (bind(sockfd_listen, (struct sockaddr *)&saddr, sizeof(saddr)) != 0) {
      log_fatal("Couldn't bind TCP (eror %s)", strerror(errno));
      exit(EXIT_FAILURE);
    }

    ret = listen(sockfd_listen, 1);
    if (ret < 0) {
      printf("listen failed: %s\n", strerror(errno));
      return 1;
    }

    int sockfd_conn = 0;
    while (!sigint_received) {
      if (sockfd_conn == 0) {
        sockfd_conn = accept(sockfd_listen, (struct sockaddr *)&caddr, &caddr_slen);
        if (sockfd_conn <= 0) {
          log_fatal("accept failed (error %s)", strerror(errno));
          exit(EXIT_FAILURE);
        }
        if (inet_ntop(AF_INET, &caddr.sin_addr, caddr_ip, INET_ADDRSTRLEN) == NULL) {
          log_fatal("Couldn't convert client address to string (error %s)", strerror(errno));
          exit(EXIT_FAILURE);
        }
        log_info("Accepted new connection %s:%d(%d)", caddr_ip, ntohs(caddr.sin_port), sockfd_conn);
        if (setsockopt(sockfd_conn, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) != 0) {
          perror("setsockopt TCP_NODELAY");
          exit(EXIT_FAILURE);
        }
        if (setsockopt(sockfd_conn, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) != 0) {
          perror("setsockopt TCP_QUICKACK");
          exit(EXIT_FAILURE);
        }
        if (protocol == ECHO_TCP_KTLS) {
          if (tcpktls_setsockopt_wrapper(sockfd_conn, 1, 0) < 0) {
          log_fatal("Couldn't set tcp ktls (error %s)", strerror(errno));
          exit(EXIT_FAILURE);
          }
        }
      }
      if (tcp_recv_send(sockfd_conn) != 0) {
        log_info("Connection %s:%d(%d) disconnected ",
          caddr_ip, ntohs(caddr.sin_port), sockfd_conn);
        memset(&caddr, 0, sizeof(caddr));
        memset(&caddr_ip, 0, sizeof(caddr_ip));
        close(sockfd_conn);
        sockfd_conn = 0;
      }
    }

    if (sockfd_conn > 0)
      close(sockfd_conn);
  }

  if (homa_recv_buf_region)
    munmap(homa_recv_buf_region, homa_recv_buf_size);
  if (tcp_recv_buf)
    free(tcp_recv_buf);

  close(sockfd_listen);
  free(send_buf);

  return 0;
}
