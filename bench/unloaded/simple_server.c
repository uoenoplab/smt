#include "echo_simple.h"

int sockfd_listen = 0, ret = 0;

char caddr_ip[INET_ADDRSTRLEN] = { 0 };
struct sockaddr_in caddr = { 0 };
socklen_t caddr_slen = sizeof(caddr);

struct iovec vecs[HOMA_MAX_BPAGES + 1];

void homa_recv_reply() {
  memset(&caddr, 0, sizeof(caddr));
  homa_recv_msghdr.msg_name = &caddr;
  homa_recv_msghdr.msg_namelen = caddr_slen;
  homa_recv_control.id = 0;
  homa_recv_control.completion_cookie = 0;
  homa_recv_msghdr.msg_controllen = sizeof(homa_recv_control);

  ret = recvmsg(sockfd_listen, &homa_recv_msghdr, 0);
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

  int recv_vecs_len = homa_recv_build_iov(vecs, homa_recv_buf_region, ret,
    homa_recv_control.num_bpages, homa_recv_control.bpage_offsets);

  if (verbose_level > 0) {
    if (inet_ntop(AF_INET, &caddr.sin_addr, caddr_ip,
                  INET_ADDRSTRLEN) == NULL) {
      log_fatal("couldn't convert client address to string (inet_ntop): %s\n",
              strerror(errno));
      exit(EXIT_FAILURE);
    }
    log_info("server recv (ip %s, port %hu, ret %d, rpcid %ld)",
      caddr_ip, ntohs(caddr.sin_port), ret, homa_recv_control.id);
    hexdump_iov(__func__, vecs, recv_vecs_len);
  }

  int send_vecs_len = recv_vecs_len;
  if (send_buf) {
    vecs[recv_vecs_len].iov_base = send_buf;
    vecs[recv_vecs_len].iov_len = resp_size - req_size;
    send_vecs_len++;
  }

  int i = 0;
  uint32_t bytes_to_send = resp_size;
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
    log_fatal("iovecs received + send_buf can not accommedate resp_size (bytes_to_send %d)", bytes_to_send);
    exit(EXIT_FAILURE);
  }
  send_vecs_len = i;

  ret = homa_replyv(sockfd_listen, vecs, send_vecs_len,
    (const sockaddr_in_union *)&caddr, homa_recv_control.id);

  if (ret < 0) {
    if (errno == EINTR)
      return;
    log_fatal("couldn't send Homa msg (ret %d error %s)", ret, strerror(errno));
    exit(EXIT_FAILURE);
  }
}

int tcp_recv_send(int sockfd) {
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
  vecs[0].iov_base = tcp_recv_buf;
  if (send_buf) {
    vecs_len = 2;
    vecs[0].iov_len = req_size;
    vecs[1].iov_base = send_buf;
    vecs[1].iov_len = resp_size - req_size;
  } else {
    vecs_len = 1;
    vecs[0].iov_len = resp_size;
  }

  struct msghdr msg = { 0 };
  msg.msg_iov = vecs;
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

    homa_recv_msghdr.msg_control = &homa_recv_control;
    homa_recv_control.flags = HOMA_RECVMSG_REQUEST;

    while (!sigint_received) {
      homa_recv_reply();
    }

    close(sockfd_listen);
    munmap(homa_recv_buf_region, homa_recv_buf_size);

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

    int sockfd_client = 0;
    while (!sigint_received) {
      if (sockfd_client == 0) {
        sockfd_client = accept(sockfd_listen, (struct sockaddr *)&caddr, &caddr_slen);
        if (sockfd_client <= 0) {
          log_fatal("accept failed (error %s)", strerror(errno));
          exit(EXIT_FAILURE);
        }
        if (inet_ntop(AF_INET, &caddr.sin_addr, caddr_ip, INET_ADDRSTRLEN) == NULL) {
          log_fatal("Couldn't convert client address to string (error %s)", strerror(errno));
          exit(EXIT_FAILURE);
        }
        log_info("Accpetd new connection %s:%d", caddr_ip, ntohs(caddr.sin_port));
        if (setsockopt(sockfd_client, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) != 0) {
          perror("setsockopt TCP_QUICKACK");
          exit(EXIT_FAILURE);
        }
        if (setsockopt(sockfd_client, IPPROTO_TCP, TCP_QUICKACK, &(int){1}, sizeof(int)) != 0) {
          perror("setsockopt TCP_NODELAY");
          exit(EXIT_FAILURE);
        }
        if (protocol == ECHO_TCP_KTLS) {
          if (tcpktls_setsockopt_wrapper(sockfd_client, 1, 0) < 0) {
          log_fatal("Couldn't set tcp ktls (error %s)", strerror(errno));
          exit(EXIT_FAILURE);
          }
        }
      }
      if (tcp_recv_send(sockfd_client) != 0) {
        log_info("Disconnected connection %s:%d", caddr_ip, ntohs(caddr.sin_port));
        memset(&caddr, 0, sizeof(caddr));
        memset(&caddr_ip, 0, sizeof(caddr_ip));
        sockfd_client = 0;
      }
    }

    close(sockfd_client);
    free(tcp_recv_buf);
    close(sockfd_listen);
  }

  free(send_buf);

  return 0;
}
