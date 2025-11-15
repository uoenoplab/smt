#include "echo.h"

// variables and structs //

// common
int protocol = -1;
int num_threads = 0;
int num_server_ports = 0; // homa only
int num_server_ips = 1; // homa client only
struct sockaddr_in saddr_alter = { 0 }; // homa client only
struct sockaddr_in saddr = { 0 };
uint32_t req_size = 0;
uint32_t resp_size = 0;
bool use_google_workload = false;

// client
int num_rpcs = 0;
int num_sockets = 0;
double net_mbps = 0.0;
_Atomic uint64_t rpc_id_counter = 0;
int client_tcp_send_batch = false;

// server
int max_conns = 0;

// variables and structs //

// common utils //

void print_help(const char *prog_name, bool is_server) {
  printf("Usage: %s [OPTIONS]\n", prog_name);
  printf("Options:\n");
  printf("  --proto <protocol>                Specify the protocol to use. Supported protocols are:\n");
  printf("\t%s: TCP (listen port must be a single port)\n", protocol_names[ECHO_TCP]);
  printf("\t%s: TCP with Kernel TLS (listen port must be a single port)\n", protocol_names[ECHO_TCP_KTLS]);
  printf("\t%s: Homa\n", protocol_names[ECHO_HOMA]);
#ifdef BUILD_HOMA_CSUM
  printf("\t%s: Homa with checksum\n",  protocol_names[ECHO_HOMA_CSUM]);
#endif
  printf("\t%s: SMT\n", protocol_names[ECHO_SMT]);
#ifdef BUILD_TCPLS
  printf("\t%s: TCPLS ('num-sockets-per-thread' must be 0, 'payload-size' must use single payload-size option, 'mbps' must be 0.00)\n", protocol_names[ECHO_TCPLS]);
#endif

  if (is_server) {
    printf("  -p, --listen-ports <port>         Specify a server port or a range of server ports to listen (e.g., 8080-8085).\n");
    printf("  -n, --max-conns-per-thread <n>    Specify the maximum connections per thread.\n");
  } else {
    printf("  -a, --server-addr <addr>          Specify the server IP address.\n");
    printf("  -b, --server-addr-alter <addr>    (Optional) Specify the secondary server IP address.\n");
    printf("  -p, --server-ports <ports>        Specify a server port or a range of server ports to use (e.g., `-p 8080-8085`).\n");
    printf("  -n, --global-num-rpc <number>     Specify the global number of RPCs to perform.\n");
    printf("  -s, --num-sockets-per-thread <n>  Specify the number of sockets per thread.\n");
    printf("  -m, --mbps <bandwidth>            Specify the TX bandwidth utilization only payload in Mbps, 0 means send continuously\n");
  }

  printf("  -t, --num-threads <threads>       Specify the number of threads to use, must larger than number of listen ports \n\t"
    "Each thread will be pinned to a CPU core in a round-robin fashion.\n");
  if (is_server) {
  printf("  -l, --payload-size <optval>       Specify the maximum payload size server can handle (bytes):\n");
  } else {
  printf("  -l, --payload-size <optval>       Specify the payload size client send and receive (bytes):\n");
  }
  printf("    <payload-size>: request and response use same payload-size\n");
  printf("    <request-size>,<response-size>: specified request and response lengths by a pair (e.g., `-l 1000,200`)\n");
  printf("    g: mixed rpc length [Google SOSP23].\n");
  printf("  -x, --hexdump                     Enable hexdump output, enable -v also if set.\n");
  printf("  -v, --verbose                     Enable verbose output with log_c LOG_DEBUG level, else log_c LOG_INFO level as default. \n");
  printf("  -vv, --extra-verbose              Enable verbose output with log_c LOG_TRACE level, else log_c LOG_INFO level as default. \n");
  printf("  -q, --quiet                       Disable all normal output with log_c LOG_WARN level\n");
  printf("  -h, --help                        Display this help and exit\n");
  printf("\n");

  exit(EXIT_FAILURE);
}

void check_args_valid(const char *argv0, bool is_server, const char *msg, bool cond) {
  if (cond) {
    log_fatal("Invalid Args: %s\n", msg);
    print_help(argv0, is_server);
    exit(EXIT_FAILURE);
  }
}

void parse_args(int argc, char *argv[], bool is_server) {
  static struct option long_options[] = {
    {"proto", required_argument, 0, 'r'},
    // server
    {"listen-ports", required_argument, 0, 'p'}, // variable shared with client
    {"max-conns-per-thread", required_argument, 0, 'n'},
    // client
    {"server-addr", required_argument, 0, 'a'},
    {"server-addr-alter", required_argument, 0, 'b'},
    {"server-ports", required_argument, 0, 'p'}, // variable shared with server
    {"global-num-rpc", required_argument, 0, 'n'},
    {"num-sockets-per-thread", required_argument, 0, 's'},
    {"mbps", required_argument, 0, 'm'},
    // common
    {"num-threads", required_argument, 0, 't'},
    {"payload-size", required_argument, 0, 'l'},
    {"hexdump", no_argument, 0, 'x'},
    {"verbose", no_argument, 0, 'v'},
    {"extra-verbose", no_argument, 0, 1000},
    {"quiet", no_argument, 0, 'q'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  int opt, option_index = 0;

  int server_port = 0;
  char *delimiter;

  char server_ipaddr_str[INET_ADDRSTRLEN];
  char server_ipaddr_alter_str[INET_ADDRSTRLEN];
  struct hostent *server_hostent;
  bool server_ipaddr_set = false;

  while ((opt = getopt_long(argc, argv, "r:a:b:p:n:s:m:t:l:xvqh", long_options, &option_index)) != -1) {
    switch (opt) {
      case 'r':
        protocol = parse_protocol(optarg);
        if (protocol == -1) {
          print_protocol_names();
          exit(EXIT_FAILURE);
        }
        break;
      case 'a':
      case 'b':
        // Server address
        // get ip addr from hostname
        server_hostent = gethostbyname(optarg);
        if (server_hostent == NULL) {
          log_fatal("Get hostname IP failed: %s", strerror(errno));
          exit(EXIT_FAILURE);
        }
        // In fact gethostbyname only return an IPv4 address
        if (server_hostent->h_addrtype != AF_INET) {
          log_fatal("Only support IPv4 address: h_addrtype %d", server_hostent->h_addrtype);
          exit(EXIT_FAILURE);
        }
        struct sockaddr_in saddr_cur = { 0 };
        saddr_cur.sin_family = AF_INET;
        memcpy((char *)&saddr_cur.sin_addr.s_addr, (char *)server_hostent->h_addr,
          server_hostent->h_length);
        server_ipaddr_set = true;
        // if opt is a
        if (opt == 'a') {
          saddr = saddr_cur;
          if (!inet_ntop(AF_INET, &(saddr_cur.sin_addr), server_ipaddr_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed");
          }
        } else {
          saddr_alter = saddr_cur;
          num_server_ips += 1;
          if (!inet_ntop(AF_INET, &(saddr_cur.sin_addr), server_ipaddr_alter_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed");
          }
        }
        break;
      case 'p':
        // Server port
        delimiter = strchr(optarg, '-');
        if (delimiter != NULL) {
          *delimiter = '\0';  // Split the string into two null-terminated strings
          server_port = parse_int(optarg);
          num_server_ports = parse_int(delimiter + 1) - server_port;
          if (num_server_ports < 0) {
            log_fatal("second port must be larger than first one!\n");
            exit(EXIT_FAILURE);
          } else {
            num_server_ports++;
          }
        } else {
          server_port = parse_int(optarg);
          num_server_ports = 1;
        }
        saddr.sin_port = htons(server_port);
        break;
      case 'n':
        // Global number of RPC (client) or max connections per thread (server)
        if (is_server) {
          max_conns = parse_int(optarg);
        } else {
          num_rpcs = parse_int(optarg);
        }
        break;
      case 's':
        // Number of sockets per thread (client only)
        num_sockets = parse_int(optarg);
      break;
      case 'm':
        // Network mbps (client only)
        net_mbps = parse_double(optarg);
        break;
      case 't':
        // Number of threads
        num_threads = parse_int(optarg);
        break;
      case 'l':
        // Payload length
        if (strcmp(optarg, "g") == 0) {
          use_google_workload = true;
          // avg is calculated here to print the value in config json dump
          get_google_workload_avg_rpc_size(&req_size, &resp_size);
        } else {
          delimiter = strchr(optarg, ',');
          if (delimiter != NULL) {
            *delimiter = '\0';  // Split the string into two null-terminated strings
            req_size = parse_int(optarg);
            resp_size = parse_int(delimiter + 1);
          } else {
            req_size = resp_size = parse_int(optarg);
          }
        }
        break;
      case 'x':
        verbose_level = 3;
        break;
      case 'v':
        if (verbose_level < 2) {
          verbose_level = 1;
        }
        break;
      case 1000:  // --extra-verbose
        if (verbose_level < 3) {
          verbose_level = 2;
        }
        break;
      case 'q':
        if (verbose_level != 0) {
          log_fatal("--quiet can not be used with --verbose, --extra-verbose or --hexdump");
          exit(EXIT_FAILURE);
        }
        verbose_level = -1;
        break;
      case 'h':
      case '?':
      default:
        print_help(argv[0], is_server);
    }
  }

  if (verbose_level == 1) {
    int v_count = 0;
    for (int i = 1; i < argc; ++i) {
      if (strncmp(argv[i], "-v", 2) == 0) {
        const char *p = argv[i] + 1;
        while (*p == 'v') {
          v_count++;
          p++;
        }
      }
    }
    if (v_count > 1) {
      verbose_level = 2;
    }
  }

  if (argc <= 1) {
    print_help(argv[0], is_server);
  }

  if (protocol < 0 || num_server_ports <= 0  || server_port <= 0 ||
    num_threads <= 0 || req_size == 0 || resp_size == 0 ||
    verbose_level < -1 || verbose_level > 3) {
    log_fatal("Invalid Args!\n");
    print_help(argv[0], is_server);
  }

  if ((req_size > HOMA_MAX_MESSAGE_LENGTH) || (req_size > HOMA_MAX_MESSAGE_LENGTH)) {
    log_fatal("req_size (%u) or resp_siez(%u) exceeds HOMA_MAX_MESSAGE_LENGTH\n", req_size, resp_size);
    print_help(argv[0], is_server);
  }

  bool is_invalid = false;

  if (is_server) {
    is_invalid |= (max_conns <= 0);
    if (protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS) {
      if (num_server_ports != 1) {
        log_fatal("TCP num_server_ports should be 1");
        print_help(argv[0], is_server);
      }
    } else if (protocol == ECHO_HOMA || protocol == ECHO_SMT
#ifdef BUILD_HOMA_CSUM
      || protocol == ECHO_HOMA_CSUM
#endif
    ) {
      if (num_threads < num_server_ports) {
        log_fatal("Homa num_threads should be equal or larger num_server_ports");
        print_help(argv[0], is_server);
      }
    }
  } else {
    is_invalid |= (!server_ipaddr_set || num_rpcs <= 0 || net_mbps < 0.0);
#ifdef BUILD_TCPLS
    int num_sockets_tmp = num_sockets;
    if (protocol == ECHO_TCPLS) {
      if (num_sockets != 0) {
        log_fatal("tcpls: num_sockets should be 0 (dummy value), actual"
          "num_sockets used by each thread will be decided by num_rpcs and"
          "num_threads \n");
        is_invalid = true;
      }
      if (use_google_workload || resp_size != req_size) {
        log_fatal("tcpls: doesn't support mixed workload or response size differnt from request size\n");
        is_invalid = true;
      }
      if (net_mbps != 0.0) {
        log_fatal("tcpls: doesn't support rate limit\n");
        is_invalid = true;
      }
      num_sockets = num_rpcs / num_threads;
    }
#endif
#ifdef MAKE_ONESOCK
    is_invalid |= (num_sockets != 1);
#else
    is_invalid |= (num_sockets <= 0);
#endif
#ifdef BUILD_TCPLS
    num_sockets = num_sockets_tmp;
#endif
    if (num_rpcs < num_threads) {
      log_warn("number of RPCs is smaller than number of threads\n");
    }
    const char *client_tcp_send_batch_str = getenv("HOMA_ECHO_CLIENT_TCP_SEND_BATCH");
    if (client_tcp_send_batch_str) client_tcp_send_batch = parse_int(client_tcp_send_batch_str);
  }
  if (is_invalid) {
    log_fatal("invalid arg(s)!\n");
    print_help(argv[0], is_server);
  }

  set_log_c_verbose_level(verbose_level);

  const char *server_config_line = "--- SERVER CONFIG ---\n";
  const char *client_config_line = "--- CLIENT CONFIG ---\n";
  printf("%s", is_server ? server_config_line : client_config_line);
  printf("{\n");
  printf("  \"protocol\": \"%s\",\n", protocol_names[protocol]);
  if (!is_server) {
    printf("  \"server_ip\": \"%s\",\n", server_ipaddr_str);
    if (num_server_ips > 1) {
      printf("  \"server_ip_alter\": \"%s\",\n", server_ipaddr_alter_str);
    }
  }
  printf("  \"server_port_base\": %d,\n", server_port);
  printf("  \"num_server_ports\": %d,\n", num_server_ports);
  if (is_server) {
    printf("  \"max_conns_per_thread\": %d,\n", max_conns);
  } else {
    printf("  \"num_global_rpcs\": %d,\n", num_rpcs);
    printf("  \"num_sockets_per_thread\": %d,\n", num_sockets);
    printf("  \"net_mbps\": %f,\n", net_mbps);
  }
  printf("  \"num_threads\": %d,\n", num_threads);
  if (use_google_workload) {
    printf("  \"payload_size\": \"%d,%d (google workload average)\",\n", req_size, resp_size);
  } else {
    printf("  \"payload_size\": \"%d,%d\",\n", req_size, resp_size);
  }
  printf("  \"verbose_level\": %d\n", verbose_level);
  printf("}\n");
  printf("%s", is_server ? server_config_line : client_config_line);
  printf("\n");
}

// first variable of args must be pthread_t
void launch_threads(void *args_list, int num_threads, size_t arg_size, void *(*thread_func)(void *)) {
  int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

  pthread_attr_t attr;
  pthread_attr_init(&attr);

  sigset_t sigmask;
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGINT);

  const char *disable_pin_core_env = getenv("HOMA_ECHO_PIN_CORE_DISABLE");
  const bool pin_core = (disable_pin_core_env == NULL) ? true : !parse_int(disable_pin_core_env);
  const char *pin_core_offset_env = getenv("HOMA_ECHO_PIN_CORE_OFFSET");
  const int pin_core_offset = (pin_core_offset_env == NULL) ? 1 : parse_int(pin_core_offset_env);

  for (int i = 0; i < num_threads; i++) {
    if (pin_core) {
        int core_id = (i + pin_core_offset) % num_cores;
        pin_core_attr(core_id, &attr);
        pthread_attr_setsigmask_np(&attr, &sigmask);
        log_info("thread %d is pinned core %d", i, core_id);
    } else {
        log_info("pin core disabled");
    }
    void *thread_arg = (char*)args_list + i * arg_size;
    pthread_t *thread_id = (pthread_t *)thread_arg;

    int ret = pthread_create(thread_id, &attr, thread_func, thread_arg);
    if (ret) {
      log_fatal("error creating thread %ld (error %s)\n", i, strerror(ret));
      exit(EXIT_FAILURE);
    }
  }

  pthread_attr_destroy(&attr);
}

// try join with timeout then kill
int shutdown_thread(pthread_t thread, long tv_nsec) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_nsec = tv_nsec;
  ts.tv_sec += ts.tv_nsec / (long)1e9;
  ts.tv_nsec = ts.tv_nsec % (long)1e9;
  // 10 * 1e6; // wait for 10 ms
  int ret = pthread_timedjoin_np(thread, NULL, &ts);
  if (ret == 0) {
    return 0;
  }
  pthread_kill(thread, SIGUSR1);
  return -1;
}

// common utils //

#if defined MAKE_IOURING

// iouring helper functions //

#define GET_SQE_OR_RETURN(ring) \
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring); \
  if (sqe == NULL) { \
    log_error("io_uring_submission queue full"); \
    return -1; \
  }

static ssize_t submit_request(struct io_uring *ring) {
  int ret = io_uring_submit(ring);
  if (ret < 0) {
    log_error("io_uring_submit failed (error %s)", strerror(-ret));
    return -1;
  } else if (ret == 0) {
    log_error("io_uring_submit returned 0 (error %s)", strerror(-ret));
    return -1;
  }
  return 0;
}

ssize_t add_connect_request(struct io_uring *ring, int fd, void *data, bool submit) {
  GET_SQE_OR_RETURN(ring);

  io_uring_prep_connect(sqe, fd, (struct sockaddr *)&saddr, sizeof(saddr));
  io_uring_sqe_set_data(sqe, data);

  return submit ? submit_request(ring) : 0;
}

ssize_t add_send_request(struct io_uring *ring, int fd, void *buf,
  size_t len, void *data, bool submit) {
  GET_SQE_OR_RETURN(ring);

  io_uring_prep_send(sqe, fd, buf, len, 0);
  io_uring_sqe_set_data(sqe, data);

  return submit ? submit_request(ring) : 0;
}

ssize_t add_recv_request(struct io_uring *ring, int fd, void *buf,
  size_t len, void *data, bool submit) {
  GET_SQE_OR_RETURN(ring);

  io_uring_prep_recv(sqe, fd, buf, len, 0);
  io_uring_sqe_set_data(sqe, data);

  return submit ? submit_request(ring) : 0;
}

ssize_t add_sendmsg_request(struct io_uring *ring, int fd,
  const struct msghdr *msg, unsigned int flags, void *data, bool submit) {
  GET_SQE_OR_RETURN(ring);

  io_uring_prep_sendmsg(sqe, fd, msg, flags);
  io_uring_sqe_set_data(sqe, data);

  return submit ? submit_request(ring) : 0;
}

ssize_t add_recvmsg_request(struct io_uring *ring, int fd,
  struct msghdr *msg, unsigned int flags, void *data, bool submit) {
  GET_SQE_OR_RETURN(ring);

  io_uring_prep_recvmsg(sqe, fd, msg, flags);
  io_uring_sqe_set_data(sqe, data);

  return submit ? submit_request(ring) : 0;
}

// iouring helper functions //

#endif // MAKE_IOURING

#ifdef MAKE_EPOLL

// epoll helper functions //

#ifdef MAKE_EPOLL_NONBLOCK
int epoll_wait_timeout = 0;
#else
int epoll_wait_timeout = -1;
#endif

static void epoll_ctl_wrapper(int epoll_fd, int op, int sockfd, uint32_t events, void *data_ptr) {
  struct epoll_event event = { 0 };
  event.data.ptr = data_ptr;
  event.events = events;
  if (epoll_ctl(epoll_fd, op, sockfd, &event) != 0) {
    log_fatal("epoll_ctl failed (epoll_fd %d, op %d, sockfd %d, events %d, error %s)",
      epoll_fd, op, sockfd, events, strerror(errno));
    exit(EXIT_FAILURE);
  }
}

void add_event(const int epoll_fd, const int sockfd, uint32_t events, void *data_ptr) {
  epoll_ctl_wrapper(epoll_fd, EPOLL_CTL_ADD, sockfd, events, data_ptr);
}

void modify_event(const int epoll_fd, const int sockfd, uint32_t events, void *data_ptr) {
  epoll_ctl_wrapper(epoll_fd, EPOLL_CTL_MOD, sockfd, events, data_ptr);
}

// epoll helper functions //

#endif // MAKE_EPOLL
