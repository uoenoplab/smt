#include "echo_loaded.h"

// variables and structs //

// common
int protocol = -1;
int num_threads = 0;
int num_server_ports = 0;
int num_server_ips = 1;
struct sockaddr_in saddr = { 0 };
struct sockaddr_in saddr_alter = { 0 };
uint32_t req_size = 0;
uint32_t resp_size = 0;
bool use_google_workload = false;

// client
int num_rpcs = 0;
int num_sockets = 0;
double net_mbps = 0.0;
_Atomic uint64_t rpc_id_counter = 0;
int client_tcp_send_batch = 0;

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
  printf("\t%s: SMT (built on Homa)\n", protocol_names[ECHO_SMT]);

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
  printf("  -v, --verbose                     Increase log level; repeat for more detail.\n");
  printf("                                      (default: info; -v: debug; -vv: trace; -vvv: trace + hexdump)\n");
  printf("  -q, --quiet                       Disable all normal output with log_c LOG_WARN level\n");
  printf("  -h, --help                        Display this help and exit\n");
  printf("\n");

  exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[], bool is_server) {
  static struct option long_options[] = {
    { "proto",                  required_argument, 0, 'r' },
    { "listen-ports",           required_argument, 0, 'p' },
    { "max-conns-per-thread",   required_argument, 0, 'n' },
    { "server-addr",            required_argument, 0, 'a' },
    { "server-addr-alter",      required_argument, 0, 'b' },
    { "server-ports",           required_argument, 0, 'p' },
    { "global-num-rpc",         required_argument, 0, 'n' },
    { "num-sockets-per-thread", required_argument, 0, 's' },
    { "mbps",                   required_argument, 0, 'm' },
    { "num-threads",            required_argument, 0, 't' },
    { "payload-size",           required_argument, 0, 'l' },
    { "verbose",                no_argument,       0, 'v' },
    { "quiet",                  no_argument,       0, 'q' },
    { "help",                   no_argument,       0, 'h' },
    { 0, 0, 0, 0 }
  };
  int opt, option_index = 0;
  int server_port = 0;
  char *delimiter;
  char server_ipaddr_str[INET_ADDRSTRLEN] = { 0 };
  char server_ipaddr_alter_str[INET_ADDRSTRLEN] = { 0 };
  struct hostent *server_hostent;
  bool server_ipaddr_set = false;

  while ((opt = getopt_long(argc, argv, "r:a:b:p:n:s:m:t:l:vqh",
          long_options, &option_index)) != -1) {
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
      server_hostent = gethostbyname(optarg);
      if (server_hostent == NULL) {
        log_fatal("Get hostname IP failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
      }
      if (server_hostent->h_addrtype != AF_INET) {
        log_fatal("Only support IPv4 address: h_addrtype %d",
                  server_hostent->h_addrtype);
        exit(EXIT_FAILURE);
      }
      struct sockaddr_in saddr_cur = { 0 };
      saddr_cur.sin_family = AF_INET;
      memcpy(&saddr_cur.sin_addr.s_addr, server_hostent->h_addr,
             server_hostent->h_length);
      if (opt == 'a') {
        saddr = saddr_cur;
        if (!inet_ntop(AF_INET, &saddr_cur.sin_addr, server_ipaddr_str,
                       INET_ADDRSTRLEN))
          log_warn("inet_ntop failed: %s", strerror(errno));
        server_ipaddr_set = true;
      } else {
        saddr_alter = saddr_cur;
        num_server_ips = 2;
        if (!inet_ntop(AF_INET, &saddr_cur.sin_addr, server_ipaddr_alter_str,
                       INET_ADDRSTRLEN))
          log_warn("inet_ntop failed: %s", strerror(errno));
      }
      break;
    case 'p':
      delimiter = strchr(optarg, '-');
      if (delimiter != NULL) {
        *delimiter = '\0';
        server_port = parse_int(optarg);
        num_server_ports = parse_int(delimiter + 1) - server_port + 1;
        if (num_server_ports <= 0) {
          log_fatal("second port must be larger than first one!");
          exit(EXIT_FAILURE);
        }
      } else {
        server_port = parse_int(optarg);
        num_server_ports = 1;
      }
      saddr.sin_port = htons(server_port);
      break;
    case 'n':
      if (is_server)
        max_conns = parse_int(optarg);
      else
        num_rpcs = parse_int(optarg);
      break;
    case 's':
      num_sockets = parse_int(optarg);
      break;
    case 'm':
      net_mbps = parse_double(optarg);
      break;
    case 't':
      num_threads = parse_int(optarg);
      break;
    case 'l':
      if (strcmp(optarg, "g") == 0) {
        use_google_workload = true;
        get_google_workload_avg_rpc_size(&req_size, &resp_size);
      } else {
        delimiter = strchr(optarg, ',');
        if (delimiter != NULL) {
          *delimiter = '\0';
          req_size = parse_int(optarg);
          resp_size = parse_int(delimiter + 1);
        } else {
          req_size = resp_size = parse_int(optarg);
        }
      }
      break;
    case 'v':
      // each -v bumps one level: -v=debug, -vv=trace, -vvv=trace+hexdump
      if (verbose_level < 3) verbose_level++;
      break;
    case 'q':
      if (verbose_level != 0) {
        log_fatal("--quiet conflicts with -v");
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

  if (argc <= 1)
    print_help(argv[0], is_server);

  if (protocol < 0 || num_server_ports <= 0 || server_port <= 0 ||
      num_threads <= 0 || req_size == 0 || resp_size == 0) {
    log_fatal("missing or invalid required args");
    print_help(argv[0], is_server);
  }
  if (req_size > HOMA_MAX_MESSAGE_LENGTH ||
      resp_size > HOMA_MAX_MESSAGE_LENGTH) {
    log_fatal("payload exceeds HOMA_MAX_MESSAGE_LENGTH");
    exit(EXIT_FAILURE);
  }

  if (is_server) {
    if (max_conns <= 0) {
      log_fatal("--max-conns-per-thread must be > 0");
      exit(EXIT_FAILURE);
    }
    if ((protocol == ECHO_TCP || protocol == ECHO_TCP_KTLS) &&
        num_server_ports != 1) {
      log_fatal("tcp server must use a single port");
      exit(EXIT_FAILURE);
    }
    if ((protocol == ECHO_HOMA || protocol == ECHO_SMT) &&
        num_threads < num_server_ports) {
      log_fatal("homa: num_threads must be >= num_server_ports");
      exit(EXIT_FAILURE);
    }
  } else {
    if (!server_ipaddr_set || num_rpcs <= 0 || num_sockets <= 0 ||
        net_mbps < 0.0) {
      log_fatal("missing or invalid client args");
      print_help(argv[0], is_server);
    }
    if (num_rpcs < num_threads)
      log_warn("num_rpcs < num_threads");
    const char *client_tcp_send_batch_str =
        getenv("HOMA_ECHO_CLIENT_TCP_SEND_BATCH");
    if (client_tcp_send_batch_str)
      client_tcp_send_batch = parse_int(client_tcp_send_batch_str);
  }

  set_log_c_verbose_level(verbose_level);

  const char *epoll_wait_timeout_str = getenv("HOMA_ECHO_EPOLL_WAIT_TIMEOUT");
  if (epoll_wait_timeout_str)
    epoll_wait_timeout = parse_int(epoll_wait_timeout_str);

  const char *banner = is_server ? "--- SERVER CONFIG ---\n"
               : "--- CLIENT CONFIG ---\n";
  printf("%s", banner);
  printf("{\n");
  printf("  \"protocol\": \"%s\",\n", protocol_names[protocol]);
  if (!is_server) {
    printf("  \"server_ip\": \"%s\",\n", server_ipaddr_str);
    if (num_server_ips > 1)
      printf("  \"server_ip_alter\": \"%s\",\n", server_ipaddr_alter_str);
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
  printf("  \"payload_size\": \"%u,%u%s\",\n", req_size, resp_size,
         use_google_workload ? " (google workload average)" : "");
  printf("  \"verbose_level\": %s\n", get_verbose_level_str(verbose_level));
  printf("}\n");
  printf("%s\n", banner);
}

void launch_threads(void *args_list, int num_threads, size_t arg_size,
                    void *(*thread_func)(void *)) {
  int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
  pthread_attr_t attr;
  sigset_t sigmask;
  const char *disable_pin_core_env = getenv("HOMA_ECHO_PIN_CORE_DISABLE");
  const bool pin_core =
      (disable_pin_core_env == NULL) ? true : !parse_int(disable_pin_core_env);
  const char *pin_core_offset_env = getenv("HOMA_ECHO_PIN_CORE_OFFSET");
  const int pin_core_offset =
      (pin_core_offset_env == NULL) ? 1 : parse_int(pin_core_offset_env);

  pthread_attr_init(&attr);
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGINT);

  for (int i = 0; i < num_threads; i++) {
    if (pin_core) {
      int core_id = (i + pin_core_offset) % num_cores;

      pin_core_attr(core_id, &attr);
      pthread_attr_setsigmask_np(&attr, &sigmask);
      log_info("thread %d is pinned core %d", i, core_id);
    } else {
      log_info("pin core disabled");
    }
    void *thread_arg = (char *)args_list + i * arg_size;
    pthread_t *thread_id = (pthread_t *)thread_arg;

    int ret = pthread_create(thread_id, &attr, thread_func, thread_arg);

    if (ret) {
      log_fatal("error creating thread %d (error %s)", i, strerror(ret));
      exit(EXIT_FAILURE);
    }
  }
  pthread_attr_destroy(&attr);
}

int shutdown_thread(pthread_t thread, long tv_nsec) {
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_nsec = tv_nsec;
  ts.tv_sec += ts.tv_nsec / (long)1e9;
  ts.tv_nsec = ts.tv_nsec % (long)1e9;
  if (pthread_timedjoin_np(thread, NULL, &ts) == 0)
    return 0;
  pthread_kill(thread, SIGUSR1);
  return -1;
}

// common utils //

// rate limit (leaky bucket) //

void rate_limit_init(double rate, struct rate_limit_context *rate_limit) {
  rate_limit->rate = rate;
  rate_limit->budget = 0.0;
  memset(&rate_limit->last_time, 0, sizeof(rate_limit->last_time));
}

void rate_limit_sleep(double wait_time) {
  if (wait_time > 0.000001) {
    struct timespec ts;

    ts.tv_sec = (time_t)wait_time;
    ts.tv_nsec = (long)((wait_time - ts.tv_sec) * 1e9);
    log_debug("sleeping for %ld.%09ld seconds", ts.tv_sec, ts.tv_nsec);
    nanosleep(&ts, NULL);
  }
}

double rate_limit_try_send(struct rate_limit_context *rate_limit,
                           uint32_t bytes_to_send) {
  if (rate_limit->rate == 0.0) {
    log_debug("no rate limit");
    return 0.0;
  }
  struct timespec current_time;

  clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);
  if (rate_limit->last_time.tv_sec == 0 && rate_limit->last_time.tv_nsec == 0) {
    rate_limit->last_time = current_time;
    rate_limit->budget += bytes_to_send;
  }
  double time_elapsed = calculate_time_delta_s(current_time,
                                               rate_limit->last_time);

  rate_limit->last_time = current_time;
  rate_limit->budget += time_elapsed * rate_limit->rate;
  if (rate_limit->budget >= (double)bytes_to_send) {
    rate_limit->budget -= (double)bytes_to_send;
    if (rate_limit->budget > rate_limit->rate)
      rate_limit->budget = rate_limit->rate;
    log_debug("can send (budget %f rate %f time_elapsed %f)",
              rate_limit->budget, rate_limit->rate, time_elapsed);
    return 0.0;
  }
  log_debug("cannot send (budget %f rate %f time_elapsed %f)",
            rate_limit->budget, rate_limit->rate, time_elapsed);
  return ((double)bytes_to_send - rate_limit->budget) / rate_limit->rate;
}

// rate limit (leaky bucket) //

// epoll helpers //

#include <sys/epoll.h>

int epoll_wait_timeout = -1;

void add_epoll_event(int epoll_fd, int sockfd, uint32_t events,
                     void *data_ptr) {
  struct epoll_event event = { 0 };
  event.data.ptr = data_ptr;
  event.events = events;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &event) != 0) {
    log_fatal("epoll_ctl ADD failed (sockfd %d): %s",
              sockfd, strerror(errno));
    exit(EXIT_FAILURE);
  }
}

void mod_epoll_event(int epoll_fd, int sockfd, uint32_t events,
                     void *data_ptr) {
  struct epoll_event event = { 0 };
  event.data.ptr = data_ptr;
  event.events = events;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sockfd, &event) != 0) {
    log_fatal("epoll_ctl MOD failed (sockfd %d): %s",
              sockfd, strerror(errno));
    exit(EXIT_FAILURE);
  }
}

// epoll helpers //
