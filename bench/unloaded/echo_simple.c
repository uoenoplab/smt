#include "echo_simple.h"

// variables and structs //

int protocol = -1;
struct sockaddr_in saddr = { 0 };
uint32_t req_size = 0;
uint32_t resp_size = 0;

// server - len is resp_size - req_size
// client - len is req_size
uint8_t *send_buf = NULL;

// server - len is req_size
// client - len is resp_size
uint8_t *tcp_recv_buf = NULL;

size_t homa_recv_buf_size = 0;
uint8_t *homa_recv_buf_region = NULL;
struct homa_recvmsg_args homa_recv_control = { 0 };
struct msghdr homa_recv_msghdr = { 0 };

// variables and structs //

// common utils //

void print_help(char *prog_name, bool is_server) {
  printf("Usage: %s [OPTIONS]\n", prog_name);
  printf("Options:\n");
  printf("  --proto <protocol>                Specify the protocol to use. Supported protocols are:\n");
  printf("\t%s: TCP (listen port must be a single port)\n", protocol_names[ECHO_TCP]);
  printf("\t%s: TCP with Kernel TLS (listen port must be a single port)\n", protocol_names[ECHO_TCP_KTLS]);
  printf("\t%s: Homa\n", protocol_names[ECHO_HOMA]);
  printf("\t%s: SMT\n", protocol_names[ECHO_SMT]);

  if (is_server) {
    printf("  -p, --listen-port <port>          Specify a listen port (e.g. 2000).\n");
  } else {
    printf("  -a, --server-address <address>    Specify the server IP address.\n");
    printf("  -p, --server-port <ports>         Specify a server port (e.g. 2000).\n");
  }

  if (is_server) {
  printf("  -l, --payload-size <optval>       Specify the maximum payload size server can handle (bytes):\n");
  } else {
  printf("  -l, --payload-size <optval>       Specify the payload size client send and receive (bytes):\n");
  }
  printf("    <payload-size>: request and response use same payload-size\n");
  printf("    <request-size>,<response-size>: specified request and response lengths by a pair (e.g., `-l 1000,200`)\n");
  printf("  -x, --hexdump                     Enable hexdump output, enable -v also if set.\n");
  printf("  -v, --verbose                     Enable verbose output with log_c LOG_TRACE level, else log_c LOG_INFO level as default. \n");
  printf("  -q, --quiet                       Disable all normal output with log_c LOG_WARN level\n");
  printf("  -h, --help                        Display this help and exit\n");
  printf("\n");

  exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[], bool is_server) {
  static struct option long_options[] = {
    {"proto", required_argument, 0, 'r'},
    // server
    {"listen-port", required_argument, 0, 'p'}, // variable shared with client
    // client
    {"server-address", required_argument, 0, 'a'},
    {"server-port", required_argument, 0, 'p'}, // variable shared with server
    // common
    {"payload-size", required_argument, 0, 'l'},
    {"hexdump", no_argument, 0, 'x'},
    {"verbose", no_argument, 0, 'v'},
    {"quiet", no_argument, 0, 'q'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  int opt, option_index = 0;

  int server_port = 0;
  char *delimiter;

  char server_ipaddr_str[INET_ADDRSTRLEN];
  struct hostent *server_hostent;
  bool server_ipaddr_set = false;

  while ((opt = getopt_long(argc, argv, "r:a:p:l:xvqh", long_options, &option_index)) != -1) {
    switch (opt) {
      case 'r':
        protocol = parse_protocol(optarg);
        if (protocol == -1) {
          print_protocol_names();
          exit(EXIT_FAILURE);
        }
        break;
      case 'a':
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
        saddr.sin_family = AF_INET;
        memcpy((char *)&saddr.sin_addr.s_addr, (char *)server_hostent->h_addr,
          server_hostent->h_length);
        if (!inet_ntop(AF_INET, &(saddr.sin_addr), server_ipaddr_str, INET_ADDRSTRLEN)) {
          perror("inet_ntop failed");
        }
        server_ipaddr_set = true;
        break;
      case 'p':
        // Server port
        server_port = parse_int(optarg);
        saddr.sin_port = htons(server_port);
        break;
      case 'l':
        // Payload length
        delimiter = strchr(optarg, ',');
        if (delimiter != NULL) {
          *delimiter = '\0';  // Split the string into two null-terminated strings
          req_size = parse_int(optarg);
          resp_size = parse_int(delimiter + 1);
        } else {
          req_size = resp_size = parse_int(optarg);
        }
        break;
      case 'x':
        verbose_level = 2;
        break;
      case 'v':
        if (verbose_level != 2) {
          verbose_level = 1;
        }
        break;
      case 'q':
        if (verbose_level != 0) {
          log_fatal("--quiet can not be used with --verbose or --hexdump");
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

  if (argc <= 1) {
    print_help(argv[0], is_server);
  }

  if (protocol < 0 || req_size == 0 || resp_size == 0 || verbose_level < -1
    || verbose_level > 2 || (!is_server && !server_ipaddr_set)) {
    log_fatal("Invalid Args!\n");
    print_help(argv[0], is_server);
  }

  if ((req_size > HOMA_MAX_MESSAGE_LENGTH) || (req_size > HOMA_MAX_MESSAGE_LENGTH)) {
    log_fatal("req_size (%u) or resp_siez(%u) exceeds HOMA_MAX_MESSAGE_LENGTH\n", req_size, resp_size);
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
  }
  printf("  \"server_port_base\": %d,\n", server_port);
  printf("  \"payload_size\": \"%d,%d\",\n", req_size, resp_size);
  printf("  \"verbose_level\": %d\n", verbose_level);
  printf("}\n");
  printf("%s", is_server ? server_config_line : client_config_line);
  printf("\n");
}

// common utils //
