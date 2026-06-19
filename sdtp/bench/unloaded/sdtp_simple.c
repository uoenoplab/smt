/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdtp_simple.h"

void
sdtp_simple_usage(const char *program, bool server)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "Options compatible with Linux simple_%s:\n",
	    server ? "server" : "client");
	fprintf(stderr, "  -r, --proto homa|sdtp|smt\n");
	if (server) {
		fprintf(stderr, "  -p, --listen-port port\n");
	} else {
		fprintf(stderr, "  -a, --server-address address\n");
		fprintf(stderr, "  -p, --server-port port\n");
	}
	fprintf(stderr,
	    "  -l, --payload-size req[,resp]\n"
	    "  -v, --verbose                 repeat for more detail\n"
	    "  -q, --quiet\n"
	    "  -h, --help\n");
	if (!server) {
		fprintf(stderr,
		    "  -n, --num-rtts count         stop after measured RTTs\n");
	}
	fprintf(stderr,
	    "FreeBSD extensions:\n"
	    "  -B, --bind-address address    default 0.0.0.0\n"
	    "  -d, --duration seconds        0 runs until interrupted\n"
	    "  -T, --tls                     force test TLS keys\n"
	    "  -P, --no-pin                  do not pin to a CPU\n");
}

static int
sdtp_simple_parse_u64(const char *text, uint64_t *value)
{
	char *end;
	uintmax_t parsed;

	if (*text == '-')
		return (-1);
	errno = 0;
	parsed = strtoumax(text, &end, 10);
	if (errno != 0 || *text == '\0' || *end != '\0' || parsed == 0)
		return (-1);
	*value = (uint64_t)parsed;
	return (0);
}

static int
sdtp_simple_parse_duration(const char *text, double *duration)
{
	char *end;

	errno = 0;
	*duration = strtod(text, &end);
	if (errno != 0 || *text == '\0' || *end != '\0' ||
	    !isfinite(*duration) || *duration < 0.0)
		return (-1);
	return (0);
}

int
sdtp_simple_parse_args(int argc, char **argv, bool server,
    struct sdtp_simple_config *config)
{
	static const struct option options[] = {
		{ "proto", required_argument, NULL, 'r' },
		{ "listen-port", required_argument, NULL, 'p' },
		{ "server-address", required_argument, NULL, 'a' },
		{ "server-addr", required_argument, NULL, 'a' },
		{ "server-port", required_argument, NULL, 'p' },
		{ "payload-size", required_argument, NULL, 'l' },
		{ "num-rtts", required_argument, NULL, 'n' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "bind-address", required_argument, NULL, 'B' },
		{ "bind-addr", required_argument, NULL, 'B' },
		{ "duration", required_argument, NULL, 'd' },
		{ "tls", no_argument, NULL, 'T' },
		{ "no-pin", no_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	const char *offset_text;
	int ch, disable_pin;

	memset(config, 0, sizeof(*config));
	config->bind_address = "0.0.0.0";
	config->pin = true;
	config->pin_offset = 1;

	while ((ch = getopt_long(argc, argv, "r:a:p:l:n:vqB:d:TPh",
		    options, NULL)) != -1) {
		switch (ch) {
		case 'r':
			if (sdtp_bench_parse_protocol(optarg,
				&config->protocol) != 0)
				return (-1);
			break;
		case 'a':
			if (server)
				return (-1);
			config->server_address = optarg;
			break;
		case 'p':
			if (sdtp_bench_parse_u16(optarg, &config->port) != 0)
				return (-1);
			break;
		case 'l':
			if (sdtp_bench_parse_sizes(optarg,
				&config->request_size,
				&config->response_size) != 0)
				return (-1);
			break;
		case 'n':
			if (server ||
			    sdtp_simple_parse_u64(optarg,
				&config->num_rtts) != 0)
				return (-1);
			break;
		case 'v':
			if (config->verbose < 3)
				config->verbose++;
			break;
		case 'q':
			if (config->verbose != 0)
				return (-1);
			config->verbose = -1;
			break;
		case 'B':
			config->bind_address = optarg;
			break;
		case 'd':
			if (sdtp_simple_parse_duration(optarg,
				&config->duration) != 0)
				return (-1);
			break;
		case 'T':
			config->force_tls = true;
			break;
		case 'P':
			config->pin = false;
			break;
		case 'h':
			return (1);
		default:
			return (-1);
		}
	}

	offset_text = getenv("HOMA_ECHO_PIN_CORE_OFFSET");
	if (offset_text == NULL)
		offset_text = getenv("SDTP_BENCH_PIN_CORE_OFFSET");
	if (offset_text != NULL &&
	    sdtp_bench_parse_int(offset_text, 0, 65535,
		&config->pin_offset) != 0)
		return (-1);
	offset_text = getenv("HOMA_ECHO_PIN_CORE_DISABLE");
	if (offset_text != NULL) {
		if (sdtp_bench_parse_int(offset_text, 0, INT_MAX,
			&disable_pin) != 0)
			return (-1);
		config->pin = disable_pin == 0;
	}

	if (optind != argc || config->protocol == SDTP_BENCH_PROTO_UNSET ||
	    config->port == 0 || config->request_size == 0 ||
	    config->response_size == 0 ||
	    (!server && config->server_address == NULL))
		return (-1);
	return (0);
}

void
sdtp_simple_print_config(const struct sdtp_simple_config *config, bool server,
    const char *server_numeric)
{
	const char *banner;

	banner = server ? "--- SERVER CONFIG ---" : "--- CLIENT CONFIG ---";
	printf("%s\n", banner);
	printf("{\n");
	printf("  \"protocol\": \"%s\",\n",
	    sdtp_bench_protocol_name(config->protocol));
	if (server) {
		printf("  \"listen\": \"%s:%u\",\n", config->bind_address,
		    config->port);
	} else {
		printf("  \"server\": \"%s:%u\",\n", server_numeric,
		    config->port);
	}
	printf("  \"payload_size\": \"%u,%u\",\n", config->request_size,
	    config->response_size);
	if (!server) {
		if (config->num_rtts != 0) {
			printf("  \"num_rtts\": %" PRIu64 ",\n",
			    config->num_rtts);
		} else {
			printf("  \"num_rtts\": \"Stop with Ctrl-C\",\n");
		}
	}
	printf("  \"verbose_level\": \"%s\"\n",
	    sdtp_bench_verbose_name(config->verbose));
	printf("}\n");
	printf("%s\n\n", banner);
}

int
sdtp_simple_open_socket(const struct sdtp_simple_config *config, bool server)
{
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_SDTP);
	if (fd < 0)
		return (-1);
	if (sdtp_bench_bind_socket(fd, config->bind_address,
		server ? config->port : 0) != 0 ||
	    ((config->protocol == SDTP_BENCH_PROTO_SMT ||
	      config->force_tls) &&
		sdtp_bench_enable_tls(fd, server) != 0)) {
		close(fd);
		return (-1);
	}
	return (fd);
}
