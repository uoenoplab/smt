/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sdtp_simple.h"

static int
server_exchange(int fd, const struct sdtp_simple_config *config,
    void *request, void *response, const void *padding)
{
	struct sdtp_bench_recvmsg_args arguments;
	struct sockaddr_in peer;
	ssize_t received, sent;
	size_t prefix_length;

	received = sdtp_bench_recv(fd, SDTP_BENCH_RECV_REQUEST, request,
	    config->request_size, &peer, &arguments);
	if (received < 0)
		return (-1);
	if ((uint32_t)received != config->request_size) {
		errno = EMSGSIZE;
		return (-1);
	}

	prefix_length = config->request_size < config->response_size ?
	    config->request_size : config->response_size;
	memcpy(response, request, prefix_length);
	if (prefix_length < config->response_size) {
		memcpy((char *)response + prefix_length, padding,
		    config->response_size - prefix_length);
	}
	sent = sdtp_bench_send_response(fd, &peer, response,
	    config->response_size, arguments.id);
	if (sent < 0)
		return (-1);
	if ((uint32_t)sent != config->response_size) {
		errno = EMSGSIZE;
		return (-1);
	}
	if (config->verbose > 0) {
		fprintf(stderr, "server rpc=%" PRIu64
		    " request=%zd response=%zd\n", arguments.id, received,
		    sent);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	struct sdtp_simple_config config;
	struct timespec benchmark_start, now;
	void *padding, *request, *response;
	uint64_t requests;
	int fd, parse_result, result;

	parse_result = sdtp_simple_parse_args(argc, argv, true, &config);
	if (parse_result != 0) {
		sdtp_simple_usage(argv[0], true);
		return (parse_result > 0 ? 0 : 2);
	}
	sdtp_bench_setup_signals();
	if (config.pin &&
	    sdtp_bench_pin_thread(0, config.pin_offset) < 0 &&
	    config.verbose >= 0) {
		fprintf(stderr, "CPU pinning failed: %s\n", strerror(errno));
	}
	if (config.verbose >= 0)
		sdtp_simple_print_config(&config, true, NULL);

	request = malloc(config.request_size);
	response = malloc(config.response_size);
	padding = malloc(config.response_size);
	if (request == NULL || response == NULL || padding == NULL ||
	    sdtp_bench_fill_payload(padding, config.response_size) != 0) {
		perror("benchmark allocation");
		free(request);
		free(response);
		free(padding);
		return (1);
	}
	fd = sdtp_simple_open_socket(&config, true);
	if (fd < 0) {
		perror("SDTP socket");
		free(request);
		free(response);
		free(padding);
		return (1);
	}

	requests = 0;
	result = 0;
	if (config.duration != 0.0 &&
	    sdtp_bench_now(&benchmark_start) != 0) {
		perror("clock_gettime");
		result = 1;
		goto server_done;
	}
	while (!sdtp_bench_stop) {
		if (server_exchange(fd, &config, request, response,
			padding) != 0) {
			if (errno == EINTR && sdtp_bench_stop)
				break;
			perror("SDTP exchange");
			result = 1;
			break;
		}
		requests++;
		if (config.duration != 0.0) {
			if (sdtp_bench_now(&now) != 0) {
				perror("clock_gettime");
				result = 1;
				break;
			}
			if (sdtp_bench_elapsed_seconds(&benchmark_start, &now) >=
			    config.duration)
				break;
		}
	}

server_done:
	if (config.verbose >= 0)
		printf("handled_requests=%" PRIu64 "\n", requests);
	close(fd);
	free(request);
	free(response);
	free(padding);
	return (result);
}
