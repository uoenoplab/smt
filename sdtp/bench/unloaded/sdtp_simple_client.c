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
client_exchange(int fd, const struct sdtp_simple_config *config,
    const struct sockaddr_in *server, const void *request, void *response,
    struct sdtp_bench_histogram *histogram, int *preheat)
{
	struct sdtp_bench_recvmsg_args arguments;
	struct sockaddr_in peer;
	struct timespec sent_at, received_at;
	ssize_t received, sent;
	double rtt_us;

	if (sdtp_bench_now(&sent_at) != 0)
		return (-1);
	sent = sdtp_bench_send_request(fd, server, request,
	    config->request_size, 1);
	if (sent < 0)
		return (-1);
	if ((uint32_t)sent != config->request_size) {
		errno = EMSGSIZE;
		return (-1);
	}

	received = sdtp_bench_recv(fd, SDTP_BENCH_RECV_RESPONSE, response,
	    config->response_size, &peer, &arguments);
	if (received < 0)
		return (-1);
	if ((uint32_t)received != config->response_size ||
	    arguments.completion_cookie != 1) {
		errno = EBADMSG;
		return (-1);
	}
	if (sdtp_bench_now(&received_at) != 0)
		return (-1);
	rtt_us = sdtp_bench_elapsed_us(&sent_at, &received_at);
	if (*preheat > 0) {
		(*preheat)--;
	} else if (sdtp_bench_hist_add(histogram, rtt_us,
		       config->request_size, config->response_size) != 0) {
		return (-1);
	}
	if (config->verbose > 0) {
		fprintf(stderr, "client response=%zd rpc=%" PRIu64
		    " rtt_us=%.2f\n", received, arguments.id, rtt_us);
	}
	return (0);
}

static int
client_print_results(struct sdtp_bench_histogram *histogram,
    const struct timespec *start, const struct timespec *end)
{
	double average_request, average_response, benchmark_time, kops;
	double request_mbps, response_mbps;

	if (histogram->count == 0) {
		errno = ENOMSG;
		return (-1);
	}
	benchmark_time = sdtp_bench_elapsed_seconds(start, end);
	if (benchmark_time <= 0.0) {
		errno = ERANGE;
		return (-1);
	}
	kops = (double)histogram->count / benchmark_time / 1000.0;
	average_request =
	    (double)histogram->total_request_bytes / histogram->count;
	average_response =
	    (double)histogram->total_response_bytes / histogram->count;
	request_mbps = kops * 1000.0 * average_request * 8.0 /
	    (1024.0 * 1024.0);
	response_mbps = kops * 1000.0 * average_response * 8.0 /
	    (1024.0 * 1024.0);

	printf("\n--- RESULT ---\n");
	printf("{\n");
	printf("  \"bench_time\": %.6f,\n", benchmark_time);
	printf("  \"total_rpcs\": %" PRIu64 ",\n", histogram->count);
	printf("  \"kops_per_second\": %.2f,\n", kops);
	printf("  \"tx_throughput_mbps\": %.2f,\n", request_mbps);
	printf("  \"rx_throughput_mbps\": %.2f,\n", response_mbps);
	printf("  \"average_rtt_us\": %.2f,\n",
	    sdtp_bench_hist_average(histogram));
	printf("  \"average_stddev_rtt_us\": %.2f,\n",
	    sdtp_bench_hist_stddev(histogram));
	printf("  \"p50_median_rtt_us\": %.2f,\n",
	    sdtp_bench_hist_percentile(histogram, 50.0));
	printf("  \"p95_rtt_us\": %.2f,\n",
	    sdtp_bench_hist_percentile(histogram, 95.0));
	printf("  \"p99_rtt_us\": %.2f\n",
	    sdtp_bench_hist_percentile(histogram, 99.0));
	printf("}\n");
	printf("--- RESULT ---\n");
	return (0);
}

int
main(int argc, char **argv)
{
	struct sdtp_simple_config config;
	struct sdtp_bench_histogram histogram;
	struct sockaddr_in server;
	struct timespec benchmark_start, benchmark_end, now;
	char server_numeric[INET_ADDRSTRLEN];
	void *request, *response;
	int fd, histogram_initialized, parse_result, preheat, result;

	parse_result = sdtp_simple_parse_args(argc, argv, false, &config);
	if (parse_result != 0) {
		sdtp_simple_usage(argv[0], false);
		return (parse_result > 0 ? 0 : 2);
	}
	if (sdtp_bench_resolve_ipv4(config.server_address, config.port,
		&server, server_numeric, sizeof(server_numeric)) != 0) {
		perror("server address");
		return (1);
	}
	sdtp_bench_setup_signals();
	if (config.pin &&
	    sdtp_bench_pin_thread(0, config.pin_offset) < 0 &&
	    config.verbose >= 0) {
		fprintf(stderr, "CPU pinning failed: %s\n", strerror(errno));
	}
	if (config.verbose >= 0)
		sdtp_simple_print_config(&config, false, server_numeric);

	request = malloc(config.request_size);
	response = malloc(config.response_size);
	histogram_initialized = 0;
	if (request != NULL && response != NULL &&
	    sdtp_bench_hist_init(&histogram) == 0)
		histogram_initialized = 1;
	if (request == NULL || response == NULL || !histogram_initialized ||
	    sdtp_bench_fill_payload(request, config.request_size) != 0) {
		perror("benchmark allocation");
		if (histogram_initialized)
			sdtp_bench_hist_destroy(&histogram);
		free(request);
		free(response);
		return (1);
	}
	fd = sdtp_simple_open_socket(&config, false);
	if (fd < 0) {
		perror("SDTP socket");
		sdtp_bench_hist_destroy(&histogram);
		free(request);
		free(response);
		return (1);
	}

	preheat = SDTP_BENCH_PREHEAT_RPCS;
	result = 0;
	if (sdtp_bench_now(&benchmark_start) != 0) {
		perror("clock_gettime");
		result = 1;
		goto client_done;
	}
	while (!sdtp_bench_stop) {
		if (client_exchange(fd, &config, &server, request, response,
			&histogram, &preheat) != 0) {
			if (errno == EINTR && sdtp_bench_stop)
				break;
			perror("SDTP exchange");
			result = 1;
			break;
		}
		if (config.num_rtts != 0 &&
		    histogram.count >= config.num_rtts)
			break;
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
	if (sdtp_bench_now(&benchmark_end) != 0) {
		perror("clock_gettime");
		result = 1;
	} else if (histogram.count != 0 &&
	    client_print_results(&histogram, &benchmark_start,
		&benchmark_end) != 0) {
		perror("benchmark results");
		result = 1;
	} else if (histogram.count == 0 && result == 0) {
		fprintf(stderr, "no measured RPCs completed\n");
		result = 1;
	}

client_done:
	close(fd);
	sdtp_bench_hist_destroy(&histogram);
	free(request);
	free(response);
	return (result);
}
