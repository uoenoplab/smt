/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SDTP_SIMPLE_H_
#define _SDTP_SIMPLE_H_

#include <sys/types.h>

#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>

#include "sdtp_bench.h"

struct sdtp_simple_config {
	const char *server_address;
	const char *bind_address;
	enum sdtp_bench_protocol protocol;
	uint16_t port;
	uint32_t request_size;
	uint32_t response_size;
	uint64_t num_rtts;
	double duration;
	bool force_tls;
	bool pin;
	int pin_offset;
	int verbose;
};

void sdtp_simple_usage(const char *, bool);
int sdtp_simple_parse_args(int, char **, bool, struct sdtp_simple_config *);
void sdtp_simple_print_config(const struct sdtp_simple_config *, bool,
    const char *);
int sdtp_simple_open_socket(const struct sdtp_simple_config *, bool);

#endif
