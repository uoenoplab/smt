/* Copyright (c) 2019-2022 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "homa_impl.h"
#include "smt_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(smt_outgoing) {
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
	int server_port;
	__u64 client_id;
	__u64 server_id;
	struct homa homa;
	struct homa_sock hsk;
	sockaddr_in_union server_addr;
	struct homa_peer *peer;
};
FIXTURE_SETUP(homa_outgoing)
{
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	self->client_id = 1234;
	self->server_id = 1235;
	homa_init(&self->homa);
	mock_cycles = 10000;
	atomic64_set(&self->homa.link_idle_time, 10000);
	self->homa.cycles_per_kbyte = 1000;
	self->homa.flags |= HOMA_FLAG_DONT_THROTTLE;
	mock_sock_init(&self->hsk, &self->homa, self->client_port);
	self->server_addr.in6.sin6_family = AF_INET;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port = htons(self->server_port);
	self->peer = homa_peer_find(&self->homa.peers,
			&self->server_addr.in6.sin6_addr, &self->hsk.inet);
	unit_log_clear();
}
FIXTURE_TEARDOWN(homa_outgoing)
{
	homa_destroy(&self->homa);
	unit_teardown();
}
