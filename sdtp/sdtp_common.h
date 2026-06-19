/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

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

#ifndef _SDTP_COMMON_H_
#define _SDTP_COMMON_H_

#include <sys/libkern.h>
#include <sys/queue.h>

#include <netinet/in.h>

#define IPPROTO_SDTP		 146
#define SDTP_MAX_MESSAGE_LENGTH	 1000000
#define SDTP_MIN_PKT_LENGTH	 26
#define SDTP_MAX_HEADER		 90
#define SDTP_HASHSIZE		 128

#define SDTP_RECVMSG_REQUEST	 0x01
#define SDTP_RECVMSG_RESPONSE	 0x02
#define SDTP_RECVMSG_NONBLOCKING 0x04
#define SDTP_RECVMSG_VALID_FLAGS 0x07

#define SDTP_CACHE_LINE_SIZE	 64
#define SDTP_CACHE_ROUNDUP(x) \
	(((x) + SDTP_CACHE_LINE_SIZE - 1) & ~(SDTP_CACHE_LINE_SIZE - 1))

#define SDTP_MIN_DEFAULT_PORT	    0x8000

#define MAX_SDTP_RPC		    0x20000
#define MAX_SDTP_PEER		    0x4000
#define MAX_SDTP_PACKET_TAILQ_ENTRY 0x4000
#define MAX_SDTP_PACKET_SLIST_ENTRY 0x4000
#define MAX_SDTP_CONTEXT	    0x4000

#define SDTP_CLIENT_RPC_BUCKETS	    1024
#define SDTP_SERVER_RPC_BUCKETS	    1024
#define SDTP_PCBMAP_BUCKETS	    1024

#define SDTP_IPV6_HEADER_LENGTH	    40
#define SDTP_IPV4_HEADER_LENGTH	    20

#define SDTP_BPAGE_SHIFT	    16
#define SDTP_BPAGE_SIZE		    (1 << SDTP_BPAGE_SHIFT)
#define SDTP_MAX_BPAGES \
	((SDTP_MAX_MESSAGE_LENGTH + SDTP_BPAGE_SIZE - 1) >> SDTP_BPAGE_SHIFT)

#define SDTP_MAX_PRIORITIES	 8
#define NUM_PEER_UNACKED_IDS	 5

#define SDTP_PEERTAB_BUCKET_BITS 20
#define SDTP_PEERTAB_BUCKETS	 (1 << SDTP_PEERTAB_BUCKET_BITS)

struct sdtp_rpc;
struct sdtp_interest;
struct sdtp_ctx;
struct sdtp_packet_tailq_entry;
struct sdtp_packet_slist_entry;
struct sdtp_pcbmap_link;
struct sdtp_peer;
struct sdtp_dead_dst;

TAILQ_HEAD(sdtp_rpc_tailq, sdtp_rpc);
LIST_HEAD(sdtp_rpc_list, sdtp_rpc);

TAILQ_HEAD(sdtp_interest_tailq, sdtp_interest);

LIST_HEAD(sdtp_ctx_list, sdtp_ctx);

TAILQ_HEAD(sdtp_packet_tailq, sdtp_packet_tailq_entry);
SLIST_HEAD(sdtp_packet_slist, sdtp_packet_slist_entry);

LIST_HEAD(sdtp_pcbmap_link_list, sdtp_pcbmap_link);

LIST_HEAD(sdtp_peer_list, sdtp_peer);

TAILQ_HEAD(sdtp_dead_dst_tailq, sdtp_dead_dst);

static inline struct in6_addr
ipv4_to_ipv6(struct in_addr *from)
{
	struct in6_addr addr = { 0 };
	addr.s6_addr[10] = 0xFF;
	addr.s6_addr[11] = 0xFF;
	memcpy(&addr.s6_addr[12], &from->s_addr, sizeof(from->s_addr));
	return (addr);
}

static inline void
ipv6_to_ipv4(struct in6_addr *from, struct in_addr *to)
{
	memset(to, 0, sizeof(*to));

	if (!IN6_IS_ADDR_V4MAPPED(from))
		return;

	memcpy(&to->s_addr, &from->s6_addr[12], sizeof(to->s_addr));
}

static inline bool
is_ipv6_same(struct in6_addr *a, struct in6_addr *b)
{
	return (memcmp(a, b, sizeof(struct in6_addr)) == 0);
}

static inline uint64_t
sdtp_local_id(uint64_t sender_id_be)
{
	return (be64toh(sender_id_be) ^ 1);
}

#endif
