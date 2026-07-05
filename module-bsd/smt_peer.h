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

#ifndef _SMT_PEER_H_
#define _SMT_PEER_H_

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/domain.h>
#include <sys/mutex.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include "smt.h"
#include "smt_utils.h"

struct smt_rpc;

struct smt_peer {
	struct in6_addr addr;
	struct nhop_object *nh;

	smt_ref_t refs;

	int unsched_cutoffs[SMT_MAX_PRIORITIES];

	uint16_t cutoff_version_be;

	unsigned long last_update_jiffies;

	struct smt_rpc_tailq grantable_rpcs;
	struct smt_rpc_tailq grantable_links;

	LIST_ENTRY(smt_peer) peermap_links;

	int outstanding_resends;
	int most_recent_resend;

	struct smt_rpc *least_recent_rpc;

	uint32_t least_recent_ticks;
	uint32_t current_ticks;

	struct smt_rpc *resend_rpc;

	int num_acks;

	struct smt_ack acks[NUM_PEER_UNACKED_IDS];

	struct mtx ack_spinlock;
};

struct smt_peermap {
	struct mtx write_spinlock;
	struct smt_dead_dst_tailq dead_dsts;
	struct smt_peer_list *buckets;
};

struct smt_peer *smt_find_peer(struct smt_peermap *peermap, struct in6_addr *addr, int *error);
void smt_peer_ack(struct smt_rpc *rpc);
void smt_peer_free(struct smt_peer *peer);
void smt_peer_lock(struct smt_peer *peer);
void smt_peer_unlock(struct smt_peer *peer);
int smt_peer_get_acks(struct smt_peer *peer, int count, struct smt_ack *ack);
int smt_unsched_priority(struct smt *smt, struct smt_peer *peer,
    int length);

static inline void
smt_peer_hold(struct smt_peer *peer)
{
	refcount_acquire(&peer->refs);
}

static inline void
smt_peer_put(struct smt_peer *peer)
{
	KASSERT(refcount_load(&peer->refs) > 0,
	    ("peer cannot have negative refs"));
	if (refcount_release(&peer->refs)) {
		smt_peer_free(peer);
	}
}

#endif
