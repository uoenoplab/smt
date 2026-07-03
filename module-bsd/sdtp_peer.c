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

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/hash.h>

#include <sys/socket.h>
#include <net/route.h>
#include <net/route/route_var.h>
#include <netinet/in.h>
#include <netinet/in_fib.h>
#include <netinet6/in6_fib.h>

#include "sdtp_common.h"
#include "sdtp_debug.h"
#include "sdtp_os.h"
#include "sdtp_output.h"
#include "sdtp_peer.h"
#include "sdtp_structs.h"

extern struct sdtp_zones zones;

void
sdtp_peer_lock(struct sdtp_peer *peer)
{
	sdtp_peer_debug(peer, "locked by %#lx", (uintptr_t)curthread);
	mtx_lock_spin(&peer->ack_spinlock);
}

void
sdtp_peer_unlock(struct sdtp_peer *peer)
{
	mtx_unlock_spin(&peer->ack_spinlock);
	sdtp_peer_debug(peer, "unlocked by %#lx", (uintptr_t)curthread);
}

void
sdtp_peer_ack(struct sdtp_rpc *rpc)
{
	struct sdtp_peer *peer = rpc->peer;
	struct sdtp_ack_header ack_header;

	sdtp_peer_lock(peer);
	if (peer->num_acks < NUM_PEER_UNACKED_IDS) {
		peer->acks[peer->num_acks].client_id_be = htobe64(rpc->id);
		peer->acks[peer->num_acks].server_port_be = htons(rpc->dport);
		sdtp_rpc_debug(rpc, "add ack for id %llx",
		    htobe64(peer->acks[peer->num_acks].client_id_be));
		++peer->num_acks;
		SDTP_METRIC(rpc->sdtpcb->sdtp, recv_rpc_acks_atomic, 1);
		sdtp_peer_unlock(peer);
		return;
	}

	memcpy(ack_header.acks, peer->acks, sizeof(peer->acks));
	ack_header.num_acks_be = htons(peer->num_acks);
	peer->num_acks = 0;
	sdtp_peer_unlock(peer);
	SDTP_METRIC(rpc->sdtpcb->sdtp, recv_rpc_acks_atomic, 1);

	// TODO: can I really drop this lock? It is a bit dangerous
	sdtp_rpc_unlock(rpc);
	sdtp_rpc_debug(rpc, "send ack");
	sdtp_send_control(rpc, SDTP_ACK, &ack_header, sizeof(ack_header));
	sdtp_rpc_lock(rpc);
}

static struct nhop_object *
sdtp_resolve_nh(struct in6_addr *addr, int *error)
{
	struct nhop_object *nh;
	struct in_addr tmp;

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		ipv6_to_ipv4(addr, &tmp);
		nh = fib4_lookup(RT_DEFAULT_FIB, tmp, 0, NHR_REF, 0);
	} else {
		nh = fib6_lookup(RT_DEFAULT_FIB, addr, 0, NHR_REF, 0);
	}

	if (nh == NULL) {
		*error = EHOSTUNREACH;
	}
	return nh;
}

struct sdtp_peer *
sdtp_find_peer(struct sdtp_peermap *peermap, struct in6_addr *addr, int *error)
{
	struct sdtp_peer *peer;

	uint32_t bucket_idx = hash32_buf(addr, sizeof(struct in6_addr),
	    HASHINIT);
	bucket_idx &= SDTP_PEERTAB_BUCKETS - 1;

	mtx_lock_spin(&peermap->write_spinlock);
	LIST_FOREACH(peer, &peermap->buckets[bucket_idx], peermap_links) {
		if (is_ipv6_same(&peer->addr, addr)) {
			mtx_unlock_spin(&peermap->write_spinlock);
			sdtp_peer_hold(peer);
			return peer;
		}
	}
	mtx_unlock_spin(&peermap->write_spinlock);

	peer = SDTP_ZONE_GET(zones.sdtp_zone_peer, struct sdtp_peer);
	if (!peer) {
		*error = ENOMEM;
		goto sdtp_find_peer_done;
	}

	peer->addr = *addr;

	peer->nh = sdtp_resolve_nh(addr, error);
	if (*error) {
		SDTP_ZONE_FREE(zones.sdtp_zone_peer, peer);
		goto sdtp_find_peer_done;
	}

	peer->unsched_cutoffs[SDTP_MAX_PRIORITIES - 1] = 0;
	peer->unsched_cutoffs[SDTP_MAX_PRIORITIES - 2] = INT_MAX;
	peer->cutoff_version_be = 0;
	peer->last_update_jiffies = 0;
	TAILQ_INIT(&peer->grantable_rpcs);
	TAILQ_INIT(&peer->grantable_links);
	peer->outstanding_resends = 0;
	peer->most_recent_resend = 0;
	peer->least_recent_rpc = NULL;
	peer->least_recent_ticks = 0;
	peer->current_ticks = -1;
	peer->resend_rpc = NULL;
	peer->num_acks = 0;
	/* one ref for the peermap, one ref for the return variable */
	refcount_init(&peer->refs, 2);
	mtx_init(&peer->ack_spinlock, "peer ack spinlock", NULL, MTX_SPIN);

	mtx_lock_spin(&peermap->write_spinlock);
	LIST_INSERT_HEAD(&peermap->buckets[bucket_idx], peer, peermap_links);
	mtx_unlock_spin(&peermap->write_spinlock);

sdtp_find_peer_done:
	return peer;
}

void
sdtp_peer_free(struct sdtp_peer *peer)
{
	/* TODO: shouldn't it free the peer from the hashmap as well? */

	KASSERT(peer != NULL, ("peer must be valid"));
	KASSERT(peer->nh != NULL, ("peer->nh must be valid"));

	nhop_free_any(peer->nh);
	SDTP_ZONE_FREE(zones.sdtp_zone_peer, peer);
}

int
sdtp_peer_get_acks(struct sdtp_peer *peer, int count, struct sdtp_ack *acks)
{
	if (peer->num_acks == 0) {
		return 0;
	}

	sdtp_peer_lock(peer);

	if (count > peer->num_acks) {
		count = peer->num_acks;
	}

	memcpy(acks, &peer->acks[peer->num_acks - count],
	    count * sizeof(struct sdtp_ack));
	peer->num_acks -= count;

	sdtp_peer_unlock(peer);
	return count;
}

int
sdtp_unsched_priority(struct sdtp *sdtp, struct sdtp_peer *peer, int length)
{
	int i;
	for (i = sdtp->num_priorities - 1;; i--) {
		if (peer->unsched_cutoffs[i] >= length) {
			return i;
		}
	}

	KASSERT(0, ("unreachable"));
	__unreachable();
}
