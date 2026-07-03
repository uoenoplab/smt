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

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include "sdtp_os.h"
#include "sdtp_pcb.h"
#include "sdtp_structs.h"
#include "sdtp_debug.h"

extern struct sdtp_zones zones;

void
insert_response_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
	PCB_LOCK_OWNED(pcb);
	MPASS(atomic_load_int(&interest->is_response_atomic) == false);

	atomic_store_int(&interest->is_response_atomic, true);
	TAILQ_INSERT_TAIL(&pcb->response_interests, interest, response_links);
}

void
remove_response_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
	PCB_LOCK_OWNED(pcb);
	MPASS(atomic_load_int(&interest->is_response_atomic) == true);

	TAILQ_REMOVE(&pcb->response_interests, interest, response_links);
	atomic_store_int(&interest->is_response_atomic, false);
}

void
insert_request_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
	PCB_LOCK_OWNED(pcb);
	MPASS(atomic_load_int(&interest->is_request_atomic) == false);

	atomic_store_int(&interest->is_request_atomic, true);
	TAILQ_INSERT_TAIL(&pcb->request_interests, interest, request_links);
}

void
remove_request_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
	PCB_LOCK_OWNED(pcb);
	MPASS(atomic_load_int(&interest->is_request_atomic) == true);

	TAILQ_REMOVE(&pcb->request_interests, interest, request_links);
	atomic_store_int(&interest->is_request_atomic, false);
}

void
sdtp_sorwakeup(struct sdtp_inpcb *pcb)
{
	struct epoch_tracker et;

	if (!pcb->shutdown) {
		NET_EPOCH_ENTER(et);

		SOCK_LOCK(sdtp_so(pcb));
		KASSERT(sdtp_so(pcb) != NULL, ("pcb socket must be valid"));
		sorwakeup(sdtp_so(pcb));
		SOCK_UNLOCK(sdtp_so(pcb));

		NET_EPOCH_EXIT(et);
	}
}

// TODO: Currently using spinlocks for readers and pcb_init! Should be using RCU
// operations

struct sdtp_inpcb *
sdtp_find_inpcb(struct sdtp_pcbmap *pcbmap, uint16_t port)
{
	mtx_assert(&pcbmap->write_spinlock, MA_OWNED);

	struct sdtp_pcbmap_link *link;
	struct sdtp_inpcb *result = NULL;

	LIST_FOREACH(link, &pcbmap->buckets[sdtp_port_hash(port)], hash_links) {
		struct sdtp_inpcb *pcb = link->sock;
		if (pcb->port == port) {
			result = pcb;
			break;
		}
	}

	return result;
}

int
sdtp_inpcb_bind(struct sdtp_pcbmap *pcbmap, uint16_t port,
    struct sdtp_inpcb *pcb)
{
	int error = 0;
	struct sdtp_inpcb *owner;

	if (port == 0) {
		return error;
	} else if (port >= SDTP_MIN_DEFAULT_PORT) {
		return EINVAL;
	}

	sdtp_pcb_lock(pcb);
	mtx_lock_spin(&pcbmap->write_spinlock);

	if (pcb->shutdown) {
		error = ESHUTDOWN;
		goto sdtp_inpcb_bind_done;
	}

	owner = sdtp_find_inpcb(pcbmap, port);
	if (owner != NULL) {
		if (owner != pcb) {
			error = EADDRINUSE;
		}
		goto sdtp_inpcb_bind_done;
	}

	LIST_REMOVE(&pcb->pcbmap_links, hash_links);
	pcb->port = port;
	LIST_INSERT_HEAD(&pcbmap->buckets[sdtp_port_hash(port)],
	    &pcb->pcbmap_links, hash_links);

sdtp_inpcb_bind_done:
	mtx_unlock_spin(&pcbmap->write_spinlock);
	sdtp_pcb_unlock(pcb);
	return error;
}

int
sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp)
{
	int i, error;
	struct sdtp_inpcb *inp;
	struct sdtp_pcbmap *pcbmap = &sdtp->port_map;

	// TODO: replace pcbmap with map from inp
	error = in_pcballoc(so, &V_sdtp_pcbinfo);
	if (error) {
		return (error);
	}
	inp = __containerof(sotoinpcb(so), struct sdtp_inpcb, inp);
	INP_WUNLOCK(&inp->inp);

	atomic_store_32(&inp->protect_count_atomic, 0);
	refcount_init(&inp->refs, 1);
	mtx_init(&inp->spinlock, "socket spinlock", NULL, MTX_SPIN);
	inp->last_locker = "none";
	inp->sdtp = sdtp;
	inp->shutdown = false;
	inp->iphlen = (INP_SOCKAF(so) == AF_INET) ?
	    SDTP_IPV4_HEADER_LENGTH :
	    SDTP_IPV6_HEADER_LENGTH;

	for (i = 0; i < SDTP_CLIENT_RPC_BUCKETS; i++) {
		struct sdtp_rpc_bucket *bucket = &inp->client_rpc_buckets[i];
		mtx_init(&bucket->spinlock, "client RPC bucket", NULL, MTX_SPIN);
		LIST_INIT(&bucket->rpcs);
	}
	for (i = 0; i < SDTP_SERVER_RPC_BUCKETS; i++) {
		struct sdtp_rpc_bucket *bucket = &inp->server_rpc_buckets[i];
		mtx_init(&bucket->spinlock, "server RPC bucket", NULL, MTX_SPIN);
		LIST_INIT(&bucket->rpcs);
		LIST_INIT(&inp->ctx_map.buckets[i]);
	}

	TAILQ_INIT(&inp->active_rpcs);
	TAILQ_INIT(&inp->dead_rpcs);
	inp->dead_bufs = 0;
	LIST_INIT(&inp->ready_requests);
	LIST_INIT(&inp->ready_responses);
	TAILQ_INIT(&inp->request_interests);
	TAILQ_INIT(&inp->response_interests);
	inp->ctx_map.reuse_ctx = NULL;
	inp->ctx_map.active = false;

	mtx_lock_spin(&pcbmap->write_spinlock);

	while (1) {
		if (sdtp->next_client_port < SDTP_MIN_DEFAULT_PORT) {
			sdtp->next_client_port = SDTP_MIN_DEFAULT_PORT;
		}
		if (!sdtp_find_inpcb(pcbmap, sdtp->next_client_port)) {
			break;
		}
		sdtp->next_client_port++;
	}

	inp->port = sdtp->next_client_port;
	sdtp->next_client_port++;
	inp->pcbmap_links.sock = inp;

	LIST_INSERT_HEAD(&pcbmap->buckets[sdtp_port_hash(inp->port)],
	    &inp->pcbmap_links, hash_links);

	mtx_unlock_spin(&pcbmap->write_spinlock);

	return 0;
}

void
sdtp_inpcb_shutdown(struct sdtp_inpcb *pcb)
{
	struct sdtp_rpc *rpc;
	struct sdtp_interest *interest;

	sdtp_pcb_lock(pcb);
	if (pcb->shutdown) {
		sdtp_pcb_unlock(pcb);
		return;
	}

	pcb->shutdown = true;
	mtx_lock_spin(&pcb->sdtp->port_map.write_spinlock);
	LIST_REMOVE(&pcb->pcbmap_links, hash_links);
	mtx_unlock_spin(&pcb->sdtp->port_map.write_spinlock);
	sdtp_pcb_unlock(pcb);

	for (;;) {
		sdtp_pcb_lock(pcb);
		rpc = TAILQ_FIRST(&pcb->active_rpcs);
		if (rpc == NULL) {
			sdtp_pcb_unlock(pcb);
			break;
		}
		sdtp_rpc_hold(rpc);
		sdtp_pcb_unlock(pcb);

		sdtp_rpc_lock(rpc);
		sdtp_rpc_free(rpc);
		sdtp_rpc_unlock(rpc);
		sdtp_rpc_put(rpc);
	}

	sdtp_pcb_lock(pcb);
	TAILQ_FOREACH(interest, &pcb->request_interests, request_links) {
		mtx_lock_spin(&interest->spinlock);
		wakeup(&interest->spinlock);
		mtx_unlock_spin(&interest->spinlock);
	}

	TAILQ_FOREACH(interest, &pcb->response_interests, response_links) {
		mtx_lock_spin(&interest->spinlock);
		wakeup(&interest->spinlock);
		mtx_unlock_spin(&interest->spinlock);
	}
	sdtp_pcb_unlock(pcb);

	/*
	 TODO:
	    homals_destroy_ctxs(hsk->homals_ctx_buckets);
	*/
}

void
sdtp_pcb_free(struct sdtp_inpcb *pcb)
{
	VALID_PCB_ASSERT(pcb);

	struct inpcb *inp = &pcb->inp;
	bool dead_rpcs_empty;
	bool released;

	while (refcount_load(&pcb->refs) != 1) {
		pause("sdtpref", 1);
	}

#ifdef INVARIANTS
	int i = 0;
#endif
	for (;;) {
		sdtp_pcb_lock(pcb);
		dead_rpcs_empty = TAILQ_EMPTY(&pcb->dead_rpcs);
		sdtp_pcb_unlock(pcb);
		if (dead_rpcs_empty) {
			break;
		}
		sdtp_rpc_reap(pcb, /* reap_all */ true);
#ifdef INVARIANTS
		KASSERT(i < 6, ("%s: hanged while freeing dead RPCs", __func__));
		++i;
#endif
	}

	sdtp_ctx_map_destroy(pcb);
	released = refcount_release(&pcb->refs);
	KASSERT(released,
	    ("%s: PCB still has operation references", __func__));
	(void)released;
	mtx_destroy(&pcb->spinlock);

	for (int i = 0; i < SDTP_CLIENT_RPC_BUCKETS; ++i) {
		mtx_destroy(&pcb->client_rpc_buckets[i].spinlock);
	}
	for (int i = 0; i < SDTP_SERVER_RPC_BUCKETS; ++i) {
		mtx_destroy(&pcb->server_rpc_buckets[i].spinlock);
	}

	INP_WLOCK(inp);
	in_pcbfree(inp);
}
