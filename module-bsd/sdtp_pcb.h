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

#ifndef _SDTP_PCB_H_
#define _SDTP_PCB_H_

#include <sys/cdefs.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include "sdtp_common.h"
#include "sdtp_ctx.h"

struct sdtp;
struct sdtp_inpcb;
struct sdtp_rpc;

struct sdtp_interest {
	struct thread *thread;

	uintptr_t ready_rpc_atomic;

	struct mtx spinlock;

	struct sdtp_rpc *reg_rpc;

	int is_response_atomic;
	int is_request_atomic;
	TAILQ_ENTRY(sdtp_interest) request_links;
	TAILQ_ENTRY(sdtp_interest) response_links;
};

struct sdtp_rpc_bucket {
	struct mtx spinlock;
	struct sdtp_rpc_list rpcs;
};

struct sdtp_pcbmap_link {
	LIST_ENTRY(sdtp_pcbmap_link) hash_links;
	struct sdtp_inpcb *sock;
};

struct sdtp_pcbmap {
	struct mtx write_spinlock;
	struct sdtp_pcbmap_link_list buckets[SDTP_PCBMAP_BUCKETS];
};

struct sdtp_inpcb {
	struct inpcb inp;

	struct mtx spinlock;
	char *last_locker;

	u_int refs;
	uint32_t protect_count_atomic;
	struct sdtp *sdtp;
	bool shutdown;
	uint16_t port;
	int iphlen;

	struct sdtp_pcbmap_link pcbmap_links;

	struct sdtp_rpc_tailq active_rpcs;
	struct sdtp_rpc_tailq dead_rpcs;

	int dead_bufs;

	struct sdtp_rpc_list ready_requests;
	struct sdtp_rpc_list ready_responses;

	struct sdtp_interest_tailq request_interests;
	struct sdtp_interest_tailq response_interests;

	struct sdtp_rpc_bucket client_rpc_buckets[SDTP_CLIENT_RPC_BUCKETS];
	struct sdtp_rpc_bucket server_rpc_buckets[SDTP_SERVER_RPC_BUCKETS];

	struct sdtp_ctx_map ctx_map;
};

#define sdtp_so_pcb(SO)	((struct sdtp_inpcb *)((SO)->so_pcb))
#define sdtp_so(PCB)	((PCB)->inp.inp_socket)

static inline void
sdtp_pcb_lock(struct sdtp_inpcb *pcb)
{
	mtx_lock_spin(&pcb->spinlock);
}

static inline void
sdtp_pcb_unlock(struct sdtp_inpcb *pcb)
{
	mtx_unlock_spin(&pcb->spinlock);
}

static inline void
sdtp_pcb_hold(struct sdtp_inpcb *pcb)
{
	refcount_acquire(&pcb->refs);
}

static inline void
sdtp_pcb_put(struct sdtp_inpcb *pcb)
{
	bool released;

	KASSERT(refcount_load(&pcb->refs) > 1,
	    ("%s: cannot release the PCB owner reference", __func__));
	released = refcount_release(&pcb->refs);
	KASSERT(!released,
	    ("%s: PCB operation reference released the object", __func__));
	(void)released;
}

void insert_response_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest);
void remove_response_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest);
void insert_request_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest);
void remove_request_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest);
void sdtp_sorwakeup(struct sdtp_inpcb *pcb);
struct sdtp_inpcb *sdtp_find_inpcb(struct sdtp_pcbmap *pcbmap, uint16_t port);
int sdtp_inpcb_bind(struct sdtp_pcbmap *pcbmap, uint16_t port,
    struct sdtp_inpcb *pcb);
int sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp);
void sdtp_inpcb_shutdown(struct sdtp_inpcb *pcb);
void sdtp_pcb_free(struct sdtp_inpcb *pcb);

#endif
