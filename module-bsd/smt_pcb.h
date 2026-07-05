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

#ifndef _SMT_PCB_H_
#define _SMT_PCB_H_

#include <sys/cdefs.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include "smt_common.h"
#include "smt_ctx.h"

struct smt;
struct smt_inpcb;
struct smt_rpc;

struct smt_interest {
	struct thread *thread;

	uintptr_t ready_rpc_atomic;

	struct mtx spinlock;

	struct smt_rpc *reg_rpc;

	int is_response_atomic;
	int is_request_atomic;
	TAILQ_ENTRY(smt_interest) request_links;
	TAILQ_ENTRY(smt_interest) response_links;
};

struct smt_rpc_bucket {
	struct mtx spinlock;
	struct smt_rpc_list rpcs;
};

struct smt_pcbmap_link {
	LIST_ENTRY(smt_pcbmap_link) hash_links;
	struct smt_inpcb *sock;
};

struct smt_pcbmap {
	struct mtx write_spinlock;
	struct smt_pcbmap_link_list buckets[SMT_PCBMAP_BUCKETS];
};

struct smt_inpcb {
	struct inpcb inp;

	struct mtx spinlock;
	char *last_locker;

	u_int refs;
	uint32_t protect_count_atomic;
	struct smt *smt;
	bool shutdown;
	uint16_t port;
	int iphlen;

	struct smt_pcbmap_link pcbmap_links;

	struct smt_rpc_tailq active_rpcs;
	struct smt_rpc_tailq dead_rpcs;

	int dead_bufs;

	struct smt_rpc_list ready_requests;
	struct smt_rpc_list ready_responses;

	struct smt_interest_tailq request_interests;
	struct smt_interest_tailq response_interests;

	struct smt_rpc_bucket client_rpc_buckets[SMT_CLIENT_RPC_BUCKETS];
	struct smt_rpc_bucket server_rpc_buckets[SMT_SERVER_RPC_BUCKETS];

	struct smt_ctx_map ctx_map;
};

#define smt_so_pcb(SO)	((struct smt_inpcb *)((SO)->so_pcb))
#define smt_so(PCB)	((PCB)->inp.inp_socket)

static inline void
smt_pcb_lock(struct smt_inpcb *pcb)
{
	mtx_lock_spin(&pcb->spinlock);
}

static inline void
smt_pcb_unlock(struct smt_inpcb *pcb)
{
	mtx_unlock_spin(&pcb->spinlock);
}

static inline void
smt_pcb_hold(struct smt_inpcb *pcb)
{
	refcount_acquire(&pcb->refs);
}

static inline void
smt_pcb_put(struct smt_inpcb *pcb)
{
	bool released;

	KASSERT(refcount_load(&pcb->refs) > 1,
	    ("%s: cannot release the PCB owner reference", __func__));
	released = refcount_release(&pcb->refs);
	KASSERT(!released,
	    ("%s: PCB operation reference released the object", __func__));
	(void)released;
}

void insert_response_interest(struct smt_inpcb *pcb, struct smt_interest *interest);
void remove_response_interest(struct smt_inpcb *pcb, struct smt_interest *interest);
void insert_request_interest(struct smt_inpcb *pcb, struct smt_interest *interest);
void remove_request_interest(struct smt_inpcb *pcb, struct smt_interest *interest);
void smt_sorwakeup(struct smt_inpcb *pcb);
struct smt_inpcb *smt_find_inpcb(struct smt_pcbmap *pcbmap, uint16_t port);
int smt_inpcb_bind(struct smt_pcbmap *pcbmap, uint16_t port,
    struct smt_inpcb *pcb);
int smt_inpcb_alloc(struct socket *so, struct smt *smt);
void smt_inpcb_shutdown(struct smt_inpcb *pcb);
void smt_pcb_free(struct smt_inpcb *pcb);

#endif
