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

#ifndef _SMT_RPC_H_
#define _SMT_RPC_H_

#include <sys/mutex.h>

#include "smt.h"
#include "smt_common.h"
#include "smt_pcb.h"
#include "smt_utils.h"
#include "smt_ctx.h"

struct smt_peer;

struct smt_packet_slist_entry {
	/*
	 * it is guaranteed that all these mbufs
	 * have ip_header as first byte, then
	 * smt_data_header next.
	 */
	struct mbuf *data;

	SLIST_ENTRY(smt_packet_slist_entry) link;
};

struct smt_packet_tailq_entry {
	/*
	 * it is guaranteed that all these mbufs
	 * have ip_header as first byte, then
	 * smt_data_header next.
	 */
	struct mbuf *data;
	struct smt_rx_logical_info rx_info;

	TAILQ_ENTRY(smt_packet_tailq_entry) link;
};

struct smt_message_out {
	int length;
	int num_bufs;

	struct smt_packet_slist packets;
	struct smt_packet_slist_entry **next_xmit;
	int next_xmit_offset;

	unsigned int active_xmits_atomic;

	int pkt_data;
	int unscheduled;
	int granted;

	uint8_t sched_priority;
	uint64_t init_cycles;
};

struct smt_message_in {
	int total_length;

	struct smt_packet_tailq packets;

	int num_bufs;

	int bytes_remaining;
	int decrypt_offset;
	struct smt_packet_tailq *decrypt_bufs;

	int gsoseg_offset;
	int nextgsoseg_length;
	int nextgsoseg_received;

	struct smt_packet_tailq *gsoseg_bufs;

	unsigned int max_pkt_data;
	int incoming;
	int priority;
	bool scheduled;
	uint64_t birth;
	int copied_out;
	uint32_t num_bpages;
	uint32_t bpage_offsets[SMT_MAX_BPAGES];
};

struct smt_rpc {
	struct smt_inpcb *smtcb;

	struct mtx *spinlock_p;

	enum {
		SMT_RPC_OUTGOING = 5,
		SMT_RPC_INCOMING = 6,
		SMT_RPC_IN_SERVICE = 8,
		SMT_RPC_DEAD = 9
	} state;

	uint32_t flags_atomic;

#define RPC_PKTS_READY	      (1 << 0)
#define RPC_COPYING_FROM_USER (1 << 1)
#define RPC_COPYING_TO_USER   (1 << 2)
#define RPC_HANDING_OFF	      (1 << 3)
#define RPC_DECRYPTING	      (1 << 4)
#define RPC_ACKING_HOMALS     (1 << 5)

#define RPC_CANT_REAP                                                    \
	(RPC_COPYING_FROM_USER | RPC_COPYING_TO_USER | RPC_HANDING_OFF | \
	    RPC_DECRYPTING | RPC_ACKING_HOMALS)

	uint32_t grants_in_progress_atomic;

	smt_ref_t refs;

	struct smt_peer *peer;

	uint16_t dport;
	uint64_t id;
	uint64_t completion_cookie;
	int error;

	struct smt_message_in msgin;
	struct smt_message_out msgout;

	LIST_ENTRY(smt_rpc) hash_links;

	int is_ready_atomic;

	LIST_ENTRY(smt_rpc) ready_links;
	TAILQ_ENTRY(smt_rpc) active_links;
	TAILQ_ENTRY(smt_rpc) dead_links;

	struct smt_interest *interest;

	struct smt_rpc_tailq grantable_links;
	struct smt_rpc_tailq throttled_links;

	int silent_ticks;
	uint32_t resend_timer_ticks;
	uint32_t done_timer_ticks;

#define SMT_RPC_MAGIC 0xdeadbeef
	int magic;

	uint64_t start_cycles;

	struct smt_rpc_crypto crypto;
};

static inline void
smt_rpc_hold(struct smt_rpc *rpc)
{
	refcount_acquire(&rpc->refs);
}

static inline void
smt_rpc_put(struct smt_rpc *rpc)
{
	KASSERT(refcount_load(&rpc->refs) > 0,
	    ("rpc cannot have negative refs"));
	refcount_release(&rpc->refs);
}

static inline bool
is_encrypted_rpc(struct smt_rpc *rpc)
{
	return rpc->crypto.ctx != NULL;
}

struct smt_rpc *smt_new_client_rpc(struct smt_inpcb *pcb,
    struct in6_addr *dest, uint16_t port, int *error);
struct smt_rpc *smt_find_client_rpc(struct smt_inpcb *pcb, uint64_t id);
struct smt_rpc *smt_find_server_rpc(struct smt_inpcb *pcb,
    struct in6_addr *source, uint16_t port, uint64_t id);
bool smt_is_client(uint64_t id);
void smt_handle_packet(struct mbuf *m, struct in6_addr *addr,
    struct smt_inpcb *pcb);
void smt_rpc_lock(struct smt_rpc *rpc);
void smt_rpc_unlock(struct smt_rpc *rpc);
void smt_free_mbuf(struct mbuf *buf);
void smt_rpc_free(struct smt_rpc *rpc);
void smt_rpc_free_locked(struct smt_rpc *rpc);
int smt_rpc_reap(struct smt_inpcb *pcb, bool reap_all);
void insert_ready_rpc(struct smt_inpcb *pcb, struct smt_rpc_list *list,
	struct smt_rpc *rpc);
void remove_ready_rpc(struct smt_inpcb *pcb, struct smt_rpc *rpc);

SMT_DEFINE_EXPECTED_TYPE(rpc_ptr, struct smt_rpc *);

#endif
