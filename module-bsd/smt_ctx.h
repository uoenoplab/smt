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

#ifndef _SMT_CTX_H_
#define _SMT_CTX_H_

#include <sys/ktls.h>

#include "smt_common.h"
#include "smt_utils.h"

#define SMT_TLS_HEADER_OFFSET \
	(sizeof(struct smt_data_header) - sizeof(struct smt_data_segment))

#define SMT_TLS_DATA_OFFSET \
	(SMT_TLS_HEADER_OFFSET + sizeof(struct tls_record_layer))

struct smt_inpcb;
struct smt_rpc;

struct smt_tls_args {
	uint32_t          peer_addr_be;
	uint16_t          peer_port_be;
	uint32_t          local_addr_be;
	struct tls_enable tls;
};

struct smt_tls_state {
	/*
	 * en is only useful in the context of reusing
	 * ctx, where the new copy will reuse the same
	 * parameters to create a new session.
	 */
	struct tls_enable    en;

	/*
	 * session can be NULL even if state is active,
	 * when the state is cloned, the session won't be
	 * cloned, and it should be lazily initialized when
	 * the user tries to recv or send.
	 */
	struct ktls_session *session;

	bool                 active;

	/*
	 * If this flag is on, then this state is a copy.
	 */
	bool                 copy;
};

struct smt_ctx {
	struct smt_tls_state tx;
	struct smt_tls_state rx;

	uint32_t addr_be;
	uint16_t port_be;

	smt_ref_t refs;

	LIST_ENTRY(smt_ctx) hash_links;
};

struct smt_rpc_crypto {
	struct smt_ctx *ctx;

	uint64_t tx_seqno;
	uint64_t rx_seqno;
	unsigned int max;
	int offset;
};

struct smt_ctx_map {
	struct smt_ctx_list buckets[SMT_SERVER_RPC_BUCKETS];
	struct smt_ctx *reuse_ctx;
	bool active;
};

struct smt_rx_logical_info {
	int start;
	int length;
	int end;
	int record_data_len;
	int record_data_offset;
	bool trailer_only;
};

int smt_rpc_ctx_init(struct smt_inpcb *pcb, struct smt_rpc *rpc);
int smt_ctx_enable(struct smt_inpcb *pcb, struct sockopt *sopt, bool is_tx);
void smt_ctx_map_destroy(struct smt_inpcb *pcb);
void smt_free_ctx(struct smt_ctx *ctx);
struct smt_rx_logical_info smt_calc_rx_logical_info(struct smt_rpc *rpc, struct mbuf *m);
bool smt_ctx_record_complete(struct smt_rpc *rpc);
int smt_ctx_decrypt(struct smt_rpc *rpc, int iphlen, struct smt_packet_tailq_entry **entries, int n, int *trailer_len);
void smt_debug_rx_info(struct smt_rpc *rpc, struct smt_rx_logical_info *rx_info);
int smt_tls_fill_packets(struct smt_rpc *rpc, struct uio *uio, int max_packet_size);
int smt_post_len(struct smt_rpc *rpc);
int smt_pre_len(struct smt_rpc *rpc);

static inline void
smt_ctx_hold(struct smt_ctx *ctx)
{
	refcount_acquire(&ctx->refs);
}

static inline void
smt_ctx_put(struct smt_ctx *ctx)
{
	KASSERT(refcount_load(&ctx->refs) > 0,
	    ("ctx cannot have negative refs"));

	if (refcount_release(&ctx->refs)) {
		smt_free_ctx(ctx);
	}
}

#endif
