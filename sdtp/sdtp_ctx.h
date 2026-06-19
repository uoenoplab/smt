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

#ifndef _SDTP_CTX_H_
#define _SDTP_CTX_H_

#include <sys/ktls.h>

#include "sdtp_common.h"
#include "sdtp_utils.h"

#define SDTP_TLS_HEADER_OFFSET \
	(sizeof(struct sdtp_data_header) - sizeof(struct sdtp_data_segment))

#define SDTP_TLS_DATA_OFFSET \
	(SDTP_TLS_HEADER_OFFSET + sizeof(struct tls_record_layer))

struct sdtp_inpcb;
struct sdtp_rpc;

struct sdtp_tls_args {
	uint32_t          peer_addr_be;
	uint16_t          peer_port_be;
	uint32_t          local_addr_be;
	struct tls_enable tls;
};

struct sdtp_tls_state {
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

struct sdtp_ctx {
	struct sdtp_tls_state tx;
	struct sdtp_tls_state rx;

	uint32_t addr_be;
	uint16_t port_be;

	sdtp_ref_t refs;

	LIST_ENTRY(sdtp_ctx) hash_links;
};

struct sdtp_rpc_crypto {
	struct sdtp_ctx *ctx;

	/*
	 * Full TLS record sequence values:
	 * [48-bit message ID][16-bit record index].
	 */
	uint64_t tx_seqno;
	uint64_t rx_seqno;
	unsigned int max;
	int offset;
};

struct sdtp_ctx_map {
	struct sdtp_ctx_list buckets[SDTP_SERVER_RPC_BUCKETS];
	struct sdtp_ctx *reuse_ctx;
	bool active;
};

struct sdtp_rx_logical_info {
	int start;
	int length;
	int end;
	int record_data_len;
	int record_data_offset;
	bool trailer_only;
};

int sdtp_rpc_ctx_init(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc);
int sdtp_ctx_enable(struct sdtp_inpcb *pcb, struct sockopt *sopt, bool is_tx);
void sdtp_ctx_map_destroy(struct sdtp_inpcb *pcb);
void sdtp_free_ctx(struct sdtp_ctx *ctx);
struct sdtp_rx_logical_info sdtp_calc_rx_logical_info(struct sdtp_rpc *rpc, struct mbuf *m);
bool sdtp_ctx_record_complete(struct sdtp_rpc *rpc);
int sdtp_ctx_decrypt(struct sdtp_rpc *rpc, int iphlen, struct sdtp_packet_tailq_entry **entries, int n, int *trailer_len);
void sdtp_debug_rx_info(struct sdtp_rpc *rpc, struct sdtp_rx_logical_info *rx_info);
int sdtp_tls_fill_packets(struct sdtp_rpc *rpc, struct uio *uio, int max_packet_size);
int sdtp_post_len(struct sdtp_rpc *rpc);
int sdtp_pre_len(struct sdtp_rpc *rpc);

static inline void
sdtp_ctx_hold(struct sdtp_ctx *ctx)
{
	refcount_acquire(&ctx->refs);
}

static inline void
sdtp_ctx_put(struct sdtp_ctx *ctx)
{
	KASSERT(refcount_load(&ctx->refs) > 0,
	    ("ctx cannot have negative refs"));

	if (refcount_release(&ctx->refs)) {
		sdtp_free_ctx(ctx);
	}
}

#endif
