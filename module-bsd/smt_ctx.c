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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockopt.h>
#include <sys/systm.h>
#include <sys/ktls.h>
#include <sys/uio.h>
#include <sys/endian.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/if_types.h>
#include <net/route/nhop.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/ktls.h>

#include "smt_os.h"
#include "smt_ctx.h"
#include "smt_debug.h"
#include "smt_structs.h"
#include "smt_output.h"

extern struct smt_zones zones;

#define SMT_MESSAGE_ID_BITS	48
#define SMT_RECORD_INDEX_BITS	16
#define SMT_RPC_ID_BITS	(SMT_MESSAGE_ID_BITS + 1)
#define SMT_RPC_ID_MASK	((1ULL << SMT_RPC_ID_BITS) - 1)

CTASSERT(SMT_MESSAGE_ID_BITS + SMT_RECORD_INDEX_BITS == 64);

static uint64_t
smt_composite_record_seqno(uint64_t rpc_id, const uint8_t rec_seq[8])
{
	uint64_t message_id, record_index;

	message_id = (rpc_id & SMT_RPC_ID_MASK) >> 1;
	record_index = be64dec(rec_seq) & ((1ULL << SMT_RECORD_INDEX_BITS) - 1);

	return ((message_id << SMT_RECORD_INDEX_BITS) | record_index);
}

static inline uint32_t
ms_rthash(const uint32_t addr, const uint16_t port)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0;
	const uint8_t *p;

	p = (const uint8_t *)&port;
	b += p[1] << 16;
	b += p[0] << 8;
	p = (const uint8_t *)&addr;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;

	a -= b; a -= c; a ^= (c >> 13);
	b -= c; b -= a; b ^= (a << 8);
	c -= a; c -= b; c ^= (b >> 13);
	a -= b; a -= c; a ^= (c >> 12);
	b -= c; b -= a; b ^= (a << 16);
	c -= a; c -= b; c ^= (b >> 5);
	a -= b; a -= c; a ^= (c >> 3);
	b -= c; b -= a; b ^= (a << 10);
	c -= a; c -= b; c ^= (b >> 15);

	return c;
}

static inline struct smt_ctx_list *
smt_get_ctx_bucket(struct smt_inpcb *pcb, uint32_t peer_addr_be, uint16_t peer_port_be)
{
	int idx = ms_rthash(peer_addr_be, peer_port_be) & (SMT_SERVER_RPC_BUCKETS - 1);
	return (&pcb->ctx_map.buckets[idx]);
}

static struct smt_ctx *
__smt_find_ctx(struct smt_ctx_list *bucket, uint32_t peer_addr_be, uint16_t peer_port_be)
{
	KASSERT(bucket != NULL, ("%s: bucket must be valid", __func__));

	struct smt_ctx *ctx;
	
	if (LIST_EMPTY(bucket)) {
		return (NULL);
	}

	LIST_FOREACH(ctx, bucket, hash_links) {
		if (ctx->addr_be == peer_addr_be && ctx->port_be == peer_port_be) {
			smt_ctx_hold(ctx);
			return (ctx);
		}
	}

	return (NULL);
}

static struct smt_ctx *
smt_find_ctx(struct smt_inpcb *pcb, uint32_t peer_addr_be, uint16_t peer_port_be)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_OWNED(pcb);

	struct smt_ctx_list *bucket;

	bucket = smt_get_ctx_bucket(pcb, peer_addr_be, peer_port_be);
	return __smt_find_ctx(bucket, peer_addr_be, peer_port_be);
}

static struct smt_ctx *
smt_get_ctx(struct smt_inpcb *pcb, uint32_t peer_addr_be, uint16_t peer_port_be, int *error)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_OWNED(pcb);

	struct smt_ctx_list *bucket;
	struct smt_ctx *ctx;

	bucket = smt_get_ctx_bucket(pcb, peer_addr_be, peer_port_be);
	ctx = __smt_find_ctx(bucket, peer_addr_be, peer_port_be);
	if (ctx == NULL) {
		ctx = smt_pool_alloc_ctx();
		if (ctx == NULL) {
			*error = ENOMEM;
			return (NULL);
		}
		ctx->addr_be = peer_addr_be;
		ctx->port_be = peer_port_be;
		refcount_init(&ctx->refs, 1);
		LIST_INSERT_HEAD(bucket, ctx, hash_links);
		smt_ctx_hold(ctx);
	}

	return ctx;
}

static void
smt_free_tls_state(struct smt_tls_state *state)
{
	if (state->active) {
		if (!state->copy) {
			ktls_cleanup_tls_enable(&state->en);
		}

		if (state->session != NULL) {
			ktls_free(state->session);
			state->session = NULL;
		}

		state->active = false;
	}
}

void
smt_free_ctx(struct smt_ctx *ctx)
{
	KASSERT(ctx != NULL, ("%s: ctx must be valid", __func__));

	LIST_REMOVE(ctx, hash_links);
	smt_free_tls_state(&ctx->tx);
	smt_free_tls_state(&ctx->rx);
	explicit_bzero(ctx, sizeof(*ctx));
	smt_pool_free_ctx(ctx);
}

void
smt_ctx_map_destroy(struct smt_inpcb *pcb)
{
	struct smt_ctx *ctx, *tmp;
	struct smt_ctx *reuse_ctx;

	VALID_PCB_ASSERT(pcb);
	KASSERT(pcb->shutdown, ("%s: PCB must be shut down", __func__));

	reuse_ctx = pcb->ctx_map.reuse_ctx;
	pcb->ctx_map.reuse_ctx = NULL;
	pcb->ctx_map.active = false;
	for (int i = 0; i < SMT_SERVER_RPC_BUCKETS; ++i) {
		LIST_FOREACH_SAFE(ctx, &pcb->ctx_map.buckets[i], hash_links,
		    tmp) {
			if (ctx == reuse_ctx) {
				continue;
			}
			KASSERT(refcount_load(&ctx->refs) == 1,
			    ("%s: context still has users", __func__));
			smt_ctx_put(ctx);
		}
	}
	if (reuse_ctx != NULL) {
		KASSERT(refcount_load(&reuse_ctx->refs) == 2,
		    ("%s: reuse context still has users", __func__));
		smt_ctx_put(reuse_ctx);
		smt_ctx_put(reuse_ctx);
	}
}

/*
 * This is a shallow clone, ktls_session won't be cloned,
 * instead it will be lazily created when it will be used.
 */
static struct smt_ctx *
smt_clone_reuse_ctx(struct smt_inpcb *pcb, uint32_t addr_be, uint16_t port_be, int *error)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_OWNED(pcb);

	struct smt_ctx *reuse_ctx, *ctx;

	reuse_ctx = pcb->ctx_map.reuse_ctx;
	if (reuse_ctx == NULL) {
		return (NULL);
	}
	KASSERT(reuse_ctx->tx.active || reuse_ctx->rx.active, ("at least one direction must be active"));

	ctx = smt_get_ctx(pcb, addr_be, port_be, error);
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->tx = reuse_ctx->tx;
	ctx->rx = reuse_ctx->rx;

	if (ctx->tx.active) {
		ctx->tx.copy = true;
		ctx->tx.session = NULL;

#ifdef INVARIANTS
		struct tls_enable *en = &ctx->tx.en;
		KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
			("cipher algorithm must be CRYPTO_AES_NIST_GCM_16, instead: %d",
			 en->cipher_algorithm));
		KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
			("tls major version must be 1, instead: %d",
			 en->tls_vmajor));
		KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
			("tls minor version must be 2, instead: %d",
			 en->tls_vminor));
#endif
	}
	if (ctx->rx.active) {
		ctx->rx.copy = true;
		ctx->rx.session = NULL;

#ifdef INVARIANTS
		struct tls_enable *en = &ctx->rx.en;
		KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
			("cipher algorithm must be CRYPTO_AES_NIST_GCM_16, instead: %d",
			 en->cipher_algorithm));
		KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
			("tls major version must be 1, instead: %d",
			 en->tls_vmajor));
		KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
			("tls minor version must be 2, instead: %d",
			 en->tls_vminor));
#endif
	}

	smt_pcb_debug(pcb, "cloned ctx with rx: %d, tx: %d", ctx->rx.active, ctx->tx.active);
	return (ctx);
}

int
smt_rpc_ctx_init(struct smt_inpcb *pcb, struct smt_rpc *rpc)
{
	VALID_PCB_ASSERT(pcb);
	VALID_RPC_ASSERT(rpc);
	PCB_LOCK_OWNED(pcb);
	KASSERT(pcb->ctx_map.active == true, ("pcb must have ctx map"));

	struct smt_ctx *ctx;
	int error = 0;
	uint32_t addr_be;
	uint16_t port_be, mtu;

	ipv6_to_ipv4(&rpc->peer->addr, (struct in_addr *) &addr_be);
	port_be = htons(rpc->dport);

	ctx = smt_find_ctx(pcb, addr_be, port_be);
	if (ctx == NULL) {
		ctx = smt_clone_reuse_ctx(pcb, addr_be, port_be, &error);
		if (ctx == NULL) {
			return (error);
		}
	}

	KASSERT(NH_IS_VALID(rpc->peer->nh), ("nh must be valid"));
	mtu = rpc->peer->nh->nh_mtu;

	rpc->crypto.ctx = ctx;
	rpc->crypto.offset = 0;
	rpc->crypto.max = mtu -
	    IP_SMT_HEADER_SIZE(rpc->smtcb, struct smt_data_header);
	rpc->crypto.tx_seqno = smt_composite_record_seqno(rpc->id,
	    ctx->tx.en.rec_seq);
	rpc->crypto.rx_seqno = smt_composite_record_seqno(rpc->id,
	    ctx->rx.en.rec_seq);

	smt_rpc_debug(rpc, "successful ctx init");

	return (0);
}

static int
smt_ktls_copyin_tls_enable(struct sockopt *sopt, struct smt_tls_args *sen)
{
	int error;

	error = sooptcopyin(sopt, sen, sizeof(*sen), sizeof(*sen));
	if (error != 0) {
		return (error);
	}

	return __ktls_copyin_tls_enable(sopt, &sen->tls);
}

static int
smt_validate_tls_enable(struct smt_inpcb *pcb, struct smt_tls_args *sen)
{
	int error = 0;

	if (sen->tls.tls_vmajor != TLS_MAJOR_VER_ONE) {
		smt_pcb_debug(pcb, "tls_vmajor invalid: %d", sen->tls.tls_vmajor);
		error = EINVAL;
		goto smt_validate_tls_enable_out;
	}

	switch (sen->tls.tls_vminor) {
	case TLS_MINOR_VER_TWO:
		break;
	case TLS_MINOR_VER_THREE:
		smt_pcb_debug(pcb, "TLS 1.3 isn't supported yet");
		error = EINVAL;
		goto smt_validate_tls_enable_out;
	default:
		smt_pcb_debug(pcb, "tls_vminor invalid: %d", sen->tls.tls_vmajor);
		error = EINVAL;
		goto smt_validate_tls_enable_out;
	}

	if (sen->tls.cipher_algorithm != CRYPTO_AES_NIST_GCM_16 ||
	    sen->tls.cipher_key_len != 16) {

		smt_pcb_debug(pcb, "Algorithm not supported: %d, %d",
		 sen->tls.cipher_algorithm, sen->tls.auth_algorithm);
		error = EINVAL;
		goto smt_validate_tls_enable_out;
	}

smt_validate_tls_enable_out:
	return error;
}

// TODO: improve these two functions!!!

static int
smt_new_ktls(struct smt_inpcb *pcb, struct tls_enable *en, struct ktls_session **ktls, int direction)
{
	int error = 0;

	error = ktls_create_session(smt_so(pcb), en, ktls, direction);
	if (error != 0) {
		smt_pcb_debug(pcb, "failed to create session: %d", error);
		return (error);
	}

	error = ktls_ocf_try(*ktls, direction);
	if (error != 0) {
		smt_pcb_debug(pcb, "failed to ocf session: %d", error);
		return (error);
	}

	error = ktls_try_ifnet(smt_so(pcb), *ktls, direction, false);
	if (error) {
		smt_pcb_debug(pcb, "failed ktls ifnet offload: %d", error);
		ktls_use_sw(*ktls);
		error = 0;
	}

	return (error);
}

static void
smt_assign_reuse_ctx(struct smt_inpcb *pcb, struct smt_ctx *ctx)
{
	if (pcb->ctx_map.reuse_ctx == ctx) {
		return;
	}

	/*
	 * Making it possible to change reuse ctx means
	 * that we'll have a lot of invalid refs.
	 */
	if (pcb->ctx_map.reuse_ctx != NULL) {
		KASSERT(0, ("changing reuse_ctx not implemented yet"));
		// smt_ctx_put(pcb->ctx_map.reuse_ctx);
	}

	pcb->ctx_map.reuse_ctx = ctx;
	smt_ctx_hold(ctx);
}

int
smt_ctx_enable(struct smt_inpcb *pcb, struct sockopt *sopt, bool is_tx)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_NOTOWNED(pcb);

	bool moved_en = false;
	int error = 0, direction = (is_tx) ? KTLS_TX : KTLS_RX;
	struct smt_tls_args sen;
	struct smt_ctx *ctx = NULL;
	struct ktls_session *ktls = NULL;
	struct smt_tls_state *slot = NULL;

	if (!ktls_offload_enabled()) {
		return (ENOTSUP);
	}

	error = smt_ktls_copyin_tls_enable(sopt, &sen);
	if (error != 0) {
		smt_pcb_debug(pcb, "ktls copyin failed: %d", error);
		/* don't go to out because sen.tls is invalid */
		return (error);
	}

	error = smt_validate_tls_enable(pcb, &sen);
	if (error != 0) {
		smt_pcb_debug(pcb, "smt_tls_args validation failed: %d", error);
		goto smt_ctx_enable_out;
	}

	smt_pcb_lock(pcb);
	if (pcb->shutdown) {
		error = ESHUTDOWN;
		goto smt_ctx_enable_locked;
	}
	ctx = smt_get_ctx(pcb, sen.peer_addr_be, sen.peer_port_be, &error);
	if (ctx == NULL) {
		smt_pcb_debug(pcb, "failed getting ctx: %d", error);
		goto smt_ctx_enable_locked;
	}

	slot = (is_tx) ? &ctx->tx : &ctx->rx;
	if (!slot->active) {
		smt_pcb_unlock(pcb);
		error = smt_new_ktls(pcb, &sen.tls, &ktls, direction);
		smt_pcb_lock(pcb);
		if (pcb->shutdown) {
			error = ESHUTDOWN;
			smt_ctx_put(ctx);
			goto smt_ctx_enable_locked;
		}

		if (error != 0) {
			smt_ctx_put(ctx);
			goto smt_ctx_enable_locked;
		}

		// we dropped the lock so we need to check again
		slot = (is_tx) ? &ctx->tx : &ctx->rx;
		if (slot->active) {
			error = EALREADY;
			smt_ctx_put(ctx);
			goto smt_ctx_enable_locked;
		}

		slot->en = sen.tls;
		moved_en = true;
		slot->session = ktls;
		ktls = NULL;
		slot->active = true;
		slot->copy = false;
	}

	if ((sen.peer_addr_be == 0) && (sen.peer_port_be == 0)) {
		smt_assign_reuse_ctx(pcb, ctx);
	}

	smt_pcb_debug(pcb, "ktls %s enabled", (is_tx) ? "tx" : "rx");
	smt_ctx_put(ctx);

	pcb->ctx_map.active = true;

smt_ctx_enable_locked:
	smt_pcb_unlock(pcb);

smt_ctx_enable_out:
	if (ktls != NULL) {
		ktls_free(ktls);
	}
	if (!moved_en) {
		ktls_cleanup_tls_enable(&sen.tls);
	}
	return (error);
}

static inline uint8_t
smt_extra_ip_id(struct smt_data_header *header)
{
	return (header->retransmit >> 4) & 0x0F;
}

static inline uint16_t
smt_logical_ip_id(struct smt_data_header *header, struct ip *ip_header)
{
	if (header->retransmit & 0x1) {
		return smt_extra_ip_id(header);
	}

	return ntohs(ip_header->ip_id);
}

static inline uint32_t
smt_gso_offset(struct smt_data_header *header)
{
	return ((uint8_t) header->padding[0] << 16)
		| ((uint8_t) header->padding[1] << 8)
		| ((uint8_t) header->padding[2]);
}

/*
 * For smt_pre_len and smt_post_len we cannot use the ktls_session
 * parameters because we don't have the guarantee that they are present.
 */

int
smt_pre_len(struct smt_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	KASSERT(rpc->crypto.ctx != NULL, ("ctx must be valid"));

	/*
	KASSERT(rpc->crypto.ctx->rx.session != NULL, ("RX session must be valid"));
	struct ktls_session *session = rpc->crypto.ctx->rx.session;
	int len = session->params.tls_hlen;
	*/

#ifdef INVARIANTS
	struct tls_enable *en = &rpc->crypto.ctx->rx.en;

	KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
		("cipher algorithm must be CRYPTO_AES_NIST_GCM_16, instead: %d",
		 en->cipher_algorithm));
	KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
		("tls major version must be 1, instead: %d",
		 en->tls_vmajor));
	KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
		("tls minor version must be 2, instead: %d",
		 en->tls_vminor));
#endif

	int len = sizeof(struct tls_record_layer) + sizeof(uint64_t);
	MUST_POSITIVE(len);
	return (len);
}

int
smt_post_len(struct smt_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	KASSERT(rpc->crypto.ctx != NULL, ("ctx must be valid"));

	/*
	KASSERT(rpc->crypto.ctx->rx.session != NULL, ("RX session must be valid"));
	struct ktls_session *session = rpc->crypto.ctx->rx.session;
	int len = session->params.tls_tlen;
	*/

#ifdef INVARIANTS
	struct tls_enable *en = &rpc->crypto.ctx->rx.en;

	KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
		("cipher algorithm must be CRYPTO_AES_NIST_GCM_16"));
	KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
		("tls major version must be 1"));
	KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
		("tls minor version must be 2"));
#endif

	int len = AES_GMAC_HASH_LEN;
	MUST_POSITIVE(len);
	return (len);
}

static inline int
smt_logical_offset(struct smt_rpc *rpc, uint16_t ip_id, uint32_t gso_offset)
{
	VALID_RPC_ASSERT(rpc);

	int max = rpc->crypto.max, extra_len = smt_pre_len(rpc) + smt_post_len(rpc);
	int offset = (int)(ip_id * max + gso_offset);

	if (ip_id != 0) {
		offset -= extra_len;
	}

	MUST_NOT_NEGATIVE(offset);
	return (offset);
}

static inline int
smt_logical_data_bytes(struct smt_rpc *rpc, struct mbuf *m, int iphlen, uint16_t ip_id)
{
	VALID_RPC_ASSERT(rpc);

	int len = smt_payload_len(m, iphlen);
	int post_len = smt_post_len(rpc);
	int extra_len = smt_pre_len(rpc) + post_len;

	if (ip_id == 0) {
		len -= extra_len;
	}
	MUST_POSITIVE(len);

	if (len + sizeof(struct smt_data_segment) > post_len) {
		return len;
	}
	return len + sizeof(struct smt_data_segment);
}

static inline bool
smt_trailer_only(struct smt_rpc *rpc, int data_bytes, uint16_t ip_id)
{
	VALID_RPC_ASSERT(rpc);

	if (ip_id == 0) {
		return false;
	}

	return (data_bytes <= smt_post_len(rpc));
}

void
smt_debug_rx_info(struct smt_rpc *rpc, struct smt_rx_logical_info *info)
{
	smt_rpc_debug(rpc, "start: %d, length: %d, end: %d, trailer_only: %d, record_data_offset: %d, record_data_len: %d",
		info->start, info->length, info->end, info->trailer_only,
		info->record_data_offset, info->record_data_len);
}

struct smt_rx_logical_info
smt_calc_rx_logical_info(struct smt_rpc *rpc, struct mbuf *m)
{
	VALID_RPC_ASSERT(rpc);
	VALID_PCB_ASSERT(rpc->smtcb);
	KASSERT(m != NULL, ("m must be valid"));

	int iphlen = rpc->smtcb->iphlen;
	int payload_len = smt_payload_len(m, iphlen);
	int record_len, max_frame_data;
	MBUF_LEN_AT_LEAST(m, SMT_TLS_DATA_OFFSET + iphlen);

	struct smt_data_header *header = SMT_MTOD(m, struct smt_data_header *, iphlen);
	struct ip *ip_header = mtod(m, struct ip *);
	uint8_t *record_header;

	struct smt_rx_logical_info info;
	uint16_t ip_id = smt_logical_ip_id(header, ip_header);
	uint32_t gso_offset = smt_gso_offset(header);

	info.start = smt_logical_offset(rpc, ip_id, gso_offset);
	info.length = smt_logical_data_bytes(rpc, m, iphlen, ip_id);
	info.end = info.start + info.length;
	info.trailer_only = smt_trailer_only(rpc, info.length, ip_id);

	if (ip_id != 0 || payload_len + sizeof(struct smt_data_header) < smt_pre_len(rpc)) {
		goto smt_calc_rx_logical_info_out;
	}

	info.record_data_offset = info.start;
	record_header = SMT_MTOD(m, uint8_t *, iphlen) + sizeof(struct smt_data_header)
		- sizeof(struct smt_data_segment);

	if ((record_header[0] != 0x17) || (record_header[1] != 0x03) || (record_header[2] != 0x03)) {
		smt_rpc_debug(rpc, "invalid TLS record: %d, %d, %d",
		 record_header[0], record_header[1], record_header[2]);
		goto smt_calc_rx_logical_info_out;
	}

	record_len = (((uint16_t) record_header[3]) << 8) | (record_header[4] & 0xFF);
	if (record_len <= 0) {
		smt_rpc_debug(rpc, "TLS record len not positive: %d", record_len);
		goto smt_calc_rx_logical_info_out;
	}

	info.record_data_len = record_len + sizeof(struct tls_record_layer) - smt_post_len(rpc);
	max_frame_data = rpc->crypto.max + sizeof(struct smt_data_segment);
	info.record_data_len -= ((info.record_data_len + max_frame_data - 1) / max_frame_data)
		* sizeof(struct smt_data_segment);
	info.record_data_len -= smt_pre_len(rpc);

	smt_debug_rx_info(rpc, &info);
	return info;

smt_calc_rx_logical_info_out:
	info.record_data_offset = -1;
	info.record_data_len = -1;
	smt_debug_rx_info(rpc, &info);
	return info;
}

bool
smt_ctx_record_complete(struct smt_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	KASSERT(!TAILQ_EMPTY(&rpc->msgin.packets), ("rpc msgin packets must not be empty"));

	struct smt_packet_tailq_entry *entry;
	struct smt_rx_logical_info *rx_info;
	int data_end, prev_end;
	bool complete = false;

	entry = TAILQ_FIRST(&rpc->msgin.packets);
	KASSERT(entry != NULL, ("entry must be valid"));

	rx_info = &entry->rx_info;

	if (rx_info->record_data_offset == -1
	    || rx_info->record_data_offset != rpc->crypto.offset) {

		smt_rpc_debug(rpc, "%s: rx info incorrect: record_data_offset: %d, rpc offset: %d",
			__func__, rx_info->record_data_offset, rpc->crypto.offset);
		goto smt_ctx_record_complete_out;
	}

	entry = TAILQ_NEXT(entry, link);
	data_end = rx_info->record_data_offset + rx_info->record_data_len;
	prev_end = rx_info->end;
	if (entry != NULL) {
		TAILQ_FOREACH_FROM(entry, &rpc->msgin.packets, link) {
			if (prev_end >= data_end) {
				break;
			}

			rx_info = &entry->rx_info;
			if (prev_end < rx_info->start) {
				smt_rpc_debug(rpc, "%s: prev end: %d, rx info start: %d",
					__func__, prev_end, rx_info->start);
				goto smt_ctx_record_complete_out;
			}

			KASSERT(rx_info->end > prev_end,
				("next end (%d) must be more than prev one (%d)",
				 rx_info->end, prev_end));
			prev_end = rx_info->end;
		}
	}

	if (prev_end < data_end) {
		smt_rpc_debug(rpc, "%s: prev end: %d, data end: %d",
			__func__, prev_end, data_end);
		goto smt_ctx_record_complete_out;
	}

	complete = true;

smt_ctx_record_complete_out:
	return (complete);
}

static struct ktls_session *
smt_ctx_get_session(struct smt_rpc *rpc, bool is_tx)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	KASSERT(rpc->crypto.ctx != NULL, ("rpc ctx must be valid"));

	int direction = (is_tx) ? KTLS_TX : KTLS_RX, error;
	struct smt_tls_state *state = (is_tx) ? &rpc->crypto.ctx->tx : &rpc->crypto.ctx->rx;
	struct ktls_session *session;
	struct tls_enable en;

	KASSERT(state->active, ("state must be active"));

	if (state->session == NULL) {
		en = state->en;

		smt_rpc_unlock(rpc);
		error = smt_new_ktls(rpc->smtcb, &en, &session, direction);
		smt_rpc_lock(rpc);

		if (error != 0) {
			return (NULL);
		}

		// we dropped the lock, so we need to check again
		state = (is_tx) ? &rpc->crypto.ctx->tx : &rpc->crypto.ctx->rx;
		if (state->session != NULL) {
			smt_rpc_unlock(rpc);
			ktls_free(session);
			smt_rpc_lock(rpc);
			return (state->session);
		}

		state->session = session;
	}

	KASSERT(state->session != NULL, ("session must be valid"));
	return (state->session);
}

/*
 * The decrypted packet will inserted as a mbuf at entries[0]
 *
 */
int
smt_ctx_decrypt(struct smt_rpc *rpc, int iphlen, struct smt_packet_tailq_entry **entries, int n, int *trailer_len)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	MUST_POSITIVE(n);
	KASSERT(entries != NULL && *entries != NULL, ("entries must be valid"));
	KASSERT(entries[0]->data->m_len > iphlen + SMT_TLS_DATA_OFFSET,
	 ("first entry must contain headers"));

	struct mbuf *m = entries[0]->data;
	struct ktls_session *session;
	struct tls_record_layer *header;
	uint64_t seqno = rpc->crypto.rx_seqno;
	int error = 0;

	session = smt_ctx_get_session(rpc, false);
	if (session == NULL) {
		return (EINVAL);
	}

	smt_rpc_unlock(rpc);

	m_adj(m, iphlen + SMT_TLS_HEADER_OFFSET);
	header = mtod(m, struct tls_record_layer *);
	entries[0]->data = NULL;
	KASSERT(header->tls_type == TLS_RLTYPE_APP, ("tls type must be correct: %d", header->tls_type));
	KASSERT(header->tls_vmajor == TLS_MAJOR_VER_ONE, ("tls major version must be correct: %d", header->tls_vmajor));
	KASSERT(header->tls_vminor == TLS_MINOR_VER_TWO, ("tls minor version must be correct: %d", header->tls_vminor));

	smt_tls_header_debug(header, NULL);
	smt_rpc_debug(rpc, "m: m_pkthdr.len %d", m->m_pkthdr.len);
	smt_debug_rx_info(rpc, &entries[0]->rx_info);

	for (int i = 1; i < n; ++i) {
		m_adj(entries[i]->data, iphlen + SMT_TLS_HEADER_OFFSET);
		smt_rpc_debug(rpc, "entry %d: m_pkthdr.len %d", i, entries[i]->data->m_pkthdr.len);
		smt_debug_rx_info(rpc, &entries[i]->rx_info);

		m_catpkt(m, entries[i]->data);
		smt_rpc_debug(rpc, "m: m_pkthdr.len %d", m->m_pkthdr.len);

		entries[i]->data = NULL;
	}

	error = ktls_ocf_decrypt(session, header, m, seqno, trailer_len);
	smt_rpc_debug(rpc, "decryption result: %d", error);
	if (error != 0) {
		smt_free_mbuf(m);
	} else {
		entries[0]->data = m;
	}

	smt_rpc_lock(rpc);
	++rpc->crypto.rx_seqno;
	return (error);
}

// Head Packet:
// [ IP header ][ SMT header ][ TLS header ][ nonce ]
// [ offset #1 ][ payload #1 ]...[ offset #N ][ payload #N ]
// [ trailer ]
//
// headers_len => [ IP header ][ SMT header ][ offset ]
// max_packet_size => frame size - [ IP header ][ SMT header ][ offset ]
// data_len => [ payload #1 ]...[ payload #N ]
// pre_len => [ TLS header ][ nonce ]
// post_len => [ trailer ]
// payload_len => [ offset #1 ][ payload #1 ]...[ offset #N ][ payload #N ]
// seg_len => [ offset ]

struct record_sizes {
	int headers;
	int max_packet;
	int data;
	int pre;
	int post;
	int nsegs;
	int payload;
	int seg;
};

static int
smt_allocate_extpg_mbuf(struct mbuf **mp, struct smt_rpc *rpc, int len)
{
	struct mbuf *m;
	int n;

	n = howmany(len, PAGE_SIZE);
	if (n > MBUF_PEXT_MAX_PGS) {
		return (EMSGSIZE);
	}

	m = mb_alloc_ext_plus_pages(len, M_NOWAIT);
	if (m == NULL) {
		return (ENOBUFS);
	}

	m->m_len = len;
	m->m_epg_1st_off = 0;
	m->m_epg_last_len = len - PAGE_SIZE * (n - 1);
	m->m_epg_hdrlen = 0;
	m->m_epg_trllen = 0;
	m->m_epg_nrdy = 0;
	m->m_epg_seqno = rpc->crypto.tx_seqno++;

	MBUF_EXT_PGS_ASSERT_SANITY(m);
	*mp = m;
	return (0);
}

static void
smt_extpg_copyin_offset(struct mbuf *m, int seg_off, uint32_t offset)
{
	struct smt_data_segment data_seg = {
		.offset_be = htonl(offset),
	};

	m_copyback(m, seg_off, sizeof(data_seg), (c_caddr_t)&data_seg);
	smt_debug("copy offset segment %d to physical offset %d\n", offset, seg_off);
}

static int
smt_tls_allocate_packet_mbuf(struct mbuf **mp, struct smt_rpc *rpc, int packet_size, int offset, uint16_t i)
{
	struct mbuf *m;
	struct ip *ip_header;

	m = m_get2(packet_size, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		return (ENOBUFS);
	}
	m->m_len = packet_size;
	m->m_pkthdr.len = packet_size;

	smt_fill_data_header(rpc, m, offset);

	ip_header = mtod(m, struct ip *);
	ip_header->ip_id = ntohs(i);

	*mp = m;

	smt_rpc_debug(rpc, "allocate pkt mbuf of size %d which has offset %d", packet_size, offset);
	return (0);
}

static void
smt_tls_fill_iov(struct iovec *iov, struct mbuf *m, int offset, int len)
{
	iov->iov_base = mtod(m, char *) + offset;
	iov->iov_len = len;
	smt_debug("create iov at offset %d with len %d\n", offset, len);
}

static struct record_sizes
smt_calc_tls_record_sizes(struct smt_rpc *rpc, int max_packet_size)
{
	struct record_sizes rsizes;

	rsizes.headers = IP_SMT_HEADER_SIZE(rpc->smtcb, struct smt_data_header);
	rsizes.max_packet = max_packet_size;
	rsizes.data = rpc->msgout.length;
	rsizes.pre = smt_pre_len(rpc);
	rsizes.post = smt_post_len(rpc);

	int record_len = rsizes.data + rsizes.pre + rsizes.post;
	rsizes.nsegs = howmany(record_len, rsizes.max_packet);
	rsizes.payload = sizeof(struct smt_data_segment) * rsizes.nsegs + rsizes.data;
	rsizes.seg = sizeof(struct smt_data_segment);

	MUST_POSITIVE(rsizes.headers);
	MUST_POSITIVE(rsizes.data);
	MUST_POSITIVE(rsizes.pre);
	MUST_POSITIVE(rsizes.post);
	MUST_POSITIVE(rsizes.nsegs);
	MUST_POSITIVE(rsizes.payload);
	MUST_POSITIVE(rsizes.seg);

	return rsizes;
}

// TODO: clean up mbufs correctly when there's an error
// TODO: handle the case a message can be split over multiple TLS records
// TODO: check locks if they are correct
int
smt_tls_fill_packets(struct smt_rpc *rpc, struct uio *uio, int max_packet_size)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	KASSERT(rpc->crypto.ctx != NULL, ("rpc ctx must be valid"));

	KASSERT(uio != NULL, ("uio must be valid"));
	MUST_POSITIVE(uio->uio_resid);

	MUST_POSITIVE(max_packet_size);
	uint64_t start_cycles = get_cyclecount();

	if (max_packet_size > MJUMPAGESIZE) {
		SMT_LATENCY(rpc->smtcb->smt, lat_fill_packets_cycles,
		    lat_fill_packets_count, start_cycles);
		return (EMSGSIZE);
	}

	int error, enq_cnt;
	struct record_sizes rsizes;
	struct mbuf *m = NULL;
	struct iovec *iov = NULL;
	struct smt_packet_slist_entry *prev = NULL;
	struct ktls_ocf_encrypt_state state;
	struct ktls_session *session = smt_ctx_get_session(rpc, true);

	if (max_packet_size > session->params.max_frame_len) {
		SMT_LATENCY(rpc->smtcb->smt, lat_fill_packets_cycles,
		    lat_fill_packets_count, start_cycles);
		return (EMSGSIZE);
	}

	rsizes = smt_calc_tls_record_sizes(rpc, max_packet_size);
	smt_rpc_debug(rpc, "total TLS message length to send: %d", rsizes.data);

	smt_rpc_unlock(rpc);

	error = smt_allocate_extpg_mbuf(&m, rpc, rsizes.payload);
	if (error != 0) {
		smt_rpc_lock(rpc);
		goto smt_tls_fill_packets_out;
	}

	iov = malloc(sizeof(*iov) * rsizes.nsegs, M_TEMP, M_NOWAIT | M_ZERO);
	if (iov == NULL) {
		error = ENOMEM;
		smt_rpc_lock(rpc);
		goto smt_tls_fill_packets_out;
	}

	smt_rpc_lock(rpc);

	int data_off = 0;
	int payload_off = 0;
	for (int i = 0; i < rsizes.nsegs; ++i) {
		struct mbuf *pktm;

		int pre = (i == 0) ? rsizes.pre : 0;
		int post = (i == rsizes.nsegs - 1) ? rsizes.post : 0;

		int payload_start = rsizes.headers - rsizes.seg + pre;
		int data_max_size = rsizes.max_packet - pre - post;
		int data_left = rsizes.data - data_off;

		if (data_max_size < 0) {
			error = EMSGSIZE;
			goto smt_tls_fill_packets_out;
		}

		int data_len = min(data_max_size, data_left);
		if (i == rsizes.nsegs - 1 && data_left != data_len) {
			error = EMSGSIZE;
			goto smt_tls_fill_packets_out;
		}

		int payload_len = rsizes.seg + data_len;
		int iov_len = payload_len + post;
		int pkt_size = payload_start + iov_len;

		smt_rpc_debug(rpc, "data_off: %d, payload_off: %d, data_len: %d, payload_len: %d, iov_len: %d, pkt_size: %d",
				data_off, payload_off, data_len, payload_len, iov_len, pkt_size);

		// 1. Create mbuf chain with [ IP header ][ SMT header ][ TLS header ][ nonce ] and [ trailer ],
		//   with enough space in the middle for the encrypted payload.

		smt_rpc_unlock(rpc);
		error = smt_tls_allocate_packet_mbuf(&pktm, rpc, pkt_size, 0, i);
		if (error != 0) {
			smt_rpc_lock(rpc);
			goto smt_tls_fill_packets_out;
		}

		smt_tls_fill_iov(&iov[i], pktm, payload_start, iov_len);

		// 2. Fill mbuf with [ offset #i ][ payload #i ] where i \in [0, nsegs).

		smt_extpg_copyin_offset(m, payload_off, data_off);

		if (data_len != 0) {
			RPC_LOCK_NOTOWNED(rpc);
			error = m_unmapped_uiomove(m, payload_off + rsizes.seg, uio, data_len);
			smt_rpc_debug(rpc, "copied from uio %d bytes of data to offset %d", data_len, payload_off + rsizes.seg);
			if (error != 0) {
				smt_free_mbuf(pktm);
				smt_rpc_lock(rpc);
				goto smt_tls_fill_packets_out;
			}
		}

		error = smt_packet_insert_list(rpc, pktm, &prev);
		if (error != 0) {
			smt_rpc_unlock(rpc);
			smt_free_mbuf(pktm);
			smt_rpc_lock(rpc);
			goto smt_tls_fill_packets_out;
		}

		data_off += data_len;
		payload_off += payload_len;
	}

	ktls_frame(m, session, &enq_cnt, TLS_RLTYPE_APP);

	struct tls_record_layer *hdr = (struct tls_record_layer *)m->m_epg_hdr;
	be64enc((char *)(hdr + 1), m->m_epg_seqno);
	memcpy((char *)iov[0].iov_base - rsizes.pre, m->m_epg_hdr, rsizes.pre);

	smt_rpc_debug(rpc,
	    "sender seq=%ju hdr=%02x %02x %02x %02x %02x explicit=%D",
	    (uintmax_t)m->m_epg_seqno,
	    m->m_epg_hdr[0], m->m_epg_hdr[1], m->m_epg_hdr[2],
	    m->m_epg_hdr[3], m->m_epg_hdr[4],
	    m->m_epg_hdr + sizeof(struct tls_record_layer), ":");

	smt_rpc_unlock(rpc);
	error = ktls_ocf_encrypt(&state, session, m, iov, rsizes.nsegs);
	smt_rpc_lock(rpc);
	if (error != 0) {
		goto smt_tls_fill_packets_out;
	}

smt_tls_fill_packets_out:
	smt_rpc_unlock(rpc);
	if (m != NULL) {
		smt_free_mbuf(m);
	}
	if (iov != NULL) {
		free(iov, M_TEMP);
	}
	smt_rpc_lock(rpc);
	SMT_LATENCY(rpc->smtcb->smt, lat_fill_packets_cycles,
	    lat_fill_packets_count, start_cycles);
	return (error);
}
