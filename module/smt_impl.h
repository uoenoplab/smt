/* Copyright (c) 2022-2025, Tianyi Gao, University of Edinburgh
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

#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <linux/bug.h>
#ifdef __UNIT_TEST__
#undef WARN
#define WARN(condition, format...)

#undef WARN_ON
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#undef WARN_ON_ONCE
#define WARN_ON_ONCE(condition) WARN_ON(condition)
#endif

#include <net/tls.h>
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/slab.h>

#include "homa_impl.h"
#include "smt.h"

#ifdef __UNIT_TEST__
#define kmalloc mock_kmalloc
extern void *mock_kmalloc(size_t size, gfp_t flags);
#endif

#ifdef SMT_DEBUG
#define SMT_INFO
#define smt_prdbg_int(fmt, arg...) pr_info(KERN_INFO fmt, ##arg)
#else
#define smt_prdbg_int(fmt, arg...) {}
#endif

#ifdef SMT_INFO
#define smt_prinf_int(fmt, arg...) pr_info(KERN_INFO fmt, ##arg)
#else
#define smt_prinf_int(fmt, arg...) {}
#endif

#define smt_prerr_int(fmt, arg...) pr_err(fmt, ##arg)

#define smt_tt_record(fmt) tt_record(fmt)
#define smt_tt_record1(fmt, arg...) tt_record1(fmt, ##arg)
#define smt_tt_record2(fmt, arg...) tt_record2(fmt, ##arg)
#define smt_tt_record3(fmt, arg...) tt_record3(fmt, ##arg)
#define smt_tt_record4(fmt, arg...) tt_record4(fmt, ##arg)

static inline void hexdump(const char *title, unsigned char *buf,
			   unsigned int len)
{
#ifdef SMT_DEBUG
	smt_prdbg_int("%s", title);
	while (len--)
		smt_prdbg_int(KERN_CONT "%02x ", *buf++);
	smt_prdbg_int(KERN_CONT "\n");
#endif
}

// TLS 1.3 AES-128-GCM
// Header
//   Record Type and TLS Version 17 03 03 - 3 Bytes
//   Length - 2 Bytes
// Data - Dynamic size
// Trailer
//   Record Type 17 - 1 Bytes (also encrypted with Data)
//   Tag - 16 Bytes
// #define SMT_RECORD_EXTRA_PRE_LENGTH 5
// #define SMT_RECORD_EXTRA_POST_LENGTH 17

// TLS 1.2 AES-128-GCM
// Header
//   Record Type and TLS Version 17 03 03 - 3 Bytes
//   Length - 2 Bytes
//   Nonce (i.e. Seq Num) - 8 Bytes
// Data - Dynamic size
// Trailer
//   Tag - 16 Bytes
#define SMT_RECORD_EXTRA_PRE_LENGTH (TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE)
#define SMT_RECORD_EXTRA_POST_LENGTH TLS_CIPHER_AES_GCM_128_TAG_SIZE

#define SMT_RECORD_EXTRA_LENGTH \
	(SMT_RECORD_EXTRA_PRE_LENGTH + SMT_RECORD_EXTRA_POST_LENGTH)

#define SMT_MAX_DECRYPT_SG 128

#define SMT_REPLAY_WINDOW_BITS 1024U

struct smt_replay_guard {
	spinlock_t lock;
	u64 window_base;
	u32 window_bits;
	unsigned long bitmap[BITS_TO_LONGS(SMT_REPLAY_WINDOW_BITS)];
};

struct smt_context {

	u8 tx_conf : 3;
	u8 rx_conf : 3;

	struct tls12_crypto_info_aes_gcm_128 crypto_info_aes_gcm_128_send;
	struct tls12_crypto_info_aes_gcm_128 crypto_info_aes_gcm_128_recv;

	uint32_t addr; // network byte order
	uint16_t port; // network byte order

	void *smt_offload_ctx_tx;
	void *smt_offload_ctx_rx;

	struct hlist_node hlist;

	struct smt_replay_guard replay_guard;
};

static inline void smt_replay_guard_init(struct smt_replay_guard *guard)
{
	spin_lock_init(&guard->lock);
	guard->window_base = 0;
	guard->window_bits = SMT_REPLAY_WINDOW_BITS;
	bitmap_zero(guard->bitmap, guard->window_bits);
}

static inline bool smt_replay_guard_check_duplicate(struct smt_context *ctx,
		__u64 id)
{
	struct smt_replay_guard *guard = &ctx->replay_guard;
	bool drop = false;
	u64 bit, limit, shift, target_base;

	spin_lock(&guard->lock);

	if (id < guard->window_base) {
		drop = true;
		goto out;
	}

	limit = guard->window_base + guard->window_bits - 1;
	if ((limit < guard->window_base) || (id > limit)) {
		if (guard->window_bits > 0) {
			if (id >= guard->window_bits - 1)
				target_base = id - (guard->window_bits - 1);
			else
				target_base = 0;
			if (target_base > guard->window_base) {
				shift = target_base - guard->window_base;
				if (shift >= guard->window_bits) {
					bitmap_zero(guard->bitmap,
							guard->window_bits);
				} else if (shift) {
					bitmap_shift_right(guard->bitmap,
							guard->bitmap, shift,
							guard->window_bits);
				}
				guard->window_base = target_base;
			}
		}
	}

	if (id < guard->window_base) {
		drop = true;
		goto out;
	}

	bit = id - guard->window_base;
	if (bit >= guard->window_bits) {
		if (guard->window_bits > 0) {
			if (id >= guard->window_bits - 1)
				guard->window_base =
					id - (guard->window_bits - 1);
			else
				guard->window_base = 0;
			bitmap_zero(guard->bitmap, guard->window_bits);
			bit = id - guard->window_base;
		} else {
			drop = false;
			goto out;
		}
	}

	if (test_bit(bit, guard->bitmap))
		drop = true;
	else
		set_bit(bit, guard->bitmap);

out:
	spin_unlock(&guard->lock);
	return drop;
}

enum {
	SMT_BASE,
	SMT_SW,
	SMT_HW,
	SMT_NUM_CONFIG,
};

struct smt_sw_crypto {
	struct crypto_aead *tfm;
	struct aead_request *aead_req;
	int aead_req_size;
	struct scatterlist decrypt_sg[SMT_MAX_DECRYPT_SG];
	struct list_head list;
};

struct smt_rpc_sw_context {
	struct smt_sw_crypto *crypto;
	u8 iv[TLS_CIPHER_AES_GCM_128_IV_SIZE +
		 TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	u8 nonce[TLS_CIPHER_AES_GCM_128_IV_SIZE +
		 TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

struct smt_sw_context {
	struct list_head crypto_list;
	spinlock_t crypto_list_lock;
	int crypto_available;
};

struct smt_rpc_hw_context_tx {
	void *driver_state;
	int queue_idx;
	// spinlock_t *xmit_lock;
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

static inline void smt_set_composite_rec_seq_num(
	__u64 message_id,
	const u8 orig_rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE],
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE])
{
	u64 composite = ((message_id & ((1ULL << 49) - 1)) >> 1) << 16;
	u64 original = get_unaligned_be64(orig_rec_seq);
	u16 low16 = original & 0xFFFF;

	composite |= low16;
	put_unaligned_be64(composite, rec_seq);
}

// we also need to make driver state map exact queue(pass driver state index)
struct smt_hw_context_tx {
	int num_tx_queues;
	int start_queue_id;
	struct net_device *netdev;
	atomic_t num_current_rpcs;
	atomic_t num_driver_states;
	atomic_t last_driver_state_used; // round robin
	void **driver_states;
	// spinlock_t *xmit_locks;
};

// smt_main.c

static inline int smt_get_tx_conf(const struct homa_rpc *rpc)
{
	return rpc->smt_ctx ?
		((struct smt_context *) rpc->smt_ctx)->tx_conf : 0;
}

static inline int smt_get_rx_conf(const struct homa_rpc *rpc)
{
	return rpc->smt_ctx ?
		((struct smt_context *) rpc->smt_ctx)->rx_conf : 0;
}

static inline void smt_free_rpc(struct homa_rpc *rpc) {
	struct smt_context *ctx = (struct smt_context *)rpc->smt_ctx;
	struct smt_hw_context_tx *offload_ctx =
		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;

	if (smt_get_tx_conf(rpc) == SMT_HW) {
		int num_current_rpcs;
		do {
			num_current_rpcs = atomic_read(&offload_ctx->num_current_rpcs);
		} while (atomic_cmpxchg(&offload_ctx->num_current_rpcs,
			num_current_rpcs, num_current_rpcs - 1) != num_current_rpcs);
	}
}

extern int smt_set_rpc_offload_context(struct homa_rpc *rpc);

extern struct smt_context *smt_set_rpc_context(struct homa_rpc *rpc,
					     const uint32_t addr,
					     const uint16_t port);

extern void smt_destroy_ctxs(struct hlist_head *buckets);

extern void smt_destroy_rpc(struct homa_rpc *rpc);

extern int smt_setsockopt(struct homa_sock *hsk, int optname,
				sockptr_t optval, unsigned int optlen);

extern int smt_load(void);

extern int smt_unload(void);

// smt_sw.c

// Copied from tls.h tls_bigint_increment
static inline bool smt_bigint_increment(u8 *seq, int len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}

	return (i == -1);
}

static inline void smt_sw_put_crypto(struct smt_sw_context *sw_ctx,
					struct smt_sw_crypto *crypto)
{
	spin_lock_bh(&sw_ctx->crypto_list_lock);
	list_add_tail(&crypto->list, &sw_ctx->crypto_list);
	sw_ctx->crypto_available++;
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
}

static inline void
smt_sw_release_resources_rpc(struct homa_rpc *rpc,
			        struct kmem_cache *smt_rpc_sw_ctx_kmem,
			        int tx)
{
	struct smt_context *ctx = rpc->smt_ctx;
	struct smt_sw_context *sw_ctx =
		(struct smt_sw_context *) ((tx) ?
		ctx->smt_offload_ctx_tx : ctx->smt_offload_ctx_rx);
	struct smt_rpc_sw_context *rpc_sw_ctx =
		(struct smt_rpc_sw_context *) ((tx) ?
		rpc->smt_rpc_offload_ctx_tx : rpc->smt_rpc_offload_ctx_rx);
	if (likely(rpc_sw_ctx)) {
		if (unlikely(rpc_sw_ctx->crypto))
			smt_sw_put_crypto(sw_ctx, rpc_sw_ctx->crypto);
		kmem_cache_free(smt_rpc_sw_ctx_kmem, rpc_sw_ctx);
	}
}

static inline void smt_sw_unset_crypto(struct homa_rpc *rpc, int tx)
{
	struct smt_context *ctx = rpc->smt_ctx;
	struct smt_rpc_sw_context *rpc_sw_ctx =
		(struct smt_rpc_sw_context *) ((tx) ?
		rpc->smt_rpc_offload_ctx_tx : rpc->smt_rpc_offload_ctx_rx);
	struct smt_sw_context *sw_ctx =
		(struct smt_sw_context *) ((tx) ?
		ctx->smt_offload_ctx_tx : ctx->smt_offload_ctx_rx);

	smt_prinf_int("%s invoked\n", __FUNCTION__);

	smt_sw_put_crypto(sw_ctx, rpc_sw_ctx->crypto);
	rpc_sw_ctx->crypto = NULL;

}

extern int smt_set_sw_offload(struct smt_context *ctx,
			  struct kmem_cache *smt_sw_ctx_kmem, int tx);

extern int smt_set_rpc_sw_offload(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			  void **rpc_offload_ctx,
			  struct kmem_cache *smt_rpc_sw_ctx_kmem,
			  __u64 rpc_id);

extern int smt_sw_set_crypto(struct homa_rpc *rpc, int tx);

extern void smt_sw_release_resources(struct smt_context *ctx,
				        struct kmem_cache *smt_sw_ctx_kmem,
					int tx);

extern int smt_sw_encrypt(struct homa_rpc *rpc, u8 *smt_header,
			u8 *smt_trailer);

extern int smt_sw_decrypt_gsosegs(struct homa_rpc *rpc);

extern int smt_sw_decrypt(struct homa_rpc *rpc);

// smt_device.c

static inline void
smt_device_release_resources_rpc_tx(struct homa_rpc *rpc,
			struct kmem_cache *smt_rpc_hw_ctx_tx_kmem)
{
	if (likely(rpc->smt_rpc_offload_ctx_tx)) {
		kmem_cache_free(smt_rpc_hw_ctx_tx_kmem, rpc->smt_rpc_offload_ctx_tx);
	}
}

enum ktls_del_smt_offload_ctx_dir {
	TCPTLS_OFFLOAD_CTX_DIR_RX,
	TCPTLS_OFFLOAD_CTX_DIR_TX,
	SMT_OFFLOAD_CTX_DIR_RX,
	SMT_OFFLOAD_CTX_DIR_TX,
};

static inline void smt_device_release_resources_tx(struct smt_context *ctx)
{
	struct smt_hw_context_tx *hw_ctx_tx =
		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;

	struct net_device *netdev = hw_ctx_tx->netdev;

	for (size_t i = 0; i < hw_ctx_tx->num_tx_queues; i++)
	{
		if (hw_ctx_tx->driver_states[i] == NULL)
			continue;

		netdev->tlsdev_ops->tls_dev_del(netdev,
			(struct tls_context *)hw_ctx_tx->driver_states[i],
			SMT_OFFLOAD_CTX_DIR_TX);
		hw_ctx_tx->driver_states[i] = NULL;
	}

	kfree(hw_ctx_tx->driver_states);
	kfree(hw_ctx_tx);
}

// static inline void smt_device_xmit_lock(struct homa_rpc *rpc) {
// 	struct smt_context *ctx = rpc->smt_ctx;
// 	struct smt_hw_context_tx *hw_ctx_tx =
// 		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;

// 	if (!ctx)
// 		return;

// 	if (ctx->tx_conf != SMT_HW)
// 		return;

// 	spin_lock_bh(&hw_ctx_tx->xmit_lock);
// }

// static inline void smt_device_xmit_unlock(struct homa_rpc *rpc) {
// 	struct smt_context *ctx = rpc->smt_ctx;
// 	struct smt_hw_context_tx *hw_ctx_tx =
// 		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;

// 	if (!ctx)
// 		return;

// 	if (ctx->tx_conf != SMT_HW)
// 		return;

// 	spin_unlock_bh(&hw_ctx_tx->xmit_lock);
// }

extern int smt_device_set_crypto_tx(struct homa_rpc *rpc);

extern int smt_set_device_offload_send(struct homa_sock *hsk,
					  struct smt_context *ctx);

extern int smt_set_rpc_device_offload(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			void **rpc_offload_ctx,
			struct kmem_cache *smt_rpc_hw_ctx_tx_kmem,
			__u64 rpc_id);

extern int smt_device_encrypt(struct homa_rpc *rpc, char *smt_header,
		      char *smt_trailer, struct sk_buff *skb);

// smt_outgoing.c

extern int smt_message_out_init(struct homa_rpc *rpc,
				   struct iov_iter *iter,
				   int xmit);

extern void smt_resend_data(struct homa_rpc *rpc,
			       int start,
			       int end,
			       int priority);

// smt_incoming.c

static inline unsigned short smt_ip_id(struct sk_buff *skb)
{
	return ntohs(ip_hdr(skb)->id);
}

static inline unsigned char smt_extra_ip_id(struct sk_buff *skb)
{
	return ((struct data_header *) skb->data)->pad;
}

static inline unsigned short smt_fake_ip_id(struct sk_buff *skb)
{
	return smt_ip_id(skb) + smt_extra_ip_id(skb);
}

static inline unsigned int smt_gso_offset(struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *) skb->data;
	return (ntohs(h->common.unused3) << 16) | (ntohs((h->common.unused4) & 0xffff));
}

static inline unsigned int smt_gso_offset_resend(struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *) skb_transport_header(skb);
	return (ntohs(h->common.unused3) << 16) | (ntohs((h->common.unused4) & 0xffff));
}

static inline unsigned int smt_fake_data_bytes(unsigned short ip_id,
						  unsigned int skb_len)
{
	skb_len -= (ip_id == 0) * SMT_RECORD_EXTRA_LENGTH;

	if (likely(skb_len > sizeof32(struct data_header)))
		return skb_len - sizeof32(struct data_header);
	else
		return skb_len + sizeof32(struct data_segment)
			- sizeof32(struct data_header);
}

static inline unsigned int smt_fake_offset(unsigned short ip_id,
					      unsigned int gso_offset,
					      struct homa_message_in *msgin)
{
	return ip_id * msgin->smt_max_pkt_data + gso_offset
		- (ip_id != 0) * SMT_RECORD_EXTRA_LENGTH;
}

static inline unsigned int smt_fake_next_offset(struct sk_buff *skb,
						   struct homa_message_in *msgin)
{
	unsigned int gso_offset = smt_gso_offset(skb);
	unsigned short ip_id = smt_fake_ip_id(skb);
	unsigned int offset = smt_fake_offset(ip_id, gso_offset, msgin);
	unsigned int data_bytes = smt_fake_data_bytes(ip_id, skb->len);

	return offset + data_bytes;
}

extern bool smt_find_gsoseg(struct homa_rpc *rpc);

extern void smt_add_packet(struct homa_rpc *rpc, struct sk_buff *skb,
			      bool *try_find_gsoseg);

extern int smt_copy_to_user(struct homa_rpc *rpc);

extern void smt_get_resend_range(struct homa_message_in *msgin,
				    struct resend_header *resend);

extern void smt_handle_acks(struct homa_rpc *rpc, int decrypted_gsosegs);

extern void smt_handle_ack(struct homa_rpc *rpc, struct sk_buff* skb);

#endif /* _SMT_IMPL_H */
