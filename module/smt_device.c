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

#include "smt_impl.h"

/* device_offload_lock is used to synchronize tls_dev_add
 * against NETDEV_DOWN notifications.
 */
static DEFINE_MUTEX(device_offload_mutex_lock);
// static DECLARE_RWSEM(device_offload_lock);
// static DEFINE_SPINLOCK(tls_device_lock);
// static LIST_HEAD(tls_device_list);

// static struct net_device *get_netdev_for_ctx(struct homa_sock *hsk, struct smt_context *ctx)
// {
// 	union sockaddr_in_union addr;
// 	struct homa_peer peer;
// 	struct dst_entry *dst;
// 	struct net_device *netdev;

// 	addr.in4.sin_addr.s_addr = ctx->addr;
// 	peer.addr = canonical_ipv6_addr(&addr);

// 	dst = homa_peer_get_dst(&peer, &hsk->inet);
// 	if (IS_ERR(dst)) {
// 		pr_err("%s: can not get dst_entry\n", __func__);
// 		return NULL;
// 	}
// 	netdev = dst->dev;
// 	dst_release(dst);
// 	return netdev;
// }

// static int sw_fallback_init(struct sock *sk, struct smt_context *ctx, int tx)
// {
// 	int rc = 0;
// 	return rc;
// }

// static int rpc_sw_fallback_init(struct sock *sk, struct smt_context *ctx, int tx)
// {
// 	int rc = 0;
// 	return rc;
// }

struct smt_tls_add_hack {
	struct tls_crypto_info *crypto_info;
	void **driver_state;
};

static int smt_device_create_driver_state(struct homa_rpc *rpc, void **driver_state) {
	struct smt_tls_add_hack tls_add_hack;
	struct smt_context *ctx = (struct smt_context *)rpc->smt_ctx;
	struct smt_hw_context_tx *offload_ctx =
		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;
	struct net_device *netdev = offload_ctx->netdev;
	int rc;

	if (!mutex_trylock(&device_offload_mutex_lock)) {
		mutex_lock(&device_offload_mutex_lock);
	}

	tls_add_hack.driver_state = driver_state;
	tls_add_hack.crypto_info = &ctx->crypto_info_aes_gcm_128_send.info;

	smt_prinf_int("%s tls_add_hack %px tls_add_hack->crypto_info %px tls_add_hack->driver_state %px \n",
		__func__, &tls_add_hack, tls_add_hack.crypto_info, tls_add_hack.driver_state);

	rc = netdev->tlsdev_ops->tls_dev_add(netdev, &rpc->hsk->sock, TLS_OFFLOAD_CTX_DIR_TX,
					     (void *)&tls_add_hack, 0);

	smt_prinf_int("%s driver_state %px \n",__func__, driver_state);

	mutex_unlock(&device_offload_mutex_lock);

	return rc;
}

int smt_device_set_crypto_tx(struct homa_rpc *rpc)
{
	struct smt_context *ctx = (struct smt_context *)rpc->smt_ctx;
	struct smt_hw_context_tx *offload_ctx =
		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;
	struct smt_rpc_hw_context_tx *ctx_rpc_tx =
		(struct smt_rpc_hw_context_tx *)rpc->smt_rpc_offload_ctx_tx;
	int rc = 0;

	const int threshold = rpc->hsk->homa->smt_hardware_state_threshold;
	int num_rpcs, num_driver_states;
	int driver_state_idx = -1;

	if (!offload_ctx->netdev)
		return -EINVAL;

	if (!offload_ctx->start_queue_id) {
		offload_ctx->start_queue_id = raw_smp_processor_id() % offload_ctx->num_tx_queues;
	}

	do {
		num_rpcs = atomic_read(&offload_ctx->num_current_rpcs);
	} while (atomic_cmpxchg(&offload_ctx->num_current_rpcs, num_rpcs, num_rpcs + 1) != num_rpcs);
	num_rpcs = num_rpcs + 1;

	num_driver_states = atomic_read(&offload_ctx->num_driver_states);

	while (unlikely(num_rpcs > num_driver_states * threshold && num_driver_states < offload_ctx->num_tx_queues)) {
		if (atomic_cmpxchg(&offload_ctx->num_driver_states, num_driver_states, num_driver_states + 1) == num_driver_states) {
			smt_prinf_int("%s num_driver_states %d &offload_ctx->driver_states[num_driver_states] %px \n",
				__func__, num_driver_states, &offload_ctx->driver_states[num_driver_states]);
			rc = smt_device_create_driver_state(rpc, &offload_ctx->driver_states[num_driver_states]);
			if (unlikely(rc)) {
				return rc;
			}
			num_driver_states++;
			driver_state_idx = num_driver_states - 1;
			break;
		} else {
			num_driver_states = atomic_read(&offload_ctx->num_driver_states);
		}
	}

	while (true) {
		if (likely(driver_state_idx == -1)) {
			driver_state_idx = (atomic_read(&offload_ctx->last_driver_state_used) + 1) % num_driver_states;
		}
		if (offload_ctx->driver_states[driver_state_idx] != NULL) {
			break;
		} else {
			driver_state_idx = (driver_state_idx + 1) % num_driver_states;
		}
	}

	atomic_set(&offload_ctx->last_driver_state_used, driver_state_idx);
	ctx_rpc_tx->driver_state = offload_ctx->driver_states[driver_state_idx];
	ctx_rpc_tx->queue_idx = (driver_state_idx + offload_ctx->start_queue_id) % offload_ctx->num_tx_queues;

	return rc;
}

int smt_device_encrypt(struct homa_rpc *rpc, char *smt_header,
		      char *smt_trailer, struct sk_buff *skb)
{
	int ret = 0;
	struct smt_context *ctx = rpc->smt_ctx;
	struct smt_hw_context_tx *ctx_tx __attribute__((unused)) =
		(struct smt_hw_context_tx *)ctx->smt_offload_ctx_tx;
	struct smt_rpc_hw_context_tx *ctx_rpc_tx =
		(struct smt_rpc_hw_context_tx *)rpc->smt_rpc_offload_ctx_tx;
	u8 *buf = (u8 *) smt_header;
	int data_len = smt_trailer - smt_header - SMT_RECORD_EXTRA_PRE_LENGTH;
	int buf_len = data_len + SMT_RECORD_EXTRA_LENGTH;
	void **cb_driver_state = (void **)(skb->cb + sizeof(skb->cb) - sizeof(void *));

	smt_prdbg_int("%s buf %px rpc %px header %px trailer %px",
		__FUNCTION__, buf, rpc, smt_header, smt_trailer);
	smt_prdbg_int("%s ctx %px ctx_tx %px",
		__FUNCTION__, ctx, ctx_tx);

	// fill_prepend
	smt_header[0] = 0x17;
	smt_header[1] = 0x03;
	smt_header[2] = 0x03;
	smt_header[3] = (buf_len - TLS_HEADER_SIZE) >> 8;
	smt_header[4] = (buf_len - TLS_HEADER_SIZE) & 0xff;
	for (int i = 0; i < TLS_CIPHER_AES_GCM_128_IV_SIZE; i++) {
		smt_header[TLS_HEADER_SIZE + i] = ctx_rpc_tx->rec_seq[i];
	}
	// hexdump("header ", smt_header, SMT_RECORD_EXTRA_PRE_LENGTH);

	smt_prdbg_int("aad | plaintext | authtag (buf_len %d)\n", buf_len);
	hexdump("", buf, buf_len);

	// pre-set queue
	skb->sk = &rpc->hsk->sock;
	skb_set_queue_mapping(skb, (u16)ctx_rpc_tx->queue_idx);

	// save driver_state to cb
	*cb_driver_state = ctx_rpc_tx->driver_state;
	smt_prdbg_int("%s cb_driver_state %px *cb_driver_state %px\n", __func__,
			cb_driver_state, *cb_driver_state);
	// update rec seq
	smt_bigint_increment(ctx_rpc_tx->rec_seq, sizeof(ctx_rpc_tx->rec_seq));
	hexdump("rec_seq (for next record) ", ctx_rpc_tx->rec_seq, sizeof(ctx_rpc_tx->rec_seq));

	return ret;
}

int smt_set_device_offload_send(struct homa_sock *hsk, struct smt_context *ctx)
{
	// struct sock *sk = &hsk->sock;
	struct net_device *netdev;
	struct smt_hw_context_tx *offload_ctx;
	int rc;

	// sw_fallback_init(sk, ctx, 1);

	if (!ctx)
		return -EINVAL;

	netdev = dev_get_by_name(&init_net, hsk->homa->smt_hardware_interface);
	if (!netdev) {
		pr_err_ratelimited("%s: netdev %s not found\n",
			__func__, hsk->homa->smt_hardware_interface);
		rc = -EINVAL;
		goto error;
	} else {
		smt_prinf_int("%s: get netdev %s\n", __func__, netdev->name);
	}

	if (!(netdev->features & NETIF_F_HW_TLS_TX)) {
		smt_prinf_int("%s: netdev doesn't support tls offload\n", __func__);
		rc = -EOPNOTSUPP;
		goto release_netdev;
	}

	/* Avoid offloading if the device is down
	 * We don't want to offload new flows after
	 * the NETDEV_DOWN event
	 *
	 * device_offload_lock is taken in tls_devices's NETDEV_DOWN
	 * handler thus protecting from the device going down before
	 * ctx was added to tls_device_list.
	 */
	// down_read(&device_offload_lock);
	if (!(netdev->flags & IFF_UP)) {
		pr_err("%s: device is down\n", __func__);
		rc = -EINVAL;
		goto release_lock;
	}

	if (ctx->smt_offload_ctx_tx) {
		rc = -EEXIST;
		goto release_lock;
	}

	offload_ctx = kzalloc(sizeof(struct smt_hw_context_tx), GFP_ATOMIC);
	if (!offload_ctx) {
		rc = -ENOMEM;
		goto release_lock;
	}

	offload_ctx->netdev = netdev;
	offload_ctx->num_tx_queues = netdev->real_num_tx_queues;

	offload_ctx->driver_states =
		kzalloc(sizeof(void *) * offload_ctx->num_tx_queues, GFP_ATOMIC);
	if (!offload_ctx->driver_states) {
		rc = -ENOMEM;
		goto free_offload_ctx;
	}

	atomic_set(&offload_ctx->num_current_rpcs, 0);
	atomic_set(&offload_ctx->num_driver_states, 0);
	atomic_set(&offload_ctx->last_driver_state_used, 0);

	// offload_ctx->xmit_locks =
	// 	kzalloc(sizeof(spinlock_t) * offload_ctx->num_tx_queues, GFP_ATOMIC);
	// if (!offload_ctx->xmit_locks) {
	// 	rc = -ENOMEM;
	// 	goto free_offload_ctx;
	// }

	ctx->smt_offload_ctx_tx = offload_ctx;

	// up_read(&device_offload_lock);
	dev_put(netdev);
	return 0;

free_offload_ctx:
	kfree(offload_ctx);
	ctx->smt_offload_ctx_tx = NULL;
release_lock:
	// up_read(&device_offload_lock);
release_netdev:
	dev_put(netdev);
error:
	return rc;
}

int smt_set_rpc_device_offload(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			void **rpc_offload_ctx,
			struct kmem_cache *smt_rpc_hw_ctx_tx_kmem,
			__u64 rpc_id)
{
	int rc = 0;

	struct smt_rpc_hw_context_tx *rpc_hw_ctx = NULL;

	rpc_hw_ctx = kmem_cache_alloc(smt_rpc_hw_ctx_tx_kmem, GFP_ATOMIC);
	if (unlikely(!rpc_hw_ctx)) {
		smt_prerr_int("%s failed to alloc memory for rpc_hw_ctx\n", __FUNCTION__);
		return -ENOMEM;
	}

	smt_set_composite_rec_seq_num(rpc_id, crypto_info->rec_seq,
					 rpc_hw_ctx->rec_seq);
	hexdump("smt_set_rpc_device_offload rpc_hw_ctx->rec_seq ", rpc_hw_ctx->rec_seq,
		TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	*rpc_offload_ctx = (void *) rpc_hw_ctx;

	return rc;
}
