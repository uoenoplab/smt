// SPDX-License-Identifier: GPL-2.0
/* SMT TX HW offload (mlx5 ktls). Compiled only when CONFIG_SMT_HW is set;
 * the Makefile drops smt_device.o from the build otherwise.
 *
 * Lifted, with light edits, from ~/repos/smt/module/smt_device.c. Kept
 * close to the original to preserve battle-tested control flow. The two
 * intentional differences vs the old module:
 *   1. composite_id is dropped (rpc_hw_ctx->rec_seq is initialized via
 *      memcpy from the ctx's TLS rec_seq; no per-RPC mixing of message_id
 *      into the high bits). Bring this back when bench requires it.
 *   2. driver_state allocation is simplified: one driver_state allocated
 *      lazily on the first encrypt, shared across all RPCs in this ctx,
 *      with queue_idx round-robined across the netdev's TX queues. The
 *      threshold-based growth from the old module is deferred.
 *
 * Per-queue xmit_lock is intentionally absent: queue pinning + one TIS
 * per TX queue makes the netdev TX queue itself the serialization point.
 */

#ifdef CONFIG_SMT_HW

#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tls.h>

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_sock.h"
#include "smt_impl.h"
#include "smt_plumbing.h"

/* device_offload_lock is used to synchronize tls_dev_add against
 * NETDEV_DOWN notifications.
 */
static DEFINE_MUTEX(device_offload_mutex_lock);

struct smt_tls_add_hack {
	struct tls_crypto_info *crypto_info;
	void **driver_state;
};

static int smt_device_create_driver_state(struct homa_rpc *rpc, void **driver_state)
{
	struct smt_tls_add_hack tls_add_hack;
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_hw_context_tx *offload_ctx =
		(struct smt_hw_context_tx *)ctx->offload_tx;
	struct net_device *netdev = offload_ctx->netdev;
	int rc;

	if (!mutex_trylock(&device_offload_mutex_lock))
		mutex_lock(&device_offload_mutex_lock);

	tls_add_hack.driver_state = driver_state;
	tls_add_hack.crypto_info =
		(struct tls_crypto_info *)&ctx->aes_gcm_128_send;

	smt_pr_info("%s tls_add_hack %px crypto_info %px driver_state %px\n",
		    __func__, &tls_add_hack, tls_add_hack.crypto_info,
		    tls_add_hack.driver_state);

	rc = netdev->tlsdev_ops->tls_dev_add(netdev, &rpc->hsk->sock,
					     TLS_OFFLOAD_CTX_DIR_TX,
					     (void *)&tls_add_hack, 0);

	smt_pr_info("%s driver_state %px\n", __func__, *driver_state);

	mutex_unlock(&device_offload_mutex_lock);

	return rc;
}

/* Pool-side bookkeeping: a TIS slot is "free" when its bit is set in
 * pool->free AND its inflight counter has reached 0. Acquire flips the
 * bit to 0 atomically; release sets it back once inflight is 0.
 */
static int smt_hw_acquire_slot(struct smt_hw_per_cpu_pool *pool)
{
	int i;

	for (i = 0; i < SMT_TIS_PER_CPU; i++) {
		if (test_and_clear_bit(i, &pool->free))
			return i;
	}
	return -EAGAIN;
}

static void smt_hw_return_slot(struct smt_hw_per_cpu_pool *pool, int slot_idx)
{
	set_bit(slot_idx, &pool->free);
}

int smt_device_set_crypto_tx(struct homa_rpc *rpc)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_hw_context_tx *offload_ctx;
	struct smt_rpc_hw_context_tx *ctx_rpc_tx = smt_rpc_hw_tx(rpc);
	struct smt_hw_per_cpu_pool *pool;
	struct smt_tis_slot *slot;
	int cpu, slot_idx, rc;

	if (unlikely(!ctx || !ctx->offload_tx)) {
		smt_pr_err("%s: rpc %lld has tx_conf==SMT_HW but offload_tx is NULL (cloned ctx without HW alloc?)\n",
			   __func__, rpc->id);
		return -EINVAL;
	}
	offload_ctx = (struct smt_hw_context_tx *)ctx->offload_tx;
	if (!offload_ctx->netdev || !offload_ctx->pools)
		return -EINVAL;

	cpu = raw_smp_processor_id();
	if (cpu >= offload_ctx->nr_cpus)
		cpu = cpu % offload_ctx->nr_cpus;  /* defensive */
	pool = &offload_ctx->pools[cpu];

	slot_idx = smt_hw_acquire_slot(pool);
	if (slot_idx < 0) {
		pr_warn_ratelimited("%s: pool exhausted on cpu %d (SMT_TIS_PER_CPU=%d)\n",
				    __func__, cpu, SMT_TIS_PER_CPU);
		return -EAGAIN;
	}
	slot = &pool->slots[slot_idx];

	/* Lazy create TIS on first use of this slot. Subsequent acquires
	 * of the same slot reuse the existing priv_tx — the NIC TLS
	 * context persists across RPCs sharing the slot.
	 */
	if (!READ_ONCE(slot->priv_tx)) {
		mutex_lock(&pool->create_lock);
		if (!slot->priv_tx) {
			rc = smt_device_create_driver_state(rpc, &slot->priv_tx);
			if (rc) {
				mutex_unlock(&pool->create_lock);
				smt_hw_return_slot(pool, slot_idx);
				return rc;
			}
		}
		mutex_unlock(&pool->create_lock);
	}

	ctx_rpc_tx->driver_state = slot->priv_tx;
	ctx_rpc_tx->home_cpu = (short)cpu;
	ctx_rpc_tx->slot_idx = (short)slot_idx;
	ctx_rpc_tx->queue_idx = (short)(cpu % offload_ctx->num_tx_queues);

	return 0;
}

void smt_device_release_tis(struct homa_rpc *rpc)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_hw_context_tx *offload_ctx;
	struct smt_rpc_hw_context_tx *ctx_rpc_tx = smt_rpc_hw_tx(rpc);
	struct smt_hw_per_cpu_pool *pool;
	struct smt_tis_slot *slot;

	if (!ctx || !ctx->offload_tx)
		return;
	if (!READ_ONCE(ctx_rpc_tx->driver_state))
		return;  /* already released (idempotent) */

	offload_ctx = (struct smt_hw_context_tx *)ctx->offload_tx;
	pool = &offload_ctx->pools[ctx_rpc_tx->home_cpu];
	slot = &pool->slots[ctx_rpc_tx->slot_idx];

	WRITE_ONCE(ctx_rpc_tx->driver_state, NULL);
	/* Return slot eagerly without waiting for in-flight skbs. A new
	 * owner acquiring this slot will use the same priv_tx; mlx5 ktls'
	 * resync path handles the rec_seq mismatch when the new owner's
	 * first record hits handle_tx_skb (one resync WQE per RPC handoff
	 * instead of per-skb under the old shared-pool design).
	 *
	 * Late-firing destructors from the previous owner's skbs are
	 * harmless: the callback now does nothing — slot reuse is gated
	 * solely by the free bitmap.
	 */
	smt_hw_return_slot(pool, ctx_rpc_tx->slot_idx);
}

int smt_device_encrypt(struct homa_rpc *rpc, u8 *smt_h, u8 *smt_t,
		       struct sk_buff *skb)
{
	struct smt_rpc_hw_context_tx *ctx_rpc_tx = smt_rpc_hw_tx(rpc);
	int data_len;
	int buf_len;

	if (unlikely(!smt_h)) {
		smt_pr_err("%s: smt_h is NULL for rpc %lld\n",
			   __func__, rpc->id);
		return -EINVAL;
	}
	if (unlikely(!ctx_rpc_tx->driver_state)) {
		/* Slot was released early (directive 2) and now a retransmit
		 * or late-burst encrypt needs to send again. Reacquire from
		 * the current CPU's pool. If exhausted, the caller's error
		 * handling will fall back to SW for this skb.
		 */
		int rc_acq = smt_device_set_crypto_tx(rpc);

		if (rc_acq)
			return rc_acq;
	}

	/* data_len = bytes between (smt_h + PRE) and smt_t. For HW offload
	 * the trailer (16-byte tag) is filled in by the NIC; we only need
	 * the LL field in the TLS record header.
	 *
	 * If smt_t is NULL (caller didn't pass a contiguous trailer pointer
	 * — current SMT-NG keeps the trailer in a frag), we can't compute
	 * data_len from the pointer subtraction. Fall back to deriving it
	 * from skb->len: total record bytes = skb->len - smt_h_offset, so
	 * LL = (skb->len - smt_h_offset) - TLS_HEADER_SIZE.
	 */
	if (smt_t) {
		data_len = (int)(smt_t - smt_h) - SMT_RECORD_EXTRA_PRE_LENGTH;
	} else {
		int smt_h_offset = (int)(smt_h - skb->data);

		data_len = (int)skb->len - smt_h_offset
			- SMT_RECORD_EXTRA_LENGTH;
	}
	buf_len = data_len + SMT_RECORD_EXTRA_LENGTH;

	smt_pr_devel("%s: rpc=%lld data_len=%d buf_len=%d\n",
		     __func__, rpc->id, data_len, buf_len);

	smt_h[0] = 0x17;
	smt_h[1] = 0x03;
	smt_h[2] = 0x03;
	smt_h[3] = (buf_len - TLS_HEADER_SIZE) >> 8;
	smt_h[4] = (buf_len - TLS_HEADER_SIZE) & 0xff;
	for (int i = 0; i < TLS_CIPHER_AES_GCM_128_IV_SIZE; i++)
		smt_h[TLS_HEADER_SIZE + i] = ctx_rpc_tx->rec_seq[i];

	/* Patched mlx5 needs skb->sk set so its ndo_select_queue can spot
	 * the IPPROTO_HOMA socket and check the homa hdr type byte.
	 */
	skb->sk = &rpc->hsk->sock;
	skb_set_queue_mapping(skb, (u16)ctx_rpc_tx->queue_idx);

	/* Hand priv_tx to the patched mlx5 TX hook via the tail of skb->cb.
	 * The NIC reads the TLS record seq from smt_h in linear and the TX
	 * queue from skb->queue_mapping, so only priv_tx rides the cb. IP /
	 * qdisc / Grant-softirq can clobber cb between here and NIC TX, so
	 * homa_xmit_data re-stamps via smt_hw_attach_skb() before xmit.
	 */
	*((void **)(skb->cb + sizeof(skb->cb) - sizeof(void *))) =
		ctx_rpc_tx->driver_state;

	/* Advance our shadow rec_seq for the next record on this RPC. */
	smt_bigint_increment(ctx_rpc_tx->rec_seq,
			     TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	return 0;
}

/* Re-stamp the cb carrier just before NIC submission.
 *
 * smt_device_encrypt() writes priv_tx into the tail of skb->cb, but IP /
 * qdisc / Grant-driven softirq layers can overwrite skb->cb between encrypt
 * and the actual NIC TX. This re-applies (priv_tx, queue) so a deferred
 * Grant send reaches the NIC with intact crypto state.
 */
void smt_hw_attach_skb(struct homa_rpc *rpc, struct sk_buff *skb)
{
	struct smt_rpc_hw_context_tx *ctx_rpc_tx;
	void **cb_driver_state;

	if (!is_smt_rpc(rpc) || SMT_RPC(rpc)->ctx->tx_conf != SMT_HW)
		return;
	ctx_rpc_tx = smt_rpc_hw_tx(rpc);
	if (!ctx_rpc_tx || !ctx_rpc_tx->driver_state)
		return;

	skb->sk = &rpc->hsk->sock;
	skb_set_queue_mapping(skb, (u16)ctx_rpc_tx->queue_idx);
	cb_driver_state = (void **)(skb->cb + sizeof(skb->cb) - sizeof(void *));
	*cb_driver_state = ctx_rpc_tx->driver_state;
}

int smt_hw_set_offload_tx(struct homa_sock *hsk, struct smt_context *ctx)
{
	struct net_device *netdev;
	struct smt_hw_context_tx *offload_ctx;
	int rc;

	if (!ctx)
		return -EINVAL;

	netdev = dev_get_by_name(&init_net, hsk->homa->smt_hardware_interface);
	if (!netdev) {
		pr_err_ratelimited("%s: netdev %s not found\n",
				   __func__, hsk->homa->smt_hardware_interface);
		rc = -EINVAL;
		goto error;
	}
	smt_pr_info("%s: got netdev %s\n", __func__, netdev->name);

	if (!(netdev->features & NETIF_F_HW_TLS_TX)) {
		smt_pr_err("%s: netdev %s doesn't support TLS TX offload\n",
			   __func__, netdev->name);
		rc = -EOPNOTSUPP;
		goto release_netdev;
	}

	if (!(netdev->flags & IFF_UP)) {
		smt_pr_err("%s: device %s is down\n", __func__, netdev->name);
		rc = -EINVAL;
		goto release_netdev;
	}

	if (ctx->offload_tx) {
		rc = -EEXIST;
		goto release_netdev;
	}

	offload_ctx = kzalloc(sizeof(*offload_ctx), GFP_ATOMIC);
	if (!offload_ctx) {
		rc = -ENOMEM;
		goto release_netdev;
	}

	offload_ctx->netdev = netdev;
	offload_ctx->num_tx_queues = netdev->real_num_tx_queues;
	offload_ctx->nr_cpus = num_possible_cpus();

	offload_ctx->pools =
		kcalloc(offload_ctx->nr_cpus,
			sizeof(struct smt_hw_per_cpu_pool), GFP_ATOMIC);
	if (!offload_ctx->pools) {
		rc = -ENOMEM;
		goto free_offload_ctx;
	}
	for (int i = 0; i < offload_ctx->nr_cpus; i++) {
		struct smt_hw_per_cpu_pool *p = &offload_ctx->pools[i];

		/* "1UL << 64" is UB; build the all-ones mask for the
		 * SMT_TIS_PER_CPU low bits via GENMASK_ULL which handles
		 * the 64-bit edge case correctly.
		 */
		p->free = GENMASK_ULL(SMT_TIS_PER_CPU - 1, 0);
		mutex_init(&p->create_lock);
	}

	ctx->offload_tx = offload_ctx;
	ctx->tx_conf = SMT_HW;

	dev_put(netdev);
	return 0;

free_offload_ctx:
	kfree(offload_ctx);
	ctx->offload_tx = NULL;
release_netdev:
	dev_put(netdev);
error:
	if (!ctx->offload_tx)
		ctx->tx_conf = 0;
	return rc;
}

int smt_hw_init_rpc(struct homa_rpc *rpc)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_rpc_hw_context_tx *r = smt_rpc_hw_tx(rpc);

	BUILD_BUG_ON(sizeof(struct smt_rpc_hw_context_tx) >
		     sizeof(((struct smt_rpc *)0)->smt_rpc_crypto_tx));

	memset(r, 0, sizeof(*r));
	memcpy(r->rec_seq, ctx->aes_gcm_128_send.rec_seq,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	smt_pr_devel("%s: rpc=%lld rec_seq init from ctx\n",
		     __func__, rpc->id);
	return 0;
}

void smt_device_release_resources_tx(struct smt_context *ctx)
{
	struct smt_hw_context_tx *hw_ctx_tx =
		(struct smt_hw_context_tx *)ctx->offload_tx;
	struct net_device *netdev;

	if (!hw_ctx_tx)
		return;

	netdev = hw_ctx_tx->netdev;
	if (netdev && netdev->tlsdev_ops &&
	    netdev->tlsdev_ops->tls_dev_del && hw_ctx_tx->pools) {
		for (int cpu = 0; cpu < hw_ctx_tx->nr_cpus; cpu++) {
			for (int j = 0; j < SMT_TIS_PER_CPU; j++) {
				void *priv_tx = hw_ctx_tx->pools[cpu].slots[j].priv_tx;

				if (!priv_tx)
					continue;
				netdev->tlsdev_ops->tls_dev_del(
					netdev,
					(struct tls_context *)priv_tx,
					(enum tls_offload_ctx_dir)
						SMT_OFFLOAD_CTX_DIR_TX);
				hw_ctx_tx->pools[cpu].slots[j].priv_tx = NULL;
			}
		}
	}

	kfree(hw_ctx_tx->pools);
	kfree(hw_ctx_tx);
	ctx->offload_tx = NULL;
}

void smt_device_release_rpc_tx(struct homa_rpc *rpc)
{
	/* RPC tear-down: ensure the TIS slot is back in the pool. The
	 * caller may not have invoked smt_device_release_tis (e.g. error
	 * paths or RPCs that finish abnormally), so call it here as a
	 * safety net. Idempotent if already released.
	 */
	smt_device_release_tis(rpc);
}

#endif /* CONFIG_SMT_HW */
