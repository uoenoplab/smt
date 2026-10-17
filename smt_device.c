// SPDX-License-Identifier: GPL-2.0
/* SMT TX HW offload (mlx5 ktls). Compiled only when CONFIG_SMT_HW is set;
 * the Makefile drops smt_device.o from the build otherwise.
 *
 * Lifted, with light edits, from ~/repos/smt/module/smt_device.c. Kept
 * close to the original to preserve battle-tested control flow. The
 * difference vs the old module: driver_state (a TIS) lives in per-CPU pools
 * of SMT_TIS_PER_CPU slots, created lazily per slot; each RPC takes a slot
 * on its CPU when its message is copied in and returns it once the message
 * has been handed to the IP stack.
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
		if (test_and_clear_bit(i, pool->free))
			return i;
	}
	return -EAGAIN;
}

static void smt_hw_return_slot(struct smt_hw_per_cpu_pool *pool, int slot_idx)
{
	set_bit(slot_idx, pool->free);
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

	if (!ctx || !ctx->offload_tx)
		return;
	if (ctx_rpc_tx->slot_idx < 0)
		return;  /* already released (idempotent) */

	offload_ctx = (struct smt_hw_context_tx *)ctx->offload_tx;

	/* Return slot to its CPU's free pool, but KEEP driver_state set
	 * so a later peer-triggered RESEND can still re-attach to mlx5
	 * with this priv_tx. The TIS struct lives in the pool slot and
	 * persists across slot reuse (lazy-created once per slot for the
	 * socket's lifetime). If another RPC has claimed the slot in the
	 * meantime, mlx5 ktls' resync path handles the expected_seq
	 * mismatch at handle_tx_skb — both streams progress correctly.
	 */
	smt_hw_return_slot(&offload_ctx->pools[ctx_rpc_tx->home_cpu],
			   ctx_rpc_tx->slot_idx);
	ctx_rpc_tx->slot_idx = -1;
}

/* Hand priv_tx to the patched mlx5 TX hook via the tail of skb->cb, and pin
 * the skb to the TIS's TX queue. The NIC reads the TLS record seq from smt_h
 * in the linear part. Called as each packet is built, just before it goes to
 * the IP stack; driver_state is held for the RPC's lifetime (release_tis
 * keeps it), so grant-driven sends and resends reach the NIC with intact
 * crypto state.
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

		bitmap_fill(p->free, SMT_TIS_PER_CPU);
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
	struct smt_rpc_hw_context_tx *r = smt_rpc_hw_tx(rpc);

	BUILD_BUG_ON(sizeof(struct smt_rpc_hw_context_tx) >
		     sizeof(((struct smt_rpc *)0)->smt_rpc_crypto_tx));

	memset(r, 0, sizeof(*r));
	r->slot_idx = -1;  /* sentinel: no pool slot yet */
	smt_rpc_init_rec_seq(rpc, true, r->rec_seq);
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
