#include "smt_plumbing.h"
#include "smt_impl.h"

/*
 * SMT profiling is now integrated into Homa's per-CPU metrics system.
 * See homa_metrics.h for smt_*_calls/cycles fields.
 * Use SMT_TIME_START()/SMT_TIME_END() macros from smt_plumbing.h.
 */

inline struct homa_smt_padding_info smt_get_padding_info(void)
{
	struct homa_smt_padding_info padding = {
		.hdr_len = SMT_RECORD_EXTRA_PRE_LENGTH,
		.trl_len = SMT_RECORD_EXTRA_POST_LENGTH
	};
	return padding;
}

int smt_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen)
{
	struct homa_sock *hsk = homa_sk(sk);
	int rc = 0;

	switch (optname) {
	case TLS_TX:
	case TLS_RX:
		homa_sock_lock(hsk);
		if (!hsk->smt) {
			rc = __smt_sock_init(hsk, hsk->homa);
			if (rc) {
				homa_sock_unlock(hsk);
				return rc;
			}
		}
		rc = smt_ctx_setup(hsk, optval, optlen,
						  optname == TLS_TX);
		homa_sock_unlock(hsk);
		break;
	default:
		rc = -ENOPROTOOPT;
		break;
	}
	return rc;
}

int smt_sock_init(struct homa_sock *hsk, struct homa *homa)
{
	// Actual SMT socket initialization is performed until smt_setsockopt
	// with __smt_sock_init
	hsk->smt = NULL;
	return 0;
}

void smt_sock_destroy(struct homa_sock *hsk)
{
	int i = 0;

	struct smt_context *ctx = NULL;
	if (!hsk->smt)
		return;
	for (; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		if (hlist_empty(&SMT_SOCK(hsk)->ctx_buckets[i]))
			continue;
		hlist_for_each_entry(ctx, &SMT_SOCK(hsk)->ctx_buckets[i], hlist) {
#ifdef CONFIG_SMT_HW
			if (ctx->tx_conf == SMT_HW)
				smt_device_release_resources_tx(ctx);
#endif
			if (ctx->tx_conf == SMT_SW)
				smt_sw_release_resources(ctx, 1);
			if (ctx->rx_conf == SMT_SW)
				smt_sw_release_resources(ctx, 0);
			smt_ctx_destory(ctx);
		}
	}
	kfree(hsk->smt);
	hsk->smt = NULL;
}

int smt_load(struct homa *homa)
{
	pr_notice("SMT loading\n");
#ifdef CONFIG_SMT_NOCRYPTO
	pr_notice("SMT compiled without actual encrypt/decrypt, only for test\n");
#endif

	homa->smt_sw_pool_init = 4;

#ifdef CONFIG_SMT_HW
	homa->smt_hardware_state_threshold = 1;
	strscpy(homa->smt_hardware_interface, "ens1f1np1",
		sizeof(homa->smt_hardware_interface));
#endif /* CONFIG_SMT_HW */

	smt_ctx_kmem = kmem_cache_create("homa_smt_ctx",
			sizeof(struct smt_context), 0, SLAB_HWCACHE_ALIGN,
			NULL);
	if (!smt_ctx_kmem)
		return -ENOMEM;
	return 0;
}

int smt_encrypt(struct homa_rpc *rpc, struct sk_buff *skb, u8 *smt_h,
		int payload_len)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;

#ifdef CONFIG_SMT_HW
	if (ctx->tx_conf == SMT_HW) {
		int err;

		if (rpc->msgout.num_skbs == 0) {
			err = smt_device_set_crypto_tx(rpc);
			if (err)
				return err;
		}
		return smt_device_encrypt(rpc, smt_h, NULL, skb);
	}
#endif
	if (ctx->tx_conf == SMT_SW)
		return smt_sw_encrypt(rpc, skb, smt_h, payload_len);
	return 0;
}

int smt_unload(void)
{
	/* SMT profiling metrics are now exported via /proc/net/homa_metrics */
	pr_info("SMT unloading (metrics available in /proc/net/homa_metrics)\n");
	if (smt_ctx_kmem)
		kmem_cache_destroy(smt_ctx_kmem);
	smt_ctx_kmem = NULL;
	return 0;
}

int smt_rpc_alloc_client_sock_lock(struct homa_sock *hsk, struct homa_rpc *rpc)
{
	return smt_rpc_ctx_init(hsk, rpc);
}


void smt_rpc_release(struct homa_rpc *rpc)
{
	if (!rpc->smt.ctx)
		return;

#ifdef CONFIG_SMT_HW
	if (rpc->smt.ctx->tx_conf == SMT_HW)
		smt_device_release_rpc_tx(rpc);
#endif

	rpc->smt.ctx = NULL;
}

// !!! TODO !!!
// homa_set_header() {
// 	// set gso offset
// }
