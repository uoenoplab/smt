// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "smt_plumbing.h"
#include "smt_impl.h"

int smt_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen)
{
	struct homa_sock *hsk = homa_sk(sk);
	int rc = 0;

	switch (optname) {
	case TLS_TX:
	case TLS_RX:
		rc = smt_ctx_setup(hsk, optval, optlen, optname == TLS_TX);
		break;
	default:
		rc = -ENOPROTOOPT;
		break;
	}
	return rc;
}

int smt_sock_init(struct homa_sock *hsk, struct homa *homa)
{
	/* Keys normally come from setsockopt (smt_ctx_setup). */
	hsk->smt = NULL;
	switch (homa->smt_fixed_key) {
	case 12:
		return smt_fixed_key_install(hsk, TLS_1_2_VERSION);
	case 13:
		return smt_fixed_key_install(hsk, TLS_1_3_VERSION);
	}
	return 0;
}

void smt_sock_destroy(struct homa_sock *hsk)
{
	struct smt_context *ctx;
	struct hlist_node *tmp;
	int i;

	if (!hsk->smt)
		return;
	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		hlist_for_each_entry_safe(ctx, tmp, &SMT_SOCK(hsk)->ctx_buckets[i],
					  hlist) {
			if (ctx->tx_conf == SMT_SW)
				smt_sw_ctx_put(ctx->offload_tx);
			if (ctx->rx_conf == SMT_SW)
				smt_sw_ctx_put(ctx->offload_rx);
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
	smt_ctx_kmem = kmem_cache_create("homa_smt_ctx",
			sizeof(struct smt_context), 0, SLAB_HWCACHE_ALIGN,
			NULL);
	if (!smt_ctx_kmem)
		return -ENOMEM;
	return 0;
}

int smt_unload(void)
{
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
	rpc->smt.ctx = NULL;
}
