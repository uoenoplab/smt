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
		rc = smt_ctx_select(hsk, optval, optlen,
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
#ifndef CONFIG_SMT_NOCRYPTO
			smt_sw_release_resources(ctx, 1);
			smt_sw_release_resources(ctx, 0);
#endif
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

	smt_ctx_kmem = kmem_cache_create("homa_smt_ctx",
			sizeof(struct smt_context), 0, SLAB_HWCACHE_ALIGN,
			NULL);
	if (!smt_ctx_kmem)
		return -ENOMEM;
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
#ifndef CONFIG_SMT_NOCRYPTO
	if (rpc->smt.ctx) {
		smt_sw_release_rpc(rpc, 1);
		smt_sw_release_rpc(rpc, 0);
	}
#endif
	rpc->smt.ctx = NULL;
}

// !!! TODO !!!
// homa_set_header() {
// 	// set gso offset
// }
