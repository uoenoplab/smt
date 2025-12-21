#include "smt_impl.h"

struct kmem_cache *smt_ctx_kmem;

int smt_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen)
{
	struct homa_sock *hsk = homa_sk(sk);
	int rc = 0;

	if (level != SOL_TLS) {
		hsk->error_msg = "smt_setsockopt invoked with level not SOL_TLS";
		return 0;
	}

	switch (optname) {
	case TLS_TX:
	case TLS_RX:
		homa_sock_lock(hsk);
		if (hsk->shutdown) {
			homa_sock_unlock(hsk);
			return -ESHUTDOWN;
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
	int result = 0;
	hsk->smt = kmalloc(sizeof(struct smt_sock), GFP_KERNEL);
	if (!hsk->smt)
		return -ENOMEM;
	int i;
	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		INIT_HLIST_HEAD(&SMT_SOCK(hsk)->ctx_buckets[i]);
	}
	SMT_SOCK(hsk)->reuse_ctx = NULL;
	return result;
}

void smt_sock_shutdown(struct homa_sock *hsk)
{
	int i = 0;

	struct smt_context *ctx = NULL;
	for (; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		if (hlist_empty(&SMT_SOCK(hsk)->ctx_buckets[i]))
			continue;
		hlist_for_each_entry(ctx, &SMT_SOCK(hsk)->ctx_buckets[i], hlist) {
			// smt_ctx_destory(ctx);
		}
	}
}

int smt_load(struct homa *homa)
{
	pr_notice("SMT loading\n");
#ifdef SMT_NOCRYPTO
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
	if (smt_ctx_kmem)
		kmem_cache_destroy(smt_ctx_kmem);
	smt_ctx_kmem = NULL;
	return 0;
}
