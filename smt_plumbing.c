#include "smt_plumbing.h"
#include "smt_impl.h"

//TODO better name - all I want is just a better name, give me one
// this is a struct that homa can use to extra basic info about how to reserve padding etc for tx
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

void smt_sock_shutdown(struct homa_sock *hsk)
{
	int i = 0;

	struct smt_context *ctx = NULL;
	if (!hsk->smt)
		return;
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
	if (smt_ctx_kmem)
		kmem_cache_destroy(smt_ctx_kmem);
	smt_ctx_kmem = NULL;
	return 0;
}

// homa_set_header() {
// 	// set doff
// 	// set gso offset
// 	// revise homa_info->wire_bytes
// 	// return trailer only or not?
// }
