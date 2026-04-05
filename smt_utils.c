#include "smt_impl.h"

#include "homa_peer.h"

struct kmem_cache *smt_ctx_kmem;

static inline unsigned int smt_peer_mtu(struct homa_peer *peer,
					struct homa_sock *hsk)
{
	struct dst_entry *dst = rcu_dereference(peer->dst);

	if (likely(dst))
		return dst_mtu(dst);
	return dst_mtu(homa_get_dst(peer, hsk));
}

static inline uint32_t ms_rthash(const uint32_t addr, const uint16_t port)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; /* hash key */
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

static inline struct hlist_head *smt_ctx_bucket(struct homa_sock *hsk,
						uint32_t peer_addr,
						uint16_t peer_port)
{
	int bucket_id = ms_rthash(peer_addr, peer_port)
			& (HOMA_SERVER_RPC_BUCKETS - 1);
	return &SMT_SOCK(hsk)->ctx_buckets[bucket_id];
}

int __smt_sock_init(struct homa_sock *hsk, struct homa *homa)
{
	int i;

	hsk->smt = kmalloc(sizeof(struct smt_sock), GFP_KERNEL);
	if (!hsk->smt)
		return -ENOMEM;

	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++)
		INIT_HLIST_HEAD(&SMT_SOCK(hsk)->ctx_buckets[i]);

	SMT_SOCK(hsk)->reuse_ctx = NULL;
	return 0;
}

// hsk->smt is expected to be not NULL before call
static inline struct smt_context *smt_ctx_clone(struct homa_sock *hsk,
					 const uint32_t peer_addr,
					 const uint16_t peer_port,
					 struct hlist_head *bucket)
{
	struct smt_context *ctx, *reuse_ctx;

	if (!SMT_SOCK(hsk)->reuse_ctx)
		return NULL;
	reuse_ctx = SMT_SOCK(hsk)->reuse_ctx;

	ctx = kmem_cache_alloc(smt_ctx_kmem, GFP_ATOMIC);
	smt_pr_devel("%s ctx %px\n", __func__, ctx);
	if (!ctx) {
		smt_pr_err("%s smt_ctx_kmem alloc failed\n", __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	ctx->tx_conf = reuse_ctx->tx_conf;
	ctx->rx_conf = reuse_ctx->rx_conf;
	ctx->peer_addr = peer_addr;
	ctx->peer_port = peer_port;
	ctx->aes_gcm_128_send = reuse_ctx->aes_gcm_128_send;
	ctx->aes_gcm_128_recv = reuse_ctx->aes_gcm_128_recv;

	hlist_add_head(&ctx->hlist, bucket);

	return ctx;
}

static struct smt_context *smt_ctx_query(struct homa_sock *hsk,
					 const uint32_t peer_addr,
					 const uint16_t peer_port,
					 struct hlist_head *ctxs)
{
	struct smt_context *ctx = NULL;

	smt_pr_info("%s ctxs->first %px", __func__, ctxs->first);
	smt_pr_info("%s peer_addr %X peer_port %d\n", __func__,
		ntohl(peer_addr), (int)ntohs(peer_port));

	if (unlikely(hlist_empty(ctxs)))
		goto out;

	hlist_for_each_entry(ctx, ctxs, hlist) {
		if (ctx->peer_addr == peer_addr && ctx->peer_port == peer_port) {
			smt_pr_devel("%s ctx %px ctx->hlist.next %px\n",
				__func__, ctx, ctx->hlist.next);
			return ctx;
		}
	}

out:
	smt_pr_info("%s no match", __func__);
	return NULL;
}

static int smt_ctx_init(struct homa_sock *hsk,
			       struct smt_aes_gcm_128_info *crypto_info_optval,
			       struct smt_context *ctx, int tx)
{
	SMT_TRACE_FUNC_ENTER();
	struct tls12_crypto_info_aes_gcm_128 *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 *alt_crypto_info;

	int rc = 0;

	if (ctx == NULL) {
		rc = -EFAULT;
		goto out;
	}

	smt_pr_info("smt_setsockopt_conf invoked on Homa socket:"
			 "crypto_info_optval %px, ctx %px\n",
			 crypto_info_optval, ctx);

	crypto_info = tx ? &(ctx->aes_gcm_128_send) :
			   &(ctx->aes_gcm_128_recv);
	alt_crypto_info = !tx ? &(ctx->aes_gcm_128_send) :
				&(ctx->aes_gcm_128_recv);

	/* Currently we don't support set crypto info more than one time */
	if (TLS_CRYPTO_INFO_READY(&crypto_info->info)) {
		rc = -EBUSY;
		goto out;
	}

	/* Copy optval to smt_ctx */
	*crypto_info = crypto_info_optval->aes_gcm_128;

	/* Ensure that TLS verscopy_from_sockptrion and ciphers are same in both
	directions */
	if (TLS_CRYPTO_INFO_READY(&alt_crypto_info->info)) {
		if (alt_crypto_info->info.version !=
			    crypto_info->info.version ||
		    alt_crypto_info->info.cipher_type !=
			    crypto_info->info.cipher_type) {
			rc = -EINVAL;
			goto out;
		}
	}

	ctx->peer_addr = crypto_info_optval->smt.peer_addr;
	ctx->peer_port = crypto_info_optval->smt.peer_port;

	smt_pr_devel("%s crypto_info %px", __func__, crypto_info);
	smt_pr_devel("%s crypto_info->info.version 0x%04X \n", __func__,
			 crypto_info->info.version);
	smt_pr_devel("%s crypto_info->info.cipher_type %hu \n",
			 __func__, crypto_info->info.cipher_type);
	smt_pr_devel("%s alt_crypto_info %px", __func__, alt_crypto_info);
	smt_pr_devel("%s alt_crypto_info->info.version 0x%04X \n",
			 __func__, alt_crypto_info->info.version);
	smt_pr_devel("%s alt_crypto_info->info.cipher_type %hu \n",
			 __func__, alt_crypto_info->info.cipher_type);

	hexdump("smt_setsockopt_conf crypto_info->salt ", crypto_info->salt,
		sizeof(crypto_info->salt));
	hexdump("smt_setsockopt_conf crypto_info->iv ", crypto_info->iv,
		sizeof(crypto_info->iv));
	hexdump("smt_setsockopt_conf crypto_info->key ", crypto_info->key,
		sizeof(crypto_info->key));
	hexdump("smt_setsockopt_conf crypto_info->rec_seq ",
		crypto_info->rec_seq, sizeof(crypto_info->rec_seq));
	smt_pr_info("%s ctx->addr %X ctx->port %d\n", __func__,
		ntohl(ctx->peer_addr), (int) ntohs(ctx->peer_port));

out:
	return rc;
}

int smt_ctx_select(struct homa_sock *hsk, sockptr_t optval,
			      unsigned int optlen, int tx)
{
	int rc = 0;
	union smt_info_union crypto_info_optval;
	struct smt_context *ctx = NULL;

	size_t optsize;

	if (sockptr_is_null(optval)) {
		rc = -EINVAL;
		pr_warn("%s: optval is NULL)\n", __func__);
		goto out;
	}

	if (optlen < sizeof(crypto_info_optval.smt_tls)) {
		rc = -EINVAL;
		pr_warn("%s optval length is shorter than struct smt_crypto_info\n",
			__func__);
		goto out;
	}

	rc = copy_safe_from_sockptr(&crypto_info_optval,
		sizeof(crypto_info_optval.smt_tls), optval, optlen);
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	hexdump("smt_ctx_select received smt_info",
		(unsigned char *)&crypto_info_optval, optlen);

	// smt_pr_devel("%s crypto_info %px", __FUNCTION__, crypto_info_optval);
	smt_pr_devel("%s crypto_info->info.version 0x%04X \n", __FUNCTION__,
			 crypto_info_optval.smt_tls.tls.version);
	smt_pr_devel("%s crypto_info->info.cipher_type %hu \n",
			 __FUNCTION__, crypto_info_optval.smt_tls.tls.cipher_type);

	switch (crypto_info_optval.smt_tls.tls.version) {
	case TLS_1_2_VERSION:
		break;
	case TLS_1_3_VERSION:
		printk(KERN_WARNING "%s smt does not support TLS 1.3 yet\n",
		       __FUNCTION__);
		rc = -EINVAL;
		goto out;
	default:
		printk(KERN_WARNING "%s invalid TLS version %hu\n",
		       __FUNCTION__,
		       crypto_info_optval.smt_tls.tls.version);
		rc = -EINVAL;
		goto out;
	}

	switch (crypto_info_optval.smt_tls.tls.cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		optsize = sizeof(struct smt_aes_gcm_128_info);
		break;
	default:
		printk(KERN_WARNING
		       "%s smt only supports TLS_CIPHER_AES_GCM_128 now\n",
		       __FUNCTION__);
		rc = -EINVAL;
		goto out;
	}

	if (optlen != optsize) {
		rc = -EINVAL;
		printk(KERN_WARNING
		       "%s optval length is not correct, should be sizeof(struct"
			   " smt_crypto_info)\n", __FUNCTION__);
		goto out;
	} else {
		rc = copy_safe_from_sockptr(&crypto_info_optval, optsize,
			optval, optlen);
		if (rc) {
			rc = -EFAULT;
			goto out;
		}
	}

	struct hlist_head *bucket = smt_ctx_bucket(hsk,
		crypto_info_optval.smt.peer_addr,
		crypto_info_optval.smt.peer_port);

	ctx = smt_ctx_query(hsk, crypto_info_optval.smt.peer_addr,
		crypto_info_optval.smt.peer_port, bucket);

	if (!ctx) {
		ctx = kmem_cache_alloc(smt_ctx_kmem, GFP_ATOMIC);
		hlist_add_head(&ctx->hlist, bucket);
	}

	if ((crypto_info_optval.smt.peer_addr == 0)
			&& (crypto_info_optval.smt.peer_port == 0)) {
		SMT_SOCK(hsk)->reuse_ctx = ctx;
	}

	rc = smt_ctx_init(hsk, &crypto_info_optval.smt_aes_gcm_128, ctx, tx);
	if (rc)
		goto err_crypto_info;

	goto out;

err_crypto_info:
	hlist_del(&ctx->hlist);
	memzero_explicit(ctx, sizeof(*ctx));
	kmem_cache_free(smt_ctx_kmem, ctx);
out:
	return rc;
}

int smt_rpc_ctx_init(struct homa_sock *hsk, struct homa_rpc *rpc)
{
	uint32_t addr;
	uint16_t port;
	struct hlist_head* bucket;
	struct smt_context *ctx;
	int rc = 0;
	u64 __t;

	if (!hsk->smt)
		return 0;

	u64 __t2;

	__t = SMT_TIME_START();

	addr = ipv6_to_ipv4(rpc->peer->addr);
	port = htons(rpc->dport);
	bucket = smt_ctx_bucket(hsk, addr, port);

	__t2 = SMT_TIME_START();
	ctx = smt_ctx_query(hsk, addr, port, bucket);
	SMT_TIME_END(smt_ctx_query, __t2);

	if (ctx == NULL) {
		__t2 = SMT_TIME_START();
		ctx = smt_ctx_clone(rpc->hsk, addr, port, bucket);
		SMT_TIME_END(smt_ctx_clone, __t2);
	}
	if (IS_ERR(ctx)) {
		rc = PTR_ERR(ctx);
		goto out;
	}

	SMT_RPC(rpc)->ctx = ctx;

	__t2 = SMT_TIME_START();
	rcu_read_lock();
	SMT_RPC(rpc)->smt_max_pkt_data = smt_peer_mtu(rpc->peer, rpc->hsk)
		- rpc->hsk->ip_header_length - sizeof(struct homa_data_hdr);
	rcu_read_unlock();
	SMT_TIME_END(smt_ctx_dst_mtu, __t2);

// TODO: better error handle
out:
	SMT_TIME_END(smt_ctx_init, __t);
	return rc;
}
