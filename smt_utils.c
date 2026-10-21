// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "smt_impl.h"

#include "homa_peer.h"

struct kmem_cache *smt_ctx_kmem;

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

	ctx = kmem_cache_zalloc(smt_ctx_kmem, GFP_ATOMIC);
	smt_pr_devel("%s ctx %px\n", __func__, ctx);
	if (!ctx) {
		smt_pr_err("%s smt_ctx_kmem alloc failed\n", __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

#ifndef CONFIG_SMT_NO_REPLAY_GUARD
	spin_lock_init(&ctx->replay.lock);
#endif
	ctx->tx_conf = reuse_ctx->tx_conf;
	ctx->rx_conf = reuse_ctx->rx_conf;
	ctx->peer_addr = peer_addr;
	ctx->peer_port = peer_port;
	ctx->crypto_send = reuse_ctx->crypto_send;
	ctx->crypto_recv = reuse_ctx->crypto_recv;

	/* This runs in atomic context (softirq for a server RPC), where no
	 * tfm can be allocated, and the clone has the wildcard's keys: share
	 * the wildcard's SW crypto pools.
	 */
	if (ctx->tx_conf == SMT_SW)
		ctx->offload_tx = smt_sw_ctx_get(reuse_ctx->offload_tx);
	if (ctx->rx_conf == SMT_SW)
		ctx->offload_rx = smt_sw_ctx_get(reuse_ctx->offload_rx);

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

static int smt_ctx_init(struct homa_sock *hsk, const struct smt_info *peer,
			const union tls_crypto_context *info,
			struct smt_context *ctx, int tx,
			struct smt_sw_context **sw)
{
	union tls_crypto_context *crypto_info = tx ? &ctx->crypto_send :
						     &ctx->crypto_recv;
	union tls_crypto_context *alt_crypto_info = tx ? &ctx->crypto_recv :
							 &ctx->crypto_send;
	int rc = 0;

	SMT_TRACE_FUNC_ENTER();

	/* Currently we don't support set crypto info more than one time */
	if (TLS_CRYPTO_INFO_READY(&crypto_info->info)) {
		rc = -EBUSY;
		goto out;
	}

	/* Both directions use the same TLS version and cipher. */
	if (TLS_CRYPTO_INFO_READY(&alt_crypto_info->info) &&
	    (alt_crypto_info->info.version != info->info.version ||
	     alt_crypto_info->info.cipher_type != info->info.cipher_type)) {
		rc = -EINVAL;
		goto out;
	}

	*crypto_info = *info;
	ctx->peer_addr = peer->peer_addr;
	ctx->peer_port = peer->peer_port;

	smt_hexdump("smt_ctx_init key ", smt_crypto_key(info),
		    smt_crypto_key_size(info));
	smt_pr_info("%s ctx->addr %X ctx->port %d version 0x%04x cipher %u\n",
		    __func__, ntohl(ctx->peer_addr), (int)ntohs(ctx->peer_port),
		    info->info.version, info->info.cipher_type);

#ifdef CONFIG_SMT_NOCRYPTO
	goto out;
#endif

	if (tx && !ctx->offload_tx) {
		ctx->tx_conf = SMT_SW;
		ctx->offload_tx = *sw;
		*sw = NULL;
	}

	if (!tx && !ctx->offload_rx) {
		ctx->rx_conf = SMT_SW;
		ctx->offload_rx = *sw;
		*sw = NULL;
	}

out:
	return rc;
}

/**
 * smt_ctx_install() - Install one direction's key for a peer on a socket.
 * May sleep.
 * @hsk:   The socket.
 * @peer:  The peer's address and port (network order); both 0 for a key
 *         that serves every peer without one of its own.
 * @info:  The key, version and cipher already checked.
 * @tx:    Nonzero for the sending direction.
 * Return: 0 or a negative errno.
 */
static int smt_ctx_install(struct homa_sock *hsk, const struct smt_info *peer,
			   const union tls_crypto_context *info, int tx)
{
	struct smt_sw_context *sw = NULL;
	struct smt_context *ctx;
	struct hlist_head *bucket;
	struct smt_sock *smt;
	bool created = false;
	int rc;

	/* Everything that may sleep happens before taking the socket lock. */
	smt = kzalloc(sizeof(*smt), GFP_KERNEL);
	if (!smt)
		return -ENOMEM;
#ifndef CONFIG_SMT_NOCRYPTO
	sw = smt_sw_ctx_alloc(info, hsk->homa->smt_sw_pool_init);
	if (IS_ERR(sw)) {
		kfree(smt);
		return PTR_ERR(sw);
	}
#endif

	homa_sock_lock(hsk);
	if (!hsk->smt) {
		hsk->smt = smt;
		smt = NULL;
	}
	bucket = smt_ctx_bucket(hsk, peer->peer_addr, peer->peer_port);
	ctx = smt_ctx_query(hsk, peer->peer_addr, peer->peer_port, bucket);
	if (!ctx) {
		ctx = kmem_cache_zalloc(smt_ctx_kmem, GFP_ATOMIC);
		if (!ctx) {
			rc = -ENOMEM;
			goto unlock;
		}
#ifndef CONFIG_SMT_NO_REPLAY_GUARD
		spin_lock_init(&ctx->replay.lock);
#endif
		hlist_add_head(&ctx->hlist, bucket);
		created = true;
	}

	rc = smt_ctx_init(hsk, peer, info, ctx, tx, &sw);
	if (rc) {
		/* A ctx that existed before may be in use by RPCs. */
		if (created) {
			hlist_del(&ctx->hlist);
			memzero_explicit(ctx, sizeof(*ctx));
			kmem_cache_free(smt_ctx_kmem, ctx);
		}
		goto unlock;
	}

	if (!peer->peer_addr && !peer->peer_port) {
		if (SMT_SOCK(hsk)->reuse_ctx
		    && SMT_SOCK(hsk)->reuse_ctx != ctx)
			smt_pr_err("%s: reuse_ctx changing %px -> %px\n",
				   __func__, SMT_SOCK(hsk)->reuse_ctx, ctx);
		SMT_SOCK(hsk)->reuse_ctx = ctx;
	}

unlock:
	homa_sock_unlock(hsk);
	/* Whatever the socket and the ctx did not take. */
	kfree(smt);
	smt_sw_ctx_put(sw);
	return rc;
}

int smt_ctx_setup(struct homa_sock *hsk, sockptr_t optval,
			      unsigned int optlen, int tx)
{
	int rc = 0;
	union smt_info_union crypto_info_optval;
	union tls_crypto_context info = {};
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

	smt_hexdump("smt_ctx_setup received smt_info",
		    (unsigned char *)&crypto_info_optval, optlen);

	smt_pr_devel("%s crypto_info->info.version 0x%04X \n", __FUNCTION__,
			 crypto_info_optval.smt_tls.tls.version);
	smt_pr_devel("%s crypto_info->info.cipher_type %hu \n",
			 __FUNCTION__, crypto_info_optval.smt_tls.tls.cipher_type);

	switch (crypto_info_optval.smt_tls.tls.version) {
	case TLS_1_2_VERSION:
	case TLS_1_3_VERSION:
		break;
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
	case TLS_CIPHER_AES_GCM_256:
		optsize = sizeof(struct smt_aes_gcm_256_info);
		break;
	default:
		printk(KERN_WARNING
		       "%s smt only supports AES-GCM-128 and AES-GCM-256\n",
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

	memcpy(&info, &crypto_info_optval.smt_tls.tls,
	       optsize - sizeof(struct smt_info));
	/* TLS 1.2 records carry their sequence number as the explicit nonce
	 * (see smt_rpc_init_rec_seq), so iv must equal rec_seq.
	 */
	if (info.info.version == TLS_1_2_VERSION &&
	    memcmp(smt_crypto_iv(&info), smt_crypto_rec_seq(&info),
		   TLS_CIPHER_AES_GCM_128_IV_SIZE)) {
		rc = -EINVAL;
		goto out;
	}

	return smt_ctx_install(hsk, &crypto_info_optval.smt, &info, tx);
out:
	return rc;
}

/* The key net.homa.smt_fixed_key gives every new socket, for measuring
 * without a handshake: it is in the source, so it protects nothing.
 */
static const u8 smt_fixed_key[TLS_CIPHER_AES_GCM_128_KEY_SIZE] = {
	0x53, 0x4d, 0x54, 0x2d, 0x4e, 0x47, 0x20, 0x74,
	0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, 0x21,	/* "SMT-NG test key!" */
};

/**
 * smt_fixed_key_install() - Give @hsk the fixed AES-GCM-128 key in both
 * directions for every peer, salt and IV 0. May sleep.
 * @hsk:      The socket.
 * @version:  TLS_1_2_VERSION or TLS_1_3_VERSION.
 * Return: 0 or a negative errno.
 */
int smt_fixed_key_install(struct homa_sock *hsk, u16 version)
{
	static const struct smt_info any_peer;
	union tls_crypto_context info = {};
	int rc;

	info.aes_gcm_128.info.version = version;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memcpy(info.aes_gcm_128.key, smt_fixed_key, sizeof(smt_fixed_key));
	rc = smt_ctx_install(hsk, &any_peer, &info, 1);
	if (!rc)
		rc = smt_ctx_install(hsk, &any_peer, &info, 0);
	return rc;
}

int smt_rpc_ctx_init(struct homa_sock *hsk, struct homa_rpc *rpc)
{
	uint32_t addr;
	uint16_t port;
	struct hlist_head* bucket;
	struct smt_context *ctx;
	bool tls13;
	int rc = 0;

	if (!hsk->smt)
		return 0;

	addr = ipv6_to_ipv4(rpc->route->peer->addr);
	port = htons(rpc->dport);
	bucket = smt_ctx_bucket(hsk, addr, port);

	ctx = smt_ctx_query(hsk, addr, port, bucket);

	if (ctx == NULL)
		ctx = smt_ctx_clone(rpc->hsk, addr, port, bucket);
	/* NULL: no key for this peer and no wildcard to clone from. */
	if (IS_ERR_OR_NULL(ctx)) {
		rc = PTR_ERR_OR_ZERO(ctx);
		goto out;
	}
#ifndef CONFIG_SMT_NOCRYPTO
	/* An RPC both sends and receives: without the RX key smt_sw_decrypt
	 * has no crypto pool, and without the TX key the message would leave
	 * in clear.
	 */
	if (ctx->tx_conf == SMT_BASE || ctx->rx_conf == SMT_BASE) {
		rc = -ENOKEY;
		goto out;
	}
#endif
	/* Every direction that has a key uses one version (smt_ctx_init). */
	tls13 = ctx->crypto_send.info.version == TLS_1_3_VERSION ||
		ctx->crypto_recv.info.version == TLS_1_3_VERSION;
	SMT_RPC(rpc)->rec_pre = TLS_HEADER_SIZE +
				(tls13 ? 0 : TLS_CIPHER_AES_GCM_128_IV_SIZE);
	SMT_RPC(rpc)->rec_post = TLS_CIPHER_AES_GCM_128_TAG_SIZE + tls13;

	SMT_RPC(rpc)->ctx = ctx;
	SMT_RPC(rpc)->decrypt_offset = 0;

	/* Must match the sender's msgout.max_seg_data (symmetric MTU). */
	rcu_read_lock();
	SMT_RPC(rpc)->smt_max_pkt_data =
		dst_mtu(rcu_dereference(rpc->route->dst)) -
		rpc->hsk->ip_header_length - sizeof(struct homa_data_hdr);
	rcu_read_unlock();

	if (ctx->tx_conf == SMT_SW)
		smt_sw_init_rpc(rpc, 1);
	if (ctx->rx_conf == SMT_SW)
		smt_sw_init_rpc(rpc, 0);

out:
	return rc;
}
