// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "smt_impl.h"

#include "homa_peer.h"

struct kmem_cache *smt_ctx_kmem;
struct workqueue_struct *smt_wq;

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

#ifndef CONFIG_SMT_NO_REPLAY_GUARD
static void smt_replay_put(struct smt_replay_window *w)
{
	if (w && refcount_dec_and_test(&w->refs))
		kfree(w);
}
#endif

static void smt_ctx_free(struct work_struct *work)
{
	struct smt_context *ctx = container_of(work, struct smt_context,
					       free_work);

	if (ctx->tx_conf == SMT_SW)
		smt_sw_ctx_put(ctx->offload_tx);
	if (ctx->rx_conf == SMT_SW)
		smt_sw_ctx_put(ctx->offload_rx);
#ifndef CONFIG_SMT_NO_REPLAY_GUARD
	smt_replay_put(ctx->replay);
#endif
	memzero_explicit(ctx, sizeof(*ctx));
	kmem_cache_free(smt_ctx_kmem, ctx);
}

/**
 * smt_ctx_put() - Drop a reference to a ctx. The last RPC can let go in
 * softirq (homa_dispatch_pkts reaps), so the free, which frees crypto
 * transforms, runs from smt_wq.
 * @ctx:  The ctx.
 */
void smt_ctx_put(struct smt_context *ctx)
{
	if (refcount_dec_and_test(&ctx->refs))
		queue_work(smt_wq, &ctx->free_work);
}

/* A ctx for a peer, without keys, holding the reference of the socket's
 * table; NULL if out of memory.
 */
static struct smt_context *smt_ctx_alloc(u32 peer_addr, u16 peer_port,
					 gfp_t gfp)
{
	struct smt_context *ctx = kmem_cache_zalloc(smt_ctx_kmem, gfp);

	if (!ctx)
		return NULL;
#ifndef CONFIG_SMT_NO_REPLAY_GUARD
	ctx->replay = kzalloc(sizeof(*ctx->replay), gfp);
	if (!ctx->replay) {
		kmem_cache_free(smt_ctx_kmem, ctx);
		return NULL;
	}
	spin_lock_init(&ctx->replay->lock);
	refcount_set(&ctx->replay->refs, 1);
#endif
	ctx->peer_addr = peer_addr;
	ctx->peer_port = peer_port;
	refcount_set(&ctx->refs, 1);
	ctx->last_use = jiffies;
	INIT_WORK(&ctx->free_work, smt_ctx_free);
	return ctx;
}

/* Take a ctx out of the socket's table and drop the table's reference.
 * Called with the socket locked.
 */
static void smt_ctx_unhash(struct homa_sock *hsk, struct smt_context *ctx)
{
	hlist_del(&ctx->hlist);
	if (SMT_SOCK(hsk)->reuse_ctx == ctx)
		SMT_SOCK(hsk)->reuse_ctx = NULL;
	smt_ctx_put(ctx);
}

/* A ctx with the built-in key (SMT_DEBUG_FIXED_KEY) for a peer without
 * keys of its own, added to @bucket; NULL if the socket has no built-in
 * key.
 */
static struct smt_context *smt_ctx_clone(struct homa_sock *hsk,
					 const uint32_t peer_addr,
					 const uint16_t peer_port,
					 struct hlist_head *bucket)
{
	struct smt_context *ctx, *reuse_ctx = SMT_SOCK(hsk)->reuse_ctx;

	if (!reuse_ctx)
		return NULL;
	ctx = smt_ctx_alloc(peer_addr, peer_port, GFP_ATOMIC);
	if (!ctx) {
		smt_pr_err("%s smt_ctx_kmem alloc failed\n", __func__);
		return ERR_PTR(-ENOMEM);
	}
	ctx->tx_conf = reuse_ctx->tx_conf;
	ctx->rx_conf = reuse_ctx->rx_conf;
	ctx->crypto_send = reuse_ctx->crypto_send;
	ctx->crypto_recv = reuse_ctx->crypto_recv;

	/* This runs in atomic context (softirq for a server RPC), where no
	 * tfm can be allocated, and the clone has the built-in key: share
	 * the SW crypto pools of the built-in key.
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

/* Set one direction's key in @ctx, which has none for it; *@sw becomes its
 * SW crypto pool.
 */
static int smt_ctx_init(const union tls_crypto_context *info,
			struct smt_context *ctx, int tx,
			struct smt_sw_context **sw)
{
	union tls_crypto_context *crypto_info = tx ? &ctx->crypto_send :
						     &ctx->crypto_recv;
	union tls_crypto_context *alt_crypto_info = tx ? &ctx->crypto_recv :
							 &ctx->crypto_send;

	SMT_TRACE_FUNC_ENTER();

	/* Both directions use the same TLS version and cipher. */
	if (TLS_CRYPTO_INFO_READY(&alt_crypto_info->info) &&
	    (alt_crypto_info->info.version != info->info.version ||
	     alt_crypto_info->info.cipher_type != info->info.cipher_type))
		return -EINVAL;

	*crypto_info = *info;

	smt_hexdump("smt_ctx_init key ", smt_crypto_key(info),
		    smt_crypto_key_size(info));
	smt_pr_info("%s ctx->addr %X ctx->port %d version 0x%04x cipher %u\n",
		    __func__, ntohl(ctx->peer_addr), (int)ntohs(ctx->peer_port),
		    info->info.version, info->info.cipher_type);

#ifndef CONFIG_SMT_NOCRYPTO
	if (tx) {
		ctx->tx_conf = SMT_SW;
		ctx->offload_tx = *sw;
	} else {
		ctx->rx_conf = SMT_SW;
		ctx->offload_rx = *sw;
	}
	*sw = NULL;
#endif
	return 0;
}

/* Give @nctx, which replaces @old, the key of the direction that stays
 * (@tx: the TX key is replaced). A kept RX key keeps its replay window: it
 * records the requests that key authenticated.
 */
static void smt_ctx_carry(struct smt_context *nctx, struct smt_context *old,
			  int tx)
{
	if (tx) {
		nctx->rx_conf = old->rx_conf;
		nctx->crypto_recv = old->crypto_recv;
		if (old->rx_conf == SMT_SW)
			nctx->offload_rx = smt_sw_ctx_get(old->offload_rx);
#ifndef CONFIG_SMT_NO_REPLAY_GUARD
		smt_replay_put(nctx->replay);
		nctx->replay = old->replay;
		refcount_inc(&nctx->replay->refs);
#endif
	} else {
		nctx->tx_conf = old->tx_conf;
		nctx->crypto_send = old->crypto_send;
		if (old->tx_conf == SMT_SW)
			nctx->offload_tx = smt_sw_ctx_get(old->offload_tx);
	}
}

/**
 * smt_ctx_install() - Install one direction's key for a peer on a socket.
 * A key that replaces one goes into a new ctx, with the other direction's
 * key: the RPCs already using the old ctx finish with its keys. May sleep.
 * @hsk:   The socket.
 * @peer:  The peer's address and port (network order). Both 0 only for
 *         the built-in key (smt_fixed_key_setup), which serves every peer
 *         without a key of its own.
 * @info:  The key, version and cipher already checked.
 * @tx:    Nonzero for the sending direction.
 * Return: 0 or a negative errno.
 */
static int smt_ctx_install(struct homa_sock *hsk, const struct smt_info *peer,
			   const union tls_crypto_context *info, int tx)
{
	struct smt_context *ctx, *nctx, *drop;
	struct smt_sw_context *sw = NULL;
	struct hlist_head *bucket;
	struct smt_sock *smt;
	int rc = -ENOMEM;

	/* Everything that may sleep happens before taking the socket lock. */
	smt = kzalloc(sizeof(*smt), GFP_KERNEL);
	nctx = smt_ctx_alloc(peer->peer_addr, peer->peer_port, GFP_KERNEL);
	drop = nctx;
	if (!smt || !nctx)
		goto out;
#ifndef CONFIG_SMT_NOCRYPTO
	sw = smt_sw_ctx_alloc(info, hsk->homa->smt_sw_pool_init);
	if (IS_ERR(sw)) {
		rc = PTR_ERR(sw);
		sw = NULL;
		goto out;
	}
#endif

	homa_sock_lock(hsk);
	if (!hsk->smt) {
		hsk->smt = smt;
		smt = NULL;
	}
	bucket = smt_ctx_bucket(hsk, peer->peer_addr, peer->peer_port);
	ctx = smt_ctx_query(hsk, peer->peer_addr, peer->peer_port, bucket);
	if (ctx && !TLS_CRYPTO_INFO_READY(tx ? &ctx->crypto_send.info :
					       &ctx->crypto_recv.info)) {
		/* The first key for this direction: no RPC uses a ctx
		 * without both (smt_rpc_ctx_init), so it goes in place.
		 */
		rc = smt_ctx_init(info, ctx, tx, &sw);
		goto unlock;
	}
	if (ctx)
		smt_ctx_carry(nctx, ctx, tx);
	rc = smt_ctx_init(info, nctx, tx, &sw);
	if (rc)
		goto unlock;
	if (ctx)
		smt_ctx_unhash(hsk, ctx);
	hlist_add_head(&nctx->hlist, bucket);
	if (!peer->peer_addr && !peer->peer_port)
		SMT_SOCK(hsk)->reuse_ctx = nctx;
	drop = NULL;

unlock:
	homa_sock_unlock(hsk);
out:
	/* Whatever the socket and its table did not take. */
	kfree(smt);
	smt_sw_ctx_put(sw);
	if (drop)
		smt_ctx_put(drop);
	return rc;
}

/**
 * smt_ctx_delete() - Delete a socket's keys for one peer (SMT_KEY_DEL).
 * RPCs already using them finish with them; a new RPC with the peer fails
 * with ENOKEY, or uses the built-in key.
 * @hsk:     The socket.
 * @optval:  struct smt_info: the peer's address and port (network order).
 * @optlen:  sizeof(struct smt_info).
 * Return: 0, -ENOENT if the socket has no keys for the peer, or another
 * negative errno.
 */
int smt_ctx_delete(struct homa_sock *hsk, sockptr_t optval,
		   unsigned int optlen)
{
	struct smt_context *ctx = NULL;
	struct smt_info peer;

	if (optlen != sizeof(peer))
		return -EINVAL;
	if (copy_from_sockptr(&peer, optval, sizeof(peer)))
		return -EFAULT;
	if (!peer.peer_addr && !peer.peer_port)
		return -EINVAL;
	homa_sock_lock(hsk);
	if (hsk->smt) {
		ctx = smt_ctx_query(hsk, peer.peer_addr, peer.peer_port,
				    smt_ctx_bucket(hsk, peer.peer_addr,
						   peer.peer_port));
		if (ctx)
			smt_ctx_unhash(hsk, ctx);
	}
	homa_sock_unlock(hsk);
	return ctx ? 0 : -ENOENT;
}

/**
 * smt_gc_due() - Whether the Homa timer calls smt_ctx_gc for each socket
 * on this tick: about once a second, when net.homa.smt_key_idle_secs is
 * set. Called by the timer thread only.
 * @homa:  Overall data about the Homa protocol implementation.
 * Return: true if it is time.
 */
bool smt_gc_due(struct homa *homa)
{
	static unsigned long next;

	if (!READ_ONCE(homa->smt_key_idle_secs) || time_before(jiffies, next))
		return false;
	next = jiffies + HZ;
	return true;
}

/**
 * smt_ctx_gc() - Delete the keys of a socket that no RPC has used for
 * net.homa.smt_key_idle_secs (see smt_gc_due).
 * @hsk:  The socket; not locked.
 */
void smt_ctx_gc(struct homa_sock *hsk)
{
	unsigned long idle = HZ *
		(unsigned long)READ_ONCE(hsk->homa->smt_key_idle_secs);
	struct smt_context *ctx;
	struct hlist_node *tmp;
	int i;

	if (!hsk->smt)
		return;
	/* A dead RPC holds its ctx until it is reaped, and Homa reaps
	 * lazily: an idle socket can keep its last RPCs for good.
	 */
	while (homa_rpc_reap(hsk))
		;
	homa_sock_lock(hsk);
	if (hsk->shutdown || !hsk->smt)
		goto unlock;
	for (i = 0; i < HOMA_SERVER_RPC_BUCKETS; i++)
		hlist_for_each_entry_safe(ctx, tmp,
					  &SMT_SOCK(hsk)->ctx_buckets[i], hlist)
			/* With the socket locked no RPC can take it, so the
			 * table's reference alone means that no RPC uses it.
			 * RPCs use clones of the built-in key, which stays.
			 */
			if (ctx != SMT_SOCK(hsk)->reuse_ctx &&
			    refcount_read(&ctx->refs) == 1 &&
			    time_after(jiffies, ctx->last_use + idle))
				smt_ctx_unhash(hsk, ctx);
unlock:
	homa_sock_unlock(hsk);
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

	/* A key from user space is for one peer (from a handshake). */
	if (!crypto_info_optval.smt.peer_addr &&
	    !crypto_info_optval.smt.peer_port) {
		rc = -EINVAL;
		goto out;
	}
	return smt_ctx_install(hsk, &crypto_info_optval.smt, &info, tx);
out:
	return rc;
}

/* The built-in key of SMT_DEBUG_FIXED_KEY, for measuring without a
 * handshake: it is in the source, so it protects nothing. AES-GCM-128 takes
 * the first 16 bytes.
 */
static const u8 smt_fixed_key[TLS_CIPHER_AES_GCM_256_KEY_SIZE] = {
	0x53, 0x4d, 0x54, 0x2d, 0x4e, 0x47, 0x20, 0x74,
	0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, 0x21,	/* "SMT-NG test key!" */
	0x53, 0x4d, 0x54, 0x2d, 0x4e, 0x47, 0x20, 0x74,
	0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, 0x21,	/* twice */
};

/**
 * smt_fixed_key_setup() - SMT_DEBUG_FIXED_KEY: give @hsk the built-in key
 * in both directions for every peer without a key of its own, salt and IV
 * 0. May sleep.
 * @hsk:     The socket.
 * @optval:  struct tls_crypto_info: TLS_1_2_VERSION or TLS_1_3_VERSION,
 *           TLS_CIPHER_AES_GCM_128 or TLS_CIPHER_AES_GCM_256.
 * @optlen:  sizeof(struct tls_crypto_info).
 * Return: 0, -EPERM unless net.homa.debug_only_smt_fixed_key is set, or
 * another negative errno: -EINVAL for a version or cipher other than that
 * of the socket's built-in key (smt_ctx_init).
 */
int smt_fixed_key_setup(struct homa_sock *hsk, sockptr_t optval,
			unsigned int optlen)
{
	static const struct smt_info any_peer;
	union tls_crypto_context info = {};
	int rc;

	if (!READ_ONCE(hsk->homa->debug_only_smt_fixed_key))
		return -EPERM;
	if (optlen != sizeof(info.info))
		return -EINVAL;
	if (copy_from_sockptr(&info.info, optval, sizeof(info.info)))
		return -EFAULT;
	if (info.info.version != TLS_1_2_VERSION &&
	    info.info.version != TLS_1_3_VERSION)
		return -EINVAL;
	switch (info.info.cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		memcpy(info.aes_gcm_128.key, smt_fixed_key,
		       TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		break;
	case TLS_CIPHER_AES_GCM_256:
		memcpy(info.aes_gcm_256.key, smt_fixed_key,
		       TLS_CIPHER_AES_GCM_256_KEY_SIZE);
		break;
	default:
		return -EINVAL;
	}
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
	/* NULL: no key for this peer (and no built-in key to clone). A
	 * socket with keys talks with no peer in clear.
	 */
	if (IS_ERR_OR_NULL(ctx)) {
		rc = ctx ? PTR_ERR(ctx) : -ENOKEY;
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

	refcount_inc(&ctx->refs);
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
