/* Copyright (c) 2022-2025, Tianyi Gao, University of Edinburgh
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "smt_impl.h"

struct kmem_cache *smt_ctx_kmem = NULL;
struct kmem_cache *smt_sw_ctx_kmem = NULL;
struct kmem_cache *smt_rpc_sw_ctx_kmem = NULL;
struct kmem_cache *smt_rpc_hw_ctx_tx_kmem = NULL;

#define mix(a, b, c)                                                    \
do {                                                                    \
        a -= b; a -= c; a ^= (c >> 13);                                 \
        b -= c; b -= a; b ^= (a << 8);                                  \
        c -= a; c -= b; c ^= (b >> 13);                                 \
        a -= b; a -= c; a ^= (c >> 12);                                 \
        b -= c; b -= a; b ^= (a << 16);                                 \
        c -= a; c -= b; c ^= (b >> 5);                                  \
        a -= b; a -= c; a ^= (c >> 3);                                  \
        b -= c; b -= a; b ^= (a << 10);                                 \
        c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static uint32_t ms_rthash(const uint32_t addr, const uint16_t port)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key
	uint8_t *p;

	// b += *ptrs->proto;
	p = (uint8_t *)&port;
	b += p[1] << 16;
	b += p[0] << 8;
	p = (uint8_t *)&addr;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;
	mix(a, b, c);
	return c;
}
#undef mix

static struct smt_context *smt_clone_ctx(struct homa_sock *hsk,
					       const uint32_t addr,
					       const uint16_t port)
{
	struct hlist_head *ctxs;
	struct smt_context *ctx = NULL;
	struct smt_context *reuse_ctx = (struct smt_context *)hsk->smt_reuse_ctx;

	if (!reuse_ctx)
		return NULL;

	ctxs = &hsk->smt_ctx_buckets[ms_rthash(addr, port)
			& (HOMA_SERVER_RPC_BUCKETS - 1)];

	ctx = kmem_cache_alloc(smt_ctx_kmem, GFP_ATOMIC);

	if (!ctx) {
		smt_prerr_int("%s smt_ctx_kmem alloc failed\n", __FUNCTION__);
		return NULL;
	}

	ctx->tx_conf = reuse_ctx->tx_conf;
	ctx->rx_conf = reuse_ctx->rx_conf;
	ctx->addr = addr;
	ctx->port = port;
	smt_replay_guard_init(&ctx->replay_guard);
	ctx->crypto_info_aes_gcm_128_send = reuse_ctx->crypto_info_aes_gcm_128_send;
	ctx->crypto_info_aes_gcm_128_recv = reuse_ctx->crypto_info_aes_gcm_128_recv;

	// clone offload for tx
	if (ctx->tx_conf == SMT_SW) {
		int rc = smt_set_sw_offload(ctx, smt_sw_ctx_kmem, 1);
		if (rc != 0) {
			printk("failed to set smt_ctx-level sw offload on tx");
			return NULL;
		}
	} else if (ctx->tx_conf == SMT_HW) {
		int rc = smt_set_device_offload_send(hsk, ctx);
		if (rc != 0) {
			printk("failed to set smt_ctx-level sw offload on tx");
			return NULL;
		}
	}

	// clone offload for rx
	if (ctx->rx_conf == SMT_SW) {
		int rc = smt_set_sw_offload(ctx, smt_sw_ctx_kmem, 0);
		if (rc != 0) {
			printk("failed to set smt_ctx-level sw offload on rx");
			return NULL;
		}
	}

	hlist_add_head(&ctx->hlist, ctxs);

	return ctx;
}

static struct smt_context *smt_query_ctx(struct homa_sock *hsk,
					   const uint32_t addr,
					   const uint16_t port)
{
	struct hlist_head *ctxs = &hsk->smt_ctx_buckets[ms_rthash(addr, port)
		& (HOMA_SERVER_RPC_BUCKETS - 1)];
	struct smt_context *ctx = NULL;

	smt_prinf_int("%s addr %X ctx->port %d\n", __FUNCTION__, ntohl(addr),
			 (int)ntohs(port));
	smt_prinf_int("%s ctxs->first %px", __FUNCTION__, ctxs->first);

	if (unlikely(hlist_empty(ctxs)))
		goto out;

	hlist_for_each_entry(ctx, ctxs, hlist) {
		if (likely(ctx->addr == addr && ctx->port == port)) {
			smt_prdbg_int(
				"%s ctx %px ctx->addr %X ctx->port %d ctx->hlist.next %px\n",
				__FUNCTION__, ctx, ntohl(ctx->addr),
				(int)ntohs(ctx->port), ctx->hlist.next);
			return ctx;
		}
	}

	out:
	smt_prinf_int("%s no match", __FUNCTION__);
	return NULL;
}

// Caller is expect to hold at minimal rpc lock
int smt_set_rpc_offload_context(struct homa_rpc *rpc)
{
	struct smt_context *ctx = (struct smt_context *)rpc->smt_ctx;
	int rc;

	if (ctx->tx_conf == SMT_SW) {
		rc = smt_set_rpc_sw_offload(&ctx->crypto_info_aes_gcm_128_send,
			&rpc->smt_rpc_offload_ctx_tx, smt_rpc_sw_ctx_kmem,
			rpc->id);
		if (rc != 0) {
			smt_prerr_int("failed to set rpc-level sw offload on tx");
			goto tx_offload;
		}
	} else if (ctx->tx_conf == SMT_HW) {
		rc = smt_set_rpc_device_offload(&ctx->crypto_info_aes_gcm_128_send,
			&rpc->smt_rpc_offload_ctx_tx, smt_rpc_hw_ctx_tx_kmem,
			rpc->id);
		if (rc != 0) {
			smt_prerr_int("failed to set rpc-level sw offload on tx");
			goto tx_offload;
		}
	}

	// Setup RPC-wide seq_num and nonce
	if (ctx->rx_conf == SMT_SW) {
		rc = smt_set_rpc_sw_offload(&ctx->crypto_info_aes_gcm_128_recv,
			&rpc->smt_rpc_offload_ctx_rx, smt_rpc_sw_ctx_kmem,
			rpc->id);
		if (rc != 0) {
			smt_prerr_int("failed to set rpc-level sw offload on rx");
			goto rx_offload;
		}
	}

	return 0;

rx_offload:
	if (smt_get_tx_conf(rpc) == SMT_SW)
		smt_sw_release_resources_rpc(rpc, smt_rpc_sw_ctx_kmem, 1);
	else if (smt_get_tx_conf(rpc) == SMT_HW)
		smt_device_release_resources_rpc_tx(rpc, smt_rpc_hw_ctx_tx_kmem);
tx_offload:
	return rc;
}

// Caller is expect to hold socket lock
struct smt_context *smt_set_rpc_context(struct homa_rpc *rpc,
				      const uint32_t addr,
				      const uint16_t port)
{
	struct smt_context *ctx;

	smt_prinf_int("%s invoked\n", __FUNCTION__);

	// Setup smt_ctx which is shared by all 5-tuples
	ctx = smt_query_ctx(rpc->hsk, addr, port);
	if (!ctx)
		ctx = smt_clone_ctx(rpc->hsk, addr, port);
	if (!ctx)
		return NULL;
	return ctx;
}

static void smt_destroy_ctx(struct smt_context *ctx)
{
	smt_prinf_int("%s free ctx %px addr %u port %hu\n",
		__FUNCTION__, ctx, ctx->addr, ctx->port);

	if (unlikely(!ctx))
		return;

	if (ctx->tx_conf == SMT_SW)
		smt_sw_release_resources(ctx, smt_sw_ctx_kmem, 1);
	else if (ctx->tx_conf == SMT_HW)
		smt_device_release_resources_tx(ctx);

	if (ctx->rx_conf == SMT_SW)
		smt_sw_release_resources(ctx, smt_sw_ctx_kmem, 0);

	kmem_cache_free(smt_ctx_kmem, ctx);
}

void smt_destroy_ctxs(struct hlist_head *buckets)
{
	int i = 0;
	struct smt_context *ctx = NULL;
	struct hlist_node *n;
	for (; i < HOMA_SERVER_RPC_BUCKETS; i++) {
		if (hlist_empty(&buckets[i]))
			continue;
		hlist_for_each_entry_safe(ctx, n, &buckets[i], hlist) {
			smt_destroy_ctx(ctx);
		}
	}
}

void smt_destroy_rpc(struct homa_rpc *rpc)
{
	if (smt_get_tx_conf(rpc) == SMT_SW)
		smt_sw_release_resources_rpc(rpc, smt_rpc_sw_ctx_kmem, 1);
	else if (smt_get_tx_conf(rpc) == SMT_HW)
		smt_device_release_resources_rpc_tx(rpc, smt_rpc_hw_ctx_tx_kmem);

	if (smt_get_rx_conf(rpc) == SMT_SW)
		smt_sw_release_resources_rpc(rpc, smt_rpc_sw_ctx_kmem, 0);
}

static int
smt_setsockopt_conf(struct homa_sock *hsk,
		       struct smt_crypto_info *crypto_info_optval,
		       struct smt_context *ctx,
		       int tx)
{
	struct tls12_crypto_info_aes_gcm_128 *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 *alt_crypto_info;

	int rc = 0;
	int conf;

	if (ctx == NULL) {
		rc = -EFAULT;
		goto out;
	}

	smt_prinf_int("smt_setsockopt_conf invoked on Homa socket:"
			 "crypto_info_optval %px, ctx %px\n",
			 crypto_info_optval, ctx);

	crypto_info = tx ? &(ctx->crypto_info_aes_gcm_128_send) :
			   &(ctx->crypto_info_aes_gcm_128_recv);
	alt_crypto_info = !tx ? &(ctx->crypto_info_aes_gcm_128_send) :
				&(ctx->crypto_info_aes_gcm_128_recv);

	smt_prdbg_int("%s crypto_info %px", __FUNCTION__, crypto_info);
	smt_prdbg_int("%s crypto_info->info.version 0x%04X \n", __FUNCTION__,
			 crypto_info->info.version);
	smt_prdbg_int("%s crypto_info->info.cipher_type %hu \n",
			 __FUNCTION__, crypto_info->info.cipher_type);
	smt_prdbg_int("%s alt_crypto_info %px", __FUNCTION__, alt_crypto_info);
	smt_prdbg_int("%s alt_crypto_info->info.version 0x%04X \n",
			 __FUNCTION__, alt_crypto_info->info.version);
	smt_prdbg_int("%s alt_crypto_info->info.cipher_type %hu \n",
			 __FUNCTION__, alt_crypto_info->info.cipher_type);

	/* Currently we don't support set crypto info more than one time */
	if (TLS_CRYPTO_INFO_READY(&crypto_info->info)) {
		rc = -EBUSY;
		goto out;
	}

	/* Copy optval to smt_ctx */
	*crypto_info = crypto_info_optval->crypto_info_aes_gcm_128;

	/* Ensure that TLS verscopy_from_sockptrion and ciphers are same in both directions */
	if (TLS_CRYPTO_INFO_READY(&alt_crypto_info->info)) {
		if (alt_crypto_info->info.version !=
			    crypto_info->info.version ||
		    alt_crypto_info->info.cipher_type !=
			    crypto_info->info.cipher_type) {
			rc = -EINVAL;
			goto out;
		}
	}

	ctx->addr = crypto_info_optval->addr;
	ctx->port = crypto_info_optval->port;

	hexdump("smt_setsockopt_conf crypto_info->salt ", crypto_info->salt,
		sizeof(crypto_info->salt));
	hexdump("smt_setsockopt_conf crypto_info->iv ", crypto_info->iv,
		sizeof(crypto_info->iv));
	hexdump("smt_setsockopt_conf crypto_info->key ", crypto_info->key,
		sizeof(crypto_info->key));
	hexdump("smt_setsockopt_conf crypto_info->rec_seq ",
		crypto_info->rec_seq, sizeof(crypto_info->rec_seq));
	smt_prinf_int("%s ctx->addr %X ctx->port %d\n", __FUNCTION__,
		ntohl(ctx->addr), (int) ntohs(ctx->port));

	if (tx) {
		// try to set hw offload first
		rc = smt_set_device_offload_send(hsk, ctx);
		conf = SMT_HW;

		// set sw offload if hw unavailiable
		if (rc) {
			smt_prinf_int("%s failed to set nic offload on tx", __FUNCTION__);
			rc = smt_set_sw_offload(ctx, smt_sw_ctx_kmem, 1);
			// setup crypto list
			if (rc) {
				smt_prerr_int("%s failed to set sw offload on tx", __FUNCTION__);
				goto out;
			}
			conf = SMT_SW;
		}
	} else {
		// rx only supports sw now
		conf = SMT_SW;
		if (conf == SMT_SW) {
			// setup crypto list
			int rc = smt_set_sw_offload(ctx, smt_sw_ctx_kmem, 0);
			if (rc) {
				printk("failed to set smt_ctx-level sw offload on tx");
				goto out;
			}
		}
	}

	if (rc)
		goto out;

	if (tx)
		ctx->tx_conf = conf;
	else
		ctx->rx_conf = conf;

out:
	return rc;
}

int smt_setsockopt_select_ctx(struct homa_sock *hsk, sockptr_t optval,
					unsigned int optlen, int tx)
{
	int rc = 0;
	struct smt_crypto_info crypto_info_optval;
	struct smt_context *ctx = NULL;

	size_t optsize;

	if (sockptr_is_null(optval) ||
	    (optlen < sizeof(crypto_info_optval))) {
		rc = -EINVAL;
		printk(KERN_WARNING
		       "%s optval length is not correct, should be sizeof(struct smt_crypto_info)\n",
		       __FUNCTION__);
		goto out;
	}

	// copy key info from userspace
	rc = copy_from_sockptr(&crypto_info_optval, optval,
			       sizeof(struct smt_crypto_info));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	switch (crypto_info_optval.crypto_info_aes_gcm_128.info.cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		optsize = sizeof(struct smt_crypto_info);
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
	}

	ctx = smt_query_ctx(hsk, crypto_info_optval.addr,
				  crypto_info_optval.port);
	// malloc a new ctx if can not find one
	if (!ctx) {
		struct hlist_head *ctxs;

		ctx = kmem_cache_alloc(smt_ctx_kmem, GFP_ATOMIC);
		if (!ctx) {
			rc = -ENOMEM;
			goto out;
		}
		smt_replay_guard_init(&ctx->replay_guard);

		ctxs = &hsk->smt_ctx_buckets[
			ms_rthash(crypto_info_optval.addr, crypto_info_optval.port)
			& (HOMA_SERVER_RPC_BUCKETS - 1)];

		hlist_add_head(&ctx->hlist, ctxs);

		if (crypto_info_optval.reuse)
			hsk->smt_reuse_ctx = ctx;
	}

	rc = smt_setsockopt_conf(hsk, &crypto_info_optval, ctx, tx);
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

int smt_setsockopt(struct homa_sock *hsk, int optname, sockptr_t optval,
		      unsigned int optlen)
{
	int rc = 0;

	switch (optname) {
	case TLS_TX:
	case TLS_RX:
		homa_sock_lock(hsk, "smt_setsockopt");
		if (hsk->shutdown) {
			homa_sock_unlock(hsk);
			return -ESHUTDOWN;
		}
		rc = smt_setsockopt_select_ctx(hsk, optval, optlen,
						  optname == TLS_TX);
		homa_sock_unlock(hsk);
		break;
	default:
		rc = -ENOPROTOOPT;
		break;
	}
	return rc;
}

int smt_load(void)
{
	smt_ctx_kmem = kmem_cache_create(
			"smt_ctx_kmem",
			sizeof(struct smt_context),
			0, SLAB_PANIC, NULL);
	smt_sw_ctx_kmem = kmem_cache_create(
			"smt_sw_ctx_kmem",
			sizeof(struct smt_sw_context),
			0, SLAB_PANIC, NULL);
	smt_rpc_sw_ctx_kmem = kmem_cache_create(
			"smt_rpc_sw_ctx_kmem",
			sizeof(struct smt_rpc_sw_context),
			0, SLAB_PANIC, NULL);
	smt_rpc_hw_ctx_tx_kmem = kmem_cache_create(
			"smt_rpc_hw_context_tx",
			sizeof(struct smt_rpc_hw_context_tx),
			0, SLAB_PANIC, NULL);
	return 0;
}

int smt_unload(void)
{
	if (smt_ctx_kmem)
		kmem_cache_destroy(smt_ctx_kmem);
	if (smt_sw_ctx_kmem)
		kmem_cache_destroy(smt_sw_ctx_kmem);
	if (smt_rpc_sw_ctx_kmem)
		kmem_cache_destroy(smt_rpc_sw_ctx_kmem);
	if (smt_rpc_hw_ctx_tx_kmem)
		kmem_cache_destroy(smt_rpc_hw_ctx_tx_kmem);
	return 0;
}
