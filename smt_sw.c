// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "smt_impl.h"

#include "homa_peer.h"
#include "homa_pool.h"
#include "homa_rpc.h"

#include <crypto/aead.h>
#include <crypto/scatterwalk.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <net/tls.h>

#include "homa_tx_pool.h"

/* Allocate a new crypto_aead + aead_request bound to @info's key. May
 * sleep (crypto_alloc_aead).
 */
static struct smt_sw_crypto *
smt_sw_alloc_crypto(const union tls_crypto_context *info)
{
	struct smt_sw_crypto *crypto;
	int rc;

	crypto = kzalloc(sizeof(*crypto), GFP_KERNEL);
	if (!crypto)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&crypto->list);

	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm)) {
		rc = PTR_ERR(crypto->tfm);
		kfree(crypto);
		return ERR_PTR(rc);
	}
	rc = crypto_aead_setkey(crypto->tfm, smt_crypto_key(info),
				smt_crypto_key_size(info));
	if (rc)
		goto err_free_tfm;
	rc = crypto_aead_setauthsize(crypto->tfm,
				     TLS_CIPHER_AES_GCM_128_TAG_SIZE);
	if (rc)
		goto err_free_tfm;

	crypto->aead_req = aead_request_alloc(crypto->tfm, GFP_KERNEL);
	if (!crypto->aead_req) {
		rc = -ENOMEM;
		goto err_free_tfm;
	}
	crypto->aead_req_size = sizeof(*crypto->aead_req)
				+ crypto_aead_reqsize(crypto->tfm);
	return crypto;

err_free_tfm:
	crypto_free_aead(crypto->tfm);
	kfree(crypto);
	return ERR_PTR(rc);
}

/**
 * smt_sw_ctx_alloc() - Allocate a crypto pool for one direction's key.
 * May sleep, so it must not be called in atomic context. Entries are
 * borrowed for one encrypt/decrypt call, so the pool rarely grows past
 * the number of CPUs; smt_sw_borrow_crypto adds entries if it runs dry.
 * @info:  The key.
 * @n:     Number of entries to pre-allocate (capped at the number of
 *         online CPUs).
 * Return: The pool, or an ERR_PTR.
 */
struct smt_sw_context *
smt_sw_ctx_alloc(const union tls_crypto_context *info, int n)
{
	struct smt_sw_context *sw_ctx;
	struct smt_sw_crypto *crypto;
	int i;

	sw_ctx = kmalloc(sizeof(*sw_ctx), GFP_KERNEL);
	if (!sw_ctx)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&sw_ctx->crypto_list);
	spin_lock_init(&sw_ctx->crypto_list_lock);
	refcount_set(&sw_ctx->refs, 1);

	n = min_t(int, num_online_cpus(), n);
	for (i = 0; i < n; i++) {
		crypto = smt_sw_alloc_crypto(info);
		if (IS_ERR(crypto))
			break;
		list_add_tail(&crypto->list, &sw_ctx->crypto_list);
	}
	return sw_ctx;
}

/**
 * smt_sw_ctx_put() - Drop a reference to a pool, freeing it with the last.
 * @sw_ctx:  The pool; NULL is ignored.
 */
void smt_sw_ctx_put(struct smt_sw_context *sw_ctx)
{
	struct smt_sw_crypto *crypto, *tmp;

	if (!sw_ctx || !refcount_dec_and_test(&sw_ctx->refs))
		return;
	list_for_each_entry_safe(crypto, tmp, &sw_ctx->crypto_list, list) {
		list_del(&crypto->list);
		if (crypto->aead_req)
			aead_request_free(crypto->aead_req);
		if (crypto->tfm && !IS_ERR(crypto->tfm))
			crypto_free_aead(crypto->tfm);
		kfree(crypto);
	}
	kfree(sw_ctx);
}

/* Initialize per-RPC rec_seq and nonce base (see smt_nonce) from the
 * context's crypto_info. The crypto tfm is borrowed lazily on first
 * encrypt/decrypt call.
 */
int smt_sw_init_rpc(struct homa_rpc *rpc, int tx)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	union tls_crypto_context *info = tx ? &ctx->crypto_send :
					      &ctx->crypto_recv;
	struct smt_rpc_sw_context *r =
		tx ? smt_rpc_sw_tx(rpc) : smt_rpc_sw_rx(rpc);

	BUILD_BUG_ON(sizeof(struct smt_rpc_sw_context) >
		     sizeof(((struct smt_rpc *)0)->smt_rpc_crypto_tx));

	smt_rpc_init_rec_seq(rpc, tx, r->rec_seq);
	memcpy(r->iv, smt_crypto_salt(info), TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	if (info->info.version == TLS_1_3_VERSION)
		memcpy(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
		       smt_crypto_iv(info), TLS_CIPHER_AES_GCM_128_IV_SIZE);
	else
		memset(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, 0,
		       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	return 0;
}
