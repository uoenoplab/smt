// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* SMT software AES-GCM-128 encrypt/decrypt, modeled on the old HomaModule
 * homals_sw.c. Provides a per-smt_context pool of crypto_aead/aead_request
 * objects borrowed per-RPC, and in-place record encryption/decryption.
 *
 * The record layout on the wire (per Homa GSO unit / per reassembled record)
 * is:
 *
 *   [homa_data_hdr - seg_hdr][smt_h (13B)][seg_hdr][data][seg_hdr][data]
 *     ...[seg_hdr][data][smt_t (16B)]
 *
 * smt_h is the AAD (5B TLS header + 8B explicit nonce/rec_seq) and smt_t is
 * the AES-GCM authentication tag.
 */

#include "smt_impl.h"

#include "homa_peer.h"
#include "homa_rpc.h"

#include <crypto/aead.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <net/tls.h>

/* Offset (from skb->data / transport_header) where smt_h begins in the
 * linear part. Same on TX (outgoing GSO skb) and RX (received per-packet skb):
 * immediately after the truncated homa_data_hdr (which omits the final
 * homa_seg_hdr).
 */
#define SMT_SW_SGVEC_OFFSET \
	(int)(sizeof(struct homa_data_hdr) - sizeof(struct homa_seg_hdr))

static struct smt_sw_crypto *smt_sw_pop_crypto(struct smt_sw_context *sw_ctx)
{
	struct smt_sw_crypto *crypto;

	spin_lock_bh(&sw_ctx->crypto_list_lock);
	if (list_empty(&sw_ctx->crypto_list)) {
		spin_unlock_bh(&sw_ctx->crypto_list_lock);
		return NULL;
	}
	crypto = list_first_entry(&sw_ctx->crypto_list,
				  struct smt_sw_crypto, list);
	list_del(&crypto->list);
	sw_ctx->crypto_available--;
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
	return crypto;
}

static void smt_sw_push_crypto(struct smt_sw_context *sw_ctx,
			       struct smt_sw_crypto *crypto)
{
	spin_lock_bh(&sw_ctx->crypto_list_lock);
	list_add_tail(&crypto->list, &sw_ctx->crypto_list);
	sw_ctx->crypto_available++;
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
}

/* Allocate a new crypto_aead + aead_request and bind the per-direction
 * key from the smt_context.
 */
static struct smt_sw_crypto *smt_sw_alloc_crypto(struct smt_context *ctx,
						 int tx)
{
	struct smt_sw_crypto *crypto;
	struct tls12_crypto_info_aes_gcm_128 *info =
		tx ? &ctx->aes_gcm_128_send : &ctx->aes_gcm_128_recv;
	int rc;

	crypto = kzalloc(sizeof(*crypto), GFP_ATOMIC);
	if (!crypto)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&crypto->list);

	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm)) {
		rc = PTR_ERR(crypto->tfm);
		kfree(crypto);
		return ERR_PTR(rc);
	}
	rc = crypto_aead_setkey(crypto->tfm, info->key,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (rc)
		goto err_free_tfm;
	rc = crypto_aead_setauthsize(crypto->tfm,
				     TLS_CIPHER_AES_GCM_128_TAG_SIZE);
	if (rc)
		goto err_free_tfm;

	crypto->aead_req = aead_request_alloc(crypto->tfm, GFP_ATOMIC);
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

int smt_sw_set_offload(struct smt_context *ctx, int tx)
{
	struct smt_sw_context *sw_ctx;

	sw_ctx = kmalloc(sizeof(*sw_ctx), GFP_ATOMIC);
	if (!sw_ctx)
		return -ENOMEM;
	INIT_LIST_HEAD(&sw_ctx->crypto_list);
	spin_lock_init(&sw_ctx->crypto_list_lock);
	sw_ctx->crypto_available = 0;

	if (tx) {
		ctx->offload_tx = sw_ctx;
		ctx->tx_conf = SMT_SW;
	} else {
		ctx->offload_rx = sw_ctx;
		ctx->rx_conf = SMT_SW;
	}
	return 0;
}

void smt_sw_release_resources(struct smt_context *ctx, int tx)
{
	struct smt_sw_context *sw_ctx = tx ? ctx->offload_tx : ctx->offload_rx;
	struct smt_sw_crypto *crypto, *tmp;

	if (!sw_ctx)
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
	if (tx) {
		ctx->offload_tx = NULL;
	} else {
		ctx->offload_rx = NULL;
	}
}

/* Initialize per-RPC iv/salt/rec_seq from the context's crypto_info. The
 * crypto tfm is borrowed lazily on first encrypt/decrypt call.
 */
int smt_sw_init_rpc(struct homa_rpc *rpc, int tx)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct tls12_crypto_info_aes_gcm_128 *info =
		tx ? &ctx->aes_gcm_128_send : &ctx->aes_gcm_128_recv;
	struct smt_rpc_sw_context *r =
		tx ? smt_rpc_sw_tx(rpc) : smt_rpc_sw_rx(rpc);

	BUILD_BUG_ON(sizeof(struct smt_rpc_sw_context) >
		     sizeof(((struct smt_rpc *)0)->smt_rpc_crypto_tx));

	memset(r, 0, sizeof(*r));
	memcpy(r->iv, info->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, info->iv,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(r->rec_seq, info->rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	r->crypto = NULL;
	return 0;
}

void smt_sw_release_rpc(struct homa_rpc *rpc, int tx)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_sw_context *sw_ctx;
	struct smt_rpc_sw_context *r;

	if (!ctx)
		return;
	sw_ctx = tx ? ctx->offload_tx : ctx->offload_rx;
	r = tx ? smt_rpc_sw_tx(rpc) : smt_rpc_sw_rx(rpc);
	if (!sw_ctx || !r->crypto)
		return;
	smt_sw_push_crypto(sw_ctx, r->crypto);
	r->crypto = NULL;
}

/* Borrow a crypto pool entry if not already held, else return the held one.
 * Lazily allocate the per-ctx sw pool if it hasn't been set up yet (e.g.
 * for cloned contexts created by smt_ctx_clone).
 */
static int smt_sw_borrow_crypto(struct homa_rpc *rpc,
				struct smt_rpc_sw_context *r, int tx)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_sw_context *sw_ctx;
	struct smt_sw_crypto *crypto;
	int rc;

	if (r->crypto)
		return 0;

	sw_ctx = tx ? ctx->offload_tx : ctx->offload_rx;
	if (!sw_ctx) {
		rc = smt_sw_set_offload(ctx, tx);
		if (rc)
			return rc;
		sw_ctx = tx ? ctx->offload_tx : ctx->offload_rx;
	}

	crypto = smt_sw_pop_crypto(sw_ctx);
	if (!crypto) {
		crypto = smt_sw_alloc_crypto(ctx, tx);
		if (IS_ERR(crypto))
			return PTR_ERR(crypto);
	}
	r->crypto = crypto;
	return 0;
}

static int smt_sw_do_crypt(struct smt_rpc_sw_context *r,
			   struct scatterlist *sgin,
			   struct scatterlist *sgout,
			   int crypt_len, bool encrypt)
{
	struct aead_request *req = r->crypto->aead_req;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	aead_request_set_tfm(req, r->crypto->tfm);
	aead_request_set_ad(req, SMT_RECORD_EXTRA_PRE_LENGTH);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sgin, sgout, crypt_len, r->nonce);

	ret = crypto_wait_req(encrypt ? crypto_aead_encrypt(req)
				      : crypto_aead_decrypt(req),
			      &wait);
	memset(req, 0, r->crypto->aead_req_size);
	return ret;
}

/**
 * smt_sw_encrypt() - Encrypt one outgoing GSO skb in place.
 * @rpc:           The SMT RPC owning the skb.
 * @skb:           The outgoing GSO skb. smt_h must already exist in the
 *                 linear part at SMT_SW_SGVEC_OFFSET. smt_t (tag) must be
 *                 reserved (16 bytes) at the tail of the frags.
 * @smt_h_offset:  Offset in @skb->data where smt_h begins. Callers pass
 *                 SMT_SW_SGVEC_OFFSET; kept as a parameter for clarity.
 * @payload_len:   Bytes in the plaintext region (not including smt_h /
 *                 smt_t), i.e. the sum of (seg_hdr + seg_data) pairs.
 *
 * On entry, smt_h and smt_t memory is reserved but contains undefined
 * bytes. On return, smt_h holds the TLS 1.2 record header + explicit nonce
 * and the plaintext region has been replaced with ciphertext followed by
 * the 16-byte tag (in smt_t).
 */
int smt_sw_encrypt(struct homa_rpc *rpc, struct sk_buff *skb,
		   int smt_h_offset, int payload_len)
{
	struct smt_rpc_sw_context *r = smt_rpc_sw_tx(rpc);
	struct scatterlist *sg;
	int total_len = SMT_RECORD_EXTRA_PRE_LENGTH + payload_len +
			SMT_RECORD_EXTRA_POST_LENGTH;
	u8 *smt_h;
	int nsg, ret;

	ret = smt_sw_borrow_crypto(rpc, r, 1);
	if (ret)
		return ret;

	sg = r->crypto->crypt_sg;
	memset(sg, 0, sizeof(struct scatterlist) * SMT_MAX_CRYPT_SG);

	smt_h = skb->data + smt_h_offset;
	memcpy(smt_h, r->rec_seq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 0] = 0x17;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 1] = 0x03;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 2] = 0x03;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 3] = payload_len >> 8;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 4] = payload_len & 0xff;

	memcpy(r->nonce, r->iv, sizeof(r->nonce));

	sg_init_table(sg, SMT_MAX_CRYPT_SG);
	nsg = skb_to_sgvec(skb, sg, smt_h_offset, total_len);
	if (nsg <= 0) {
		smt_pr_err("%s: skb_to_sgvec failed %d\n", __func__, nsg);
		return nsg < 0 ? nsg : -EINVAL;
	}

	ret = smt_sw_do_crypt(r, sg, sg, payload_len, true);
	if (unlikely(ret)) {
		smt_pr_err("%s: encrypt failed %d\n", __func__, ret);
		return ret;
	}
	// printk(KERN_NOTICE "smt_sw_encrypt: rpc %lld payload_len=%d total_len=%d nsg=%d rec_seq=%*phN\n",
	//        rpc->id, payload_len, total_len, nsg,
	//        TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE, r->rec_seq);

	smt_h[0] = 0x17;
	smt_h[1] = 0x03;
	smt_h[2] = 0x03;
	smt_h[3] = (payload_len + SMT_RECORD_EXTRA_POST_LENGTH +
		    TLS_CIPHER_AES_GCM_128_IV_SIZE) >> 8;
	smt_h[4] = (payload_len + SMT_RECORD_EXTRA_POST_LENGTH +
		    TLS_CIPHER_AES_GCM_128_IV_SIZE) & 0xff;
	memcpy(smt_h + TLS_HEADER_SIZE, r->rec_seq,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);

	smt_bigint_increment(r->rec_seq, sizeof(r->rec_seq));
	smt_bigint_increment(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			     TLS_CIPHER_AES_GCM_128_IV_SIZE);
	return 0;
}

/**
 * smt_sw_decrypt() - Decrypt an assembled record in place.
 * @rpc:  SMT RPC.
 * @skbs: Array of skbs that together form exactly one TLS record, in
 *        order. The first skb must be the first packet of the record
 *        (ip_id == 0) and carry smt_h in its linear part at offset
 *        SMT_SW_SGVEC_OFFSET. The last skb must carry the trailer (tag).
 * @n:    Number of skbs.
 *
 * On success the plaintext (seg_hdrs and segment data) is written back
 * into the same skb buffers in place.
 */
int smt_sw_decrypt(struct homa_rpc *rpc, struct sk_buff **skbs, int n)
{
	struct smt_rpc_sw_context *r = smt_rpc_sw_rx(rpc);
	struct scatterlist *sg;
	u8 *smt_h;
	int i, nsg_total = 0, ret, crypt_len;
	int total_sg_bytes = 0;

	if (n <= 0)
		return -EINVAL;

	ret = smt_sw_borrow_crypto(rpc, r, 0);
	if (ret)
		return ret;

	sg = r->crypto->crypt_sg;
	sg_init_table(sg, SMT_MAX_CRYPT_SG);

	for (i = 0; i < n; i++) {
		struct sk_buff *skb = skbs[i];
		int offset = SMT_SW_SGVEC_OFFSET;
		int len = skb->len - offset;
		int nsg;

		if (unlikely(len <= 0))
			continue;
		if (unlikely(nsg_total >= SMT_MAX_CRYPT_SG - 4)) {
			smt_pr_err("%s: sgvec overflow (%d skbs)\n",
				   __func__, n);
			return -EMSGSIZE;
		}
		nsg = skb_to_sgvec_nomark(skb, &sg[nsg_total], offset, len);
		if (nsg <= 0) {
			smt_pr_err("%s: skb_to_sgvec_nomark failed %d\n",
				   __func__, nsg);
			return nsg < 0 ? nsg : -EINVAL;
		}
		nsg_total += nsg;
		total_sg_bytes += len;
	}
	if (nsg_total == 0)
		return -EINVAL;
	sg_mark_end(&sg[nsg_total - 1]);

	if (total_sg_bytes < SMT_RECORD_EXTRA_LENGTH)
		return -EBADMSG;
	crypt_len = total_sg_bytes - SMT_RECORD_EXTRA_PRE_LENGTH;

	smt_h = skbs[0]->data + SMT_SW_SGVEC_OFFSET;
	memcpy(smt_h, r->rec_seq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 0] = 0x17;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 1] = 0x03;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 2] = 0x03;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 3] =
		(crypt_len - SMT_RECORD_EXTRA_POST_LENGTH) >> 8;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 4] =
		(crypt_len - SMT_RECORD_EXTRA_POST_LENGTH) & 0xff;

	memcpy(r->nonce, r->iv, sizeof(r->nonce));
	// printk(KERN_NOTICE "smt_sw_decrypt: rpc %lld n=%d crypt_len=%d total_sg_bytes=%d record_start=%d record_len=%d rec_seq=%*phN\n",
	//        rpc->id, n, crypt_len, total_sg_bytes,
	//        SMT_RX_INFO(skbs[0])->start, SMT_RX_INFO(skbs[0])->record_data_len,
	//        TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE, r->rec_seq);

	ret = smt_sw_do_crypt(r, sg, sg, crypt_len, false);
	if (unlikely(ret)) {
		printk("%s: decrypt failed %d rpc %lld\n",
			   __func__, ret, rpc->id);
		printk("%s: failure crypt_len=%d total_sg_bytes=%d first_skb=%px first_header=%*phN\n",
			   __func__, crypt_len, total_sg_bytes, skbs[0],
			   SMT_RECORD_EXTRA_PRE_LENGTH, smt_h);
		return ret;
	}

	smt_bigint_increment(r->rec_seq, sizeof(r->rec_seq));
	smt_bigint_increment(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			     TLS_CIPHER_AES_GCM_128_IV_SIZE);
	return 0;
}
