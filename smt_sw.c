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
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
	return crypto;
}

static void smt_sw_push_crypto(struct smt_sw_context *sw_ctx,
			       struct smt_sw_crypto *crypto)
{
	spin_lock_bh(&sw_ctx->crypto_list_lock);
	list_add_tail(&crypto->list, &sw_ctx->crypto_list);
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
}

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

/* Borrow a crypto pool entry for one encrypt/decrypt call. The entry is
 * released back via smt_sw_push_crypto at the end of the call. The pool
 * is pre-populated by smt_sw_ctx_alloc, so the alloc-on-empty
 * branch should not fire in steady state.
 */
static struct smt_sw_crypto *smt_sw_borrow_crypto(struct homa_rpc *rpc,
						  int tx)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_sw_context *sw_ctx;
	struct smt_sw_crypto *crypto;

	sw_ctx = tx ? ctx->offload_tx : ctx->offload_rx;
	crypto = smt_sw_pop_crypto(sw_ctx);
	if (!crypto) {
		crypto = smt_sw_alloc_crypto(tx ? &ctx->crypto_send :
						     &ctx->crypto_recv);
		if (IS_ERR(crypto))
			return crypto;
	}
	return crypto;
}

static int smt_sw_do_crypt(struct smt_sw_crypto *crypto,
			   struct scatterlist *sgin,
			   struct scatterlist *sgout, int aad_len,
			   int crypt_len, u8 *iv, bool encrypt)
{
	struct aead_request *req = crypto->aead_req;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	/* tfm pinned by aead_request_alloc. */
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, aad_len);
	aead_request_set_crypt(req, sgin, sgout, crypt_len, iv);

	ret = crypto_wait_req(encrypt ? crypto_aead_encrypt(req)
				      : crypto_aead_decrypt(req),
			      &wait);
	return ret;
}

/**
 * smt_sw_encrypt() - Encrypt one outgoing record in place in
 * rpc->msgout.frags.
 * @rpc:          The SMT RPC owning the record.
 * @rec:          Index of the record within the message.
 * @pos:          Position in rpc->msgout.frags of the record's first byte.
 * @payload_len:  Bytes of plaintext in the record (seg_hdrs, data and, in
 *                TLS 1.3, the content type); the 16-byte tag follows
 *                them and is overwritten.
 * Return:        Zero for success, otherwise a negative errno.
 */
int smt_sw_encrypt(struct homa_rpc *rpc, u32 rec,
		   const struct homa_frag_filler *pos, int payload_len)
{
	struct smt_rpc_sw_context *r = smt_rpc_sw_tx(rpc);
	struct smt_sw_context *sw_ctx = SMT_RPC(rpc)->ctx->offload_tx;
	int bytes = payload_len + TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	u64 seq = get_unaligned_be64(r->rec_seq) + rec;
	u8 iv[TLS_CIPHER_AES_GCM_128_SALT_SIZE +
	      TLS_CIPHER_AES_GCM_128_IV_SIZE];
	int aad_len, len;
	u8 *hdr;
	int frags_left = pos->num_frags;
	skb_frag_t *frag = pos->frag;
	int off = pos->offset;
	struct smt_sw_crypto *crypto;
	struct scatterlist *sg;
	int nsg, ret;

	crypto = smt_sw_borrow_crypto(rpc, 1);
	if (IS_ERR(crypto))
		return PTR_ERR(crypto);

	/* AAD: in TLS 1.2 the sequence number then the header with the
	 * plaintext length, in TLS 1.3 the record header (length counts the
	 * tag).
	 */
	if (smt_rpc_tls13(rpc)) {
		aad_len = TLS_HEADER_SIZE;
		len = payload_len + TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	} else {
		aad_len = TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE;
		len = payload_len;
		put_unaligned_be64(seq, crypto->aad);
	}
	hdr = crypto->aad + aad_len - TLS_HEADER_SIZE;
	hdr[0] = 0x17;
	hdr[1] = 0x03;
	hdr[2] = 0x03;
	put_unaligned_be16(len, hdr + 3);
	smt_nonce(iv, r->iv, seq);

	sg = crypto->crypt_sg;
	sg_init_table(sg, min(frags_left + 1, SMT_MAX_CRYPT_SG));
	sg_set_buf(&sg[0], crypto->aad, aad_len);
	for (nsg = 1; bytes > 0; nsg++) {
		int n;

		while (off >= skb_frag_size(frag)) {
			off -= skb_frag_size(frag);
			frag++;
			if (--frags_left <= 0) {
				ret = -EINVAL;
				goto out;
			}
		}
		if (unlikely(nsg >= SMT_MAX_CRYPT_SG)) {
			ret = -EMSGSIZE;
			goto out;
		}
		n = min_t(int, bytes, skb_frag_size(frag) - off);
		sg_set_page(&sg[nsg], skb_frag_page(frag), n,
			    skb_frag_off(frag) + off);
		off += n;
		bytes -= n;
	}
	sg_mark_end(&sg[nsg - 1]);

	ret = smt_sw_do_crypt(crypto, sg, sg, aad_len, payload_len, iv, true);
	if (unlikely(ret))
		smt_pr_err("%s: encrypt failed %d\n", __func__, ret);
out:
	smt_sw_push_crypto(sw_ctx, crypto);
	return ret;
}

/**
 * smt_sw_decrypt() - Decrypt an assembled record in place.
 * @rpc:        SMT RPC.
 * @skbs:       Array of skbs that together form exactly one TLS record, in
 *              order. The first skb must be the first packet of the record
 *              (ip_id == 0) and carry smt_h in its linear part at offset
 *              SMT_SW_SGVEC_OFFSET. The last skb must carry the trailer.
 * @n:          Number of skbs.
 * @rec_offset: Message offset of the record's data.
 * @rec_len:    Bytes of data in the record.
 * @delivered:  Set to whether the data is in the user's buffers; if not,
 *              the plaintext (seg_hdrs and segment data) is in the skbs.
 */
int smt_sw_decrypt(struct homa_rpc *rpc, struct sk_buff **skbs, int n,
		   int rec_offset, int rec_len, bool *delivered)
{
	struct smt_rpc_sw_context *r = smt_rpc_sw_rx(rpc);
	struct smt_sw_context *sw_ctx = SMT_RPC(rpc)->ctx->offload_rx;
	int pre = SMT_RPC(rpc)->rec_pre, post = SMT_RPC(rpc)->rec_post;
	u8 iv[TLS_CIPHER_AES_GCM_128_SALT_SIZE +
	      TLS_CIPHER_AES_GCM_128_IV_SIZE];
	struct smt_sw_crypto *crypto;
	struct scatterlist *sg;
	u8 *smt_h, type = 0;
	int i, nsg_total = 0, ret, crypt_len;
	int total_sg_bytes = 0;
	struct scatterlist *dst;

	*delivered = false;

	if (n <= 0)
		return -EINVAL;

	crypto = smt_sw_borrow_crypto(rpc, 0);
	if (IS_ERR(crypto))
		return PTR_ERR(crypto);

	sg = crypto->crypt_sg;
	{
		int max_nsg = 0;

		for (i = 0; i < n; i++)
			max_nsg += skb_shinfo(skbs[i])->nr_frags + 1;
		if (max_nsg < 1)
			max_nsg = 1;
		if (max_nsg > SMT_MAX_CRYPT_SG)
			max_nsg = SMT_MAX_CRYPT_SG;
		sg_init_table(sg, max_nsg);
	}

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
			ret = -EMSGSIZE;
			goto out;
		}
		/* Fast path: NIC delivers small skbs entirely in linear; build
		 * one sg entry directly. Multi-frag skbs (GRO jumbo) fall back
		 * to skb_to_sgvec_nomark.
		 */
		if (likely(skb_shinfo(skb)->nr_frags == 0)) {
			sg_set_buf(&sg[nsg_total], skb->data + offset, len);
			nsg = 1;
		} else {
			nsg = skb_to_sgvec_nomark(skb, &sg[nsg_total], offset,
						  len);
			if (nsg <= 0) {
				smt_pr_err("%s: skb_to_sgvec_nomark failed %d\n",
					   __func__, nsg);
				ret = nsg < 0 ? nsg : -EINVAL;
				goto out;
			}
		}
		nsg_total += nsg;
		total_sg_bytes += len;
	}
	if (nsg_total == 0) {
		ret = -EINVAL;
		goto out;
	}
	sg_mark_end(&sg[nsg_total - 1]);

	if (total_sg_bytes < pre + post) {
		ret = -EBADMSG;
		goto out;
	}
	crypt_len = total_sg_bytes - pre;

	/* The AAD takes the place of smt_h. TLS 1.3's is the record header
	 * as received; TLS 1.2's is the sequence number (which the explicit
	 * nonce is overwritten with) and the header with the plaintext
	 * length.
	 */
	smt_h = skbs[0]->data + SMT_SW_SGVEC_OFFSET;
	if (!smt_rpc_tls13(rpc)) {
		memcpy(smt_h, r->rec_seq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
		smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 0] = 0x17;
		smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 1] = 0x03;
		smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 2] = 0x03;
		put_unaligned_be16(crypt_len - post,
				   smt_h + TLS_CIPHER_AES_GCM_128_IV_SIZE + 3);
	}
	smt_nonce(iv, r->iv, get_unaligned_be64(r->rec_seq));

	smt_pr_devel(KERN_NOTICE "smt_sw_decrypt: rpc %lld n=%d crypt_len=%d total_sg_bytes=%d record_start=%d record_len=%d rec_seq=%*phN\n",
	       rpc->id, n, crypt_len, total_sg_bytes,
	       SMT_RX_INFO(skbs[0])->start, SMT_RX_INFO(skbs[0])->record_data_len,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE, r->rec_seq);

	dst = sg;
	/* The AAD is the first pre bytes, smt_h's place, in both versions. */
	ret = smt_sw_do_crypt(crypto, sg, dst, pre, crypt_len, iv, false);
	/* TLS 1.3's content type, while sg still maps the plaintext. */
	if (smt_rpc_tls13(rpc) && dst == sg)
		scatterwalk_map_and_copy(&type, sg, total_sg_bytes - post, 1, 0);
	if (unlikely(ret)) {
		smt_pr_err("%s: decrypt failed %d rpc %lld n=%d crypt_len=%d total_sg_bytes=%d\n",
			   __func__, ret, rpc->id, n, crypt_len,
			   total_sg_bytes);
		smt_pr_err("%s: rec_seq=%*phN iv=%*phN aad=%*phN\n",
			   __func__,
			   (int)TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE,
			   r->rec_seq,
			   (int)sizeof(iv), iv, pre, smt_h);
		/* Dump per-skb: header (first 48 B after transport) and, for
		 * the last skb, the trailing 16 B that should be the GCM tag.
		 * Content comes via skb_copy_bits because bytes may live in
		 * frags.
		 */
		for (i = 0; i < n; i++) {
			struct sk_buff *skb = skbs[i];
			int off = SMT_SW_SGVEC_OFFSET;
			int len = skb->len - off;
			u8 buf[48];
			int dump = min(len, (int)sizeof(buf));
			struct homa_data_hdr *dh =
				(struct homa_data_hdr *)skb_transport_header(skb);
			u8 retrans = dh ? dh->retransmit : 0;
			u32 seq = dh ? ntohl(dh->common.sequence) : 0;

			smt_pr_err("%s: rpc %lld skb[%d] retransmit=0x%02x sequence=%u skb=%px\n",
				   __func__, rpc->id, i, retrans, seq, skb);
			if (dump <= 0)
				continue;
			if (skb_copy_bits(skb, off, buf, dump) == 0)
				smt_pr_err("%s: rpc %lld skb[%d] head(%d/%d): %*phN\n",
					   __func__, rpc->id, i, dump, len,
					   dump, buf);
			if (i == n - 1 && len >= 16) {
				u8 tag[16];

				if (skb_copy_bits(skb, off + len - 16,
						  tag, 16) == 0)
					smt_pr_err("%s: rpc %lld skb[%d] tail(16): %*phN\n",
						   __func__, rpc->id, i, 16, tag);
			}
		}
		goto out;
	}

	/* TLS 1.3: the plaintext ends with its content type, which must be
	 * application data (SMT never pads).
	 */
	if (smt_rpc_tls13(rpc)) {
		if (unlikely(type != 0x17)) {
			smt_pr_err("%s: rpc %lld record content type 0x%02x\n",
				   __func__, rpc->id, type);
			ret = -EBADMSG;
			goto out;
		}
	}

	smt_bigint_increment(r->rec_seq, sizeof(r->rec_seq));
	*delivered = dst != sg;
	if (!homa_is_client(rpc->id) &&
	    SMT_RX_INFO(skbs[0])->record_data_offset == 0)
		smt_replay_accept(rpc);
	ret = 0;
out:
	smt_sw_push_crypto(sw_ctx, crypto);
	return ret;
}
