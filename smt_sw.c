// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

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
	u64 __t = SMT_TIME_START();

	spin_lock_bh(&sw_ctx->crypto_list_lock);
	if (list_empty(&sw_ctx->crypto_list)) {
		spin_unlock_bh(&sw_ctx->crypto_list_lock);
		SMT_TIME_END(smt_sw_pop, __t);
		return NULL;
	}
	crypto = list_first_entry(&sw_ctx->crypto_list,
				  struct smt_sw_crypto, list);
	list_del(&crypto->list);
	sw_ctx->crypto_available--;
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
	SMT_TIME_END(smt_sw_pop, __t);
	return crypto;
}

static void smt_sw_push_crypto(struct smt_sw_context *sw_ctx,
			       struct smt_sw_crypto *crypto)
{
	u64 __t = SMT_TIME_START();

	spin_lock_bh(&sw_ctx->crypto_list_lock);
	list_add_tail(&crypto->list, &sw_ctx->crypto_list);
	sw_ctx->crypto_available++;
	spin_unlock_bh(&sw_ctx->crypto_list_lock);
	SMT_TIME_END(smt_sw_push, __t);
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
	/* assoclen is constant for this pool's lifetime; set once here.
	 * tfm is already pinned by aead_request_alloc(), no need to repeat.
	 */
	aead_request_set_ad(crypto->aead_req, SMT_RECORD_EXTRA_PRE_LENGTH);
	return crypto;

err_free_tfm:
	crypto_free_aead(crypto->tfm);
	kfree(crypto);
	return ERR_PTR(rc);
}

int smt_sw_set_offload(struct smt_context *ctx, int tx)
{
	struct smt_sw_context *sw_ctx;
	struct smt_sw_crypto *crypto;
	int target = min_t(int, num_online_cpus(),
			   homa_net(current->nsproxy->net_ns)->homa->smt_sw_pool_init);
	int i;

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

	/* Pre-populate the pool with one entry per online CPU. With per-call
	 * borrow scope, peak concurrent crypts <= N_CPUs, so the pool stays
	 * at this size forever and the alloc-on-empty branch never fires in
	 * the hot path. Best-effort: if any alloc fails partway, ship what
	 * we have; smt_sw_borrow will lazy-alloc later if it ever runs dry.
	 */
	for (i = 0; i < target; i++) {
		crypto = smt_sw_alloc_crypto(ctx, tx);
		if (IS_ERR(crypto))
			break;
		list_add_tail(&crypto->list, &sw_ctx->crypto_list);
		sw_ctx->crypto_available++;
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

	memcpy(r->iv, info->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, info->iv,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(r->rec_seq, info->rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	return 0;
}

/* Borrow a crypto pool entry for one encrypt/decrypt call. The entry is
 * released back via smt_sw_push_crypto at the end of the call. The pool
 * is pre-populated at smt_sw_set_offload time, so the alloc-on-empty
 * branch should not fire in steady state.
 */
static struct smt_sw_crypto *smt_sw_borrow_crypto(struct homa_rpc *rpc,
						  int tx)
{
	struct smt_context *ctx = SMT_RPC(rpc)->ctx;
	struct smt_sw_context *sw_ctx;
	struct smt_sw_crypto *crypto;
	u64 __t = SMT_TIME_START();
	u64 __t_alloc;

	sw_ctx = tx ? ctx->offload_tx : ctx->offload_rx;
	crypto = smt_sw_pop_crypto(sw_ctx);
	if (!crypto) {
		__t_alloc = SMT_TIME_START();
		crypto = smt_sw_alloc_crypto(ctx, tx);
		SMT_TIME_END(smt_sw_alloc, __t_alloc);
		if (IS_ERR(crypto))
			return crypto;
	}
	SMT_TIME_END(smt_sw_borrow, __t);
	return crypto;
}

static int smt_sw_do_crypt(struct smt_sw_crypto *crypto,
			   struct scatterlist *sgin,
			   struct scatterlist *sgout,
			   int crypt_len, u8 *iv, bool encrypt)
{
	struct aead_request *req = crypto->aead_req;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;
	u64 __t;

	/* tfm pinned by aead_request_alloc; assoclen pinned in alloc_crypto. */
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sgin, sgout, crypt_len, iv);

	__t = SMT_TIME_START();
	ret = crypto_wait_req(encrypt ? crypto_aead_encrypt(req)
				      : crypto_aead_decrypt(req),
			      &wait);
	if (encrypt)
		SMT_TIME_END(smt_sw_aead_enc, __t);
	else
		SMT_TIME_END(smt_sw_aead_dec, __t);
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
int smt_sw_encrypt(struct homa_rpc *rpc, struct sk_buff *skb, u8 *smt_h,
		   int payload_len)
{
	struct smt_rpc_sw_context *r = smt_rpc_sw_tx(rpc);
	struct smt_sw_context *sw_ctx = SMT_RPC(rpc)->ctx->offload_tx;
	struct smt_sw_crypto *crypto;
	struct scatterlist *sg;
	int nsg, ret;
	u64 __t = SMT_TIME_START();

	crypto = smt_sw_borrow_crypto(rpc, 1);
	if (IS_ERR(crypto))
		return PTR_ERR(crypto);

	sg = crypto->crypt_sg;

	memcpy(smt_h, r->rec_seq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 0] = 0x17;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 1] = 0x03;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 2] = 0x03;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 3] = payload_len >> 8;
	smt_h[TLS_CIPHER_AES_GCM_128_IV_SIZE + 4] = payload_len & 0xff;

#ifdef CONFIG_SMT_TX_LINEAR
	/* TODO: make ~200B-and-smaller messages always go through alloc_skb()
	 * into linear so this single-sg path covers them by default.
	 */
	if (skb_shinfo(skb)->nr_frags == 0) {
		/* TX-linear: smt_h + payload + tag are contiguous in linear,
		 * starting at smt_h. One sg entry covers the whole AEAD range.
		 */
		int total_len = SMT_RECORD_EXTRA_PRE_LENGTH + payload_len +
				SMT_RECORD_EXTRA_POST_LENGTH;

		sg_init_table(sg, 1);
		sg_set_buf(&sg[0], smt_h, total_len);
		nsg = 1;
	} else {
#endif
	int n = skb_shinfo(skb)->nr_frags;
	int i;

	if (unlikely(n > SMT_MAX_CRYPT_SG)) {
		smt_pr_err("%s: too many frags %d\n", __func__, n);
		ret = -EMSGSIZE;
		goto out;
	}
	sg_init_table(sg, n);
	for (i = 0; i < n; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];

		sg_set_page(&sg[i], skb_frag_page(f),
				skb_frag_size(f), skb_frag_off(f));
	}
	nsg = n;
#ifdef CONFIG_SMT_TX_LINEAR
	}
#endif
	ret = smt_sw_do_crypt(crypto, sg, sg, payload_len, r->iv, true);
	if (unlikely(ret)) {
		smt_pr_err("%s: encrypt failed %d\n", __func__, ret);
		goto out;
	}
	smt_pr_info("smt_sw_encrypt: rpc %lld payload_len=%d nsg=%d rec_seq=%*phN\n",
	       rpc->id, payload_len, nsg,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE, r->rec_seq);

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
	ret = 0;
out:
	smt_sw_push_crypto(sw_ctx, crypto);
	SMT_TIME_END(smt_sw_encrypt, __t);
	return ret;
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
	struct smt_sw_context *sw_ctx = SMT_RPC(rpc)->ctx->offload_rx;
	struct smt_sw_crypto *crypto;
	struct scatterlist *sg;
	u8 *smt_h;
	int i, nsg_total = 0, ret, crypt_len;
	int total_sg_bytes = 0;
	u64 __t = SMT_TIME_START();

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

	if (total_sg_bytes < SMT_RECORD_EXTRA_LENGTH) {
		ret = -EBADMSG;
		goto out;
	}
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

	smt_pr_devel(KERN_NOTICE "smt_sw_decrypt: rpc %lld n=%d crypt_len=%d total_sg_bytes=%d record_start=%d record_len=%d rec_seq=%*phN\n",
	       rpc->id, n, crypt_len, total_sg_bytes,
	       SMT_RX_INFO(skbs[0])->start, SMT_RX_INFO(skbs[0])->record_data_len,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE, r->rec_seq);

	ret = smt_sw_do_crypt(crypto, sg, sg, crypt_len, r->iv, false);
	if (unlikely(ret)) {
		smt_pr_err("%s: decrypt failed %d rpc %lld n=%d crypt_len=%d total_sg_bytes=%d\n",
			   __func__, ret, rpc->id, n, crypt_len,
			   total_sg_bytes);
		smt_pr_err("%s: rec_seq=%*phN iv=%*phN aad=%*phN\n",
			   __func__,
			   (int)TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE,
			   r->rec_seq,
			   (int)TLS_CIPHER_AES_GCM_128_SALT_SIZE +
				(int)TLS_CIPHER_AES_GCM_128_IV_SIZE,
			   r->iv,
			   SMT_RECORD_EXTRA_PRE_LENGTH, smt_h);
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

	smt_bigint_increment(r->rec_seq, sizeof(r->rec_seq));
	smt_bigint_increment(r->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			     TLS_CIPHER_AES_GCM_128_IV_SIZE);
	ret = 0;
out:
	smt_sw_push_crypto(sw_ctx, crypto);
	SMT_TIME_END(smt_sw_decrypt, __t);
	return ret;
}
