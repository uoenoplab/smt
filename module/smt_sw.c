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

// Copied from tls.h xor_iv_with_seq
static inline void smt_xor_iv_with_seq(u8 *iv, u8 *seq)
{
	int i;
	for (i = 0; i < 8; i++) {
		iv[i + 4] ^= seq[i];
	}
}

static int
__skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset, int len,
	       unsigned int recursion_level)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int elt = 0;

	if (unlikely(recursion_level >= 24))
		return -EMSGSIZE;

	if (copy > 0) {
		if (copy > len)
			copy = len;
		sg_set_buf(sg, skb->data + offset, copy);
		elt++;
		if ((len -= copy) == 0)
			return elt;
		offset += copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_frag_size(&skb_shinfo(skb)->frags[i]);
		if ((copy = end - offset) > 0) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			if (unlikely(elt && sg_is_last(&sg[elt - 1])))
				return -EMSGSIZE;

			if (copy > len)
				copy = len;
			sg_set_page(&sg[elt], skb_frag_page(frag), copy,
				    skb_frag_off(frag) + offset - start);
			elt++;
			if (!(len -= copy))
				return elt;
			offset += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end, ret;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (unlikely(elt && sg_is_last(&sg[elt - 1])))
				return -EMSGSIZE;

			if (copy > len)
				copy = len;
			ret = __skb_to_sgvec(frag_iter, sg+elt, offset - start,
					      copy, recursion_level + 1);
			if (unlikely(ret < 0))
				return ret;
			elt += ret;
			if ((len -= copy) == 0)
				return elt;
			offset += copy;
		}
		start = end;
	}
	BUG_ON(len);
	return elt;
}

static int inline
smt_skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg)
{
	// Mark start point after data_header (excluding data_segment)
	const int offset = sizeof(struct data_header) - sizeof(struct data_segment);

	// uncomment for debug on Mellanox NiC
	// sg_set_buf(sg, skb->data + offset, skb->len - offset);
	// return 1;

	return __skb_to_sgvec(skb, sg, offset, skb->len - offset, 0);
}

static struct smt_sw_crypto *
smt_sw_get_crypto(struct smt_sw_context *sw_ctx)
{
	struct smt_sw_crypto *crypto;

	spin_lock_bh(&sw_ctx->crypto_list_lock);

	if (list_empty(&sw_ctx->crypto_list)) {
		spin_unlock_bh(&sw_ctx->crypto_list_lock);
		return NULL;
	}

	crypto = list_first_entry(&sw_ctx->crypto_list, struct smt_sw_crypto, list);
	list_del(&crypto->list);

	spin_unlock_bh(&sw_ctx->crypto_list_lock);

	return crypto;
}

// Setup smt_ctx-level (5-tuple) sw context
int smt_set_sw_offload(struct smt_context *ctx,
			  struct kmem_cache *smt_sw_ctx_kmem, int tx)
{
	struct smt_sw_context *sw_ctx = NULL;

	sw_ctx = kmem_cache_alloc(smt_sw_ctx_kmem, GFP_ATOMIC);
	if (unlikely(!sw_ctx)) {
		smt_prerr_int("%s failed to alloc memory for sw_ctx\n", __FUNCTION__);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&sw_ctx->crypto_list);
	spin_lock_init(&sw_ctx->crypto_list_lock);
	sw_ctx->crypto_available = 0;

	if (tx)
		ctx->smt_offload_ctx_tx = sw_ctx;
	else
		ctx->smt_offload_ctx_rx = sw_ctx;

	return 0;
}

// Setup RPC-level sw context
int smt_set_rpc_sw_offload(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			  void **rpc_offload_ctx,
			  struct kmem_cache *smt_rpc_sw_ctx_kmem,
			  __u64 rpc_id)
{
	int rc = 0;
	struct smt_rpc_sw_context *rpc_sw_ctx = NULL;

	smt_prinf_int(KERN_WARNING "%s invoked\n", __FUNCTION__);

	rpc_sw_ctx = kmem_cache_alloc(smt_rpc_sw_ctx_kmem, GFP_ATOMIC);
	if (unlikely(!rpc_sw_ctx)) {
		smt_prerr_int("%s failed to alloc memory for rpc_sw_ctx\n", __FUNCTION__);
		return -ENOMEM;
	}

	// tfm is set later in syscall context at smt_sw_set_crypto
	rpc_sw_ctx->crypto = NULL;

	smt_set_composite_rec_seq_num(rpc_id, crypto_info->rec_seq,
					 rpc_sw_ctx->rec_seq);
	hexdump("smt_set_rpc_sw_offload rpc_sw_ctx->rec_seq ", rpc_sw_ctx->rec_seq,
		TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

	memcpy(rpc_sw_ctx->iv, crypto_info->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(rpc_sw_ctx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, rpc_sw_ctx->rec_seq,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	hexdump("smt_set_rpc_sw_offload rpc_sw_ctx->iv ", rpc_sw_ctx->iv,
		TLS_CIPHER_AES_GCM_128_IV_SIZE + TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	*rpc_offload_ctx = (void *) rpc_sw_ctx;

	return rc;
}

int smt_sw_set_crypto(struct homa_rpc *rpc, int tx)
{
	struct smt_context *ctx = rpc->smt_ctx;
	struct smt_sw_context *sw_ctx;
	struct smt_rpc_sw_context *rpc_sw_ctx;
	struct smt_sw_crypto *crypto;
	int rc = 0;

	sw_ctx = (struct smt_sw_context *)
		((tx) ? ctx->smt_offload_ctx_tx : ctx->smt_offload_ctx_rx);
	rpc_sw_ctx = (struct smt_rpc_sw_context *)
		((tx) ? rpc->smt_rpc_offload_ctx_tx : rpc->smt_rpc_offload_ctx_rx);

	// check whether can get a tfm from pool
	crypto = smt_sw_get_crypto(sw_ctx);
	if (crypto) {
		goto done;
	}

	// if not, create a new crpto
	crypto = kmalloc(sizeof(struct smt_sw_crypto), GFP_ATOMIC);
	if (unlikely(!crypto)) {
		smt_prerr_int("%s failed to alloc memory for crypto\n", __FUNCTION__);
		rc = -ENOMEM;
		goto error;
	}

	memset(crypto->decrypt_sg, 0, sizeof(crypto->decrypt_sg));

	// create tfm
	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm)) {
		smt_prerr_int("%s failed to alloc tfm\n", __FUNCTION__);
		rc = PTR_ERR(crypto->tfm);
		goto free_crypto;
	}
	if (tx)
		crypto_aead_setkey(crypto->tfm,
				   ctx->crypto_info_aes_gcm_128_send.key,
				   TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	else
		crypto_aead_setkey(crypto->tfm,
				   ctx->crypto_info_aes_gcm_128_recv.key,
				   TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	crypto_aead_setauthsize(crypto->tfm, TLS_CIPHER_AES_GCM_128_TAG_SIZE);

	// create aead_req
	crypto->aead_req = aead_request_alloc(crypto->tfm, GFP_ATOMIC);
	crypto->aead_req_size = sizeof(*crypto->aead_req)
				+ crypto_aead_reqsize(crypto->tfm);

	if (unlikely(!crypto->aead_req)) {
		rc = -ENOMEM;
		goto free_tfm;
	}

	goto done;

free_tfm:
	crypto_free_aead(crypto->tfm);
free_crypto:
	kfree(crypto);
error:
	crypto = NULL;
done:
	rpc_sw_ctx->crypto = crypto;
	return rc;
}

void
smt_sw_release_resources(struct smt_context *ctx,
			    struct kmem_cache *smt_sw_ctx_kmem, int tx)
{
	struct smt_sw_context *sw_ctx;
	struct smt_sw_crypto *crypto, *crypto_tmp;

	smt_prinf_int("%s invoked\n", __FUNCTION__);

	sw_ctx = (struct smt_sw_context *)
		((tx) ? ctx->smt_offload_ctx_tx : ctx->smt_offload_ctx_rx);

	list_for_each_entry_safe(crypto, crypto_tmp, &sw_ctx->crypto_list, list) {
		list_del(&crypto->list);
		crypto_free_aead(crypto->tfm);
		aead_request_free(crypto->aead_req);
		kfree(crypto);
	}

	kmem_cache_free(smt_sw_ctx_kmem, sw_ctx);
}

static int smt_sw_do_encrypt(struct sock *sk,
				struct smt_rpc_sw_context *rpc_sw_ctx,
				u8 *buf,
				int buf_len,
				int data_len)
{
	int ret = 0;
	struct scatterlist sg;
	struct aead_request *aead_req = rpc_sw_ctx->crypto->aead_req;
	DECLARE_CRYPTO_WAIT(async_wait);
	const int tail_size = 0;
	// const int tail_size = 1; // the one byte after real payload for TLS 1.3

	sg_init_one(&sg, buf, buf_len);

	aead_request_set_tfm(aead_req, rpc_sw_ctx->crypto->tfm);
	aead_request_set_ad(aead_req, SMT_RECORD_EXTRA_PRE_LENGTH);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &async_wait);
	aead_request_set_crypt(aead_req, &sg, &sg, data_len + tail_size,
			       rpc_sw_ctx->nonce);

	ret = crypto_wait_req(crypto_aead_encrypt(aead_req), &async_wait);
	if (unlikely(ret && (ret != -EINPROGRESS))) {
		printk(KERN_ERR "smt_sw_do_encrypt Software Encrypt Failed");
	}

	memset(aead_req, 0, rpc_sw_ctx->crypto->aead_req_size);
	return ret;
}

int smt_sw_encrypt(struct homa_rpc *rpc, u8 *smt_header,
		      u8 *smt_trailer)
{
	int ret = 0;
	struct smt_context *ctx __attribute__((unused)) = rpc->smt_ctx;
	struct smt_rpc_sw_context *ctx_tx =
		(struct smt_rpc_sw_context *)rpc->smt_rpc_offload_ctx_tx;
	u8 *buf = smt_header;
	int data_len = smt_trailer - smt_header - SMT_RECORD_EXTRA_PRE_LENGTH;
	int buf_len = data_len + SMT_RECORD_EXTRA_LENGTH;

	smt_prdbg_int("%s buf %px rpc %px header %px trailer %px",
		__FUNCTION__, buf, rpc, smt_header, smt_trailer);
	smt_prdbg_int("%s ctx %px ctx_tx %px ctx_tx->crypto->tfm %px",
		__FUNCTION__, ctx, ctx_tx, ctx_tx->crypto->tfm);

	// Make AAD (seq_num | tls_header)
	memcpy(smt_header, ctx_tx->rec_seq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	smt_header[TLS_CIPHER_AES_GCM_128_IV_SIZE+0] = 0x17;
	smt_header[TLS_CIPHER_AES_GCM_128_IV_SIZE+1] = 0x03;
	smt_header[TLS_CIPHER_AES_GCM_128_IV_SIZE+2] = 0x03;
	smt_header[TLS_CIPHER_AES_GCM_128_IV_SIZE+3] = data_len >> 8;
	smt_header[TLS_CIPHER_AES_GCM_128_IV_SIZE+4] = data_len & 0xff;

	memcpy(ctx_tx->nonce, ctx_tx->iv, sizeof(ctx_tx->nonce));
	hexdump("nonce ", ctx_tx->nonce, sizeof(ctx_tx->nonce));

	smt_prdbg_int("aad | plaintext | authtag (buf_len %d)\n", buf_len);
	hexdump("", buf, buf_len);

	ret = smt_sw_do_encrypt(&rpc->hsk->sock, ctx_tx, buf, buf_len, data_len);

	smt_prdbg_int("aad | ciphertext | authtag (buf_len %d)\n", buf_len);
	hexdump("", buf, buf_len);

	// Make header
	smt_header[0] = 0x17;
	smt_header[1] = 0x03;
	smt_header[2] = 0x03;
	smt_header[3] = (buf_len - TLS_HEADER_SIZE) >> 8;
	smt_header[4] = (buf_len - TLS_HEADER_SIZE) & 0xff;
	memcpy(smt_header + TLS_HEADER_SIZE, ctx_tx->rec_seq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	hexdump("header ", smt_header, SMT_RECORD_EXTRA_PRE_LENGTH);

	smt_bigint_increment(ctx_tx->rec_seq, sizeof(ctx_tx->rec_seq));
	smt_bigint_increment(ctx_tx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	hexdump("rec_seq (for next record) ", ctx_tx->rec_seq, sizeof(ctx_tx->rec_seq));
	hexdump("iv (for next record) ", ctx_tx->iv, sizeof(ctx_tx->iv));

	return ret;
}

static int smt_sw_do_decrypt(struct sock *sk,
				struct smt_rpc_sw_context *rpc_sw_ctx,
				struct scatterlist *sgin,
				struct scatterlist *sgout,
				int buf_len)
{
	int ret;
	struct aead_request *aead_req = rpc_sw_ctx->crypto->aead_req;
	DECLARE_CRYPTO_WAIT(async_wait);

	aead_request_set_tfm(aead_req, rpc_sw_ctx->crypto->tfm);
	aead_request_set_ad(aead_req, SMT_RECORD_EXTRA_PRE_LENGTH);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &async_wait);
	aead_request_set_crypt(aead_req, sgin, sgout,
			       buf_len - SMT_RECORD_EXTRA_PRE_LENGTH,
			       rpc_sw_ctx->nonce);

	ret = crypto_wait_req(crypto_aead_decrypt(aead_req), &async_wait);
	if (unlikely(ret))
		printk(KERN_ERR "%s software decrypt failed", __FUNCTION__);

	memset(aead_req, 0, rpc_sw_ctx->crypto->aead_req_size);
	return ret;
}

int smt_sw_decrypt(struct homa_rpc *rpc)
{
	struct sk_buff *skb, *skb_gso_head, *skb_gso_tail;
	struct scatterlist *sg, *sgout;
	struct smt_rpc_sw_context *ctx_rx =
		(struct smt_rpc_sw_context *) rpc->smt_rpc_offload_ctx_rx;
	struct homa_message_in *msgin = &rpc->msgin;
	u8 *smt_header;
	int skbs_nsg_offset = 0, decrypt_offset;
	int ret = 0;
	u16 smt_header_datalen;
	short gso_segs;

	skb_gso_head = skb_peek(msgin->smt_decrypt_skb);
	if (unlikely(!skb_gso_head))
		return -EBADMSG;

	smt_prinf_int("%s skb_gso_head %px\n", __FUNCTION__, skb_gso_head);

	atomic_or(RPC_DECRYPTING, &rpc->flags);
	homa_rpc_unlock(rpc);

	if (!ctx_rx->crypto)
		ret = smt_sw_set_crypto(rpc, 0);
	if (unlikely(ret))
		goto err;

	sg = ctx_rx->crypto->decrypt_sg;

	// /* Allocate a single block of memory which contains
	//  * aead_req || sg[]
	//  * the decryption is performed inplace for now os sgin is same with sgout
	//  */

	hexdump("skb_gso_head->data ", skb_gso_head->data, HOMA_MAX_HEADER);
	gso_segs = skb_shinfo(skb_gso_head)->gso_segs;
	smt_header = skb_gso_head->data + sizeof(struct data_header) - sizeof(struct data_segment);
	smt_header_datalen = (smt_header[3] << 8) | (smt_header[4] & 0xff);
	smt_header_datalen -= TLS_CIPHER_AES_GCM_128_IV_SIZE + TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	memcpy(smt_header, ctx_rx->rec_seq, sizeof(ctx_rx->rec_seq));
	smt_header += TLS_CIPHER_AES_GCM_128_IV_SIZE;
	smt_header[0] = TLS_RECORD_TYPE_DATA;
	smt_header[1] = TLS_1_2_VERSION_MAJOR;
	smt_header[2] = TLS_1_2_VERSION_MINOR;
	smt_header[3] = smt_header_datalen >> 8;
	smt_header[4] = smt_header_datalen & 0xFF;
	hexdump("skb_gso_head->data ", skb_gso_head->data, HOMA_MAX_HEADER);

	smt_prdbg_int("%s gso_segs %d smt_header_datalen %d", __func__, gso_segs, smt_header_datalen);

	for (skb = skb_gso_head;; skb = skb->next) {
		smt_prdbg_int("%s skb_gso_head %px skb %px skb->next %px",
			__FUNCTION__, skb_gso_head, skb, skb->next);
		smt_prdbg_int("%s skbs_nsg_offset %d\n", __FUNCTION__, skbs_nsg_offset);
		ret = smt_skb_to_sgvec(skb, &sg[skbs_nsg_offset]);
		if (unlikely(ret <= 0)) {
			ret = -EBADMSG;
			goto end;
		}
		skbs_nsg_offset += ret;
		if ((smt_fake_ip_id(skb) + 1 == gso_segs) ||
			(skb == (void *) msgin->smt_gsoseg_skb))
			break;
	}
	ret = 0;
	smt_prinf_int("%s skbs_nsg_offset %d\n", __FUNCTION__, skbs_nsg_offset);
	sg_mark_end(&sg[skbs_nsg_offset - 1]);
	skb_gso_tail = skb;

	// Setup destination for the decrypted data here, now it is just sgin
	sgout = sg;

	memcpy(ctx_rx->nonce, ctx_rx->iv, sizeof(ctx_rx->nonce));
	hexdump("nonce ", ctx_rx->nonce, sizeof(ctx_rx->nonce));

	ret = smt_sw_do_decrypt(&rpc->hsk->sock, ctx_rx, sg, sgout,
		smt_header_datalen + SMT_RECORD_EXTRA_LENGTH);
	if (unlikely(ret)) {
		hexdump("rec_seq ", ctx_rx->rec_seq, sizeof(ctx_rx->rec_seq));
		hexdump("iv ", ctx_rx->iv, sizeof(ctx_rx->iv));
		hexdump("nonce ", ctx_rx->nonce, sizeof(ctx_rx->nonce));
		printk("%s decrypt_offset %d", __FUNCTION__, decrypt_offset);
		for (skb = skb_gso_head; skb != skb_gso_tail->next; skb = skb->next) {
			int len = skb->len - 40;
			unsigned char* buf = skb->data + 40;
			printk("%s rpc->id %lld gso_offset %d ip_id %d extra_ip_id %d skb->len %d \n",
				__FUNCTION__, rpc->id, smt_gso_offset(skb),
				smt_ip_id(skb), smt_extra_ip_id(skb), skb->len);
			while (len--) {
				printk(KERN_CONT "%02x ", *buf);
				buf++;
			}
			printk(KERN_CONT "\n");
		}
		// ret = 0;
		// smt_sw_unset_crypto(rpc, 0);
		// goto err;
	}
	sg_unmark_end(&sg[skbs_nsg_offset - 1]);
	// memset(ctx_rx->crypto->decrypt_sg, 0, sizeof(struct scatterlist) * skbs_nsg_offset);

	// all incoming data from is rpc is decrypted, put back crypto instance
	decrypt_offset = smt_gso_offset(skb) + smt_header_datalen -
		gso_segs * sizeof(struct data_segment);
	smt_prinf_int("%s skb_gso_tail %px decrypt_offset %d\n",
		__FUNCTION__, skb_gso_tail, decrypt_offset);
	if (decrypt_offset == msgin->total_length)
		smt_sw_unset_crypto(rpc, 0);

	smt_bigint_increment(ctx_rx->rec_seq, sizeof(ctx_rx->rec_seq));
	smt_bigint_increment(ctx_rx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	hexdump("rec_seq (for next record) ", ctx_rx->rec_seq, sizeof(ctx_rx->rec_seq));
	hexdump("iv (for next record) ", ctx_rx->iv, sizeof(ctx_rx->iv));

	homa_rpc_lock(rpc);
	atomic_andnot(RPC_DECRYPTING, &rpc->flags);

	msgin->smt_decrypt_offset = decrypt_offset;
	msgin->smt_decrypt_skb = (struct sk_buff_head *) skb_gso_tail;

	smt_prdbg_int("%s offset %d skb %px\n",
		__FUNCTION__, msgin->smt_decrypt_offset, msgin->smt_decrypt_skb);

	// delete last skb if last skb does not contain segment header, only TLS trailer
	if (unlikely(skb_gso_tail->len < sizeof32(struct data_header))) {
		msgin->smt_decrypt_skb = (struct sk_buff_head *) skb_gso_tail->prev;
		if (unlikely(msgin->smt_gsoseg_skb == (struct sk_buff_head *) skb_gso_tail))
			msgin->smt_gsoseg_skb = msgin->smt_decrypt_skb;
		skb_unlink(skb_gso_tail, &msgin->packets);

		// smt_prdbg_int(
		// 	"%s:\n"
		// 	"  offset: %d\n"
		// 	"  skb_gso_tail: %px (len: %d, prev: %px, next: %px)\n"
		// 	"  smt_decrypt_skb: %px (prev: %px, next: %px)\n"
		// 	"  smt_gsoseg_skb: %px\n"
		// 	"  packets queue head: %px (next: %px, prev: %px, empty: %d)\n",
		// 	__FUNCTION__,
		// 	msgin->smt_decrypt_offset,
		// 	skb_gso_tail, skb_gso_tail->len, skb_gso_tail->prev, skb_gso_tail->next,
		// 	msgin->smt_decrypt_skb, msgin->smt_decrypt_skb->prev, msgin->smt_decrypt_skb->next,
		// 	msgin->smt_gsoseg_skb,
		// 	&msgin->packets, msgin->packets.next, msgin->packets.prev,
		// 	skb_queue_empty(&msgin->packets)
		// );

		kfree_skb(skb_gso_tail);
	}

	goto end;

err:
	homa_rpc_lock(rpc);
end:
	return ret;
}
