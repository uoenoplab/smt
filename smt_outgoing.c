// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* SMT transmit path. Each GSO packet of an SMT message is one TLS record:
 *
 *   linear: homa_data_hdr minus its homa_seg_hdr, then smt_h (TLS record
 *           header, plus the explicit nonce in TLS 1.2)
 *   frags:  seg_hdr, data, seg_hdr, data, ..., trailer (TLS 1.3's content
 *           type, then the tag)
 *
 * GSO cuts the payload every max_seg_data + sizeof(homa_seg_hdr) bytes, so
 * the first segment carries smt_h plus max_seg_data - rec_pre data bytes,
 * and the trailer spills into a final segment without a seg_hdr when the
 * last one has no room for it. With CONFIG_SMT_NO_SEG_HDR the frags carry
 * no seg_hdrs (data, then the trailer), so every segment carries
 * SMT_SEG_DATA(max_seg_data) bytes of the record. A record
 * holds rpc->msgout.max_gso_data message bytes (the last one may hold
 * fewer). The frags part of every record is laid out in rpc->msgout.frags
 * when the message is copied in from user space, and encrypted there for
 * SW crypto; smt_h is derived from the record index whenever the packet is
 * built, so a retransmitted record is byte-identical to the original.
 */

#include <linux/unaligned.h>
#include <net/tls.h>

#include "smt_impl.h"

#include "homa_tx_pool.h"

/* h->pad holds a record's offset in 24 bits, and smt_rpc_rec_seq leaves 16
 * bits to count a message's records.
 */
static_assert(HOMA_MAX_MESSAGE_LENGTH < 1 << 24);
static_assert(DIV_ROUND_UP(HOMA_MAX_MESSAGE_LENGTH,
			   HOMA_MIN_SEG_DATA - SMT_RECORD_PRE_MAX -
			   SMT_RECORD_POST_MAX) < 1 << 16);

/* Message bytes in the record that starts at @offset. */
static inline int smt_tx_rec_len(struct homa_rpc *rpc, u32 offset)
{
	return min_t(int, rpc->msgout.length - offset,
		     rpc->msgout.max_gso_data);
}

/* Number of segments in a record of @len message bytes that carry data
 * (and hence a homa_seg_hdr).
 */
static inline int smt_tx_rec_segs(struct homa_rpc *rpc, int len)
{
	return DIV_ROUND_UP(len + SMT_RPC(rpc)->rec_pre,
			    SMT_SEG_DATA(rpc->msgout.max_seg_data));
}

/* Bytes of rpc->msgout.frags occupied by a record of @len message bytes. */
static inline int smt_tx_rec_frag_bytes(struct homa_rpc *rpc, int len)
{
	return smt_tx_rec_segs(rpc, len) * SMT_SEG_HDR + len +
	       SMT_RPC(rpc)->rec_post;
}

/**
 * smt_tx_init() - Adjust the packet geometry set by homa_message_out_init
 * for an SMT message: each GSO packet is one record, whose header and tag
 * take room from message data. A record holds at most TLS_MAX_PAYLOAD_SIZE
 * bytes of plaintext and reaches the receiver in at most
 * SMT_MAX_RECORD_SEGS packets.
 * @rpc:  RPC whose outgoing message is being initialized.
 */
void smt_tx_init(struct homa_rpc *rpc)
{
	int extra = SMT_RPC(rpc)->rec_pre + SMT_RPC(rpc)->rec_post;
	int segs = min_t(int, rpc->msgout.max_gso_segs, SMT_MAX_RECORD_SEGS);

	segs = min_t(int, segs, (TLS_MAX_PAYLOAD_SIZE + extra) /
		     (rpc->msgout.max_seg_data + sizeof(struct homa_seg_hdr)));
	rpc->msgout.max_gso_segs = max(segs, 1);
	rpc->msgout.max_gso_data = rpc->msgout.max_gso_segs *
				   SMT_SEG_DATA(rpc->msgout.max_seg_data) - extra;
}

/**
 * smt_tx_frag_bytes() - Return the number of bytes needed in
 * rpc->msgout.frags to hold an SMT message. homa_message_out_init must
 * have been invoked.
 * @rpc:  RPC whose outgoing message is to be laid out.
 * Return: See above.
 */
int smt_tx_frag_bytes(struct homa_rpc *rpc)
{
	int recs = rpc->msgout.length / rpc->msgout.max_gso_data;
	int rest = rpc->msgout.length - recs * rpc->msgout.max_gso_data;

	return recs * smt_tx_rec_frag_bytes(rpc, rpc->msgout.max_gso_data) +
	       (rest ? smt_tx_rec_frag_bytes(rpc, rest) : 0);
}

/**
 * smt_tx_fill() - Copy an SMT message in from user space, laying it out
 * as records in rpc->msgout.frags and sealing each record before making it
 * visible to homa_xmit_data via rpc->msgout.copied_from_user. The RPC must
 * not be locked.
 * @rpc:     RPC whose outgoing message is being filled.
 * @filler:  Positioned at the start of rpc->msgout.frags.
 * @iter:    Message data in user space.
 * @xmit:    Whether the caller transmits once the message is filled. With
 *           CONFIG_SMT_TX_PIPELINE, each record but the last is then passed
 *           to homa_xmit_data (still subject to grants, with the RPC locked
 *           around it) as soon as it is sealed, so that transmission
 *           overlaps the encryption of the next; upstream sends nothing
 *           before the whole message is copied in.
 * Return:   Zero for success, otherwise a negative errno.
 */
int smt_tx_fill(struct homa_rpc *rpc, struct homa_frag_filler *filler,
		struct iov_iter *iter, bool xmit)
{
	int pre = SMT_RPC(rpc)->rec_pre, post = SMT_RPC(rpc)->rec_post;
	u8 trailer[SMT_RECORD_POST_MAX];
	u32 offset, seg, end;
	int size, err;

#ifdef CONFIG_SMT_NOCRYPTO
	memset(trailer, 0xff, sizeof(trailer));
#else
	/* SW encryption and the NIC both overwrite the tag. */
	memset(trailer, 0, sizeof(trailer));
#endif
	/* TLS 1.3: the content type (application data) ends the plaintext. */
	if (smt_rpc_tls13(rpc))
		trailer[0] = 0x17;

	for (offset = 0; offset < rpc->msgout.length; offset = end) {
		struct homa_frag_filler rec = *filler;

		end = offset + smt_tx_rec_len(rpc, offset);
		for (seg = offset; seg < end; seg += size) {
			struct homa_seg_hdr seg_hdr;

			size = min_t(u32, end - seg,
				     SMT_SEG_DATA(rpc->msgout.max_seg_data) -
				     (seg == offset ? pre : 0));
			if (SMT_SEG_HDR) {
				seg_hdr.offset = htonl(seg);
				err = homa_copy_to_frags(filler, &seg_hdr,
							 sizeof(seg_hdr));
				if (unlikely(err))
					return err;
			}
			err = homa_copy_iter_to_frags(filler, iter, size);
			if (unlikely(err))
				return err;
		}
		err = homa_copy_to_frags(filler, trailer, post);
		if (unlikely(err))
			return err;
		if (SMT_RPC(rpc)->ctx->tx_conf == SMT_SW) {
			err = smt_sw_encrypt(rpc, offset / rpc->msgout.max_gso_data,
					     &rec, smt_tx_rec_frag_bytes(rpc, end - offset) -
					     TLS_CIPHER_AES_GCM_128_TAG_SIZE);
			if (unlikely(err))
				return err;
		}
		smp_store_release(&rpc->msgout.copied_from_user, end);
#ifdef CONFIG_SMT_TX_PIPELINE
		if (xmit && end < rpc->msgout.length) {
			homa_rpc_lock(rpc);
			homa_xmit_data(rpc);
			homa_rpc_unlock(rpc);
		}
#endif
	}
	return 0;
}

/**
 * smt_tx_skb_range() - Find the record to transmit for a given offset.
 * @rpc:     RPC whose message is being transmitted.
 * @offset:  Offset within the message that the packet must contain;
 *           modified to hold the offset of the record's first byte.
 * @end:     Modified to hold the offset just after the record's last byte.
 * @bytes:   Modified to hold the number of bytes of rpc->msgout.frags that
 *           make up the record.
 * @segs:    Modified to hold the number of GSO segments in the record.
 * Return:   Offset within rpc->msgout.frags of the record's first byte.
 */
int smt_tx_skb_range(struct homa_rpc *rpc, u32 *offset, u32 *end,
		     int *bytes, u64 *segs)
{
	u32 rec = *offset / rpc->msgout.max_gso_data;

	*offset = rec * rpc->msgout.max_gso_data;
	*end = *offset + smt_tx_rec_len(rpc, *offset);
	*bytes = smt_tx_rec_frag_bytes(rpc, *end - *offset);
	*segs = DIV_ROUND_UP(SMT_RPC(rpc)->rec_pre + *bytes,
			     rpc->msgout.max_seg_data +
			     sizeof(struct homa_seg_hdr));
	return rec * smt_tx_rec_frag_bytes(rpc, rpc->msgout.max_gso_data);
}

/**
 * smt_tx_skb_hdr() - Add the SMT fields to the linear part of an outgoing
 * DATA packet, after Homa has filled in its homa_data_hdr and before any
 * frags are attached.
 * @rpc:     RPC whose message is being transmitted.
 * @skb:     The packet.
 * @offset:  Offset within the message of the packet's record.
 */
void smt_tx_skb_hdr(struct homa_rpc *rpc, struct sk_buff *skb, u32 offset)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)
				  skb_transport_header(skb);
	u8 *smt_h = skb_transport_header(skb) + sizeof(struct homa_data_hdr) -
		    sizeof(struct homa_seg_hdr);
	int nonce_len = smt_rpc_tls13(rpc) ? 0 : TLS_CIPHER_AES_GCM_128_IV_SIZE;
	int len = smt_tx_rec_len(rpc, offset);
	int tls_len;

	/* smt_h takes the place of the first seg_hdr, which leads the
	 * record's frags instead.
	 */
	skb_put(skb, SMT_RPC(rpc)->rec_pre - sizeof(struct homa_seg_hdr));
	tls_len = nonce_len + smt_tx_rec_frag_bytes(rpc, len);
	smt_h[0] = 0x17;
	smt_h[1] = 0x03;
	smt_h[2] = 0x03;
	smt_h[3] = tls_len >> 8;
	smt_h[4] = tls_len & 0xff;
	/* TLS 1.2's explicit nonce is the record's sequence number. */
	if (nonce_len) {
#ifdef CONFIG_SMT_NOCRYPTO
		memset(smt_h + TLS_HEADER_SIZE, 0xff, nonce_len);
#else
		put_unaligned_be64(get_unaligned_be64(smt_rpc_tx_rec_seq(rpc)) +
				   offset / rpc->msgout.max_gso_data,
				   smt_h + TLS_HEADER_SIZE);
#endif
	}

	/* The receiver places each segment by the record's offset in pad
	 * (GSO replicates it into every segment) and the segment's IP id;
	 * sequence carries the offset too.
	 */
	h->pad[0] = (offset >> 16) & 0xff;
	h->pad[1] = (offset >> 8) & 0xff;
	h->pad[2] = offset & 0xff;
	h->common.sequence = htonl(offset);
}

