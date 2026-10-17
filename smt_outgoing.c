// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* SMT transmit path. Each GSO packet of an SMT message is one TLS record:
 *
 *   linear: homa_data_hdr minus its homa_seg_hdr, then smt_h (TLS record
 *           header + explicit nonce)
 *   frags:  seg_hdr, data, seg_hdr, data, ..., tag
 *
 * GSO cuts the payload every max_seg_data + sizeof(homa_seg_hdr) bytes, so
 * the first segment carries smt_h plus max_seg_data -
 * SMT_RECORD_EXTRA_PRE_LENGTH data bytes, and the tag spills into a final
 * segment without a seg_hdr when the last one has no room for it. A record
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
			   HOMA_MIN_SEG_DATA - SMT_RECORD_EXTRA_LENGTH) < 1 << 16);

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
	return DIV_ROUND_UP(len + SMT_RECORD_EXTRA_PRE_LENGTH,
			    rpc->msgout.max_seg_data);
}

/* Bytes of rpc->msgout.frags occupied by a record of @len message bytes. */
static inline int smt_tx_rec_frag_bytes(struct homa_rpc *rpc, int len)
{
	return smt_tx_rec_segs(rpc, len) * sizeof(struct homa_seg_hdr) + len +
	       SMT_RECORD_EXTRA_POST_LENGTH;
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
	int segs = min_t(int, rpc->msgout.max_gso_segs, SMT_MAX_RECORD_SEGS);

	segs = min_t(int, segs, (TLS_MAX_PAYLOAD_SIZE + SMT_RECORD_EXTRA_LENGTH) /
		     (rpc->msgout.max_seg_data + sizeof(struct homa_seg_hdr)));
	rpc->msgout.max_gso_segs = max(segs, 1);
	rpc->msgout.max_gso_data = rpc->msgout.max_gso_segs *
				   rpc->msgout.max_seg_data -
				   SMT_RECORD_EXTRA_LENGTH;
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
 * Return:   Zero for success, otherwise a negative errno.
 */
int smt_tx_fill(struct homa_rpc *rpc, struct homa_frag_filler *filler,
		struct iov_iter *iter)
{
	u8 tag[SMT_RECORD_EXTRA_POST_LENGTH];
	u32 offset, seg, end;
	int size, err;

#ifdef CONFIG_SMT_NOCRYPTO
	memset(tag, 0xff, sizeof(tag));
#else
	/* SW encryption and the NIC both overwrite the tag. */
	memset(tag, 0, sizeof(tag));
#endif
#ifdef CONFIG_SMT_HW
	if (SMT_RPC(rpc)->ctx->tx_conf == SMT_HW) {
		err = smt_device_set_crypto_tx(rpc);
		if (err)
			return err;
	}
#endif

	for (offset = 0; offset < rpc->msgout.length; offset = end) {
		struct homa_frag_filler rec = *filler;

		end = offset + smt_tx_rec_len(rpc, offset);
		for (seg = offset; seg < end; seg += size) {
			struct homa_seg_hdr seg_hdr;

			size = min_t(u32, end - seg, rpc->msgout.max_seg_data -
				     (seg == offset ?
				      SMT_RECORD_EXTRA_PRE_LENGTH : 0));
			seg_hdr.offset = htonl(seg);
			err = homa_copy_to_frags(filler, &seg_hdr,
						 sizeof(seg_hdr));
			if (unlikely(err))
				return err;
			err = homa_copy_iter_to_frags(filler, iter, size);
			if (unlikely(err))
				return err;
		}
		err = homa_copy_to_frags(filler, tag, sizeof(tag));
		if (unlikely(err))
			return err;
		if (SMT_RPC(rpc)->ctx->tx_conf == SMT_SW) {
			err = smt_sw_encrypt(rpc, offset / rpc->msgout.max_gso_data,
					     &rec, smt_tx_rec_frag_bytes(rpc, end - offset) -
					     SMT_RECORD_EXTRA_POST_LENGTH);
			if (unlikely(err))
				return err;
		}
		smp_store_release(&rpc->msgout.copied_from_user, end);
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
	*segs = DIV_ROUND_UP(SMT_RECORD_EXTRA_PRE_LENGTH + *bytes,
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
	int len = smt_tx_rec_len(rpc, offset);
	int tls_len;

	/* smt_h takes the place of the first seg_hdr, which leads the
	 * record's frags instead.
	 */
	skb_put(skb, SMT_SKB_LINEAR_EXTRA);
	tls_len = TLS_CIPHER_AES_GCM_128_IV_SIZE +
		  smt_tx_rec_frag_bytes(rpc, len);
	smt_h[0] = 0x17;
	smt_h[1] = 0x03;
	smt_h[2] = 0x03;
	smt_h[3] = tls_len >> 8;
	smt_h[4] = tls_len & 0xff;
#ifdef CONFIG_SMT_NOCRYPTO
	memset(smt_h + TLS_HEADER_SIZE, 0xff, TLS_CIPHER_AES_GCM_128_IV_SIZE);
#else
	put_unaligned_be64(get_unaligned_be64(smt_rpc_tx_rec_seq(rpc)) +
			   offset / rpc->msgout.max_gso_data,
			   smt_h + TLS_HEADER_SIZE);
#endif

	/* The receiver places each segment using the record's offset
	 * (replicated into every segment by GSO) and the segment's IP id.
	 * The HW path has always sent the same value in the sequence field.
	 */
	h->pad[0] = (offset >> 16) & 0xff;
	h->pad[1] = (offset >> 8) & 0xff;
	h->pad[2] = offset & 0xff;
	h->common.sequence = htonl(offset);
#ifdef CONFIG_SMT_HW
	smt_hw_attach_skb(rpc, skb);
#endif
}

#ifdef CONFIG_SMT_HW
/**
 * smt_tx_xmit_done() - Called at the end of homa_xmit_data: once all of
 * the message has been handed to the IP stack, return the RPC's TIS slot
 * to its pool (its driver_state stays valid for retransmissions).
 * @rpc:  RPC that has been transmitting.
 */
void smt_tx_xmit_done(struct homa_rpc *rpc)
{
	if (SMT_RPC(rpc)->ctx->tx_conf == SMT_HW &&
	    rpc->msgout.next_xmit_offset >= rpc->msgout.length)
		smt_device_release_tis(rpc);
}
#endif /* CONFIG_SMT_HW */
