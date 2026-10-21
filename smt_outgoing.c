// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* SMT transmit path. An SMT message is a sequence of TLS records, each
 * filling whole segments, and a GSO packet carries one or more whole
 * records. The segments of a record are:
 *
 *   first:  homa_data_hdr minus its homa_seg_hdr, smt_h (TLS record
 *           header, plus the explicit nonce in TLS 1.2), seg_hdr, data
 *   others: homa_data_hdr minus its homa_seg_hdr, seg_hdr, data
 *
 * and the trailer (TLS 1.3's content type, then the tag) ends the last one.
 * GSO cuts the payload every max_seg_data + sizeof(homa_seg_hdr) bytes, so
 * the first segment carries max_seg_data - rec_pre data bytes, and the
 * trailer spills into a final segment without a seg_hdr when the last one
 * has no room for it. A full record is rec_segs segments holding rec_data
 * message bytes; only the message's last record is shorter. The receiver
 * finds each segment's record from its IP id, rec_segs and the offset of
 * the packet's first record (smt_tx_skb_hdr). The payload of every record,
 * smt_h included, is laid out in rpc->msgout.frags when the message is
 * copied in from user space, and encrypted there for SW crypto, so a
 * retransmitted record is byte-identical to the original.
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

/* Payload bytes in a full GSO segment. */
static inline int smt_tx_seg_bytes(struct homa_rpc *rpc)
{
	return rpc->msgout.max_seg_data + sizeof(struct homa_seg_hdr);
}

/* Message bytes in the record that starts at @offset. */
static inline int smt_tx_rec_len(struct homa_rpc *rpc, u32 offset)
{
	return min_t(int, rpc->msgout.length - offset, SMT_RPC(rpc)->rec_data);
}

/* Number of segments in a record of @len message bytes that carry data
 * (and hence a homa_seg_hdr).
 */
static inline int smt_tx_rec_segs(struct homa_rpc *rpc, int len)
{
	return DIV_ROUND_UP(len + SMT_RPC(rpc)->rec_pre,
			    SMT_SEG_DATA(rpc->msgout.max_seg_data));
}

/* Bytes of rpc->msgout.frags occupied by a record of @len message bytes:
 * rec_segs full segments for a full record.
 */
static inline int smt_tx_rec_frag_bytes(struct homa_rpc *rpc, int len)
{
	return SMT_RPC(rpc)->rec_pre + smt_tx_rec_segs(rpc, len) * SMT_SEG_HDR +
	       len + SMT_RPC(rpc)->rec_post;
}

/**
 * smt_tx_init() - Adjust the packet geometry set by homa_message_out_init
 * for an SMT message. A record holds at most TLS_MAX_PAYLOAD_SIZE bytes of
 * plaintext and fills at most SMT_MAX_RECORD_SEGS segments (and
 * net.homa.smt_record_segs, if set); its header and tag take room from
 * message data. A GSO packet holds whole records.
 * @rpc:  RPC whose outgoing message is being initialized.
 */
void smt_tx_init(struct homa_rpc *rpc)
{
	int extra = SMT_RPC(rpc)->rec_pre + SMT_RPC(rpc)->rec_post;
	int limit = rpc->hsk->homa->smt_record_segs;
	int segs = min_t(int, rpc->msgout.max_gso_segs, SMT_MAX_RECORD_SEGS);

	segs = min_t(int, segs, (TLS_MAX_PAYLOAD_SIZE + extra) /
		     smt_tx_seg_bytes(rpc));
	if (limit > 0)
		segs = min(segs, limit);
	segs = max(segs, 1);
	SMT_RPC(rpc)->rec_segs = segs;
	SMT_RPC(rpc)->rec_data = segs * SMT_SEG_DATA(rpc->msgout.max_seg_data) -
				 extra;
	rpc->msgout.max_gso_segs -= rpc->msgout.max_gso_segs % segs;
	/* homa_xmit_data waits for this much sealed data before it sends
	 * during the copy: one record, so that each record leaves as soon as
	 * it is sealed. Packets built later (after the copy, on grants and
	 * for retransmits) hold up to max_gso_segs / segs records.
	 */
	rpc->msgout.max_gso_data = SMT_RPC(rpc)->rec_data;
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
	int recs = rpc->msgout.length / SMT_RPC(rpc)->rec_data;
	int rest = rpc->msgout.length - recs * SMT_RPC(rpc)->rec_data;

	return recs * SMT_RPC(rpc)->rec_segs * smt_tx_seg_bytes(rpc) +
	       (rest ? smt_tx_rec_frag_bytes(rpc, rest) : 0);
}

/* Write smt_h of record @rec, which holds @len message bytes. */
static void smt_tx_rec_hdr(struct homa_rpc *rpc, u32 rec, int len, u8 *smt_h)
{
	/* The length counts everything after the header. */
	int tls_len = smt_tx_rec_frag_bytes(rpc, len) - TLS_HEADER_SIZE;

	smt_h[0] = 0x17;
	smt_h[1] = 0x03;
	smt_h[2] = 0x03;
	smt_h[3] = tls_len >> 8;
	smt_h[4] = tls_len & 0xff;
	/* TLS 1.2's explicit nonce is the record's sequence number. */
	if (smt_rpc_tls13(rpc))
		return;
#ifdef CONFIG_SMT_NOCRYPTO
	memset(smt_h + TLS_HEADER_SIZE, 0xff, TLS_CIPHER_AES_GCM_128_IV_SIZE);
#else
	put_unaligned_be64(get_unaligned_be64(smt_rpc_tx_rec_seq(rpc)) + rec,
			   smt_h + TLS_HEADER_SIZE);
#endif
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
	u8 smt_h[SMT_RECORD_PRE_MAX], trailer[SMT_RECORD_POST_MAX];
	u32 offset, seg, end, rec;
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

	for (offset = 0, rec = 0; offset < rpc->msgout.length;
	     offset = end, rec++) {
		struct homa_frag_filler pos;

		end = offset + smt_tx_rec_len(rpc, offset);
		smt_tx_rec_hdr(rpc, rec, end - offset, smt_h);
		err = homa_copy_to_frags(filler, smt_h, pre);
		if (unlikely(err))
			return err;
		pos = *filler;
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
			err = smt_sw_encrypt(rpc, rec, &pos,
					     smt_tx_rec_frag_bytes(rpc, end - offset) -
					     pre - TLS_CIPHER_AES_GCM_128_TAG_SIZE);
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
 * smt_tx_skb_range() - Find the records to transmit in one packet: the
 * record holding a given offset and those after it, up to the one holding
 * the last byte wanted, the last one sealed, or as many as a GSO packet
 * holds.
 * @rpc:     RPC whose message is being transmitted.
 * @offset:  Offset within the message that the packet must contain;
 *           modified to hold the offset of the first record's first byte.
 * @end:     Offset just after the last byte wanted; modified to hold the
 *           offset just after the last record's last byte.
 * @bytes:   Modified to hold the number of bytes of rpc->msgout.frags that
 *           make up the records.
 * @segs:    Modified to hold the number of GSO segments in the packet.
 * Return:   Offset within rpc->msgout.frags of the first record's first
 *           byte.
 */
int smt_tx_skb_range(struct homa_rpc *rpc, u32 *offset, u32 *end,
		     int *bytes, u64 *segs)
{
	int data = SMT_RPC(rpc)->rec_data;
	int full = SMT_RPC(rpc)->rec_segs * smt_tx_seg_bytes(rpc);
	u32 first = *offset / data;
	u32 last = (max(*end, *offset + 1) - 1) / data;
	int sealed;

	/* Only records that smt_tx_fill has sealed (pairs with its
	 * smp_store_release); the caller makes sure that the first one is.
	 */
	sealed = smp_load_acquire(&rpc->msgout.copied_from_user);
	last = min_t(u32, last, (sealed - 1) / data);
	last = min_t(u32, last, first + rpc->msgout.max_gso_segs /
		     SMT_RPC(rpc)->rec_segs - 1);
	*offset = first * data;
	*end = min_t(u32, (last + 1) * data, rpc->msgout.length);
	*bytes = (last - first) * full +
		 smt_tx_rec_frag_bytes(rpc, *end - last * data);
	*segs = DIV_ROUND_UP(*bytes, smt_tx_seg_bytes(rpc));
	return first * full;
}

/**
 * smt_tx_skb_hdr() - Fill in the SMT fields of an outgoing DATA packet,
 * after Homa has filled in its homa_data_hdr and before any frags are
 * attached.
 * @rpc:     RPC whose message is being transmitted.
 * @skb:     The packet.
 * @offset:  Offset within the message of the packet's first record.
 */
void smt_tx_skb_hdr(struct homa_rpc *rpc, struct sk_buff *skb, u32 offset)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)
				  skb_transport_header(skb);

	/* The payload, smt_h first, is all in frags. */
	__skb_trim(skb, skb->len - sizeof(struct homa_seg_hdr));

	/* The receiver places each segment by the offset of the packet's
	 * first record in pad, the segments in each record in reserved1
	 * (GSO replicates both into every segment) and the segment's IP id;
	 * sequence carries the offset too.
	 */
	h->reserved1 = htonl(SMT_RPC(rpc)->rec_segs);
	h->pad[0] = (offset >> 16) & 0xff;
	h->pad[1] = (offset >> 8) & 0xff;
	h->pad[2] = offset & 0xff;
	h->common.sequence = htonl(offset);
}
