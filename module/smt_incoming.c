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

#include "homa_impl.h"
#include "homa_lcache.h"

#include "smt_impl.h"

/**
 * @brief smt_find_gsoseg - Check whether there is a complete list
 * of packets which are same GSO segment.
 *
 * If a message have multiple GSO segments, for the non-last GSO segements, we
 * can only tell whether current GSO segment pkts are complete after the first
 * packet from next GSO segment has arrived by comparing the data bytes with
 * gso_offset field (currently unused3 | unused4). For the last GSO segment,
 * or a message only has one GSO segment, we can
 * compare the data bytes length the message length in the Homa header.
 *
 * @return int 0 for no existing complete GSO seg
 */
bool smt_find_gsoseg(struct homa_rpc *rpc)
{
	struct homa_message_in *msgin = &rpc->msgin;
	struct sk_buff *skb, *skb_gso_head;
	unsigned short ip_id;
	int data_bytes;
	unsigned int gso_offset, offset, offset_record;
	u8 *smt_header;
	int smt_header_datalen;
	bool found_gsoseg = false;
	bool found_gsoseg_this = true;

	smt_prinf_int("%s invoked\n", __FUNCTION__);

scan:

	smt_prdbg_int("%s smt_gsoseg_skb %px smt_gsoseg_skb->next %px",
		__FUNCTION__, msgin->smt_gsoseg_skb, msgin->smt_gsoseg_skb->next);

	skb = skb_peek(msgin->smt_gsoseg_skb);
	skb_gso_head = skb;

	// no skb in the list
	if (!skb || ((void *)skb == (void *)&msgin->packets))
		goto out;

	gso_offset = smt_gso_offset(skb);
	// only handle GSO seg right after the one decrypted
	if (msgin->smt_gsoseg_offset != gso_offset)
		goto out;

	ip_id = smt_fake_ip_id(skb);
	data_bytes = smt_fake_data_bytes(ip_id, skb->len);
	offset = gso_offset + data_bytes;
	offset_record = data_bytes + sizeof(struct data_segment);

	// the first skb in the list is not the first pkt in the GSO seg
	if (ip_id != 0) {
		found_gsoseg_this = false;
		smt_header_datalen = INT_MAX;
	} else {
		smt_header = skb_gso_head->data + sizeof(struct data_header) - sizeof(struct data_segment);
		smt_header_datalen = (int) (smt_header[3] << 8) | (smt_header[4] & 0xff);
		smt_header_datalen -= TLS_CIPHER_AES_GCM_128_IV_SIZE + TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		if (offset_record == smt_header_datalen) {
			goto found;
		}
		msgin->smt_nextgsoseg_length = smt_header_datalen;
	}

	smt_prdbg_int("%s ip_id %hu gso_offset %u offset %u data_bytes %d",
		__FUNCTION__, ip_id, gso_offset, offset, data_bytes);

	skb = skb->next;
	skb_queue_walk_from(&msgin->packets, skb) {
		unsigned short ip_id_cur = smt_fake_ip_id(skb);
		unsigned int gso_offset_cur = smt_gso_offset(skb);

		data_bytes = smt_fake_data_bytes(ip_id_cur, skb->len);
		offset += data_bytes;

		if (likely(skb->len > sizeof32(struct data_header)))
			offset_record += data_bytes + sizeof(struct data_segment);
		else
			offset_record += data_bytes;

		smt_prdbg_int("%s ip_id %hu gso_offset %u offset %u data_bytes %d",
			__FUNCTION__, ip_id, gso_offset, offset, data_bytes);

		// gso_offset should be same throughtout all skbs of one gso seg
		if (unlikely(gso_offset_cur != gso_offset)) {
			msgin->smt_nextgsoseg_received = offset_record;
			goto out;
		}

		// ip_id should be continuous
		if (ip_id_cur != (ip_id + 1))
			found_gsoseg_this = false;

		ip_id = ip_id_cur;

		// current skb reaches the end of the message
		if (offset_record == smt_header_datalen && found_gsoseg_this) {
			goto found;
		}
	}

	// not found after walking the whole list
	msgin->smt_nextgsoseg_received = offset_record;
	goto out;

found:
	smt_prinf_int("%s found gso seg: offset %d\n", __FUNCTION__, offset);
	skb_shinfo(skb_gso_head)->gso_segs = ip_id + 1;
	msgin->smt_gsoseg_skb =  (struct sk_buff_head *)skb;
	msgin->smt_gsoseg_offset = offset;
	msgin->smt_nextgsoseg_length = INT_MAX;
	msgin->smt_nextgsoseg_received = 0;
	found_gsoseg = true;

	smt_prinf_int("%s: msgin->smt_gsoseg_offset %d\n", __FUNCTION__,
		msgin->smt_gsoseg_offset);

	goto scan;

out:
	smt_prdbg_int("%s ip_id %hu gso_offset %u offset %u data_bytes %d",
		__FUNCTION__, ip_id, gso_offset, offset, data_bytes);
	return found_gsoseg;
}

/**
 * smt_add_packet() - Add an incoming packet to the contents of a
 * partially received **encrypted** SMT packets.
 * @rpc:   Add the packet to the msgin for this RPC.
 * @skb:   The new packet. This function takes ownership of the packet
 *         and will free it, if it doesn't get added to msgin (because
 *         it provides no new data).
 */
void smt_add_packet(struct homa_rpc *rpc, struct sk_buff *skb, bool *try_find_gsoseg)
{
	struct data_header *h = (struct data_header *) skb->data;
	struct sk_buff *skb2;
	unsigned int gso_offset2 = UINT_MAX, offset2, data_bytes2;
	unsigned short ip_id2;

	unsigned short ip_id = smt_fake_ip_id(skb);
	unsigned int gso_offset = smt_gso_offset(skb);

	unsigned int offset = smt_fake_offset(ip_id, gso_offset, &rpc->msgin);
	int data_bytes = smt_fake_data_bytes(ip_id, skb->len);

	/* Any data from the packet with offset less than this is
	 * of no value.*/
	int floor = rpc->msgin.copied_out;

	/* Any data with offset >= this is useless. */
	int ceiling = rpc->msgin.total_length;

	smt_tt_record4("homa_add_packet adding packet at fake_offset %u fake_data_bytes %d gso_offset %u ip_id %hu"
		, offset, data_bytes, gso_offset, ip_id);
	smt_prdbg_int("%s rpc->id %llu skb %px ip_id %hu gso_offset %u offset %u "
		"data_bytes %d copied_out %d total_length %d\n", __FUNCTION__,
		rpc->id, skb, ip_id, gso_offset, offset, data_bytes, floor, ceiling);

	/* Figure out where in the list of existing packets to insert the
	 * new one. It doesn't necessarily go at the end, but it almost
	 * always will in practice, so work backwards from the end of the
	 * list.
	 */
	skb_queue_reverse_walk(&rpc->msgin.packets, skb2) {
		ip_id2 = smt_fake_ip_id(skb2);
		gso_offset2 = smt_gso_offset(skb2);
		offset2 = smt_fake_offset(ip_id2, gso_offset2, &rpc->msgin);
		data_bytes2 = smt_fake_data_bytes(ip_id2, skb2->len);

		smt_prdbg_int(
			"%s skb2 %px ip_id2 %hu gso_offset2 %u offset2 %u data_bytes2 %d\n",
			__FUNCTION__, skb2, ip_id2, gso_offset2, offset2, data_bytes2);

		if (offset2 < offset) {
			floor = offset2 + data_bytes2;
			break;
		}
		ceiling = offset2;
	}

	/* New packet goes right after skb2 (which may refer to the header).
	 * Packets shouldn't overlap in byte ranges, but the code below
	 * assumes they might, so it computes how many non-overlapping bytes
	 * are contributed by the new packet.
	 */
	if ((offset < floor) || ((offset + data_bytes) > ceiling)) {
		/* This packet is redundant. */
//		char buffer[100];
//		printk(KERN_NOTICE "redundant Homa packet: %s\n",
//			homa_print_packet(skb, buffer, sizeof(buffer)));
		INC_METRIC(redundant_packets, 1);
		tt_record4("smt_add_packet discarding packet for id %d, "
				"offset %d, copied_out %d, remaining %d",
				rpc->id, offset, rpc->msgin.copied_out,
				rpc->msgin.total_length);
		kfree_skb(skb);
		return;
	}
	if (h->retransmit) {
		INC_METRIC(resent_packets_used, 1);
		homa_freeze(rpc, PACKET_LOST, "Freezing because of lost "
				"packet, id %d, peer 0x%x");
	}
	__skb_insert(skb, skb2, skb2->next, &rpc->msgin.packets);
	rpc->msgin.bytes_remaining -= data_bytes;
	rpc->msgin.num_skbs++;

	smt_prinf_int("%s: rpc->msgin.smt_gsoseg_offset %d gso_offset %d "
		"gso_offset2 %d ip_id %d \n", __FUNCTION__,
		rpc->msgin.smt_gsoseg_offset, gso_offset, gso_offset2, ip_id);

	smt_prinf_int("%s: 1. rpc->msgin.smt_nextgsoseg_length %d "
		"rpc->msgin.smt_nextgsoseg_received %d \n",
		__FUNCTION__, rpc->msgin.smt_nextgsoseg_length,
		rpc->msgin.smt_nextgsoseg_received);

	if (rpc->msgin.smt_gsoseg_offset == gso_offset) {
		if (ip_id == 0) {
			u8 *smt_header;
			int smt_header_datalen;
			smt_header = skb->data + sizeof(struct data_header) - sizeof(struct data_segment);
			smt_header_datalen = (int) (smt_header[3] << 8) | (smt_header[4] & 0xff);
			smt_header_datalen -= TLS_CIPHER_AES_GCM_128_IV_SIZE + TLS_CIPHER_AES_GCM_128_TAG_SIZE;
			rpc->msgin.smt_nextgsoseg_length = smt_header_datalen;
		}
		rpc->msgin.smt_nextgsoseg_received += data_bytes + sizeof(struct data_segment);
		if (rpc->msgin.smt_nextgsoseg_received >= rpc->msgin.smt_nextgsoseg_length)
			*try_find_gsoseg = true;
	}

	smt_prinf_int("%s: 2. rpc->msgin.smt_nextgsoseg_length %d "
		"rpc->msgin.smt_nextgsoseg_received %d \n",
		__FUNCTION__, rpc->msgin.smt_nextgsoseg_length,
		rpc->msgin.smt_nextgsoseg_received);

	smt_prdbg_int("%s bytes_remaining %d floor %d ceiling %d",
			__FUNCTION__, rpc->msgin.bytes_remaining, floor, ceiling);
}

/**
 * smt_copy_to_user() - Copy as much decrypted skbs from incoming
 * packet buffers to buffers in user space.
 * @rpc:     RPC for which data should be copied. Must be locked by caller.
 * Return:   Zero for success or a negative errno if there is an error.
 */
static int smt_do_copy_to_user(struct homa_rpc *rpc)
{
#ifdef __UNIT_TEST__
#define MAX_SKBS 3
#else
#define MAX_SKBS 10
#endif
	struct sk_buff *skbs[MAX_SKBS];
	int n = 0;             /* Number of filled entries in skbs. */
	int error = 0;
	int count;
	/* Number of bytes that have already been copied to user space
	 * from the current packet.
	 */
	int copied_from_seg;

	/* Tricky note: we can't hold the RPC lock while we're actually
	 * copying to user space, because (a) it's illegal to hold a spinlock
	 * while copying to user space and (b) we'd like for homa_softirq
	 * to add more packets to the RPC while we're copying these out.
	 * So, collect a bunch of chunks to copy, then release the lock,
	 * copy them, and reacquire the lock.
	 */
	while (true) {
		struct sk_buff *skb = skb_peek(&rpc->msgin.packets);
		struct data_header *h;
		int i, seg_offset;

		if (!skb || (rpc->msgin.copied_out >= rpc->msgin.total_length))
			goto copy_out;

		if (rpc->msgin.copied_out >= rpc->msgin.smt_decrypt_offset)
			goto copy_out;

		if (unlikely(smt_fake_ip_id(skb) == 0))
			h = (struct data_header *) (skb->data
				+ SMT_RECORD_EXTRA_PRE_LENGTH);
		else
			h = (struct data_header *) skb->data;

		seg_offset = ntohl(h->seg.offset);
		if (rpc->msgin.copied_out < seg_offset) {
			/* The next data to copy hasn't yet been received;
			 * wait for more packets to arrive.
			 */
			goto copy_out;
		}
		BUG_ON(rpc->msgin.copied_out != seg_offset);
		skbs[n] = skb;
		n++;
		skb_dequeue(&rpc->msgin.packets);

		if ((void *) skb == (void *) rpc->msgin.smt_decrypt_skb)
			rpc->msgin.smt_decrypt_skb = &rpc->msgin.packets;
		if ((void *) skb == (void *) rpc->msgin.smt_gsoseg_skb)
			rpc->msgin.smt_gsoseg_skb = &rpc->msgin.packets;

		rpc->msgin.num_skbs--;
		rpc->msgin.copied_out = seg_offset + ntohl(h->seg.segment_length);

		//printk("seg_offset %d ntohl(h->seg.segment_length) %d", seg_offset, ntohl(h->seg.segment_length));
		//printk("rpc->msgin.copied_out %d rpc->msgin.num_skbs %d", rpc->msgin.copied_out, rpc->msgin.num_skbs);

		if (n < MAX_SKBS)
			continue;

copy_out:
		if (n == 0)
			break;
		atomic_or(RPC_COPYING_TO_USER, &rpc->flags);
		homa_rpc_unlock(rpc);

		smt_tt_record1("starting copy to user space for id %d",
				rpc->id);

		/* Each iteration of this loop copies (part of?) an skb
		 * to a contiguous range of buffer space.
		 */
		count = 0;
		copied_from_seg = 0;
		for (i = 0; i < n && !error; ) {
			int skb_bytes, buf_bytes, next_copied, smt_header_offset;
			char *dst;
			struct iovec iov;
			struct iov_iter iter;

			skb = skbs[i];

			smt_header_offset = smt_fake_ip_id(skb) ? 0 : SMT_RECORD_EXTRA_PRE_LENGTH;
			h = (struct data_header *) (skb->data + smt_header_offset);
			skb_bytes = ntohl(h->seg.segment_length) - copied_from_seg;
			dst = homa_pool_get_buffer(rpc,
					ntohl(h->seg.offset) + copied_from_seg,
					&buf_bytes);
			if (dst == NULL) {
				error = -ENOMEM;
				break;
			}
			if (buf_bytes < skb_bytes) {
				if (buf_bytes == 0) {
					/* skb seems to have data beyond the
					 * end of the message.
					 */
					break;
				}
				skb_bytes = buf_bytes;
				next_copied = copied_from_seg + skb_bytes;
			} else {
				i++;
				next_copied = 0;
			}
			if (skb_bytes <= 0) {
				int len = skb->len - 40;
				unsigned char* buf = skb->data + 40;
				printk("%s rpc->id %lld gso_offset %d ip_id %d extra_ip_id %d skb->len %d \n",
					__FUNCTION__, rpc->id, smt_gso_offset(skb),
					smt_ip_id(skb), smt_extra_ip_id(skb), skb->len);
				printk("%s ntohl(h->seg.segment_length)) %d ntohl(h->seg.offset)) %d", __func__, ntohl(h->seg.segment_length), ntohl(h->seg.offset));
				printk("%s skb_bytes %d buf_bytes %d smt_header_offset %d copied_from_seg %d\n", __func__, skb_bytes, buf_bytes, smt_header_offset, copied_from_seg);
				while (len--) {
					printk(KERN_CONT "%02x ", *buf);
					buf++;
				}
				printk(KERN_CONT "\n");
			}
			BUG_ON(skb_bytes <= 0);
			error = import_single_range(READ, dst, skb_bytes, &iov,
					&iter);
			if (error)
				break;
			error = skb_copy_datagram_iter(skb,
					sizeof(*h) + copied_from_seg + smt_header_offset
					, &iter, skb_bytes);
			copied_from_seg = next_copied;
			count += skb_bytes;
		}
		smt_tt_record3("finished copying %d bytes for id %d, copied_out %d",
				count, rpc->id, ntohl(h->seg.offset)
				+ ntohl(h->seg.segment_length));

		/* Free skbs. */
		for (i = 0; i < n; i++)
			kfree_skb(skbs[i]);
		smt_tt_record2("finished freeing %d skbs for id %d",
				n, rpc->id);
		n = 0;
		homa_rpc_lock(rpc);
		atomic_andnot(RPC_COPYING_TO_USER, &rpc->flags);
		if (error)
			break;
	}
	if (error)
		smt_tt_record2("homa_copy_to_user returning error %d for id %d",
				-error, rpc->id);
	return error;
}

int smt_copy_to_user(struct homa_rpc *rpc)
{
	int rc;
	if (!rpc->smt_rpc_offload_ctx_rx && !rpc->smt_rpc_offload_ctx_tx) {
		smt_set_rpc_offload_context(rpc);
	}
	while (rpc->msgin.smt_decrypt_skb != rpc->msgin.smt_gsoseg_skb) {
		int decrypted_gsosegs = 0;
		while (rpc->msgin.smt_decrypt_skb != rpc->msgin.smt_gsoseg_skb) {
			if (smt_get_rx_conf(rpc) == SMT_SW) {
				smt_prinf_int("%s smt_decrypt_skb %px\n",
					__FUNCTION__, rpc->msgin.smt_decrypt_skb);
				rc = smt_sw_decrypt(rpc);
				if (rc)
					goto end;
			}
			decrypted_gsosegs++;
		}
		smt_handle_acks(rpc, decrypted_gsosegs);
		rc = smt_do_copy_to_user(rpc);
		if (rc)
			goto end;
	}
end:
	return rc;
}

void smt_handle_acks(struct homa_rpc *rpc, int decrypted_gsosegs)
{
#define MAX_SMT_ACKS 10
	struct homa_ack acks[MAX_SMT_ACKS];
	struct in6_addr saddrs[MAX_SMT_ACKS];
	int num_acks = 0;

	struct sk_buff *skb;
	struct data_header *h;

	smt_prinf_int("%s invoked\n", __FUNCTION__);

	for (skb = (struct sk_buff *)rpc->msgin.smt_decrypt_skb;; skb = skb->prev) {
		unsigned short ip_id = smt_fake_ip_id(skb);

		// shift header after querying all variables in data_header and
		// common header
		if (likely(ip_id != 0))
			h = (struct data_header *) (skb->data);
		else
			h = (struct data_header *) (skb->data
				+ SMT_RECORD_EXTRA_PRE_LENGTH);

		if (h->seg.ack.client_id != 0) {
			num_acks++;
			acks[num_acks] = h->seg.ack;
			saddrs[num_acks] = skb_canonical_ipv6_saddr(skb);
		}

		// the number of acks reaches the batch size
		if (unlikely(num_acks == MAX_SMT_ACKS || ip_id == 0)) {
			if (num_acks != 0)
				smt_prinf_int("%s handle %d acks\n",
					__FUNCTION__, num_acks);

			atomic_or(RPC_ACKING_SMT, &rpc->flags);
			homa_rpc_unlock(rpc);

			// batch handle acks in acks
			for (; num_acks > 0; num_acks--) {
				homa_rpc_acked(rpc->hsk, &saddrs[num_acks],
					&acks[num_acks]);
			}

			homa_rpc_lock(rpc);
			atomic_andnot(RPC_ACKING_SMT, &rpc->flags);
		}

		if (unlikely(ip_id == 0)) {
			decrypted_gsosegs--;
			if (decrypted_gsosegs == 0)
				break;
		}
	}

	smt_prinf_int("%s leaving\n", __FUNCTION__);
}

void smt_handle_ack(struct homa_rpc *rpc, struct sk_buff* skb)
{
	struct data_header *h = (struct data_header *) (skb->data);
	const struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);

	smt_prinf_int("%s invoked\n", __FUNCTION__);

	if (h->seg.ack.client_id != 0) {
		// printk("%s sender_id %lld (pkt from client) "
		// 		"ack.client_id %lld (ack from client)",
		// 		__FUNCTION__, be64_to_cpu(h->common.sender_id),
		// 		be64_to_cpu(h->seg.ack.client_id));
		// atomic_or(RPC_ACKING_SMT, &rpc->flags);
		// homa_rpc_unlock(rpc);
		homa_rpc_acked(rpc->hsk, &saddr, &h->seg.ack);
		// homa_rpc_lock(rpc);
		// atomic_andnot(RPC_ACKING_SMT, &rpc->flags);
	}

	smt_prinf_int("%s leaving\n", __FUNCTION__);
}

void smt_get_resend_range(struct homa_message_in *msgin,
		struct resend_header *resend)
{
	struct sk_buff *skb;
	int missing_bytes;
	/* This will eventually be the top of the first missing range. */
	int end_offset;

	if (msgin->total_length < 0) {
		/* Haven't received any data for this message; request
		 * retransmission of just the first packet (the sender
		 * will send at least one full packet, regardless of
		 * the length below).
		 */
		resend->offset = 0;
		resend->length = htonl(100);
		return;
	}

	end_offset = msgin->incoming;
	smt_prinf_int("smt_get_resend_range end_offset(1) %d\n", end_offset);

	/* The code below handles the case where we've received data past
	 * msgin->incoming. In this case, end_offset should start off at
	 * the offset just after the last byte received.
	 */
	skb = skb_peek_tail(&msgin->packets);
	if (skb) {
		int data_end = smt_fake_next_offset(skb, msgin);
		if (data_end > end_offset)
			end_offset = data_end;
		smt_tt_record1("smt_get_resend_range data_end %d", data_end);
		smt_prinf_int("smt_get_resend_range data_end %d h->incoming %d\n",
			data_end, ntohl(((struct data_header *) skb_transport_header(skb))->incoming));
	}

	smt_prinf_int("smt_get_resend_range end_offset(2) %d\n", end_offset);

	missing_bytes = msgin->bytes_remaining
			- (msgin->total_length - end_offset);

	smt_prinf_int("smt_get_resend_range bytes_remaining %d missing_bytes %d\n",
		msgin->bytes_remaining, missing_bytes);

	if (missing_bytes == 0) {
		smt_prinf_int("%s decrypt_offset %d gsoseg_offset %d copied_out %d\n",
			__FUNCTION__, msgin->smt_decrypt_offset, msgin->smt_gsoseg_offset,
			msgin->copied_out);
		resend->offset = 0;
		resend->length = 0;
		return;
	}

	/* Basic idea: walk backwards through the message's packets until
	 * we have accounted for all missing bytes; this will identify
	 * the first missing range.
	 */
	skb_queue_reverse_walk(&msgin->packets, skb) {
		unsigned int gso_offset = smt_gso_offset(skb);
		unsigned short ip_id = smt_fake_ip_id(skb);
		int offset = smt_fake_offset(ip_id, gso_offset, msgin);
		int pkt_length = smt_fake_data_bytes(ip_id, skb->len);
		int gap;

		if (pkt_length > (end_offset - offset))
			pkt_length = end_offset - offset;
		gap = end_offset - (offset + pkt_length);
		missing_bytes -= gap;
		if (missing_bytes == 0) {
			resend->offset = htonl(offset + pkt_length);
			resend->length = htonl(gap);
			smt_tt_record2("smt_get_resend_range offset %d length %d",
				ntohl(resend->offset), ntohl(resend->length));
			return;
		}
		end_offset = offset;

		smt_prdbg_int("%s skb->len %d gso_offset %d ip_id %d offset %d\n",
			__FUNCTION__, skb->len, gso_offset, (int) ip_id, offset);
		smt_prdbg_int("%s missing_bytes %d gap %d pkt_length %d end_offset %d\n",
			__FUNCTION__, missing_bytes, gap, pkt_length, end_offset);
	}

	/* The first packet(s) are missing. */
	smt_tt_record4("first packets missing, missing_bytes %d, copied_out %d, "
			"incoming %d, length %d",
			missing_bytes, msgin->copied_out, msgin->incoming,
			msgin->total_length);
	smt_prinf_int("%s first pkts missing, missing_bytes %d, copied_out %d, "
			"incoming %d, length %d\n", __FUNCTION__, missing_bytes,
			msgin->copied_out, msgin->incoming, msgin->total_length);
	resend->offset = htonl(msgin->copied_out);
	resend->length = htonl(missing_bytes);
}
