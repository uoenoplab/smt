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

#include "smt_impl.h"

int smt_message_out_init(struct homa_rpc *rpc, struct iov_iter *iter, int xmit)
{
	/* Geometry information for packets:
	 * mtu:              largest size for an on-the-wire packet (including
	 *                   all headers through IP header, but not Ethernet
	 *                   header).
	 * max_pkt_data:     largest amount of Homa message data that
	 *                   fits in an on-the-wire packet.
	 * gso_size:         space required in each sk_buff (pre-GSO), starting
	 *                   with IP header.
	 */
	int mtu, max_pkt_data, gso_size;
	int bytes_left;
	int err;
	struct sk_buff **last_link;
	struct dst_entry *dst;
	int overlap_xmit;
	unsigned int gso_type;

	const int smt_len = SMT_RECORD_EXTRA_LENGTH;
	const int smt_header_len = SMT_RECORD_EXTRA_PRE_LENGTH;
	const int smt_trailer_len = SMT_RECORD_EXTRA_POST_LENGTH;
	const int smt_conf = smt_get_tx_conf(rpc);

	rpc->msgout.length = iter->count;
	rpc->msgout.num_skbs = 0;
	rpc->msgout.packets = NULL;
	rpc->msgout.next_xmit = &rpc->msgout.packets;
	rpc->msgout.next_xmit_offset = 0;
	atomic_set(&rpc->msgout.active_xmits, 0);
	rpc->msgout.sched_priority = 0;
	rpc->msgout.init_cycles = get_cycles();

	if (unlikely((rpc->msgout.length > HOMA_MAX_MESSAGE_LENGTH)
			|| (iter->count == 0))) {
		err = -EINVAL;
		goto error;
	}

	smt_prinf_int("%s smt_conf %d smt_len %d",
		__FUNCTION__, smt_conf, smt_len);

	/* Compute the geometry of packets, both how they will end up on the
	 * wire and large they will be here (before GSO).
	 */
	dst = homa_get_dst(rpc->peer, rpc->hsk);
	mtu = dst_mtu(dst);
	max_pkt_data = mtu - rpc->hsk->ip_header_length
			- sizeof(struct data_header);
	gso_type = (rpc->hsk->homa->gso_force_software) ? 0xd : SKB_GSO_TCPV6;

	if (rpc->msgout.length + smt_len <= max_pkt_data) {
		/* Message fits in a single packet: no need for GSO. */
		rpc->msgout.unscheduled = rpc->msgout.length;
		rpc->msgout.gso_pkt_data = rpc->msgout.length + smt_len;
		gso_size = mtu;
	} else {
		/* Can use GSO to pass multiple network packets through the
		 * IP stack at once.
		 */
		int repl_length, pkts_per_gso;

		gso_size = rpc->peer->dst->dev->gso_max_size;
		if (gso_size > rpc->hsk->homa->max_gso_size)
			gso_size = rpc->hsk->homa->max_gso_size;

		/* Round gso_size down to an even # of mtus. */
		repl_length = rpc->hsk->ip_header_length
				+ sizeof32(struct data_header)
				- sizeof32(struct data_segment);
		pkts_per_gso = (gso_size - repl_length)/(mtu - repl_length);
		if (pkts_per_gso == 0)
			pkts_per_gso = 1;
		rpc->msgout.gso_pkt_data = pkts_per_gso * max_pkt_data;
		gso_size = repl_length + (pkts_per_gso * (mtu - repl_length));

		/* Round unscheduled bytes *up* to an even number of gsos. */
		rpc->msgout.unscheduled = rpc->hsk->homa->unsched_bytes
				+ rpc->msgout.gso_pkt_data - 1;
		rpc->msgout.unscheduled -= rpc->msgout.unscheduled
				% rpc->msgout.gso_pkt_data;
		rpc->msgout.unscheduled -= SMT_RECORD_EXTRA_LENGTH *
				(rpc->msgout.unscheduled / rpc->msgout.gso_pkt_data);
		if (rpc->msgout.unscheduled > rpc->msgout.length)
			rpc->msgout.unscheduled = rpc->msgout.length;
	}
	UNIT_LOG("; ", "mtu %d, max_pkt_data %d, gso_size %d, gso_pkt_data %d",
			mtu, max_pkt_data, gso_size, rpc->msgout.gso_pkt_data);

	smt_prinf_int("%s: mtu %d, max_pkt_data %d, gso_size %d, gso_pkt_data %d",
		__func__, mtu, max_pkt_data, gso_size, rpc->msgout.gso_pkt_data);

	overlap_xmit = rpc->msgout.length > 2*rpc->msgout.gso_pkt_data;
	rpc->msgout.granted = rpc->msgout.unscheduled;
	atomic_or(RPC_COPYING_FROM_USER, &rpc->flags);

	/* Copy message data from user space and form sk_buffs. Each
	 * iteration of the outer loop creates one sk_buff, which may
	 * contain info for multiple packets on the wire (via TSO or GSO).
	 */
	smt_tt_record3("starting copy from user space for id %d, length %d, "
			"unscheduled %d",
			rpc->id, rpc->msgout.length, rpc->msgout.unscheduled);
	last_link = &rpc->msgout.packets;
	for (bytes_left = rpc->msgout.length; bytes_left > 0; ) {
		struct data_header *h;
		struct data_segment *seg;
		int available;
		struct sk_buff *skb;
		char *smt_header, *smt_trailer;
		unsigned int gso_offset;
		int avail_pkt_data;

		homa_rpc_unlock(rpc);

		skb = alloc_skb(HOMA_SKB_EXTRA + gso_size
				+ sizeof32(struct homa_skb_info), GFP_KERNEL);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			homa_rpc_lock(rpc);
			goto error;
		}
		if ((bytes_left + smt_len > max_pkt_data)
				&& (rpc->msgout.gso_pkt_data > max_pkt_data)) {
			skb_shinfo(skb)->gso_size = sizeof(struct data_segment)
					+ max_pkt_data;
			skb_shinfo(skb)->gso_type = gso_type;
		}
		skb_shinfo(skb)->gso_segs = 0;

		/* Fill in the initial portion (which will be replicated in
		 * every network packet by GSO/TSO).
		 */
		skb_reserve(skb, rpc->hsk->ip_header_length + HOMA_SKB_EXTRA);
		skb_reset_transport_header(skb);
		h = (struct data_header *) skb_put(skb,
				sizeof(*h) - sizeof(struct data_segment));
		h->common.sport = htons(rpc->hsk->port);
		h->common.dport = htons(rpc->dport);
		homa_set_doff(h);
		h->common.type = DATA;
		h->common.sender_id = cpu_to_be64(rpc->id);
		h->message_length = htonl(rpc->msgout.length);
		h->incoming = htonl(rpc->msgout.unscheduled);
		h->cutoff_version = rpc->peer->cutoff_version;
		h->retransmit = 0;
		homa_get_skb_info(skb)->wire_bytes = 0;

		// SMT
		// store offset of this GSO segment into two seperate parts
		// unused3 (high 16 bits) || unused4 (low 16 bits)
		gso_offset = rpc->msgout.length - bytes_left;
		h->common.unused3 = htons((unsigned short) (gso_offset >> 16));
		h->common.unused4 = htons((unsigned short) (gso_offset & 0xffff));

		available = rpc->msgout.gso_pkt_data - smt_len;

		/* Each iteration of the following loop adds one segment
		 * (which will become a separate packet after GSO) to the buffer.
		 */
		do {
			int seg_size;

			avail_pkt_data = max_pkt_data;

			if (skb_shinfo(skb)->gso_segs == 0) {
				avail_pkt_data -= smt_header_len;
				homa_get_skb_info(skb)->wire_bytes += smt_header_len;
				smt_header = skb_put(skb, smt_header_len);
			}

			seg = (struct data_segment *) skb_put(skb, sizeof(*seg));
			seg->offset = htonl(rpc->msgout.length - bytes_left);
			if (bytes_left <= avail_pkt_data)
				seg_size = bytes_left;
			else
				seg_size = avail_pkt_data;

			if (seg_size > available) {
				seg_size = available;
			}

			seg->segment_length = htonl(seg_size);
			seg->ack.client_id = 0;
			homa_peer_get_acks(rpc->peer, 1, &seg->ack);
			if (copy_from_iter(skb_put(skb, seg_size), seg_size,
					iter) != seg_size) {
				err = -EFAULT;
				kfree_skb(skb);
				homa_rpc_lock(rpc);
				goto error;
			}
			bytes_left -= seg_size;
			avail_pkt_data -= seg_size;
			(skb_shinfo(skb)->gso_segs)++;
			available -= seg_size;
			homa_get_skb_info(skb)->wire_bytes += mtu
					- (max_pkt_data - seg_size)
					+ HOMA_ETH_OVERHEAD;
		} while ((available > 0) && (bytes_left > 0));

		if (avail_pkt_data < smt_trailer_len) {
			(skb_shinfo(skb)->gso_segs)++;
			homa_get_skb_info(skb)->wire_bytes +=
					rpc->hsk->ip_header_length
					+ sizeof(struct data_header)
					- sizeof(struct data_segment)
					+ (smt_trailer_len - avail_pkt_data)
					+ HOMA_ETH_OVERHEAD;
		} else {
			homa_get_skb_info(skb)->wire_bytes += smt_trailer_len;
		}

		smt_trailer = (char *) skb_put(skb, smt_trailer_len);

		// Perform encryption here
		if (likely(smt_conf == SMT_SW)) {
			if (rpc->msgout.num_skbs == 0) {
				err = smt_sw_set_crypto(rpc, 1);
				if (unlikely(err))
					goto error;
			}
			err = smt_sw_encrypt(rpc, smt_header,
					smt_trailer);
			if (unlikely(err)) {
				smt_sw_unset_crypto(rpc, 1);
				goto error;
			}
		} else if (smt_conf == SMT_HW) {
			if (rpc->msgout.num_skbs == 0) {
				err = smt_device_set_crypto_tx(rpc);
				if (unlikely(err))
					goto error;
			}
			err = smt_device_encrypt(rpc, smt_header,
					smt_trailer, skb);
			if (unlikely(err))
				goto error;
		}

		homa_rpc_lock(rpc);

		*last_link = skb;
		last_link = &(homa_get_skb_info(skb)->next_skb);
		*last_link = NULL;
		rpc->msgout.num_skbs++;
		if (overlap_xmit && list_empty(&rpc->throttled_links) && xmit) {
			smt_tt_record1("waking up pacer for id %d", rpc->id);
			homa_add_to_throttled(rpc);
		}
	}
	if (smt_conf == SMT_SW)
		smt_sw_unset_crypto(rpc, 1);

	smt_tt_record2("finished copy from user space for id %d, length %d",
			rpc->id, rpc->msgout.length);
	atomic_andnot(RPC_COPYING_FROM_USER, &rpc->flags);
	INC_METRIC(sent_msg_bytes, rpc->msgout.length);
	if (!overlap_xmit && xmit)
		homa_xmit_data(rpc, false);
	return 0;

    error:
	atomic_andnot(RPC_COPYING_FROM_USER, &rpc->flags);
	return err;
}

static void smt_resend_data_sw(struct homa_rpc *rpc, int start, int end,
		int priority)
{
	struct sk_buff *skb;
	unsigned int max_pkt_data = dst_mtu(homa_get_dst(rpc->peer, rpc->hsk))
				- rpc->hsk->ip_header_length
				 - sizeof(struct data_header);

	smt_tt_record2("homa_resend start %d end %d", start, end);
	smt_prinf_int("%s rpc->id %llu start %d end %d\n",
			__FUNCTION__, rpc->id, start, end);

	if (end <= start)
		return;

	/* The nested loop below scans each data_segment in each
	 * packet, looking for those that overlap the range of
	 * interest.
	 */
	for (skb = rpc->msgout.packets; skb !=  NULL;
			skb = homa_get_skb_info(skb)->next_skb) {
		int offset, length, skb_data_offset, count;
		struct data_segment *seg;
		struct data_header *h;
		unsigned char extra_ip_id = 0;

		count = skb_shinfo(skb)->gso_segs;
		if (count < 1)
			count = 1;

		offset = smt_gso_offset_resend(skb);
		skb_data_offset = (skb_transport_header(skb) - skb->data)
				+ sizeof32(*h) - sizeof32(*seg);

		for ( ; count > 0; count--, extra_ip_id++, offset+=length) {
			struct sk_buff *new_skb;
			int length_smt;

			seg = (struct data_segment *) (skb->data + skb_data_offset);

			length_smt = max_pkt_data + sizeof32(*seg);
			if (skb_data_offset + length_smt > skb->len) {
				length_smt = skb->len - skb_data_offset;
			}
			skb_data_offset += length_smt;

			if (length_smt < sizeof32(*seg)) {
				length = length_smt; // trailer only packet
			} else {
				length = length_smt - sizeof32(*seg);
			}
			if (!extra_ip_id)
				length -= SMT_RECORD_EXTRA_LENGTH;

			smt_prinf_int("%s extra_ip_id %d transport_header %px skb->data %p"
				"skb->len %d seg-transport_header %ld seg-data %ld\n",
				__FUNCTION__, (int) extra_ip_id, skb_transport_header(skb),
				skb->data, skb->len, (unsigned char *)seg - skb_transport_header(skb),
				(unsigned char *)seg - skb->data);

			if (end <= offset)
				return;
			if ((offset + length) <= start)
				continue;

			/* This segment must be retransmitted. Copy it into
			 * a clean sk_buff.
			 */
			new_skb = alloc_skb(length_smt + sizeof(struct data_header)
					- sizeof(struct data_segment)
					+ rpc->hsk->ip_header_length
					+ HOMA_SKB_EXTRA, GFP_KERNEL);
			if (unlikely(!new_skb)) {
				if (rpc->hsk->homa->verbose)
					printk(KERN_NOTICE "homa_resend_data "
						"couldn't allocate skb\n");
				continue;
			}
			skb_reserve(new_skb, rpc->hsk->ip_header_length
				+ HOMA_SKB_EXTRA);
			skb_reset_transport_header(new_skb);
			__skb_put_data(new_skb, skb_transport_header(skb),
					sizeof32(struct data_header)
					- sizeof32(struct data_segment));
			__skb_put_data(new_skb, seg, length_smt);
			h = ((struct data_header *) skb_transport_header(new_skb));
			h->retransmit = 1;
			h->pad = extra_ip_id;
			if ((offset + length) <= rpc->msgout.granted)
				h->incoming = htonl(rpc->msgout.granted);
			else if ((offset + length) > rpc->msgout.length)
				h->incoming = htonl(rpc->msgout.length);
			else
				h->incoming = htonl(offset + length);
			smt_prinf_int("%s h->message_length %d h->incoming %d gso_offset %d "
				"offset %d length %d rpc->msgout.granted %d skb_data_offset %d"
				"length_smt %d new_skb->len %d \n",
				__FUNCTION__, ntohl(h->message_length), ntohl(h->incoming)
				, smt_gso_offset_resend(skb), offset, length, rpc->msgout.granted,
				skb_data_offset, length_smt, new_skb->len);
			smt_tt_record3("retransmitting offset %d, length %d, id %d",
					offset, length, rpc->id);
			homa_check_nic_queue(rpc->hsk->homa, new_skb, true);
			__homa_xmit_data(new_skb, rpc, priority);
			INC_METRIC(resent_packets, 1);
		}
	}
}

static void smt_resend_data_hw(struct homa_rpc *rpc, int start, int end,
		int priority)
{
	struct sk_buff *skb;

	smt_tt_record2("homa_resend start %d end %d", start, end);
	smt_prinf_int("%s rpc->id %llu start %d end %d\n",
			__FUNCTION__, rpc->id, start, end);

	if (end <= start)
		return;

	/* The nested loop below scans each data_segment in each
	 * packet, looking for those that overlap the range of
	 * interest.
	 */
	for (skb = rpc->msgout.packets; skb !=  NULL;
			skb = homa_get_skb_info(skb)->next_skb) {
		int offset, length, length_homa, count;
		struct data_segment *seg;
		struct data_header *h;
		struct sk_buff *new_skb;
		struct smt_rpc_hw_context_tx *ctx_rpc_tx;
		void **cb_driver_state;

		count = skb_shinfo(skb)->gso_segs;
		if (count < 1)
			count = 1;

		offset = smt_gso_offset_resend(skb);

		length_homa = skb->len - (skb_transport_header(skb) - skb->data);
		length = length_homa - (count - 1) * sizeof32(*seg) - sizeof32(*h)
			- SMT_RECORD_EXTRA_LENGTH;

		smt_prinf_int("%s count %d offset %d length_homa %d length %d\n",
			__FUNCTION__, count, offset, length_homa, length);

		if (end <= offset)
			return;
		if ((offset + length) <= start)
			continue;

		/* This segment must be retransmitted. Copy it into
		* a clean sk_buff.
		*/
		new_skb = alloc_skb(length_homa + rpc->hsk->ip_header_length
				+ HOMA_SKB_EXTRA, GFP_KERNEL);
		if (unlikely(!new_skb)) {
			if (rpc->hsk->homa->verbose)
				printk(KERN_NOTICE "smt_resend_data_hw "
					"couldn't allocate skb\n");
			continue;
		}

		skb_shinfo(new_skb)->gso_size = skb_shinfo(skb)->gso_size;
		skb_shinfo(new_skb)->gso_type = skb_shinfo(skb)->gso_type;
		skb_shinfo(new_skb)->gso_segs = skb_shinfo(skb)->gso_segs;

		skb_reserve(new_skb, rpc->hsk->ip_header_length
			+ HOMA_SKB_EXTRA);
		skb_reset_transport_header(new_skb);
		__skb_put_data(new_skb, skb_transport_header(skb), length_homa);

		h = ((struct data_header *) skb_transport_header(new_skb));
		h->retransmit = 1;

		if ((offset + length) <= rpc->msgout.granted)
			h->incoming = htonl(rpc->msgout.granted);
		else if ((offset + length) > rpc->msgout.length)
			h->incoming = htonl(rpc->msgout.length);
		else
			h->incoming = htonl(offset + length);

		// pre-set queue
		ctx_rpc_tx = (struct smt_rpc_hw_context_tx *)rpc->smt_rpc_offload_ctx_tx;

		new_skb->sk = &rpc->hsk->sock;
		skb_set_queue_mapping(new_skb, (u16)ctx_rpc_tx->queue_idx);
		// save driver_state to cb
		cb_driver_state = (void **)(new_skb->cb + sizeof(new_skb->cb) - sizeof(void *));
		*cb_driver_state = ctx_rpc_tx->driver_state;

		smt_prinf_int("%s h->message_length %d h->incoming %d rpc->msgout.granted %d new_skb->len %d \n",
			__FUNCTION__, ntohl(h->message_length), ntohl(h->incoming)
			, rpc->msgout.granted, new_skb->len);

		smt_tt_record3("retransmitting offset %d, length %d, id %d",
				offset, length, rpc->id);
		homa_check_nic_queue(rpc->hsk->homa, new_skb, true);
		__homa_xmit_data(new_skb, rpc, priority);
		INC_METRIC(resent_packets, 1);
	}
}

void smt_resend_data(struct homa_rpc *rpc, int start, int end,
		int priority)
{
	const int conf = smt_get_tx_conf(rpc);
	if (conf == SMT_HW) {
		return smt_resend_data_hw(rpc, start, end, priority);
	} else if (conf == SMT_SW) {
		return smt_resend_data_sw(rpc, start, end, priority);
	}

	while (true) {
		struct sk_buff *skb_next;
		int pkt_end;
		struct sk_buff *skb;

		skb = *rpc->msgout.next_xmit;
		if (skb == NULL)
			break;
		skb_next = homa_get_skb_info(skb)->next_skb;
		if (skb_next != NULL) {
			pkt_end = smt_gso_offset_resend(skb_next);
		} else {
			pkt_end = rpc->msgout.length;
		}
		if (pkt_end > end)
			break;
		rpc->msgout.next_xmit = &(homa_get_skb_info(skb)->next_skb);
		rpc->msgout.next_xmit_offset = pkt_end;
	}
}
