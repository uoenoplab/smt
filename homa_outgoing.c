// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

/* This file contains functions related to the sender side of message
 * transmission. It also contains utility functions for sending packets.
 */

#include "homa_impl.h"
#include "homa_peer.h"
#include "homa_rpc.h"
#include "homa_wire.h"

#ifndef __STRIP__ /* See strip.py */
#include "homa_hijack.h"
#include "homa_pacer.h"
#include "homa_qdisc.h"
#include "homa_skb.h"
#else /* See strip.py */
#include "homa_stub.h"
#endif /* See strip.py */

#ifdef CONFIG_SMT
#include "smt_plumbing.h"
#endif

#ifdef CONFIG_SMT_MOCK_RESEND
#include "smt_impl.h"
#endif

/**
 * homa_message_out_init() - Initialize rpc->msgout.
 * @rpc:       RPC whose output message should be initialized. Must be
 *             locked by caller.
 * @length:    Number of bytes that will eventually be in rpc->msgout.
 */
void homa_message_out_init(struct homa_rpc *rpc, int length)
	__must_hold(rpc->bucket->lock)
{
	memset(&rpc->msgout, 0, sizeof(rpc->msgout));
	rpc->msgout.length = length;
	rpc->msgout.next_xmit = &rpc->msgout.packets;
#ifndef __STRIP__ /* See strip.py */
	rpc->msgout.unscheduled = rpc->hsk->homa->unsched_bytes;
	if (rpc->msgout.unscheduled > length)
		rpc->msgout.unscheduled = length;
#endif /* See strip.py */
	rpc->msgout.init_time = homa_clock();
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_fill_data_interleaved() - This function is invoked to fill in the
 * part of a data packet after the initial header, when GSO is being used
 * but TCP hijacking is not. As result, homa_seg_hdrs must be interleaved
 * with the data to provide the correct offset for each segment.
 * @rpc:            RPC whose output message is being created. Must be
 *                  locked by caller.
 * @skb:            The packet being filled. The initial homa_data_hdr was
 *                  created and initialized by the caller and the
 *                  homa_skb_info has been filled in with the packet geometry.
 * @iter:           Describes location(s) of (remaining) message data in user
 *                  space.
 * Return:          Either a negative errno or 0 (for success).
 */
#else /* See strip.py */
/**
 * homa_fill_data_interleaved() - This function is invoked to fill in the
 * part of a data packet after the initial header, when GSO is being used.
 * homa_seg_hdrs must be interleaved with the data to provide the correct
 * offset for each segment.
 * @rpc:            RPC whose output message is being created. Must be
 *                  locked by caller.
 * @skb:            The packet being filled. The initial homa_data_hdr was
 *                  created and initialized by the caller and the
 *                  homa_skb_info has been filled in with the packet geometry.
 * @iter:           Describes location(s) of (remaining) message data in user
 *                  space.
 * Return:          Either a negative errno or 0 (for success).
 */
#endif /* See strip.py */
int homa_fill_data_interleaved(struct homa_rpc *rpc, struct sk_buff *skb,
			       struct iov_iter *iter,
			       struct homa_smt_padding_info pad_info)
	__must_hold(rpc->bucket->lock)
{
	struct homa_skb_info *homa_info = homa_get_skb_info(skb);
	int seg_length = homa_info->seg_length;
	int bytes_left = homa_info->data_bytes;
#ifdef CONFIG_SMT
	/* first segment is smaller for TLS header */
	seg_length -= pad_info.hdr_len;
#endif
	int offset = homa_info->offset;
	int err;

	/* Each iteration of the following loop adds info for one packet,
	 * which includes a homa_seg_hdr followed by the data for that
	 * segment. The first homa_seg_hdr was already added by the caller.
	 */
	while (1) {
		struct homa_seg_hdr seg;

		if (bytes_left < seg_length)
			seg_length = bytes_left;
		err = homa_skb_append_from_iter(rpc->hsk->homa, skb, iter,
						seg_length);
		if (err != 0)
			return err;
		bytes_left -= seg_length;
		offset += seg_length;

		if (bytes_left == 0)
			break;

		seg.offset = htonl(offset);
		err = homa_skb_append_to_frag(rpc->hsk->homa, skb, &seg,
					      sizeof(seg));
		if (err != 0)
			return err;

		seg_length = homa_info->seg_length;
	}
	return 0;
}

/**
 * homa_tx_data_pkt_alloc() - Allocate a new sk_buff and fill it with an
 * outgoing Homa data packet. The resulting packet will be a GSO packet
 * that will eventually be segmented by the NIC.
 * @rpc:          RPC that packet will belong to (msgout must have been
 *                initialized). Must be locked by caller.
 * @iter:         Describes location(s) of (remaining) message data in user
 *                space.
 * @offset:       Offset in the message of the first byte of data in this
 *                packet.
 * @length:       How many bytes of data to include in the skb. Caller must
 *                ensure that this amount of data isn't too much for a
 *                well-formed GSO packet, and that iter has at least this
 *                much data.
 * @max_seg_data: Maximum number of bytes of message data that can go in
 *                a single segment of the GSO packet.
 * Return:        A pointer to the new packet, or a negative errno. Sets
 *                rpc->hsk->error_msg on errors.
 */
struct sk_buff *homa_tx_data_pkt_alloc(struct homa_rpc *rpc,
				       struct iov_iter *iter, int offset,
				       int length, int max_seg_data,
				       struct homa_smt_padding_info pad_info)
	__must_hold(rpc->bucket->lock)
{
	struct homa_sock *hsk = rpc->hsk;
	struct homa_skb_info *homa_info;
	struct homa_data_hdr *h;
	struct homa_seg_hdr *h_s;
	struct sk_buff *skb;
	int err, gso_size;
	u64 segs;
	bool trailer_only = false;
#ifdef CONFIG_SMT
#define MAX_SMT_PADDING 32
	int smt_length = pad_info.hdr_len + pad_info.trl_len + length;
	u8 *smt_h = NULL;
	u8 smt_zero[MAX_SMT_PADDING] = {0};
	bool smt_inline = false;
	/* HW-offload skb layout (smt_h in linear) is chosen at runtime per RPC
	 * based on ctx->tx_conf. SW fallback (ctx->tx_conf == SMT_SW even when
	 * built with CONFIG_SMT_HW) uses the SW frag layout that
	 * smt_sw_encrypt expects. In non-HW build the layout is always SW so
	 * the flag is hardcoded false.
	 */
#ifdef CONFIG_SMT_HW
	bool smt_is_hw = is_smt_rpc(rpc) &&
			 SMT_RPC(rpc)->ctx->tx_conf == SMT_HW;
#else
	bool smt_is_hw = false;
#endif
	segs = smt_length + max_seg_data - 1;
#else
	segs = length + max_seg_data - 1;
#endif
	do_div(segs, max_seg_data);

#ifdef CONFIG_SMT
	if (smt_length + max_seg_data <= pad_info.trl_len + segs * max_seg_data)
		trailer_only = 1;
	smt_pr_devel("%s: length=%d max_seg_data=%d pad_hdr=%d pad_trl=%d smt_length=%d segs=%lld trailer_only=%d\n", __func__,
	       length, max_seg_data, pad_info.hdr_len, pad_info.trl_len, smt_length, segs, trailer_only);
#endif

	/* Initialize the overall skb. Layouts:
	 *  - SMT_HW: linear = data_hdr_minus_seg + smt_h (NIC TLS engine reads
	 *    TLS rec hdr from linear at skb_tcp_all_headers offset).
	 *  - SMT (SW): linear = data_hdr_minus_seg; smt_h + first seg_hdr +
	 *    payload + trailer all in frags[0] (single-page sg for AEAD).
	 *  - default: data_hdr in linear; payload in frags.
	 */
#ifdef CONFIG_SMT
	if (is_smt_rpc(rpc)) {
		size_t linear = sizeof(struct homa_data_hdr) -
				sizeof(struct homa_seg_hdr);

		if (smt_is_hw)
			linear += pad_info.hdr_len;
		skb = homa_skb_alloc_tx(linear);
	}
	else
#endif
#ifndef __STRIP__ /* See strip.py */
		skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr));
#else /* See strip.py */
		skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr) + length +
					(segs - 1) * sizeof(struct homa_seg_hdr));
#endif /* See strip.py */
	if (!skb) {
		hsk->error_msg = "couldn't allocate sk_buff for outgoing message";
		return ERR_PTR(-ENOMEM);
	}

	/* Fill in the Homa header (which will be replicated in every
	 * network packet by GSO).
	 */
	h = (struct homa_data_hdr *)skb_put(skb,
		sizeof(struct homa_data_hdr) - sizeof(struct homa_seg_hdr));
	h->common.sport = htons(hsk->port);
	h->common.dport = htons(rpc->dport);
	h->common.sequence = htonl(offset);
	h->common.type = DATA;
	homa_set_doff(skb, sizeof(struct homa_data_hdr));
#ifdef CONFIG_SMT
	if (smt_is_hw)
		homa_set_doff(skb, sizeof(struct homa_data_hdr) -
				sizeof(struct homa_seg_hdr));
#endif /* CONFIG_SMT */
	h->common.checksum = 0;
	h->common.sender_id = cpu_to_be64(rpc->id);
	h->message_length = htonl(rpc->msgout.length);
	IF_NO_STRIP(h->incoming = htonl(rpc->msgout.unscheduled));
	h->ack.client_id = 0;
	homa_peer_get_acks(rpc->peer, 1, &h->ack);
	IF_NO_STRIP(h->cutoff_version = rpc->peer->cutoff_version);
	h->retransmit = 0;
	h->pad[0] = 0;
	h->pad[1] = 0;
	h->pad[2] = 0;
#ifdef CONFIG_SMT
	if (is_smt_rpc(rpc)) {
		u32 gso_offset = (u32)offset;
		h->pad[0] = (gso_offset >> 16) & 0xff;
		h->pad[1] = (gso_offset >> 8) & 0xff;
		h->pad[2] = gso_offset & 0xff;
	}
#endif

#ifdef CONFIG_SMT
	if (is_smt_rpc(rpc)) {
		if (smt_is_hw) {
			/* HW: smt_h placeholder in linear (NIC TLS
			 * engine reads TLS rec hdr at
			 * skb_tcp_all_headers offset).
			 */
			smt_h = skb_put(skb, pad_info.hdr_len);
			memset(smt_h, 0, pad_info.hdr_len);
		}

		if (segs == 1) {
			/* segs==1 contig frag.
			 * HW: seg_hdr + payload + trailer.
			 * SW: smt_h + seg_hdr + payload + trailer.
			 */
			int total = sizeof(struct homa_seg_hdr) +
				    length + pad_info.trl_len;
			u8 *frag_base;

			if (!smt_is_hw)
				total += pad_info.hdr_len;
			if (total > HOMA_SKB_PAGE_SIZE ||
			    skb_shinfo(skb)->nr_frags >= MAX_SKB_FRAGS) {
				err = -ENOMEM;
				goto error;
			}
			frag_base = homa_skb_extend_frags(rpc->hsk->homa,
							  skb, &total,
							  true);
			if (!frag_base) {
				err = -ENOMEM;
				goto error;
			}
			if (smt_is_hw) {
				h_s = (struct homa_seg_hdr *)frag_base;
			} else {
				smt_h = frag_base;
				memset(smt_h, 0, pad_info.hdr_len);
				h_s = (struct homa_seg_hdr *)
					(frag_base + pad_info.hdr_len);
			}
			memset(h_s, 0, sizeof(*h_s));
			smt_inline = true;
		} else {
			/* segs>1.
			 * HW: seg_hdr_0 in frag; rest interleaved.
			 * SW: smt_h + seg_hdr_0 in frag; rest interleaved.
			 */
			int first = sizeof(struct homa_seg_hdr);

			if (!smt_is_hw)
				first += pad_info.hdr_len;
			err = homa_skb_append_to_frag(rpc->hsk->homa,
						      skb, smt_zero,
						      first);
			if (err)
				goto error;
			if (smt_is_hw) {
				h_s = (struct homa_seg_hdr *)
					skb_frag_address(&skb_shinfo(skb)->frags[0]);
			} else {
				smt_h = (u8 *)skb_frag_address(
						&skb_shinfo(skb)->frags[0]);
				h_s = (struct homa_seg_hdr *)
					(smt_h + pad_info.hdr_len);
			}
		}
	} else
#endif
	h_s = (struct homa_seg_hdr *)skb_put(skb, sizeof(struct homa_seg_hdr));
#ifndef __STRIP__ /* See strip.py */
	h_s->offset = htonl(-1);
#else /* See strip.py */
	h_s->offset = htonl(offset);
#endif /* See strip.py */

	homa_info = homa_get_skb_info(skb);
	homa_info->next_skb = NULL;
#ifdef CONFIG_SMT_HW
	homa_info->smt_state_set = false;
#endif
	homa_info->wire_bytes = length + segs * (sizeof(struct homa_data_hdr)
			+ hsk->ip_header_length + HOMA_ETH_OVERHEAD);
#ifdef CONFIG_SMT
	homa_info->wire_bytes += pad_info.hdr_len + pad_info.trl_len
			- trailer_only * sizeof(struct homa_seg_hdr);
#endif
	homa_info->data_bytes = length;
	homa_info->seg_length = max_seg_data;
	homa_info->offset = offset;
	homa_info->rpc = rpc;
	homa_info->dont_defer = false;

#ifdef CONFIG_SMT
	smt_pr_devel("%s: wire_bytes=%d data_bytes=%d seg_length=%d offset=%d\n", __func__,
	       homa_info->wire_bytes, homa_info->data_bytes, homa_info->seg_length, homa_info->offset);
	smt_pr_devel("%s: segs=%lld homa_data_hdr=%zu ip_hdr=%d eth_overhead=%d\n", __func__,
	       segs, sizeof(struct homa_data_hdr), hsk->ip_header_length, HOMA_ETH_OVERHEAD);
#endif

#ifndef __STRIP__ /* See strip.py */
	if (segs > 1 && !homa_sock_hijacked(hsk)) {
#else /* See strip.py */
	if (segs > 1) {
#endif /* See strip.py */
		homa_set_doff(skb, sizeof(struct homa_data_hdr)  -
				sizeof(struct homa_seg_hdr));
#ifndef __STRIP__ /* See strip.py */
		h_s->offset = htonl(offset);
#endif /* See strip.py */
		gso_size = max_seg_data + sizeof(struct homa_seg_hdr);
		err = homa_fill_data_interleaved(rpc, skb, iter,
							 pad_info);
	} else {
		gso_size = max_seg_data;
#ifdef CONFIG_SMT
		if (smt_inline) {
			void *dst = (u8 *)h_s + sizeof(struct homa_seg_hdr);

			if (copy_from_iter(dst, length, iter) != length)
				err = -EFAULT;
			else
				err = 0;
		}
		else
#endif
		err = homa_skb_append_from_iter(hsk->homa, skb, iter, length);
	}
	if (err) {
		hsk->error_msg = "couldn't copy message body into packet buffers";
		goto error;
	}

	if (segs > 1) {
		skb_shinfo(skb)->gso_segs = segs;
		skb_shinfo(skb)->gso_size = gso_size;

		/* It's unclear what gso_type should be used to force software
		 * GSO; the value below seems to work...
		 */
		skb_shinfo(skb)->gso_type =
		    hsk->homa->gso_force_software ? 0xd :
		    (hsk->inet.sk.sk_family == AF_INET6) ? SKB_GSO_TCPV6 :
		    SKB_GSO_TCPV4;

#ifdef CONFIG_SMT
		smt_pr_devel("%s: segs=%lld gso_size=%d gso_type=0x%x\n", __func__,
		       segs, gso_size, skb_shinfo(skb)->gso_type);
#endif
	}

#ifdef CONFIG_SMT
	if (!is_smt_rpc(rpc))
		goto out;


#ifdef CONFIG_SMT_NOCRYPTO
	for (int i = 0; i < pad_info.trl_len; i++)
		smt_zero[i] = 0xFF;
#endif

	if (smt_inline) {
		/* trailer region was zero'd by the initial memset of the
		 * reserved frag; for NOCRYPTO, overwrite with the 0xFF pattern.
		 */
#ifdef CONFIG_SMT_NOCRYPTO
		memset((u8 *)h_s + sizeof(struct homa_seg_hdr) + length,
		       0xFF, pad_info.trl_len);
#endif
		err = 0;
	} else {
		err = homa_skb_append_to_frag(rpc->hsk->homa, skb, smt_zero,
					      pad_info.trl_len);
	}
	if (err)
		goto error;

#ifdef CONFIG_SMT_NOCRYPTO
	smt_h[0] = 0x17;
	smt_h[1] = 0x03;
	smt_h[2] = 0x03;
	{
		int smt_h_l = length + pad_info.hdr_len - 5 +
				pad_info.trl_len +
				segs * sizeof(struct homa_seg_hdr) -
				trailer_only *
				sizeof(struct homa_seg_hdr);
		smt_h[3] = smt_h_l >> 8;
		smt_h[4] = smt_h_l & 0xff;
	}
	for (int i = 5; i < pad_info.hdr_len; i++)
		smt_h[i] = 0xFF;
	goto out;
#endif

	int payload_len = length + (int)((segs - trailer_only) *
			sizeof(struct homa_seg_hdr));

	err = smt_encrypt(rpc, skb, smt_h, payload_len);
	if (err) {
		smt_pr_err("%s: smt_encrypt failed %d\n",
				__func__, err);
		goto error;
	}

out:
	smt_pr_devel("%s: len=%d data_len=%d truesize=%d headroom=%d tailroom=%d\n", __func__,
	       skb->len, skb->data_len, skb->truesize,
	       skb_headroom(skb), skb_tailroom(skb));
	smt_pr_devel("%s: nr_frags=%d\n", __func__,
	       skb_shinfo(skb)->nr_frags);

#endif /* CONFIG_SMT */
	return skb;

error:
	homa_skb_free_tx(hsk->homa, skb);
	return ERR_PTR(err);
}

/**
 * homa_message_out_fill() - Initializes information for sending a message
 * for an RPC (either request or response); copies the message data from
 * user space and (possibly) begins transmitting the message.
 * @rpc:     RPC for which to send message; this function must not
 *           previously have been called for the RPC. Must be locked. The RPC
 *           will be unlocked while copying data, but will be locked again
 *           before returning.
 * @iter:    Describes location(s) of message data in user space.
 * @xmit:    Nonzero means this method should start transmitting packets;
 *           transmission will be overlapped with copying from user space.
 *           Zero means the caller will initiate transmission after this
 *           function returns.
 *
 * Return:   0 for success, or a negative errno for failure. It is possible
 *           for the RPC to be freed while this function is active. If that
 *           happens, copying will cease, -EINVAL will be returned, and
 *           rpc->state will be RPC_DEAD. Sets rpc->hsk->error_msg on errors.
 */
int homa_message_out_fill(struct homa_rpc *rpc, struct iov_iter *iter, int xmit)
	__must_hold(rpc->bucket->lock)
{
	/* Geometry information for packets:
	 * mtu:              largest size for an on-the-wire packet (including
	 *                   all headers through IP header, but not Ethernet
	 *                   header).
	 * max_seg_data:     largest amount of Homa message data that fits
	 *                   in an on-the-wire packet (after segmentation).
	 * max_gso_data:     largest amount of Homa message data that fits
	 *                   in a GSO packet (before segmentation).
	 */
	int mtu, max_seg_data, max_gso_data;
	struct sk_buff **last_link;
	struct dst_entry *dst;
	struct homa_smt_padding_info pad_info = {.hdr_len = 0, .trl_len = 0};
	u64 segs_per_gso;
	/* Bytes of the message that haven't yet been copied into skbs. */
	int bytes_left;
	int gso_size;
	int err;

#ifdef CONFIG_SMT
	if (is_smt_rpc(rpc)) {
		smt_pr_devel("homa_message_out_fill: SMT rpc %lld detected\n",
			     rpc->id);
		pad_info = smt_get_padding_info();
	}
#endif

	if (unlikely(iter->count == 0)) {
		rpc->hsk->error_msg = "message has length zero";
		err = -EINVAL;
		goto error;
	}
	if (unlikely(iter->count > HOMA_MAX_MESSAGE_LENGTH)) {
		rpc->hsk->error_msg = "message length exceeded HOMA_MAX_MESSAGE_LENGTH";
		err = -EINVAL;
		goto error;
	}
	homa_message_out_init(rpc, iter->count);

	/* Compute the geometry of packets. */
	dst = homa_get_dst(rpc->peer, rpc->hsk);
	mtu = dst_mtu(dst);

	smt_pr_devel("%s: peer_addr=%pI6c dst_dev=%s dst_mtu=%d\n", __func__,
	       &rpc->peer->addr, dst->dev ? dst->dev->name : "NULL", mtu);

	max_seg_data = mtu - rpc->hsk->ip_header_length
			- sizeof(struct homa_data_hdr);
	gso_size = dst->dev->gso_max_size;

	smt_pr_devel("%s:  rpc_id=%lld msg_len=%zu mtu=%d ip_hdr_len=%d homa_data_hdr=%zu max_seg_data=%d\n", __func__,
	       rpc->id, iter->count, mtu, rpc->hsk->ip_header_length, sizeof(struct homa_data_hdr), max_seg_data);
#ifdef CONFIG_SMT
	smt_pr_devel("%s:  hdr_len=%d trl_len=%d\n", __func__,
	       pad_info.hdr_len, pad_info.trl_len);
#endif
	if (gso_size > rpc->hsk->homa->max_gso_size)
		gso_size = rpc->hsk->homa->max_gso_size;
	dst_release(dst);

#ifndef __STRIP__ /* See strip.py */
	/* Round gso_size down to an even # of mtus; calculation depends
	 * on whether we're doing TCP hijacking (need more space in TSO packet
	 * if no hijacking).
	 */
#ifndef CONFIG_SMT
	if (homa_sock_hijacked(rpc->hsk)) {
		/* Hijacking */
		segs_per_gso = gso_size - rpc->hsk->ip_header_length
				- sizeof(struct homa_data_hdr);
		do_div(segs_per_gso, max_seg_data);
	} else {
#endif
		/* No hijacking */
		segs_per_gso = gso_size - rpc->hsk->ip_header_length -
				sizeof(struct homa_data_hdr) +
				sizeof(struct homa_seg_hdr);
		do_div(segs_per_gso, max_seg_data +
				sizeof(struct homa_seg_hdr));
#ifndef CONFIG_SMT
	}
#endif
#else /* See strip.py */
	/* Round gso_size down to an even # of mtus. */
	segs_per_gso = gso_size - rpc->hsk->ip_header_length -
			sizeof(struct homa_data_hdr) +
			sizeof(struct homa_seg_hdr);
	do_div(segs_per_gso, max_seg_data +
			sizeof(struct homa_seg_hdr));
#endif /* See strip.py */
	if (segs_per_gso == 0)
		segs_per_gso = 1;
	max_gso_data = segs_per_gso * max_seg_data;
	UNIT_LOG("; ", "mtu %d, max_seg_data %d, max_gso_data %d",
		 mtu, max_seg_data, max_gso_data);

	smt_pr_devel("%s:  gso_size=%d segs_per_gso=%lld max_gso_data=%d\n", __func__,
	       gso_size, segs_per_gso, max_gso_data);

#ifndef __STRIP__ /* See strip.py */
	rpc->msgout.granted = rpc->msgout.unscheduled;
#endif /* See strip.py */
	// Stash pages based on payload length; we ignore padding/seg overhead
	// here because HOMA_SKB_PAGE_SIZE is 64KB which hedges most msgs
	homa_skb_stash_pages(rpc->hsk->homa, rpc->msgout.length);

	/* Each iteration of the loop below creates one GSO packet. */
#ifndef __STRIP__ /* See strip.py */
	tt_record3("starting copy from user space for id %d, length %d, unscheduled %d",
		   rpc->id, rpc->msgout.length, rpc->msgout.unscheduled);
#else /* See strip.py */
	tt_record2("starting copy from user space for id %d, length %d",
		   rpc->id, rpc->msgout.length);
#endif /* See strip.py */
	last_link = &rpc->msgout.packets;
	for (bytes_left = rpc->msgout.length; bytes_left > 0; ) {
		int skb_msg_data_bytes, offset;
		struct sk_buff *skb;

		homa_rpc_unlock(rpc);
		skb_msg_data_bytes = max_gso_data;
#ifdef CONFIG_SMT
		// reserve bytes for smt header and trailer
		skb_msg_data_bytes -= pad_info.hdr_len + pad_info.trl_len;
#endif
		offset = rpc->msgout.length - bytes_left;

#ifdef CONFIG_SMT
		smt_pr_devel("%s:  max_gso_data=%d pad_hdr=%d pad_trl=%d skb_msg_data_bytes=%d offset=%d bytes_left=%d\n", __func__,
		       max_gso_data, pad_info.hdr_len, pad_info.trl_len, skb_msg_data_bytes, offset, bytes_left);
#endif
#ifndef __STRIP__ /* See strip.py */
		/* Skip the unscheduled-boundary truncation only for SMT-HW
		 * RPCs: NIC TLS-GSO needs uniform TLS records, an odd-sized
		 * record at the unsched/sched boundary would break the
		 * receiver's record framing. homa_xmit_data still enforces
		 * the grant limit via next_xmit_offset >= granted. Plain
		 * Homa and SMT-SW RPCs keep the original truncation.
		 */
#ifdef CONFIG_SMT_HW
		bool rpc_is_hw = is_smt_rpc(rpc) &&
				 SMT_RPC(rpc)->ctx->tx_conf == SMT_HW;
#else
		bool rpc_is_hw = false;
#endif
		if (!rpc_is_hw) {
			if (offset < rpc->msgout.unscheduled &&
			    (offset + skb_msg_data_bytes) > rpc->msgout.unscheduled) {
				/* Insert a packet boundary at the unscheduled
				 * limit, so we don't transmit extra data.
				 */
				skb_msg_data_bytes = rpc->msgout.unscheduled - offset;
			}
		}
#endif /* See strip.py */
		if (skb_msg_data_bytes > bytes_left)
			skb_msg_data_bytes = bytes_left;
		skb = homa_tx_data_pkt_alloc(rpc, iter, offset, skb_msg_data_bytes,
					     max_seg_data, pad_info);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			homa_rpc_lock(rpc);
			goto error;
		}
		bytes_left -= skb_msg_data_bytes;

		homa_rpc_lock(rpc);
		if (rpc->state == RPC_DEAD) {
			/* RPC was freed while we were copying. */
			rpc->hsk->error_msg = "rpc deleted while creating outgoing message";
			err = -EINVAL;
			homa_skb_free_tx(rpc->hsk->homa, skb);
			goto error;
		}
		*last_link = skb;
		last_link = &(homa_get_skb_info(skb)->next_skb);
		*last_link = NULL;
		rpc->msgout.num_skbs++;
		rpc->msgout.skb_memory += skb->truesize;
		rpc->msgout.copied_from_user = rpc->msgout.length - bytes_left;
		rpc->msgout.first_not_tx = rpc->msgout.packets;
#ifndef __STRIP__ /* See strip.py */
		/* The code below improves pipelining for long messages
		 * by overlapping transmission with copying from user space.
		 * This is a bit tricky because sending the packets takes
		 * a significant amount time. On high-speed networks (e.g.
		 * 100 Gbps and above), copying from user space is the
		 * bottleneck, so transmitting the packets here will slow
		 * that down. Thus, we only transmit the unscheduled packets
		 * here, to fill the pipe. Packets after that can be
		 * transmitted by SoftIRQ in response to incoming grants;
		 * this allows us to use two cores: this core copying data
		 * and the SoftIRQ core sending packets.
		 */
		if (offset < rpc->msgout.unscheduled && xmit)
			homa_xmit_data(rpc, false);
#endif /* See strip.py */
	}
	tt_record2("finished copy from user space for id %d, length %d",
		   rpc->id, rpc->msgout.length);
	INC_METRIC(sent_msg_bytes, rpc->msgout.length);
	refcount_add(rpc->msgout.skb_memory, &rpc->hsk->sock.sk_wmem_alloc);
	if (xmit)
#ifndef __STRIP__ /* See strip.py */
		homa_xmit_data(rpc, false);
#else /* See strip.py */
		homa_xmit_data(rpc);
#endif /* See strip.py */
	return 0;

error:
	refcount_add(rpc->msgout.skb_memory, &rpc->hsk->sock.sk_wmem_alloc);
	return err;
}

/**
 * homa_xmit_control() - Send a control packet to the other end of an RPC.
 * @type:      Packet type, such as DATA.
 * @contents:  Address of buffer containing the contents of the packet.
 *             Only information after the common header must be valid;
 *             the common header will be filled in by this function.
 * @length:    Length of @contents (including the common header).
 * @rpc:       The packet will go to the socket that handles the other end
 *             of this RPC. Addressing info for the packet, including all of
 *             the fields of homa_common_hdr except type, will be set from this.
 *             Caller must hold either the lock or a reference.
 *
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int homa_xmit_control(enum homa_packet_type type, void *contents,
		      size_t length, struct homa_rpc *rpc)
{
	struct homa_common_hdr *h = contents;

	memset(h, 0, sizeof(*h));
	h->type = type;
	h->sport = htons(rpc->hsk->port);
	h->dport = htons(rpc->dport);
	h->sender_id = cpu_to_be64(rpc->id);
	return __homa_xmit_control(contents, length, rpc->peer, rpc->hsk);
}

/**
 * __homa_xmit_control() - Lower-level version of homa_xmit_control: sends
 * a control packet.
 * @contents:  Address of buffer containing the contents of the packet.
 *             The caller must have filled in all of the information,
 *             including the common header.
 * @length:    Length of @contents.
 * @peer:      Destination to which the packet will be sent.
 * @hsk:       Socket via which the packet will be sent.
 *
 * Return:     Either zero (for success), or a negative errno value if there
 *             was a problem.
 */
int __homa_xmit_control(void *contents, size_t length, struct homa_peer *peer,
			struct homa_sock *hsk)
{
	struct homa_common_hdr *h;
	struct sk_buff *skb;
	int extra_bytes;
	int result;

	IF_NO_STRIP(int priority);

	skb = homa_skb_alloc_tx(HOMA_MAX_HEADER);
	if (unlikely(!skb))
		return -ENOBUFS;
	skb_dst_set(skb, homa_get_dst(peer, hsk));

	h = skb_put(skb, length);
	memcpy(h, contents, length);
	extra_bytes = HOMA_MIN_PKT_LENGTH - length;
	if (extra_bytes > 0) {
		memset(skb_put(skb, extra_bytes), 0, extra_bytes);
		UNIT_LOG(",", "padded control packet with %d bytes",
			 extra_bytes);
	}
#ifndef __STRIP__ /* See strip.py */
	priority = hsk->homa->num_priorities - 1;
#endif /* See strip.py */
	skb->ooo_okay = 1;
	homa_set_doff(skb, 20);
	INC_METRIC(packets_sent[h->type - DATA], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
#ifndef __STRIP__ /* See strip.py */
	if (hsk->inet.sk.sk_family == AF_INET6) {
		homa_hijack_set_hdr(skb, peer, true);
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				  NULL, hsk->homa->priority_map[priority] << 5,
				  0);
	} else {
		homa_hijack_set_hdr(skb, peer, false);

		/* This will find its way to the DSCP field in the IPv4 hdr. */
		hsk->inet.tos = hsk->homa->priority_map[priority] << 5;
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
	}
	if (unlikely(result != 0))
		INC_METRIC(control_xmit_errors, 1);
#else /* See strip.py */
	if (hsk->inet.sk.sk_family == AF_INET6)
		result = ip6_xmit(&hsk->inet.sk, skb, &peer->flow.u.ip6, 0,
				  NULL, 0, 0);
	else
		result = ip_queue_xmit(&hsk->inet.sk, skb, &peer->flow);
#endif /* See strip.py */
	return result;
}

/**
 * homa_xmit_unknown() - Send an RPC_UNKNOWN packet to a peer.
 * @skb:         Buffer containing an incoming packet; identifies the peer to
 *               which the RPC_UNKNOWN packet should be sent.
 * @hsk:         Socket that should be used to send the RPC_UNKNOWN packet.
 */
void homa_xmit_unknown(struct sk_buff *skb, struct homa_sock *hsk)
{
	struct homa_common_hdr *h = (struct homa_common_hdr *)skb->data;
	struct in6_addr saddr = skb_canonical_ipv6_saddr(skb);
	struct homa_rpc_unknown_hdr unknown;
	struct homa_peer *peer;

#ifndef __STRIP__ /* See strip.py */
	if (hsk->homa->verbose)
		pr_notice("sending RPC_UNKNOWN to peer %s:%d for id %llu",
			  homa_print_ipv6_addr(&saddr),
			  ntohs(h->sport), homa_local_id(h->sender_id));
#endif /* See strip.py */
	tt_record3("sending unknown to 0x%x:%d for id %llu",
		   tt_addr(saddr), ntohs(h->sport),
		   homa_local_id(h->sender_id));
	memset(&unknown, 0, sizeof(unknown));
	unknown.common.sport = h->dport;
	unknown.common.dport = h->sport;
	unknown.common.type = RPC_UNKNOWN;
	unknown.common.sender_id = cpu_to_be64(homa_local_id(h->sender_id));
	peer = homa_peer_get(hsk, &saddr);
	if (!IS_ERR(peer)) {
		__homa_xmit_control(&unknown, sizeof(unknown), peer, hsk);
		homa_peer_release(peer);
	}
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent (some may be sent immediately; others may be sent
 * later by the pacer thread).
 * @rpc:       RPC to check for transmittable packets. Must be locked by
 *             caller. Note: this function will release the RPC lock while
 *             passing packets through the RPC stack, then reacquire it
 *             before returning. It is possible that the RPC gets terminated
 *             when the lock isn't held, in which case the state will
 *             be RPC_DEAD on return.
 * @force:     True means send at least one packet, even if the NIC queue
 *             is too long. False means that zero packets may be sent, if
 *             the NIC queue is sufficiently long.
 */
void homa_xmit_data(struct homa_rpc *rpc, bool force)
#else /* See strip.py */
/**
 * homa_xmit_data() - If an RPC has outbound data packets that are permitted
 * to be transmitted according to the scheduling mechanism, arrange for
 * them to be sent.
 * @rpc:       RPC to check for transmittable packets. Must be locked by
 *             caller. Note: this function will release the RPC lock while
 *             passing packets through the RPC stack, then reacquire it
 *             before returning. It is possible that the RPC gets terminated
 *             when the lock isn't held, in which case the state will
 *             be RPC_DEAD on return.
 */
void homa_xmit_data(struct homa_rpc *rpc)
#endif /* See strip.py */
	__must_hold(rpc->bucket->lock)
{
	int length;

	IF_NO_STRIP(struct homa *homa = rpc->hsk->homa);
	IF_NO_STRIP(struct netdev_queue *txq);

	while (*rpc->msgout.next_xmit && rpc->state != RPC_DEAD) {
		struct sk_buff *skb = *rpc->msgout.next_xmit;

		IF_NO_STRIP(int priority);

#ifndef __STRIP__ /* See strip.py */
		if (rpc->msgout.next_xmit_offset >= rpc->msgout.granted) {
			tt_record3("homa_xmit_data stopping at offset %d for id %u: granted is %d",
				   rpc->msgout.next_xmit_offset, rpc->id,
				   rpc->msgout.granted);
			break;
		}

		if (rpc->msgout.length - rpc->msgout.next_xmit_offset >
		    homa->qshared->defer_min_bytes &&
		    !homa_qdisc_active(rpc->hsk->homa)) {
			if (!homa_pacer_check_nic_q(homa->pacer, skb, force)) {
				tt_record1("homa_xmit_data adding id %u to throttle queue",
					   rpc->id);
				homa_pacer_manage_rpc(rpc);
				break;
			}
		}

		if (rpc->msgout.next_xmit_offset < rpc->msgout.unscheduled)
			priority = homa_unsched_priority(homa, rpc->peer,
							 rpc->msgout.length);
		else
			priority = rpc->msgout.sched_priority;
#endif /* See strip.py */
		rpc->msgout.next_xmit = &(homa_get_skb_info(skb)->next_skb);
		length = homa_get_skb_info(skb)->data_bytes;
		rpc->msgout.next_xmit_offset += length;
#ifndef __STRIP__ /* See strip.py */
		if (homa_is_client(rpc->id)) {
			INC_METRIC(client_request_bytes_done, length);
			INC_METRIC(client_requests_done,
				   rpc->msgout.next_xmit_offset ==
				   rpc->msgout.length);
		} else {
			INC_METRIC(server_response_bytes_done, length);
			INC_METRIC(server_responses_done,
				   rpc->msgout.next_xmit_offset ==
				   rpc->msgout.length);
		}
#endif /* See strip.py */

		homa_rpc_unlock(rpc);
		/* Re-stamp the cb carrier: this skb may have sat on the
		 * throttle queue and reached the IP stack from a Grant-driven
		 * softirq, where cb was clobbered after encrypt.
		 */
		smt_hw_attach_skb(rpc, skb);
		skb_get(skb);
#ifndef __STRIP__ /* See strip.py */
		__homa_xmit_data(skb, rpc, priority);
		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		if (netif_tx_queue_stopped(txq))
			tt_record4("homa_xmit_data found stopped txq for id %d, qid %d, num_queued %d, limit %d",
				   rpc->id, skb->queue_mapping,
				   txq->dql.num_queued, txq->dql.adj_limit);
		force = false;
#else /* See strip.py */
		__homa_xmit_data(skb, rpc);
#endif /* See strip.py */
		homa_rpc_lock(rpc);
	}
#ifdef CONFIG_SMT_HW
	/* Directive 2: once all data has been handed to the IP stack, the
	 * HW TIS slot can return to its per-CPU pool. Outstanding skbs hold
	 * an inflight refcount so the actual return waits for completion.
	 * Only RPCs that actually used HW offload have a TIS to release.
	 */
	if (is_smt_rpc(rpc) &&
	    SMT_RPC(rpc)->ctx->tx_conf == SMT_HW &&
	    rpc->msgout.next_xmit_offset >= rpc->msgout.length)
		smt_device_release_tis(rpc);
#endif
}

#ifndef __STRIP__ /* See strip.py */
/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 * @priority: Priority level at which to transmit the packet.
 */
void __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc, int priority)
#else /* See strip.py */
/**
 * __homa_xmit_data() - Handles packet transmission stuff that is common
 * to homa_xmit_data and homa_resend_data.
 * @skb:      Packet to be sent. The packet will be freed after transmission
 *            (and also if errors prevented transmission).
 * @rpc:      Information about the RPC that the packet belongs to.
 */
void __homa_xmit_data(struct sk_buff *skb, struct homa_rpc *rpc)
#endif /* See strip.py */
{
#ifndef __STRIP__ /* See strip.py */
	int err;

	/* Update info that may have changed since the message was initially
	 * created.
	 */
	((struct homa_data_hdr *)skb_transport_header(skb))->cutoff_version =
			rpc->peer->cutoff_version;
#endif /* See strip.py */

	skb_dst_set(skb, homa_get_dst(rpc->peer, rpc->hsk));

	skb->ooo_okay = 1;
	if (rpc->hsk->inet.sk.sk_family == AF_INET6) {
		tt_record4("calling ip6_xmit: wire_bytes %d, peer 0x%x, id %d, offset %d",
			   homa_get_skb_info(skb)->wire_bytes,
			   tt_addr(rpc->peer->addr), rpc->id,
			   homa_get_skb_info(skb)->offset);
#ifndef __STRIP__ /* See strip.py */
		homa_hijack_set_hdr(skb, rpc->peer, true);
		err = ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
			       0, NULL,
			       rpc->hsk->homa->priority_map[priority] << 5, 0);
#else /* See strip.py */
		ip6_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow.u.ip6,
			 0, NULL, 0, 0);
#endif /* See strip.py */
	} else {
		tt_record4("calling ip_queue_xmit: wire_bytes %d, peer 0x%x, id %d, offset %d",
			   homa_get_skb_info(skb)->wire_bytes,
			   tt_addr(rpc->peer->addr), rpc->id,
			   homa_get_skb_info(skb)->offset);

#ifndef __STRIP__ /* See strip.py */
		homa_hijack_set_hdr(skb, rpc->peer, false);
		rpc->hsk->inet.tos =
				rpc->hsk->homa->priority_map[priority] << 5;
		err = ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
#else /* See strip.py */
		ip_queue_xmit(&rpc->hsk->inet.sk, skb, &rpc->peer->flow);
#endif /* See strip.py */
	}
	tt_record4("Finished queueing packet: rpc id %llu, offset %d, len %d, qid %d",
		   rpc->id, homa_get_skb_info(skb)->offset,
		   homa_get_skb_info(skb)->data_bytes, skb->queue_mapping);
#ifndef __STRIP__ /* See strip.py */
	if (err)
		INC_METRIC(data_xmit_errors, 1);
#endif /* See strip.py */
	INC_METRIC(packets_sent[0], 1);
	INC_METRIC(priority_bytes[priority], skb->len);
	INC_METRIC(priority_packets[priority], 1);
}

#ifndef __STRIP__ /* See strip.py */
/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packet(s) containing a given range of bytes
 * from a message.
 * @rpc:      RPC for which data should be resent. Must be locked by caller.
 * @start:    Offset within @rpc->msgout of the first byte to retransmit.
 * @end:      Offset within @rpc->msgout of the byte just after the last one
 *            to retransmit.
 * @priority: Priority level to use for the retransmitted data packets.
 */
void homa_resend_data(struct homa_rpc *rpc, int start, int end,
		      int priority)
#else /* See strip.py */
/**
 * homa_resend_data() - This function is invoked as part of handling RESEND
 * requests. It retransmits the packet(s) containing a given range of bytes
 * from a message.
 * @rpc:      RPC for which data should be resent.
 * @start:    Offset within @rpc->msgout of the first byte to retransmit.
 * @end:      Offset within @rpc->msgout of the byte just after the last one
 *            to retransmit.
 */
void homa_resend_data(struct homa_rpc *rpc, int start, int end)
#endif /* See strip.py */
	__must_hold(rpc->bucket->lock)
{
	struct homa_skb_info *homa_info;
	struct sk_buff *skb;
#ifdef CONFIG_SMT
	struct homa_smt_padding_info smt_pad = smt_get_padding_info();
#endif

	if (end <= start)
		return;

	/* Each iteration of this loop checks one packet in the message
	 * to see if it contains segments that need to be retransmitted.
	 */
	for (skb = rpc->msgout.packets; skb; skb = homa_info->next_skb) {
		int seg_offset, offset, seg_length, data_left;
		struct homa_data_hdr *h;
#ifdef CONFIG_SMT
		int extra_ip_id = -1;
		bool smt_multi_seg = false;
#endif

		homa_info = homa_get_skb_info(skb);
		offset = homa_info->offset;
		if (offset >= end)
			break;
		if (start >= (offset + homa_info->data_bytes))
			continue;

		offset = homa_info->offset;
		seg_offset = sizeof(struct homa_data_hdr);
		data_left = homa_info->data_bytes;
		if (skb_shinfo(skb)->gso_segs <= 1) {
			seg_length = data_left;
#ifdef CONFIG_SMT
			if (is_smt_rpc(rpc)) {
				seg_length = data_left +
					     smt_pad.hdr_len + smt_pad.trl_len;
				data_left = seg_length;
			}
#endif
		} else {
			seg_length = homa_info->seg_length;
			h = (struct homa_data_hdr *)skb_transport_header(skb);
#ifdef CONFIG_SMT
			if (is_smt_rpc(rpc)) {
				smt_multi_seg = true;
				data_left = homa_info->data_bytes +
					    smt_pad.hdr_len + smt_pad.trl_len;
			}
#endif
		}
		for ( ; data_left > 0; data_left -= seg_length,
		     offset += seg_length,
		     seg_offset += skb_shinfo(skb)->gso_size) {
			struct homa_skb_info *new_homa_info;
			struct sk_buff *new_skb;
			int err;
#ifdef CONFIG_SMT
			int logical_offset;
			int logical_length;
			extra_ip_id++;
#endif

			if (seg_length > data_left)
				seg_length = data_left;

#ifdef CONFIG_SMT
			logical_offset = offset;
			logical_length = seg_length;
			if (smt_multi_seg) {
				logical_offset = homa_info->offset +
					(int)extra_ip_id * homa_info->seg_length;
				if (extra_ip_id != 0)
					logical_offset -= smt_pad.hdr_len +
							  smt_pad.trl_len;
				else
					logical_length = seg_length -
						smt_pad.hdr_len -
						smt_pad.trl_len;
			}

			if (end <= logical_offset)
				goto resend_done;
			if ((logical_offset + logical_length) <= start)
				continue;
#else
			if (end <= offset)
				goto resend_done;
			if ((offset + seg_length) <= start)
				continue;
#endif

			/* This segment must be retransmitted. */
#ifndef __STRIP__ /* See strip.py */
#ifdef CONFIG_SMT
			if (is_smt_rpc(rpc))
				new_skb = homa_skb_alloc_tx(
					sizeof(struct homa_data_hdr) +
					smt_pad.hdr_len);
			else
#endif
				new_skb = homa_skb_alloc_tx(
					sizeof(struct homa_data_hdr));
#else /* See strip.py */
			new_skb = homa_skb_alloc_tx(sizeof(struct homa_data_hdr) +
						    seg_length);
#endif /* See strip.py */
			if (unlikely(!new_skb)) {
				UNIT_LOG("; ", "skb allocation error");
				goto resend_done;
			}
#ifdef CONFIG_SMT
			if (is_smt_rpc(rpc))
				/* SMT wire hdr is 52 bytes (data_hdr minus
				 * seg_hdr); the seg_hdr ciphertext is
				 * reinstated in the following append_from_skb
				 * call via the seg_hdr-reserve.
				 */
				h = __skb_put_data(new_skb,
					skb_transport_header(skb),
					sizeof(struct homa_data_hdr) -
					sizeof(struct homa_seg_hdr));
			else
#endif
				h = __skb_put_data(new_skb,
					skb_transport_header(skb),
					sizeof(struct homa_data_hdr));
			h->common.sequence = htonl(offset);
#ifdef CONFIG_SMT
			if (!is_smt_rpc(rpc))
#endif
			h->seg.offset = htonl(offset);
			h->retransmit = 1;
			IF_NO_STRIP(h->incoming = htonl(end));
#ifdef CONFIG_SMT
			if (is_smt_rpc(rpc)) {
				bool smt_trailer_only = smt_multi_seg &&
					seg_length <= smt_pad.trl_len;

				h->retransmit |= (extra_ip_id & 0x0f) << 4;
				err = homa_skb_append_from_skb(rpc->hsk->homa,
					new_skb, skb,
					seg_offset -
					(int)sizeof(struct homa_seg_hdr),
					smt_trailer_only ? seg_length :
					seg_length +
					(int)sizeof(struct homa_seg_hdr),
					smt_pad.hdr_len +
					(int)sizeof(struct homa_seg_hdr));
			} else
#endif
			err = homa_skb_append_from_skb(rpc->hsk->homa, new_skb,
						       skb, seg_offset,
						       seg_length, 0);
			if (err != 0) {
				pr_err("%s got error %d from homa_skb_append_from_skb\n",
				       __func__, err);
				UNIT_LOG("; ", "%s got error %d while copying data",
					 __func__, -err);
				kfree_skb(new_skb);
				goto resend_done;
			}

			new_homa_info = homa_get_skb_info(new_skb);
			new_homa_info->next_skb = rpc->msgout.to_free;
			new_homa_info->wire_bytes = rpc->hsk->ip_header_length
					+ sizeof(struct homa_data_hdr)
					+ seg_length + HOMA_ETH_OVERHEAD;
			new_homa_info->data_bytes = seg_length;
			new_homa_info->seg_length = seg_length;
			new_homa_info->offset = offset;
			new_homa_info->rpc = rpc;
			new_homa_info->dont_defer = false;

			rpc->msgout.to_free = new_skb;
			rpc->msgout.num_skbs++;
			skb_get(new_skb);
			tt_record3("retransmitting offset %d, length %d, id %d",
				   offset, seg_length, rpc->id);
#ifndef __STRIP__ /* See strip.py */
			homa_pacer_check_nic_q(rpc->hsk->homa->pacer, new_skb,
					       true);
			__homa_xmit_data(new_skb, rpc, priority);
#else /* See strip.py */
			__homa_xmit_data(new_skb, rpc);
#endif /* See strip.py */
			INC_METRIC(resent_packets, 1);
		}
	}

resend_done:
	return;
}

/**
 * homa_rpc_tx_end() - Return the offset of the first byte in an
 * RPC's outgoing message that has not yet been fully transmitted.
 * "Fully transmitted" means the message has been transmitted by the
 * NIC and the skb has been released by the driver. This is different from
 * rpc->msgout.next_xmit_offset, which computes the first offset that
 * hasn't yet been passed to the IP stack.
 * @rpc:    RPC to check
 * Return:  See above. If the message has been fully transmitted then
 *          rpc->msgout.length is returned.
 */
int homa_rpc_tx_end(struct homa_rpc *rpc)
{
	struct sk_buff *skb = rpc->msgout.first_not_tx;

	while (skb) {
		struct homa_skb_info *homa_info = homa_get_skb_info(skb);

		/* next_xmit_offset tells us whether the packet has been
		 * passed to the IP stack. Checking the reference count tells
		 * us whether the packet has been released by the driver
		 * (which only happens after notification from the NIC that
		 * transmission is complete).
		 */
		if (homa_info->offset >= rpc->msgout.next_xmit_offset ||
		    refcount_read(&skb->users) > 1)
			return homa_info->offset;
		skb = homa_info->next_skb;
		rpc->msgout.first_not_tx = skb;
	}
	return rpc->msgout.length;
}
