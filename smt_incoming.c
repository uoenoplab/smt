// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "smt_impl.h"

#include "homa_peer.h"

struct smt_rx_logical_info smt_calc_rx_logical_info(struct homa_rpc *rpc,
						    struct sk_buff *skb)
{
	struct smt_rx_logical_info info;
	u16 ip_id = smt_logical_ip_id(skb);
	u32 gso_offset = smt_gso_offset(skb);

	info.start = smt_logical_offset(rpc, ip_id, gso_offset);
	info.length = smt_logical_data_bytes(rpc, skb, ip_id);
	info.end = info.start + info.length;

	if (ip_id != 0)
		goto out;

	u8 *smt_header;
	int record_len, max_frame_data;

	info.record_data_offset = info.start;

	if (skb->len - skb_transport_offset(skb) < sizeof(struct homa_data_hdr) -
	    sizeof(struct homa_seg_hdr) + SMT_RPC(rpc)->rec_pre) {
		goto out;
	}

	smt_header = skb_transport_header(skb)
		+ sizeof(struct homa_data_hdr) - sizeof(struct homa_seg_hdr);

	/* Validate TLS record header */
	if ((smt_header[0] != 0x17) || (smt_header[1] != 0x03) ||
		(smt_header[2] != 0x03)) {
		goto out;
	}

	record_len = (smt_header[3] << 8) | (smt_header[4] & 0xff);
	if (record_len <= 0) {
		goto out;
	}

	/* record_len counts everything after the header. */
	info.record_data_len = record_len + TLS_HEADER_SIZE -
				SMT_RPC(rpc)->rec_post;
	max_frame_data = SMT_RPC(rpc)->smt_max_pkt_data +
				sizeof(struct homa_seg_hdr);
	info.record_data_len -= ((info.record_data_len + max_frame_data - 1) /
					max_frame_data) * SMT_SEG_HDR;
	info.record_data_len -= SMT_RPC(rpc)->rec_pre;

	return info;

out:
	info.record_data_offset = -1;
	info.record_data_len = -1;
	return info;
}

bool smt_record_complete(struct homa_rpc *rpc, struct sk_buff *skb)
{
	struct sk_buff *first_skb;
	struct smt_rx_logical_info *info;
	int data_end;
	struct homa_gap *gap;
	bool result = false;

	first_skb = skb_peek(&rpc->msgin.packets);
	if (!first_skb)
		goto out;

	info = SMT_RX_INFO(first_skb);

	if (info->record_data_offset == -1)
		goto out;

	if (info->record_data_offset != SMT_RPC(rpc)->decrypt_offset)
		goto out;

	data_end = info->record_data_offset + info->record_data_len;

	if (rpc->msgin.recv_end < data_end)
		goto out;

	list_for_each_entry(gap, &rpc->msgin.gaps, links) {
		if (gap->start >= data_end)
			break;
		goto out;
	}
	result = true;

out:
	return result;
}

int smt_data_offset(struct homa_rpc *rpc, struct sk_buff *skb)
{
	int offset = SMT_SW_SGVEC_OFFSET + SMT_SEG_HDR;

	/* Only a record's first packet has a record_data_offset (see
	 * smt_calc_rx_logical_info); cb is hot, the IP header often isn't.
	 */
	if (SMT_RX_INFO(skb)->record_data_offset != -1)
		offset += SMT_RPC(rpc)->rec_pre;
	return offset;
}

/* Whether @rpc's request can't be new: its message number is older than the
 * window or was authenticated already. Counts the reason.
 */
static bool smt_replay_seen(struct homa_rpc *rpc)
{
	struct smt_replay_window *w = &SMT_RPC(rpc)->ctx->replay;
	u64 m = rpc->id >> 1;
	bool seen = false;

	spin_lock_bh(&w->lock);
	if (m <= w->top) {
		if (w->top - m >= SMT_REPLAY_WINDOW) {
			INC_METRIC(smt_replay_too_old, 1);
			seen = true;
		} else if (test_bit(m % SMT_REPLAY_WINDOW, w->seen)) {
			INC_METRIC(smt_replay_drops, 1);
			seen = true;
		}
	}
	spin_unlock_bh(&w->lock);
	return seen;
}

/**
 * smt_replay_accept() - Record that the request of server RPC @rpc has been
 * authenticated (its first record decrypted), so a replay of it is dropped
 * by smt_rpc_alloc_server_sock_lock. Unauthenticated packets never move the
 * window. Called with the RPC unlocked, so the RPC may already have ended
 * and been unhashed; a replay arriving in that gap gets through.
 * @rpc:  Server RPC whose first record has just been decrypted.
 */
void smt_replay_accept(struct homa_rpc *rpc)
{
	struct smt_replay_window *w = &SMT_RPC(rpc)->ctx->replay;
	u64 m = rpc->id >> 1;

	spin_lock_bh(&w->lock);
	if (m > w->top) {
		u64 skipped = m - w->top - 1;

		if (skipped >= SMT_REPLAY_WINDOW) {
			bitmap_zero(w->seen, SMT_REPLAY_WINDOW);
		} else {
			/* Clear the slots of the numbers skipped over. */
			u32 start = (w->top + 1) % SMT_REPLAY_WINDOW;
			u32 n = min_t(u64, skipped, SMT_REPLAY_WINDOW - start);

			bitmap_clear(w->seen, start, n);
			bitmap_clear(w->seen, 0, skipped - n);
		}
		w->top = m;
	} else if (w->top - m >= SMT_REPLAY_WINDOW) {
		/* Too old to record; a replay of it is too old as well. */
		goto out;
	}
	__set_bit(m % SMT_REPLAY_WINDOW, w->seen);
out:
	spin_unlock_bh(&w->lock);
}

int smt_rpc_alloc_server_sock_lock(struct homa_sock *hsk, struct homa_rpc *rpc)
{
	int err;

	err = smt_rpc_ctx_init(hsk, rpc);
	if (!err && is_smt_rpc(rpc) && smt_replay_seen(rpc))
		err = -EALREADY;
	return err;
}
