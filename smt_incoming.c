// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

#include "smt_impl.h"

#include "homa_peer.h"

struct smt_rx_logical_info smt_calc_rx_logical_info(struct homa_rpc *rpc,
						    struct sk_buff *skb)
{
	struct smt_rx_logical_info info;
	u16 ip_id = smt_logical_ip_id(skb);
	u32 gso_offset = smt_gso_offset(skb);
	u64 __t = SMT_TIME_START();

	info.start = smt_logical_offset(rpc, ip_id, gso_offset);
	info.length = smt_logical_data_bytes(skb, ip_id);
	info.end = info.start + info.length;
	info.trailer_only = smt_trailer_only(skb, ip_id);

	if (ip_id != 0)
		goto out;

	u8 *smt_header;
	int record_len, max_frame_data;

	info.record_data_offset = info.start;

	if (skb->len - skb_transport_offset(skb) < SMT_RECORD_EXTRA_PRE_LENGTH) {
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

	info.record_data_len = record_len + TLS_HEADER_SIZE -
				SMT_RECORD_EXTRA_POST_LENGTH;
	max_frame_data = SMT_RPC(rpc)->smt_max_pkt_data +
				sizeof(struct homa_seg_hdr);
	info.record_data_len -= ((info.record_data_len + max_frame_data - 1) /
					max_frame_data) * sizeof(struct homa_seg_hdr);
	info.record_data_len -= SMT_RECORD_EXTRA_PRE_LENGTH;

	return info;

out:
	info.record_data_offset = -1;
	info.record_data_len = -1;
	SMT_TIME_END(smt_rx_calc, __t);
	return info;
}

bool smt_record_complete(struct homa_rpc *rpc, struct sk_buff *skb)
{
	struct sk_buff *first_skb;
	struct smt_rx_logical_info *info;
	int data_end;
	struct homa_gap *gap;
	bool result = false;
	u64 __t = SMT_TIME_START();

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
	SMT_TIME_END(smt_record_complete, __t);
	if (result)
		SMT_COUNT(smt_record_complete_true);
	return result;
}

int smt_data_offset(struct sk_buff *skb)
{
	int offset = sizeof(struct homa_data_hdr);

	if (smt_logical_ip_id(skb) == 0)
		offset += SMT_RECORD_EXTRA_PRE_LENGTH;
	return offset;
}

int smt_rpc_alloc_server_sock_lock(struct homa_sock *hsk, struct homa_rpc *rpc)
{
	int err;

	err = smt_rpc_ctx_init(hsk, rpc);
	if (err)
		return err;
	return 0;
}
