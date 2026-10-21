// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

#include "homa_impl.h"
#include "homa_rpc.h"
#include "homa_sock.h"
#include "smt_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(smt_outgoing) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client_ip[1];
	struct in6_addr server_ip[1];
	int server_port;
};
FIXTURE_SETUP(smt_outgoing)
{
	struct smt_aes_gcm_128_info info = {};
	int i;

	mock_ipv6 = false;
	homa_init(&self->homa);
	smt_load(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->server_port = 99;
	info.smt.peer_addr = self->server_ip[0].s6_addr32[3];
	info.smt.peer_port = htons(self->server_port);
	info.aes_gcm_128.info.version = TLS_1_2_VERSION;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	for (i = TLS_TX; i <= TLS_RX; i++)
		EXPECT_EQ(0, smt_setsockopt(&self->hsk.sock, SOL_TLS, i,
					    KERNEL_SOCKPTR(&info),
					    sizeof(info)));
	unit_log_clear();
}
FIXTURE_TEARDOWN(smt_outgoing)
{
	homa_destroy(&self->homa);
	smt_unload();
	unit_teardown();
}

TEST_F(smt_outgoing, smt_rpc_init_rec_seq__both_ends_agree)
{
	struct homa_rpc client = {.id = 1000}, server = {.id = 1001};
	u8 ctx[8], srx[8], stx[8], crx[8];

	smt_rpc_init_rec_seq(&client, true, ctx);
	smt_rpc_init_rec_seq(&server, false, srx);
	smt_rpc_init_rec_seq(&server, true, stx);
	smt_rpc_init_rec_seq(&client, false, crx);
	EXPECT_EQ(500ULL << 17, get_unaligned_be64(ctx));
	EXPECT_EQ(get_unaligned_be64(ctx), get_unaligned_be64(srx));
	EXPECT_EQ(get_unaligned_be64(ctx) | 1 << 16, get_unaligned_be64(stx));
	EXPECT_EQ(get_unaligned_be64(stx), get_unaligned_be64(crx));
}

TEST_F(smt_outgoing, smt_tx_init__record_limits)
{
	struct homa_rpc *crpc;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port, 1000,
			       100000, 100);
	ASSERT_NE(NULL, crpc);
	ASSERT_TRUE(is_smt_rpc(crpc));
	EXPECT_GE(SMT_MAX_RECORD_SEGS, crpc->msgout.max_gso_segs);
	EXPECT_GE(TLS_MAX_PAYLOAD_SIZE, crpc->msgout.max_gso_data +
		  SMT_RPC(crpc)->rec_pre + SMT_RPC(crpc)->rec_post);
}

TEST_F(smt_outgoing, smt_tx_skb_range__record_of_offset)
{
	struct homa_rpc *crpc;
	u32 offset, end;
	int bytes, start;
	u64 segs;

	crpc = unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port, 1000,
			       100000, 100);
	ASSERT_NE(NULL, crpc);

	/* The second record, a full one: it follows the first one. */
	offset = crpc->msgout.max_gso_data + 7;
	start = smt_tx_skb_range(crpc, &offset, &end, &bytes, &segs);
	EXPECT_EQ(crpc->msgout.max_gso_data, offset);
	EXPECT_EQ(2 * crpc->msgout.max_gso_data, end);
	EXPECT_EQ(bytes, start);
	EXPECT_EQ(crpc->msgout.max_gso_segs, segs);

	/* The last record is short and ends the frags. */
	offset = 99999;
	start = smt_tx_skb_range(crpc, &offset, &end, &bytes, &segs);
	EXPECT_EQ(100000, end);
	EXPECT_EQ(crpc->msgout.frag_bytes, start + bytes);
}

/* A client RPC with a 100000-byte message, sent with GSO packets of up to
 * 40 segments.
 */
static struct homa_rpc *big_gso_rpc(FIXTURE_DATA(smt_outgoing) *self)
{
	mock_devices[0].gso_max_segs = 40;
	mock_devices[0].gso_max_size = 100000;
	self->homa.max_gso_size = 100000;
	return unit_client_rpc(&self->hsk, UNIT_OUTGOING, self->client_ip,
			       self->server_ip, self->server_port, 1000,
			       100000, 100);
}

TEST_F(smt_outgoing, smt_tx_init__records_fill_whole_segments)
{
	int extra, seg_data;
	struct homa_rpc *crpc;

	crpc = big_gso_rpc(self);
	ASSERT_NE(NULL, crpc);
	extra = SMT_RPC(crpc)->rec_pre + SMT_RPC(crpc)->rec_post;
	seg_data = SMT_SEG_DATA(crpc->msgout.max_seg_data);

	/* 11 segments of 1400 bytes hold 16 KB with the header and tag. */
	EXPECT_EQ(11, SMT_RPC(crpc)->rec_segs);
	EXPECT_EQ(11 * seg_data - extra, SMT_RPC(crpc)->rec_data);
	EXPECT_EQ(33, crpc->msgout.max_gso_segs);
	EXPECT_EQ(SMT_RPC(crpc)->rec_data, crpc->msgout.max_gso_data);
}
TEST_F(smt_outgoing, smt_tx_init__smt_record_segs)
{
	struct homa_rpc *crpc;

	self->homa.smt_record_segs = 3;
	crpc = big_gso_rpc(self);
	ASSERT_NE(NULL, crpc);
	EXPECT_EQ(3, SMT_RPC(crpc)->rec_segs);
	EXPECT_EQ(39, crpc->msgout.max_gso_segs);
}
TEST_F(smt_outgoing, smt_tx_skb_range__several_records)
{
	struct homa_rpc *crpc;
	int bytes, start, data, full;
	u32 offset, end;
	u64 segs;

	crpc = big_gso_rpc(self);
	ASSERT_NE(NULL, crpc);
	data = SMT_RPC(crpc)->rec_data;
	full = 11 * (crpc->msgout.max_seg_data + sizeof(struct homa_seg_hdr));

	/* As many records as a GSO packet holds, from the one at offset. */
	offset = data + 7;
	end = 100000;
	start = smt_tx_skb_range(crpc, &offset, &end, &bytes, &segs);
	EXPECT_EQ(data, offset);
	EXPECT_EQ(4 * data, end);
	EXPECT_EQ(full, start);
	EXPECT_EQ(3 * full, bytes);
	EXPECT_EQ(33, segs);

	/* Up to the record that holds the last byte wanted. */
	offset = 0;
	end = data + 1;
	smt_tx_skb_range(crpc, &offset, &end, &bytes, &segs);
	EXPECT_EQ(2 * data, end);
	EXPECT_EQ(22, segs);

	/* Only sealed records. */
	crpc->msgout.copied_from_user = data;
	offset = 0;
	end = 100000;
	smt_tx_skb_range(crpc, &offset, &end, &bytes, &segs);
	EXPECT_EQ(data, end);
	EXPECT_EQ(full, bytes);

	/* The last record is short and ends the frags. */
	crpc->msgout.copied_from_user = 100000;
	offset = 99999;
	end = 100000;
	start = smt_tx_skb_range(crpc, &offset, &end, &bytes, &segs);
	EXPECT_EQ(6 * data, offset);
	EXPECT_EQ(100000, end);
	EXPECT_EQ(crpc->msgout.frag_bytes, start + bytes);
}
TEST_F(smt_outgoing, smt_tx_skb_hdr__first_record_and_rec_segs)
{
	struct homa_data_hdr *h;
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end = 100000;
	int data;

	crpc = big_gso_rpc(self);
	ASSERT_NE(NULL, crpc);
	data = SMT_RPC(crpc)->rec_data;
	skb = homa_tx_skb_alloc(crpc, data + 7, &end);
	ASSERT_FALSE(IS_ERR(skb));
	h = (struct homa_data_hdr *)skb_transport_header(skb);
	EXPECT_EQ(11, ntohl(h->reserved1));
	EXPECT_EQ(data, (h->pad[0] << 16) | (h->pad[1] << 8) | h->pad[2]);
	EXPECT_EQ(data, ntohl(h->common.sequence));
	EXPECT_EQ(4 * data, end);
	kfree_skb(skb);
}
TEST_F(smt_outgoing, homa_tx_skb_alloc__half_as_many_records)
{
	struct homa_rpc *crpc;
	struct sk_buff *skb;
	u32 end = 100000;
	int data;

	/* Pages of 4 KB: a record takes 5 frags. */
	mock_no_high_order_pages = true;
	crpc = big_gso_rpc(self);
	ASSERT_NE(NULL, crpc);
	data = SMT_RPC(crpc)->rec_data;

	/* 3 and 2 records need more frags than 6; 1 record does not. */
	mock_max_skb_frags = 6;
	skb = homa_tx_skb_alloc(crpc, 0, &end);
	ASSERT_FALSE(IS_ERR(skb));
	EXPECT_EQ(data, end);
	EXPECT_GE(6, skb_shinfo(skb)->nr_frags);
	kfree_skb(skb);

	/* Fails if even one record needs too many. */
	mock_max_skb_frags = 1;
	end = 100000;
	skb = homa_tx_skb_alloc(crpc, 0, &end);
	EXPECT_TRUE(IS_ERR(skb));
	EXPECT_EQ(EINVAL, -PTR_ERR(skb));
}
