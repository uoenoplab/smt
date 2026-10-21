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

FIXTURE(smt_incoming) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr client_ip[1];
	int client_port;
	struct in6_addr server_ip[1];
};
FIXTURE_SETUP(smt_incoming)
{
	struct smt_aes_gcm_128_info info = {};
	int i;

	mock_ipv6 = false;
	homa_init(&self->homa);
	smt_load(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	mock_sock_init(&self->hsk, self->hnet, 99);
	self->client_ip[0] = unit_get_in_addr("196.168.0.1");
	self->client_port = 40000;
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	info.smt.peer_addr = self->client_ip[0].s6_addr32[3];
	info.smt.peer_port = htons(self->client_port);
	info.aes_gcm_128.info.version = TLS_1_3_VERSION;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	for (i = TLS_TX; i <= TLS_RX; i++)
		EXPECT_EQ(0, smt_setsockopt(&self->hsk.sock, SOL_TLS, i,
					    KERNEL_SOCKPTR(&info),
					    sizeof(info)));
	unit_log_clear();
}
FIXTURE_TEARDOWN(smt_incoming)
{
	homa_destroy(&self->homa);
	smt_unload();
	unit_teardown();
}

/* A server RPC for message number @m (RPC id >> 1) of the client, or NULL
 * if SMT refuses it. With @accept, the RPC authenticates its request and
 * ends.
 */
static struct homa_rpc *request(FIXTURE_DATA(smt_incoming) *self, u64 m,
				bool accept)
{
	struct homa_rpc *srpc = unit_server_rpc(&self->hsk,
						UNIT_RCVD_START_MSG,
						self->client_ip,
						self->server_ip,
						self->client_port,
						2 * m + 1, 100, 100);

	if (srpc && accept) {
		smt_replay_accept(srpc);
		homa_rpc_lock(srpc);
		homa_rpc_end(srpc);
		homa_rpc_unlock(srpc);
	}
	return srpc;
}

TEST_F(smt_incoming, smt_replay__drops_authenticated_request)
{
	ASSERT_NE(NULL, request(self, 10, true));
	EXPECT_EQ(NULL, request(self, 10, false));
	EXPECT_EQ(1, homa_metrics_per_cpu()->smt_replay_drops);
	EXPECT_NE(NULL, request(self, 9, false));
}
TEST_F(smt_incoming, smt_replay__drops_request_older_than_window)
{
	ASSERT_NE(NULL, request(self, SMT_REPLAY_WINDOW + 5, true));
	EXPECT_EQ(NULL, request(self, 5, false));
	EXPECT_EQ(1, homa_metrics_per_cpu()->smt_replay_too_old);
	EXPECT_NE(NULL, request(self, 6, false));
}
TEST_F(smt_incoming, smt_replay_accept__clears_slots_it_skips)
{
	ASSERT_NE(NULL, request(self, 5, true));
	ASSERT_NE(NULL, request(self, SMT_REPLAY_WINDOW + 10, true));

	/* Slot 5 is that of message 5, which the window no longer covers. */
	EXPECT_NE(NULL, request(self, SMT_REPLAY_WINDOW + 5, false));
	EXPECT_EQ(0, homa_metrics_per_cpu()->smt_replay_drops);
}

/* Where smt_calc_rx_logical_info places a DATA segment of @srpc with IP id
 * @ip_id, in a GSO packet whose first record starts at @rec_offset and has
 * @rec_segs segments.
 */
static struct smt_rx_logical_info segment(FIXTURE_DATA(smt_incoming) *self,
					  struct homa_rpc *srpc, u16 ip_id,
					  u32 rec_offset, u32 rec_segs)
{
	struct smt_rx_logical_info info;
	struct homa_data_hdr h = {};
	struct sk_buff *skb;

	h.common.type = DATA;
	h.reserved1 = htonl(rec_segs);
	h.pad[0] = rec_offset >> 16;
	h.pad[1] = rec_offset >> 8;
	h.pad[2] = rec_offset;
	skb = mock_skb_alloc(self->client_ip, self->server_ip, &h.common, 1400,
			     0);
	ip_hdr(skb)->id = htons(ip_id);
	info = smt_calc_rx_logical_info(srpc, skb);
	kfree_skb(skb);
	return info;
}

TEST_F(smt_incoming, smt_calc_rx_logical_info__several_records)
{
	struct homa_rpc *srpc = request(self, 10, false);
	struct smt_rx_logical_info a, b;
	int rec;

	ASSERT_NE(NULL, srpc);
	rec = 11 * SMT_SEG_DATA(SMT_RPC(srpc)->smt_max_pkt_data) -
	      SMT_RPC(srpc)->rec_pre - SMT_RPC(srpc)->rec_post;

	/* Segment 13 with 11 segments in each record is segment 2 of the
	 * second record.
	 */
	a = segment(self, srpc, 13, 1000, 11);
	b = segment(self, srpc, 2, 1000 + rec, 0);
	EXPECT_EQ(b.start, a.start);
	EXPECT_EQ(b.length, a.length);

	/* The first segment of the second record. */
	a = segment(self, srpc, 11, 1000, 11);
	EXPECT_EQ(1000 + rec, a.start);
}
TEST_F(smt_incoming, smt_calc_rx_logical_info__one_record_in_gso_packet)
{
	struct homa_rpc *srpc = request(self, 10, false);
	struct smt_rx_logical_info a, b;

	ASSERT_NE(NULL, srpc);

	/* reserved1 0, from a sender with one record in each GSO packet,
	 * and an impossible reserved1 both mean one record.
	 */
	a = segment(self, srpc, 13, 1000, 0);
	EXPECT_EQ(1000 + 13 * SMT_SEG_DATA(SMT_RPC(srpc)->smt_max_pkt_data) -
		  SMT_RPC(srpc)->rec_pre - SMT_RPC(srpc)->rec_post, a.start);
	b = segment(self, srpc, 13, 1000, SMT_MAX_RECORD_SEGS + 1);
	EXPECT_EQ(a.start, b.start);
}
