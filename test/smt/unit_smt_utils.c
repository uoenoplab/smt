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

/* Give @hsk the key of one direction (@optname: TLS_TX or TLS_RX) for the
 * peer at @ip and @port.
 */
static int set_key(struct homa_sock *hsk, struct in6_addr *ip, int port,
		   int optname, u16 version, u8 key0)
{
	struct smt_aes_gcm_128_info info = {};

	info.smt.peer_addr = ip->s6_addr32[3];
	info.smt.peer_port = htons(port);
	info.aes_gcm_128.info.version = version;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	info.aes_gcm_128.key[0] = key0;
	return smt_setsockopt(&hsk->sock, SOL_TLS, optname,
			      KERNEL_SOCKPTR(&info), sizeof(info));
}

static int set_keys(struct homa_sock *hsk, struct in6_addr *ip, int port,
		    u16 version)
{
	return set_key(hsk, ip, port, TLS_TX, version, 1) ?:
	       set_key(hsk, ip, port, TLS_RX, version, 2);
}

static int set_fixed_key(struct homa_sock *hsk, u16 version, u16 cipher)
{
	struct tls_crypto_info info = {.version = version,
				       .cipher_type = cipher};

	return smt_setsockopt(&hsk->sock, SOL_TLS, SMT_DEBUG_FIXED_KEY,
			      KERNEL_SOCKPTR(&info), sizeof(info));
}

FIXTURE(smt_utils) {
	struct homa homa;
	struct homa_net *hnet;
	struct homa_sock hsk;
	struct in6_addr server_ip[1];
	struct in6_addr other_ip[1];
	int server_port;
	union sockaddr_in_union server_addr;
	union sockaddr_in_union other_addr;
};
FIXTURE_SETUP(smt_utils)
{
	mock_ipv6 = false;
	homa_init(&self->homa);
	smt_load(&self->homa);
	self->hnet = mock_hnet(0, &self->homa);
	mock_sock_init(&self->hsk, self->hnet, 0);
	self->server_ip[0] = unit_get_in_addr("1.2.3.4");
	self->other_ip[0] = unit_get_in_addr("1.2.3.5");
	self->server_port = 99;
	self->server_addr.in6.sin6_family = AF_INET6;
	self->server_addr.in6.sin6_addr = self->server_ip[0];
	self->server_addr.in6.sin6_port = htons(self->server_port);
	self->other_addr = self->server_addr;
	self->other_addr.in6.sin6_addr = self->other_ip[0];
	unit_log_clear();
}
FIXTURE_TEARDOWN(smt_utils)
{
	homa_destroy(&self->homa);
	smt_unload();
	unit_teardown();
}

/* A client RPC to @addr, unlocked, or an ERR_PTR. */
static struct homa_rpc *new_client(struct homa_sock *hsk,
				   union sockaddr_in_union *addr)
{
	struct homa_rpc *crpc = homa_rpc_alloc_client(hsk, addr);

	if (!IS_ERR(crpc))
		homa_rpc_unlock(crpc);
	return crpc;
}

static void end_rpc(struct homa_rpc *rpc)
{
	homa_rpc_lock(rpc);
	homa_rpc_end(rpc);
	homa_rpc_unlock(rpc);
	while (homa_rpc_reap(rpc->hsk))
		;
}

TEST_F(smt_utils, smt_ctx_setup__bad_version)
{
	EXPECT_EQ(EINVAL, -set_key(&self->hsk, self->server_ip,
				   self->server_port, TLS_TX, 0x0302, 1));
}
TEST_F(smt_utils, smt_ctx_setup__bad_cipher)
{
	struct smt_aes_gcm_128_info info = {};

	info.smt.peer_addr = self->server_ip[0].s6_addr32[3];
	info.smt.peer_port = htons(self->server_port);
	info.aes_gcm_128.info.version = TLS_1_3_VERSION;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
	EXPECT_EQ(EINVAL, -smt_setsockopt(&self->hsk.sock, SOL_TLS, TLS_TX,
					  KERNEL_SOCKPTR(&info), sizeof(info)));
}
TEST_F(smt_utils, smt_ctx_setup__bad_length)
{
	struct smt_aes_gcm_128_info info = {};

	info.smt.peer_addr = self->server_ip[0].s6_addr32[3];
	info.smt.peer_port = htons(self->server_port);
	info.aes_gcm_128.info.version = TLS_1_3_VERSION;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_256;
	EXPECT_EQ(EINVAL, -smt_setsockopt(&self->hsk.sock, SOL_TLS, TLS_TX,
					  KERNEL_SOCKPTR(&info), sizeof(info)));
}
TEST_F(smt_utils, smt_ctx_setup__tls12_iv_must_equal_rec_seq)
{
	struct smt_aes_gcm_128_info info = {};

	info.smt.peer_addr = self->server_ip[0].s6_addr32[3];
	info.smt.peer_port = htons(self->server_port);
	info.aes_gcm_128.info.version = TLS_1_2_VERSION;
	info.aes_gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	info.aes_gcm_128.iv[0] = 1;
	EXPECT_EQ(EINVAL, -smt_setsockopt(&self->hsk.sock, SOL_TLS, TLS_TX,
					  KERNEL_SOCKPTR(&info), sizeof(info)));
	info.aes_gcm_128.info.version = TLS_1_3_VERSION;
	EXPECT_EQ(0, smt_setsockopt(&self->hsk.sock, SOL_TLS, TLS_TX,
				    KERNEL_SOCKPTR(&info), sizeof(info)));
}
TEST_F(smt_utils, smt_ctx_setup__no_key_for_every_peer)
{
	struct in6_addr any = {};

	EXPECT_EQ(EINVAL, -set_key(&self->hsk, &any, 0, TLS_TX,
				   TLS_1_3_VERSION, 1));
	EXPECT_EQ(NULL, self->hsk.smt);
}

TEST_F(smt_utils, smt_ctx_init__directions_share_version)
{
	EXPECT_EQ(0, set_key(&self->hsk, self->server_ip, self->server_port,
			     TLS_TX, TLS_1_2_VERSION, 1));
	EXPECT_EQ(EINVAL, -set_key(&self->hsk, self->server_ip,
				   self->server_port, TLS_RX,
				   TLS_1_3_VERSION, 2));
}

TEST_F(smt_utils, smt_ctx_install__replace_one_direction)
{
	struct smt_context *old, *new;
	struct homa_rpc *crpc1, *crpc2;

	ASSERT_EQ(0, set_keys(&self->hsk, self->server_ip, self->server_port,
			      TLS_1_3_VERSION));
	crpc1 = new_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(IS_ERR(crpc1));
	old = SMT_RPC(crpc1)->ctx;
	EXPECT_EQ(2, refcount_read(&old->refs));

	ASSERT_EQ(0, set_key(&self->hsk, self->server_ip, self->server_port,
			     TLS_TX, TLS_1_3_VERSION, 3));
	EXPECT_EQ(1, refcount_read(&old->refs));
	crpc2 = new_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(IS_ERR(crpc2));
	new = SMT_RPC(crpc2)->ctx;
	EXPECT_NE(old, new);
	EXPECT_EQ(3, new->crypto_send.aes_gcm_128.key[0]);
	EXPECT_EQ(2, new->crypto_recv.aes_gcm_128.key[0]);
	EXPECT_EQ(1, old->crypto_send.aes_gcm_128.key[0]);
	end_rpc(crpc1);
	end_rpc(crpc2);
}

TEST_F(smt_utils, smt_fixed_key_setup__needs_sysctl)
{
	EXPECT_EQ(EPERM, -set_fixed_key(&self->hsk, TLS_1_3_VERSION,
					TLS_CIPHER_AES_GCM_128));
	EXPECT_EQ(NULL, self->hsk.smt);
}
TEST_F(smt_utils, smt_fixed_key_setup__clone_for_each_peer)
{
	struct homa_rpc *crpc1, *crpc2;

	self->homa.debug_only_smt_fixed_key = 1;
	ASSERT_EQ(0, set_fixed_key(&self->hsk, TLS_1_2_VERSION,
				   TLS_CIPHER_AES_GCM_256));
	crpc1 = new_client(&self->hsk, &self->server_addr);
	crpc2 = new_client(&self->hsk, &self->other_addr);
	ASSERT_FALSE(IS_ERR(crpc1));
	ASSERT_FALSE(IS_ERR(crpc2));
	EXPECT_NE(SMT_RPC(crpc1)->ctx, SMT_RPC(crpc2)->ctx);
	EXPECT_EQ(TLS_CIPHER_AES_GCM_256,
		  SMT_RPC(crpc2)->ctx->crypto_send.info.cipher_type);
	EXPECT_EQ('S', SMT_RPC(crpc2)->ctx->crypto_send.aes_gcm_256.key[0]);

	/* A socket keeps the version and cipher of its built-in key. */
	EXPECT_EQ(EINVAL, -set_fixed_key(&self->hsk, TLS_1_3_VERSION,
					 TLS_CIPHER_AES_GCM_256));
	end_rpc(crpc1);
	end_rpc(crpc2);
}

TEST_F(smt_utils, smt_rpc_ctx_init__record_framing)
{
	struct homa_rpc *crpc;

	ASSERT_EQ(0, set_keys(&self->hsk, self->server_ip, self->server_port,
			      TLS_1_2_VERSION));
	ASSERT_EQ(0, set_keys(&self->hsk, self->other_ip, self->server_port,
			      TLS_1_3_VERSION));
	crpc = new_client(&self->hsk, &self->server_addr);
	ASSERT_FALSE(IS_ERR(crpc));
	EXPECT_EQ(13, SMT_RPC(crpc)->rec_pre);
	EXPECT_EQ(16, SMT_RPC(crpc)->rec_post);
	end_rpc(crpc);
	crpc = new_client(&self->hsk, &self->other_addr);
	ASSERT_FALSE(IS_ERR(crpc));
	EXPECT_EQ(5, SMT_RPC(crpc)->rec_pre);
	EXPECT_EQ(17, SMT_RPC(crpc)->rec_post);
	end_rpc(crpc);
}
TEST_F(smt_utils, smt_rpc_ctx_init__plain_homa_without_keys)
{
	struct homa_rpc *crpc = new_client(&self->hsk, &self->server_addr);

	ASSERT_FALSE(IS_ERR(crpc));
	EXPECT_FALSE(is_smt_rpc(crpc));
	end_rpc(crpc);
}
TEST_F(smt_utils, smt_rpc_ctx_init__no_key_for_peer)
{
	ASSERT_EQ(0, set_keys(&self->hsk, self->server_ip, self->server_port,
			      TLS_1_3_VERSION));
	EXPECT_EQ(ENOKEY, -PTR_ERR(new_client(&self->hsk,
					      &self->other_addr)));
}
TEST_F(smt_utils, smt_rpc_ctx_init__one_direction_only)
{
	ASSERT_EQ(0, set_key(&self->hsk, self->server_ip, self->server_port,
			     TLS_TX, TLS_1_3_VERSION, 1));
	EXPECT_EQ(ENOKEY, -PTR_ERR(new_client(&self->hsk,
					      &self->server_addr)));
}
