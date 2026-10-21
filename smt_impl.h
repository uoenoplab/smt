/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* SMT internals. */

#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#include <crypto/aead.h>
#include <linux/bits.h>
#include <linux/refcount.h>
#include <linux/scatterlist.h>
#include <linux/unaligned.h>

#include "smt_plumbing.h"
#include "smt_uapi.h"

/* helpers */

#if defined(CONFIG_SMT_HEXDUMP) && !defined(CONFIG_SMT_DEBUG)
#error "CONFIG_SMT_HEXDUMP requires CONFIG_SMT_DEBUG (use: make debug SMT_CFLAGS=-DCONFIG_SMT_HEXDUMP)"
#endif

#if defined(CONFIG_SMT_DEBUG) && defined(CONFIG_SMT_HEXDUMP)
static inline void smt_hexdump(const char *title, const unsigned char *buf,
			       unsigned int len)
{
	char line[16 * 3 + 1];
	unsigned int i, j, n;

	for (i = 0; i < len; i += 16) {
		n = min_t(unsigned int, 16, len - i);
		for (j = 0; j < n; j++)
			snprintf(line + j * 3, 4, "%02x ", buf[i + j]);
		line[n * 3] = '\0';
		pr_info("%s[%04x] %s\n", title, i, line);
	}
}
#else
#define smt_hexdump(...) do {} while (0)
#endif

/* smt structs and macros */

/* Both ciphers share every size but the key's, so the code uses the 128-bit
 * names for them.
 */
static_assert(TLS_CIPHER_AES_GCM_128_IV_SIZE == TLS_CIPHER_AES_GCM_256_IV_SIZE);
static_assert(TLS_CIPHER_AES_GCM_128_SALT_SIZE ==
	      TLS_CIPHER_AES_GCM_256_SALT_SIZE);
static_assert(TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE ==
	      TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
static_assert(TLS_CIPHER_AES_GCM_128_TAG_SIZE == TLS_CIPHER_AES_GCM_256_TAG_SIZE);
static_assert(SMT_RECORD_PRE_MAX ==
	      TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE);
static_assert(SMT_RECORD_POST_MAX == 1 + TLS_CIPHER_AES_GCM_128_TAG_SIZE);

enum {
	SMT_BASE,
	SMT_SW,
};

#define SMT_MAX_CRYPT_SG 128

/* A socket's keys for one peer. The socket's table holds a reference, and
 * so does each RPC that uses them: a replacing key takes the ctx out of
 * the table, and the RPCs already using it finish with its keys.
 */
struct smt_context {
	u8 tx_conf : 3;
	u8 rx_conf : 3;

	union tls_crypto_context crypto_send;
	union tls_crypto_context crypto_recv;

	uint32_t peer_addr; // network byte order
	uint16_t peer_port; // network byte order

	void *offload_tx;
	void *offload_rx;

	refcount_t refs;
	struct work_struct free_work;
	struct hlist_node hlist;
};

/* Per-ctx (5-tuple) software crypto pool: borrowed/returned per RPC. */
struct smt_sw_crypto {
	struct crypto_aead *tfm;
	struct aead_request *aead_req;
	int aead_req_size;
	/* AAD for one TX record; the sg list can't point at the stack. */
	u8 aad[SMT_RECORD_PRE_MAX];
	struct scatterlist crypt_sg[SMT_MAX_CRYPT_SG];
	struct list_head list;
};

struct smt_sw_context {
	struct list_head crypto_list;
	spinlock_t crypto_list_lock;
	/* The ctx that allocated it plus the ctxs that replace it and keep it. */
	refcount_t refs;
};

/* Per-RPC software crypto state. Lives inside smt_rpc::smt_rpc_crypto_tx/rx.
 * Size must stay <= 40 bytes. iv is the nonce base (see smt_nonce). RX
 * advances rec_seq once per record decrypted; TX leaves it at the message's
 * first record and derives record i's by adding i.
 */
struct smt_rpc_sw_context {
	u8 iv[TLS_CIPHER_AES_GCM_128_IV_SIZE +
	      TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

/* A direction's key fields; only the key's length differs between
 * AES-GCM-128 and -256, so salt and rec_seq move with it.
 */
static inline bool smt_crypto_256(const union tls_crypto_context *c)
{
	return c->info.cipher_type == TLS_CIPHER_AES_GCM_256;
}

static inline const u8 *smt_crypto_key(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.key : c->aes_gcm_128.key;
}

static inline int smt_crypto_key_size(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? TLS_CIPHER_AES_GCM_256_KEY_SIZE :
				   TLS_CIPHER_AES_GCM_128_KEY_SIZE;
}

static inline const u8 *smt_crypto_iv(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.iv : c->aes_gcm_128.iv;
}

static inline const u8 *smt_crypto_salt(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.salt : c->aes_gcm_128.salt;
}

static inline const u8 *smt_crypto_rec_seq(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.rec_seq :
				   c->aes_gcm_128.rec_seq;
}

/* Write the AEAD nonce of the record numbered @seq. TLS 1.2 uses
 * salt ‖ seq (the explicit nonce is the sequence number), TLS 1.3
 * (salt ‖ iv) XOR (0 ‖ seq): with @base = salt ‖ 0 for TLS 1.2 and
 * salt ‖ iv for TLS 1.3, both are base XOR (0 ‖ seq).
 */
static inline void smt_nonce(u8 *nonce, const u8 *base, u64 seq)
{
	memcpy(nonce, base, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	put_unaligned_be64(get_unaligned_be64(base +
					      TLS_CIPHER_AES_GCM_128_SALT_SIZE) ^ seq,
			   nonce + TLS_CIPHER_AES_GCM_128_SALT_SIZE);
}

struct smt_sock {
	struct hlist_head ctx_buckets[HOMA_SERVER_RPC_BUCKETS];
};

#define SMT_SOCK(hsk) ((struct smt_sock *)(hsk)->smt)

#include "smt_rpc.h"

/* smt_utils.c */

extern struct kmem_cache *smt_ctx_kmem;
extern struct workqueue_struct *smt_wq;

int smt_ctx_setup(struct homa_sock *hsk, sockptr_t optval,
		  unsigned int optlen, int tx);
void smt_ctx_put(struct smt_context *ctx);

int smt_rpc_ctx_init(struct homa_sock *hsk, struct homa_rpc *rpc);

/* smt_sw.c */

static inline struct smt_rpc_sw_context *smt_rpc_sw_tx(struct homa_rpc *rpc)
{
	return (struct smt_rpc_sw_context *)SMT_RPC(rpc)->smt_rpc_crypto_tx;
}

static inline struct smt_rpc_sw_context *smt_rpc_sw_rx(struct homa_rpc *rpc)
{
	return (struct smt_rpc_sw_context *)SMT_RPC(rpc)->smt_rpc_crypto_rx;
}

/* Set @rec_seq to the TLS sequence number of the first record of @rpc's
 * outgoing (@tx) or incoming message: the RPC id with its client/server bit
 * dropped (so both ends agree), a request/response bit (one key encrypts both
 * the requests and the responses a socket sends to a peer), and a 16-bit
 * record count from 0, which a message's fewer than 2^16 records never carry
 * out of (smt_outgoing.c). Nonces are thus unique under a key as long as the
 * key is used with one peer only and the peer's RPC ids don't repeat during
 * its lifetime.
 */
static inline void smt_rpc_init_rec_seq(struct homa_rpc *rpc, bool tx,
					u8 *rec_seq)
{
	u64 seq = ((rpc->id & GENMASK_ULL(47, 0)) >> 1) << 17;

	if (homa_is_client(rpc->id) != tx)
		seq |= 1 << 16;
	put_unaligned_be64(seq, rec_seq);
}

struct smt_sw_context *
smt_sw_ctx_alloc(const union tls_crypto_context *info, int n);
void smt_sw_ctx_put(struct smt_sw_context *sw_ctx);

static inline struct smt_sw_context *
smt_sw_ctx_get(struct smt_sw_context *sw_ctx)
{
	refcount_inc(&sw_ctx->refs);
	return sw_ctx;
}
int smt_sw_init_rpc(struct homa_rpc *rpc, int tx);

#endif /* _SMT_IMPL_H */
