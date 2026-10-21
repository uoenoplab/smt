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

/* Offset (from skb->data / transport_header) where smt_h begins in the
 * linear part of a received packet: immediately after the truncated
 * homa_data_hdr (which omits the final homa_seg_hdr).
 */
#define SMT_SW_SGVEC_OFFSET \
	(int)(sizeof(struct homa_data_hdr) - sizeof(struct homa_seg_hdr))

/* Plaintext bytes each data segment of a record starts with: the
 * homa_seg_hdr Homa puts there, which SMT's receiver never reads (it places
 * segments by IP id and the record offset in pad). CONFIG_SMT_NO_SEG_HDR
 * leaves it out, so a segment carries 4 more bytes of data; the two record
 * layouts don't interoperate.
 */
#ifdef CONFIG_SMT_NO_SEG_HDR
#define SMT_SEG_HDR 0
#else
#define SMT_SEG_HDR ((int)sizeof(struct homa_seg_hdr))
#endif

/* Data bytes in a full segment of a record, Homa's max_seg_data being @msd
 * (GSO cuts the record every msd + sizeof(struct homa_seg_hdr) bytes).
 */
#define SMT_SEG_DATA(msd) \
	((int)(msd) + (int)sizeof(struct homa_seg_hdr) - SMT_SEG_HDR)

#ifdef CONFIG_SMT_RX_ZC
/* User pages a zero-copy RX record may span, at most. */
#define SMT_RX_ZC_MAX_PAGES (DIV_ROUND_UP(TLS_MAX_PAYLOAD_SIZE, PAGE_SIZE) + 4)

/* Scatterlist entries for a zero-copy RX record of @segs segments: AAD, a
 * seg_hdr and up to two data pieces per segment (one more where a page or
 * a bpage ends), TLS 1.3's content type.
 */
#define SMT_RX_ZC_NENTS(segs) (2 + 2 * (segs) + 2 * SMT_RX_ZC_MAX_PAGES)
#endif

#ifndef CONFIG_SMT_NO_REPLAY_GUARD
/* Message numbers (RPC id >> 1) a server remembers per peer. A peer's ids
 * come from a per-host counter, so the window spans that host's RPCs across
 * all its sockets: a request whose first packet arrives after more than
 * SMT_REPLAY_WINDOW newer RPCs of that host were authenticated is dropped as
 * too old. A lost request is first resent after about resend_ticks +
 * resend_interval ms, which this covers up to ~6 M RPCs/s per client host.
 * A client host whose counter restarts (reboot, module reload, next_id) is
 * dropped as too old until it catches up; it needs a new server socket.
 */
#define SMT_REPLAY_WINDOW (1 << 16)

/* Anti-replay state for the requests a server receives from one peer: the
 * highest message number authenticated so far, and which of the
 * SMT_REPLAY_WINDOW numbers up to it have been authenticated (bit
 * m % SMT_REPLAY_WINDOW).
 */
struct smt_replay_window {
	spinlock_t lock;
	u64 top;
	DECLARE_BITMAP(seen, SMT_REPLAY_WINDOW);
};
#endif

struct smt_context {
	u8 tx_conf : 3;
	u8 rx_conf : 3;

	union tls_crypto_context crypto_send;
	union tls_crypto_context crypto_recv;

	uint32_t peer_addr; // network byte order
	uint16_t peer_port; // network byte order

	void *offload_tx;
	void *offload_rx;

#ifndef CONFIG_SMT_NO_REPLAY_GUARD
	struct smt_replay_window replay;
#endif

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
#ifdef CONFIG_SMT_RX_ZC
	/* Where smt_sw_decrypt writes a record that goes straight into the
	 * user's buffers (smt_sw_rx_zc_sg): data to the pinned zc_pages,
	 * TLS 1.3's content type to zc_type; zc_junk is the placeholder for
	 * the AAD and seg_hdrs.
	 */
	struct scatterlist zc_sg[SMT_MAX_CRYPT_SG];
	struct page *zc_pages[SMT_RX_ZC_MAX_PAGES];
	u8 zc_junk[SMT_RECORD_PRE_MAX];
	u8 zc_type;
#endif
	struct list_head list;
};

struct smt_sw_context {
	struct list_head crypto_list;
	spinlock_t crypto_list_lock;
	/* The ctx that allocated it plus the clones sharing it. */
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

/* Whether @rpc's records are TLS 1.3 (no explicit nonce) rather than 1.2. */
static inline bool smt_rpc_tls13(struct homa_rpc *rpc)
{
	return SMT_RPC(rpc)->rec_pre == TLS_HEADER_SIZE;
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
	struct smt_context *reuse_ctx;
};

#define SMT_SOCK(hsk) ((struct smt_sock *)(hsk)->smt)

#include "smt_rpc.h"

/* smt_utils.c */

extern struct kmem_cache *smt_ctx_kmem;

int smt_ctx_setup(struct homa_sock *hsk, sockptr_t optval,
		  unsigned int optlen, int tx);
int smt_fixed_key_install(struct homa_sock *hsk, u16 version);

static inline void smt_ctx_destory(struct smt_context *ctx)
{
	kmem_cache_free(smt_ctx_kmem, ctx);
}

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

/* Copied from tls.h tls_bigint_increment */
static inline bool smt_bigint_increment(u8 *seq, int len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}
	return (i == -1);
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

struct homa_frag_filler;
int smt_sw_encrypt(struct homa_rpc *rpc, u32 rec,
		   const struct homa_frag_filler *pos, int payload_len);

/* TLS sequence number of the message's first TX record. */
static inline const u8 *smt_rpc_tx_rec_seq(struct homa_rpc *rpc)
{
	return smt_rpc_sw_tx(rpc)->rec_seq;
}

/* smt_incoming.c */

#ifndef CONFIG_SMT_NO_REPLAY_GUARD
void smt_replay_accept(struct homa_rpc *rpc);
#endif

/* Index of this packet within its record: GSO/TSO number the segments of
 * each packet from IP id 0 (see homa_gso_segment), and ip_select_ident gives
 * id 0 to a DF packet from an unconnected socket. IPv4 only.
 */
static inline u16 smt_logical_ip_id(struct sk_buff *skb)
{
	return ntohs(ip_hdr(skb)->id);
}

static inline u32 smt_gso_offset(struct sk_buff *skb)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;

	return ((u8)h->pad[0] << 16) | ((u8)h->pad[1] << 8) | (u8)h->pad[2];
}

static inline int smt_logical_data_bytes(struct homa_rpc *rpc,
					 struct sk_buff *skb, u16 ip_id)
{
	int skb_len = skb->len - skb_transport_offset(skb) -
		      SMT_SW_SGVEC_OFFSET - SMT_SEG_HDR;

	/* A record's first segment always carries smt_h and a seg_hdr, however
	 * little data the record holds; a later segment holding only (part
	 * of) the trailer has no seg_hdr.
	 */
	if (ip_id == 0)
		return skb_len - SMT_RPC(rpc)->rec_pre - SMT_RPC(rpc)->rec_post;
	if (unlikely(skb_len + SMT_SEG_HDR <= SMT_RPC(rpc)->rec_post))
		return skb_len + SMT_SEG_HDR;
	return skb_len;
}

static inline int smt_logical_offset(struct homa_rpc *rpc, u16 ip_id,
				  u32 gso_offset)
{
	int offset = ip_id * SMT_SEG_DATA(SMT_RPC(rpc)->smt_max_pkt_data) +
		     (int)gso_offset;

	if (ip_id != 0)
		offset -= SMT_RPC(rpc)->rec_pre + SMT_RPC(rpc)->rec_post;
	return offset;
}

#endif /* _SMT_IMPL_H */
