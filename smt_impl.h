// SMT internal header
#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#include <crypto/aead.h>
#include <linux/bits.h>
#include <linux/scatterlist.h>
#include <linux/unaligned.h>

#include "smt_plumbing.h"
#include "smt_uapi.h"

/* helpers */

#if defined(CONFIG_SMT_HEXDUMP) && !defined(CONFIG_SMT_DEBUG)
#error "CONFIG_SMT_HEXDUMP requires CONFIG_SMT_DEBUG (use: make debug SMT_CFLAGS=-DCONFIG_SMT_HEXDUMP)"
#endif

#if defined(CONFIG_SMT_DEBUG) && defined(CONFIG_SMT_HEXDUMP)
static inline void smt_hexdump(const char *title, unsigned char *buf,
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

static inline void smt_hexdump_sg(struct scatterlist *sgl)
{
	struct scatterlist *sg;
	int i = 0;

	for (sg = sgl; sg; sg = sg_next(sg), i++) {
		u8 *buf = sg_virt(sg);
		if (!buf) {
			pr_warn("sg %d returned NULL\n", i);
			continue;
		}

		pr_info("sg entry %d length %u\n", i, sg->length);
		smt_hexdump("", buf, sg->length);
	}
}
#else
#define smt_hexdump(...) do {} while (0)
#define smt_hexdump_sg(...) do {} while (0)
#endif

/* smt structs and macros */

/*
TLS 1.3 AES-128-GCM
Header
  Record Type and TLS Version 17 03 03 - 3 Bytes
  Length - 2 Bytes
Data - Dynamic size
Trailer
  Record Type 17 - 1 Bytes (also encrypted with Data)
  Tag - 16 Bytes
#define SMT_RECORD_EXTRA_PRE_LENGTH 5
#define SMT_RECORD_EXTRA_POST_LENGTH 17

TLS 1.2 AES-128-GCM
Header
  Record Type and TLS Version 17 03 03 - 3 Bytes
  Length - 2 Bytes
  Nonce (i.e. Seq Num) - 8 Bytes
Data - Dynamic size
Trailer
  Tag - 16 Bytes
*/

static_assert(SMT_RECORD_EXTRA_PRE_LENGTH ==
	      TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE);
static_assert(SMT_RECORD_EXTRA_POST_LENGTH == TLS_CIPHER_AES_GCM_128_TAG_SIZE);

enum {
	SMT_BASE,
	SMT_SW,
	SMT_HW,
	SMT_NUM_CONFIG,
};

#define SMT_MAX_CRYPT_SG 128

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

struct smt_context {
	u8 tx_conf : 3;
	u8 rx_conf : 3;

	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128_send;
	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128_recv;

	uint32_t peer_addr; // network byte order
	uint16_t peer_port; // network byte order

	void *offload_tx;
	void *offload_rx;

	struct smt_replay_window replay;

	struct hlist_node hlist;
};

/* Per-ctx (5-tuple) software crypto pool: borrowed/returned per RPC. */
struct smt_sw_crypto {
	struct crypto_aead *tfm;
	struct aead_request *aead_req;
	int aead_req_size;
	/* AAD for one TX record; the sg list can't point at the stack. */
	u8 aad[SMT_RECORD_EXTRA_PRE_LENGTH];
	struct scatterlist crypt_sg[SMT_MAX_CRYPT_SG];
	struct list_head list;
};

struct smt_sw_context {
	struct list_head crypto_list;
	spinlock_t crypto_list_lock;
	int crypto_available;
};

/* Per-RPC software crypto state. Lives inside smt_rpc::smt_rpc_crypto_tx/rx.
 * Size must stay <= 40 bytes. RX advances iv and rec_seq once per record
 * decrypted; TX leaves them at the message's first record and derives
 * record i's values by adding i.
 */
struct smt_rpc_sw_context {
	u8 iv[TLS_CIPHER_AES_GCM_128_IV_SIZE +
	      TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

#ifdef CONFIG_SMT_HW
/* One TIS slot in a per-CPU pool. priv_tx is created lazily on first
 * acquire and persists for the slot's lifetime (the slot is reused, the
 * TIS struct isn't recreated). inflight counts skbs that still
 * reference this TIS via the mlx5 hash table; drained signals the
 * owning RPC has done early-release and the slot returns to the free
 * pool once inflight hits zero.
 */
struct smt_tis_slot {
	void *priv_tx;            /* NULL until lazy tls_dev_add */
};

/* SMT_TIS_PER_CPU per-CPU pool capacity. Bumped to 128 to test whether
 * post-3daedc3 grant scheduler increases TIS demand per CPU.
 * Total budget = NR_CPUS * 128 (e.g. 64*128=8192), still under NIC
 * log_max_tis (~16K) on ConnectX-5/6.
 */
#define SMT_TIS_PER_CPU 128

struct smt_hw_per_cpu_pool {
	struct smt_tis_slot slots[SMT_TIS_PER_CPU];
	/* free[bit_i]=1 means slots[i] is available to acquire. Updated via
	 * atomic test_and_clear_bit / set_bit on the bitmap; no spinlock on
	 * the hot path.
	 */
	DECLARE_BITMAP(free, SMT_TIS_PER_CPU);
	struct mutex create_lock; /* serializes lazy tls_dev_add per slot */
} ____cacheline_aligned;

struct smt_hw_context_tx {
	int num_tx_queues;
	struct net_device *netdev;
	int nr_cpus;              /* num_possible_cpus, also size of pools[] */
	struct smt_hw_per_cpu_pool *pools;
};

struct smt_rpc_hw_context_tx {
	void *driver_state;       /* NULL after early release */
	short home_cpu;           /* which pool slot lives in */
	short slot_idx;           /* index within pool->slots */
	short queue_idx;          /* home_cpu % num_tx_queues */
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

enum smt_ktls_del_offload_ctx_dir {
	SMT_TCPTLS_OFFLOAD_CTX_DIR_RX,
	SMT_TCPTLS_OFFLOAD_CTX_DIR_TX,
	SMT_OFFLOAD_CTX_DIR_RX,
	SMT_OFFLOAD_CTX_DIR_TX,
};
#endif /* CONFIG_SMT_HW */

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

int __smt_sock_init(struct homa_sock *hsk, struct homa *homa);

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
 * record count starting at the low 16 bits of @ctx_rec_seq. Nonces are thus
 * unique under a key as long as the key is used with one peer only and the
 * peer's RPC ids don't repeat during its lifetime.
 */
static inline void smt_rpc_init_rec_seq(struct homa_rpc *rpc, bool tx,
					const u8 *ctx_rec_seq, u8 *rec_seq)
{
	u64 seq = ((rpc->id & GENMASK_ULL(47, 0)) >> 1) << 17;

	if (homa_is_client(rpc->id) != tx)
		seq |= 1 << 16;
	put_unaligned_be64(seq | (get_unaligned_be64(ctx_rec_seq) & 0xffff),
			   rec_seq);
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

int smt_sw_set_offload(struct smt_context *ctx, int tx);
int smt_sw_init_rpc(struct homa_rpc *rpc, int tx);

struct homa_frag_filler;
int smt_sw_encrypt(struct homa_rpc *rpc, u32 rec,
		   const struct homa_frag_filler *pos, int payload_len);

void smt_sw_release_resources(struct smt_context *ctx, int tx);

#ifdef CONFIG_SMT_HW
/* smt_device.c */

static inline struct smt_rpc_hw_context_tx *smt_rpc_hw_tx(struct homa_rpc *rpc)
{
	return (struct smt_rpc_hw_context_tx *)SMT_RPC(rpc)->smt_rpc_crypto_tx;
}

int smt_hw_set_offload_tx(struct homa_sock *hsk, struct smt_context *ctx);
int smt_hw_init_rpc(struct homa_rpc *rpc);
int smt_device_set_crypto_tx(struct homa_rpc *rpc);

/* Hand priv_tx (and the TIS's TX queue) to the patched mlx5 TX hook via
 * the tail of skb->cb, just before the skb goes to the IP stack.
 */
void smt_hw_attach_skb(struct homa_rpc *rpc, struct sk_buff *skb);

void smt_device_release_rpc_tx(struct homa_rpc *rpc);
void smt_device_release_resources_tx(struct smt_context *ctx);

/* Early release: caller (homa_outgoing) signals the RPC has finished
 * passing data to the IP stack. The TIS slot is marked drained and
 * returns to the pool once outstanding skbs finish (refcount drop in
 * the skb destructor callback). Safe to call multiple times.
 */
void smt_device_release_tis(struct homa_rpc *rpc);
#endif /* CONFIG_SMT_HW */

/* TLS sequence number of the message's first TX record. */
static inline const u8 *smt_rpc_tx_rec_seq(struct homa_rpc *rpc)
{
#ifdef CONFIG_SMT_HW
	if (SMT_RPC(rpc)->ctx->tx_conf == SMT_HW)
		return smt_rpc_hw_tx(rpc)->rec_seq;
#endif
	return smt_rpc_sw_tx(rpc)->rec_seq;
}

/* smt_incoming.c */

void smt_replay_accept(struct homa_rpc *rpc);

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

static inline int smt_logical_data_bytes(struct sk_buff *skb, u16 ip_id)
{
	int skb_len = skb->len - skb_transport_offset(skb) -
		      sizeof(struct homa_data_hdr);

	/* A record's first segment always carries smt_h and a seg_hdr, however
	 * little data the record holds; a later segment holding only (part
	 * of) the tag has no seg_hdr.
	 */
	if (ip_id == 0)
		return skb_len - SMT_RECORD_EXTRA_LENGTH;
	if (unlikely(skb_len + (int)sizeof(struct homa_seg_hdr) <=
		     SMT_RECORD_EXTRA_POST_LENGTH))
		return skb_len + sizeof(struct homa_seg_hdr);
	return skb_len;
}

static inline bool smt_trailer_only(struct sk_buff *skb, u16 ip_id)
{
	if (ip_id == 0)
		return false;
	return (smt_logical_data_bytes(skb, ip_id) <= SMT_RECORD_EXTRA_POST_LENGTH);
}

static inline int smt_logical_offset(struct homa_rpc *rpc, u16 ip_id,
				  u32 gso_offset)
{
	int offset = (int)(ip_id * SMT_RPC(rpc)->smt_max_pkt_data + gso_offset);

	if (ip_id != 0)
		offset -= SMT_RECORD_EXTRA_LENGTH;
	return offset;
}

#endif /* _SMT_IMPL_H */
