// SMT internal header
#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#include <crypto/aead.h>
#include <linux/scatterlist.h>

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

#define SMT_RECORD_EXTRA_PRE_LENGTH (TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE)
#define SMT_RECORD_EXTRA_POST_LENGTH TLS_CIPHER_AES_GCM_128_TAG_SIZE

#define SMT_RECORD_EXTRA_LENGTH \
	(SMT_RECORD_EXTRA_PRE_LENGTH + SMT_RECORD_EXTRA_POST_LENGTH)

enum {
	SMT_BASE,
	SMT_SW,
	SMT_HW,
	SMT_NUM_CONFIG,
};

#define SMT_MAX_CRYPT_SG 128

struct smt_context {
	u8 tx_conf : 3;
	u8 rx_conf : 3;

	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128_send;
	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128_recv;

	uint32_t peer_addr; // network byte order
	uint16_t peer_port; // network byte order

	void *offload_tx;
	void *offload_rx;

	struct hlist_node hlist;
};

/* Per-ctx (5-tuple) software crypto pool: borrowed/returned per RPC. */
struct smt_sw_crypto {
	struct crypto_aead *tfm;
	struct aead_request *aead_req;
	int aead_req_size;
	struct scatterlist crypt_sg[SMT_MAX_CRYPT_SG];
	struct list_head list;
};

struct smt_sw_context {
	struct list_head crypto_list;
	spinlock_t crypto_list_lock;
	int crypto_available;
};

/* Per-RPC software crypto state. Lives inside smt_rpc::smt_rpc_crypto_tx/rx.
 * Size must stay <= 40 bytes.
 */
struct smt_rpc_sw_context {
	u8 iv[TLS_CIPHER_AES_GCM_128_IV_SIZE +
	      TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

#ifdef CONFIG_SMT_HW
struct smt_hw_context_tx {
	int num_tx_queues;
	int start_queue_id;
	struct net_device *netdev;
	atomic_t num_current_rpcs;
	atomic_t num_driver_states;
	atomic_t last_driver_state_used; /* round robin */
	void **driver_states;
};

struct smt_rpc_hw_context_tx {
	void *driver_state;
	int queue_idx;
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

int smt_sw_encrypt(struct homa_rpc *rpc, struct sk_buff *skb, u8 *smt_h,
		   int payload_len);

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

int smt_device_encrypt(struct homa_rpc *rpc, u8 *smt_h, u8 *smt_t,
		       struct sk_buff *skb);

void smt_device_release_rpc_tx(struct homa_rpc *rpc);
void smt_device_release_resources_tx(struct smt_context *ctx);
#endif /* CONFIG_SMT_HW */

/* smt_incoming.c */

static inline u8 smt_extra_ip_id(struct homa_data_hdr *h)
{
	return (h->retransmit >> 4) & 0x0f;
}

static inline u16 smt_logical_ip_id(struct sk_buff *skb)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;

	if (h->retransmit & 0x01)
		return smt_extra_ip_id(h);

	return ntohs(ip_hdr(skb)->id);
}

static inline u32 smt_gso_offset(struct sk_buff *skb)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;

	return ((u8)h->pad[0] << 16) | ((u8)h->pad[1] << 8) | (u8)h->pad[2];
}

static inline int smt_logical_data_bytes(struct sk_buff *skb, u16 ip_id)
{
	int skb_len = skb->len - skb_transport_offset(skb);

	if (ip_id == 0)
		skb_len -= SMT_RECORD_EXTRA_LENGTH;

	if (likely(skb_len - sizeof(struct homa_data_hdr) + sizeof(struct homa_seg_hdr) > SMT_RECORD_EXTRA_POST_LENGTH))
		return skb_len - sizeof(struct homa_data_hdr);
	return skb_len - sizeof(struct homa_data_hdr) + sizeof(struct homa_seg_hdr);
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
