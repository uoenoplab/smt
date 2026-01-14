// SMT internal header
#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#include "smt_plumbing.h"
#include "smt_uapi.h"

/* helpers */

static inline void hexdump(const char *title, unsigned char *buf,
			   unsigned int len)
{
#ifdef SMT_DEBUG
	smt_pr_devel("%s", title);
	while (len--)
		smt_pr_devel(KERN_CONT "%02x ", *buf++);
	smt_pr_devel(KERN_CONT "\n");
#endif
}

static inline void hexdump_sg(struct scatterlist *sgl)
{
#ifdef SMT_DEBUG
	struct scatterlist *sg;
	int i = 0;

	for (sg = sgl; sg; sg = sg_next(sg), i++) {
		u8 *buf = sg_virt(sg);
		if (!buf) {
			pr_warn("sg %d returned NULL\n", i);
			continue;
		}

		pr_info("sg entry %d length %u\n",
		i, sg->length);
	hexdump("", buf, sg->length);
	}
#endif
}

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

struct smt_sock {
	struct hlist_head ctx_buckets[HOMA_SERVER_RPC_BUCKETS];
	struct smt_context *reuse_ctx;
};

#define SMT_SOCK(hsk) ((struct smt_sock *)(hsk)->smt)

// TODO: rpc free
struct smt_rpc {
	struct smt_context *ctx;
	/**
	 * @smt_max_pkt_data: Max payload bytes for an SMT packet segment.
	 */
	unsigned int smt_max_pkt_data;

	char smt_rpc_crypto_tx[40];
	char smt_rpc_crypto_rx[40];
	char smt_rpc_cb_rx[72];
};

#define SMT_RPC(rpc) ((struct smt_rpc *)(rpc)->smt)

/* smt_utils.c */

extern struct kmem_cache *smt_ctx_kmem;
extern struct kmem_cache *smt_rpc_ctx_kmem;

int smt_ctx_select(struct homa_sock *hsk, sockptr_t optval,
				  unsigned int optlen, int tx);

int __smt_sock_init(struct homa_sock *hsk, struct homa *homa);

static inline void smt_ctx_destory(struct smt_context *ctx)
{
	kmem_cache_free(smt_ctx_kmem, ctx);
}

int smt_rpc_ctx_init(struct homa_sock *hsk, struct homa_rpc *rpc);

/* smt_incoming.c */


static inline u8 smt_extra_ip_id(struct homa_data_hdr *h)
{
	return (h->retransmit >> 4) & 0x0f;
}

static inline u16 smt_logical_ip_id(struct sk_buff *skb)
{
	struct homa_data_hdr *h = (struct homa_data_hdr *)skb->data;

	return ntohs(ip_hdr(skb)->id) + smt_extra_ip_id(h);
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
