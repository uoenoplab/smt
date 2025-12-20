// SMT internal header
#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#include "smt_plumbing.h"
#include "smt_uapi.h"

/* helpers */

#ifdef SMT_DEBUG
#define SMT_INFO
#define smt_pr_devel(fmt, arg...) pr_info(fmt, ##arg)
#else
#define smt_pr_devel(fmt, arg...) {}
#endif

#define SMT_TRACE_FUNC_ENTER() smt_pr_devel("%s: Enter\n", __func__)
#define SMT_TRACE_FUNC_EXIT() smt_pr_devel("%s: Leave\n", __func__)

#ifdef SMT_INFO
#define smt_pr_info(fmt, arg...) pr_info(fmt, ##arg)
#define smt_delay_flush() do { for (size_t i = 0; i < 20; i++) { printk("%s: flush", __func__); } mdelay(100); } while(0)
#else
#define smt_pr_info(fmt, arg...) {}
#define smt_delay_flush() {}
#endif

#define smt_pr_err(fmt, arg...) pr_err(fmt, ##arg)

#define smt_tt_record(fmt) tt_record(fmt)
#define smt_tt_record1(fmt, arg...) tt_record1(fmt, ##arg)
#define smt_tt_record2(fmt, arg...) tt_record2(fmt, ##arg)
#define smt_tt_record3(fmt, arg...) tt_record3(fmt, ##arg)
#define smt_tt_record4(fmt, arg...) tt_record4(fmt, ##arg)

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
	void *reuse_ctx;
};

#define SMT_SOCK(hsk) ((struct smt_sock *)(hsk)->smt)

/* smt_utils.c */

int smt_ctx_select(struct homa_sock *hsk, sockptr_t optval,
				  unsigned int optlen, int tx);

extern struct kmem_cache *smt_ctx_kmem;

#endif /* _SMT_IMPL_H */
