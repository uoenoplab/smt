/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* What Homa calls in SMT. */

#ifndef _SMT_PLUMBING_H
#define _SMT_PLUMBING_H

#include "homa_impl.h"
#include "homa_rpc.h"

#include "smt_plumbing_impl.h"

/* helpers */

#ifdef CONFIG_SMT_DEBUG
#define CONFIG_SMT_INFO
#define smt_pr_devel(fmt, arg...) pr_info(fmt, ##arg)
#else
#define smt_pr_devel(fmt, arg...) {}
#endif

#define SMT_TRACE_FUNC_ENTER() smt_pr_devel("%s: Enter\n", __func__)

#ifdef CONFIG_SMT_INFO
#define smt_pr_info(fmt, arg...) pr_info(fmt, ##arg)
#else
#define smt_pr_info(fmt, arg...) {}
#endif

#define smt_pr_err(fmt, arg...) pr_err(fmt, ##arg)

/* smt_plumbing.c */

extern int smt_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen);

extern int smt_sock_init(struct homa_sock *hsk, struct homa *homa);

extern void smt_sock_destroy(struct homa_sock *hsk);

extern int smt_load(struct homa *homa);

extern int smt_unload(void);

static inline bool is_smt_rpc(struct homa_rpc *rpc) {
	return rpc->smt.ctx != NULL;
}

extern int smt_rpc_alloc_client_sock_lock(struct homa_sock *hsk,
					  struct homa_rpc *rpc);

extern void smt_rpc_release(struct homa_rpc *rpc);

/* smt_outgoing.c */

struct homa_frag_filler;

void smt_tx_init(struct homa_rpc *rpc);
int smt_tx_frag_bytes(struct homa_rpc *rpc);
int smt_tx_fill(struct homa_rpc *rpc, struct homa_frag_filler *filler,
		struct iov_iter *iter, bool xmit);
int smt_tx_skb_range(struct homa_rpc *rpc, u32 *offset, u32 *end,
		     int *bytes, u64 *segs);
void smt_tx_skb_hdr(struct homa_rpc *rpc, struct sk_buff *skb, u32 offset);

/* smt_sw.c */

extern int smt_sw_decrypt(struct homa_rpc *rpc, struct sk_buff **skbs,
			  int n, int rec_offset, int rec_len, bool *delivered);

/* smt_incoming.c */

struct smt_rx_logical_info smt_calc_rx_logical_info(struct homa_rpc *rpc,
				      struct sk_buff *skb);

bool smt_record_complete(struct homa_rpc *rpc, struct sk_buff *skb);

int smt_data_offset(struct homa_rpc *rpc, struct sk_buff *skb);

int smt_rpc_alloc_server_sock_lock(struct homa_sock *hsk, struct homa_rpc *rpc);

#endif /* _SMT_PLUMBING_H */
