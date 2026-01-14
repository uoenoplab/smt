// SMT-HOMA shim header
#ifndef _SMT_PLUMBING_H
#define _SMT_PLUMBING_H

#include "homa_impl.h"
#include "homa_rpc.h"

#include "smt_plumbing_impl.h"

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

/* smt_plumbing.c */

extern inline struct homa_smt_padding_info smt_get_padding_info(void);

extern int smt_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen);

extern int smt_sock_init(struct homa_sock *hsk, struct homa *homa);

extern void smt_sock_destroy(struct homa_sock *hsk);

extern int smt_load(struct homa *homa);

extern int smt_unload(void);

static inline bool is_smt_rpc(struct homa_rpc *rpc) {
	// return true;
	return rpc->smt;
}

extern int smt_rpc_alloc_client_sock_lock(struct homa_sock *hsk,
					  struct homa_rpc *rpc);

extern void smt_rpc_release(struct homa_rpc *rpc);

/* smt_incoming.c */

struct smt_rx_logical_info smt_calc_rx_logical_info(struct homa_rpc *rpc,
				      struct sk_buff *skb);

bool smt_record_complete(struct homa_rpc *rpc, struct sk_buff *skb);

int smt_data_offset(struct sk_buff *skb);

int smt_rpc_alloc_server_sock_lock(struct homa_sock *hsk, struct homa_rpc *rpc);

#endif /* _SMT_PLUMBING_H */
