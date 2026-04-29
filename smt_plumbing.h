// SMT-HOMA shim header
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
#define SMT_TRACE_FUNC_EXIT() smt_pr_devel("%s: Leave\n", __func__)

#ifdef CONFIG_SMT_INFO
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

extern int smt_encrypt(struct homa_rpc *rpc, struct sk_buff *skb, u8 *smt_h,
		       int payload_len);

static inline bool is_smt_rpc(struct homa_rpc *rpc) {
	return rpc->smt.ctx != NULL;
}

#ifdef CONFIG_SMT_HW
/* Re-stamp priv_tx into the tail of skb->cb (and skb->queue_mapping) just
 * before NIC submission. smt_device_encrypt() does the first stamp, but IP /
 * qdisc / Grant-softirq layers can clobber cb between encrypt and NIC TX —
 * the patched mlx5 TX hook reads priv_tx from this cb slot.
 */
extern void smt_hw_attach_skb(struct homa_rpc *rpc, struct sk_buff *skb);
#else
static inline void smt_hw_attach_skb(struct homa_rpc *rpc, struct sk_buff *skb)
{
	(void)rpc;
	(void)skb;
}
#endif

extern int smt_rpc_alloc_client_sock_lock(struct homa_sock *hsk,
					  struct homa_rpc *rpc);

extern void smt_rpc_release(struct homa_rpc *rpc);

/* smt_sw.c */

extern int smt_sw_decrypt(struct homa_rpc *rpc, struct sk_buff **skbs,
			  int n);

/* smt_incoming.c */

struct smt_rx_logical_info smt_calc_rx_logical_info(struct homa_rpc *rpc,
				      struct sk_buff *skb);

bool smt_record_complete(struct homa_rpc *rpc, struct sk_buff *skb);

int smt_data_offset(struct sk_buff *skb);

int smt_rpc_alloc_server_sock_lock(struct homa_sock *hsk, struct homa_rpc *rpc);

#endif /* _SMT_PLUMBING_H */

/* timing helpers */

#ifdef CONFIG_HOMA_SMT_PROFILING

/**
 * smt_rdtsc() - Read the Time Stamp Counter for low-overhead timing.
 * Return: Current TSC value as u64.
 *
 * Uses inline assembly to read the TSC directly. Much faster than local_clock()
 * (~5-10ns vs ~20-30ns) but returns cycles instead of nanoseconds.
 */
static inline u64 smt_rdtsc(void)
{
	u32 lo, hi;
	asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
	return ((u64)hi << 32) | lo;
}

/**
 * SMT_TIME_START - Start timing measurement
 * Return: TSC timestamp to pass to SMT_TIME_END
 */
#define SMT_TIME_START() smt_rdtsc()

/**
 * SMT_TIME_END - End timing measurement and update per-CPU metrics
 * @metric_base: Base name of the metric (e.g., smt_rx for smt_rx_calls/cycles)
 * @start: Timestamp from SMT_TIME_START()
 *
 * Calculates elapsed TSC cycles and updates per-CPU counters using INC_METRIC.
 * No synchronization needed since each CPU has its own metric counters.
 */
#define SMT_TIME_END(metric_base, start) \
	do { \
		u64 __cycles = smt_rdtsc() - (start); \
		INC_METRIC(metric_base##_calls, 1); \
		INC_METRIC(metric_base##_cycles, __cycles); \
	} while (0)

#define SMT_COUNT(metric) INC_METRIC(metric, 1)

#else /* !CONFIG_HOMA_SMT_PROFILING */

/* When profiling is disabled, macros compile to nothing (zero overhead) */
#define SMT_TIME_START() 0
#define SMT_TIME_END(metric_base, start) do { (void)(start); } while (0)
#define SMT_COUNT(metric) do {} while (0)

#endif /* CONFIG_HOMA_SMT_PROFILING */
