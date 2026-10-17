// SMT per-RPC context — minimal header for embedding in homa_rpc
#ifndef _SMT_RPC_H
#define _SMT_RPC_H

struct smt_context;

struct smt_rpc {
	struct smt_context *ctx;
	/**
	 * @smt_max_pkt_data: Max payload bytes for an SMT packet segment.
	 */
	unsigned int smt_max_pkt_data;

	/**
	 * @decrypt_offset: Data offset of the next SMT record to decrypt.
	 * Records must be decrypted strictly in order. Updated by
	 * smt_record_complete (softirq) and copy_to_user (greedy).
	 * Protected by the RPC bucket lock.
	 */
	int decrypt_offset;

	char smt_rpc_crypto_tx[40];
	char smt_rpc_crypto_rx[40];
	char smt_rpc_cb_rx[72];
};

#define SMT_RPC(rpc) (&(rpc)->smt)

#endif /* _SMT_RPC_H */
