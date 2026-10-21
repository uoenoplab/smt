/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* SMT state in each homa_rpc. */

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
	/**
	 * @rec_pre: Bytes of each record before its data: the TLS header
	 * plus, in TLS 1.2, the explicit nonce.
	 */
	u8 rec_pre;
	/**
	 * @rec_post: Bytes of each record after its data: the tag plus, in
	 * TLS 1.3, the content type.
	 */
	u8 rec_post;

	char smt_rpc_crypto_tx[40];
	char smt_rpc_crypto_rx[40];
};

#define SMT_RPC(rpc) (&(rpc)->smt)

#endif /* _SMT_RPC_H */
