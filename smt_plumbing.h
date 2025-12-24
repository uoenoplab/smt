// SMT-HOMA shim header
#ifndef _SMT_PLUMBING_H
#define _SMT_PLUMBING_H

#include "homa_impl.h"
#include "homa_rpc.h"

#include "smt_plumbing_impl.h"

extern inline struct homa_smt_padding_info smt_get_padding_info(void);

extern int smt_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen);

extern int smt_sock_init(struct homa_sock *hsk, struct homa *homa);

extern void smt_sock_shutdown(struct homa_sock *hsk);

extern int smt_load(struct homa *homa);

extern int smt_unload(void);

static inline bool is_smt_rpc(struct homa_rpc *rpc) {
	return true;
}

#endif /* _SMT_PLUMBING_H */
