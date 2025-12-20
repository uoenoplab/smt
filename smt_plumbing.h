// SMT-HOMA shim header
#ifndef _SMT_PLUMBING_H
#define _SMT_PLUMBING_H

#include "homa_impl.h"
#include "homa_rpc.h"

extern int smt_setsockopt(struct homa_sock *hsk, int optname,
				sockptr_t optval, unsigned int optlen);

int smt_sock_init(struct homa_sock *hsk, struct homa *homa);

void smt_sock_shutdown(struct homa_sock *hsk);

extern int smt_load(struct homa *homa);

extern int smt_unload(void);

#endif /* _SMT_PLUMBING_H */
