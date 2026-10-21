/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* SMT definitions homa_impl.h needs. */

#ifndef _SMT_PLUMBING_IMPL_H
#define _SMT_PLUMBING_IMPL_H

/* Record framing around the data, the same for AES-GCM-128 and -256
 * (smt_impl.h checks these against <net/tls.h>):
 *   TLS 1.2: 5-byte header, 8-byte explicit nonce | data | 16-byte tag
 *   TLS 1.3: 5-byte header | data, content type (encrypted) | 16-byte tag
 * An RPC's values are in smt_rpc's rec_pre and rec_post; these are the
 * largest of each.
 */
#define SMT_RECORD_PRE_MAX 13
#define SMT_RECORD_POST_MAX 17

#endif /* _SMT_PLUMBING_IMPL_H */
