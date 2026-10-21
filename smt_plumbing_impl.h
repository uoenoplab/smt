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

/* Most packets in one record (homa_copy_to_user decrypts a record from at
 * most MAX_SKBS packets).
 */
#define SMT_MAX_RECORD_SEGS 20

/* Whether a DATA packet with @data_len bytes of data holds the whole
 * message of @msg_len bytes: an SMT packet also carries its record's
 * header and trailer.
 */
#ifdef CONFIG_SMT
#define SMT_WHOLE_MSG(data_len, msg_len) ((data_len) >= (msg_len))
#else
#define SMT_WHOLE_MSG(data_len, msg_len) ((data_len) == (msg_len))
#endif

struct smt_rx_logical_info {
	int start;
	int length;
	int end;
	int record_data_len;
	int record_data_offset;
};

#define SMT_RX_INFO(skb) ((struct smt_rx_logical_info *)(skb)->cb)

#endif /* _SMT_PLUMBING_IMPL_H */
