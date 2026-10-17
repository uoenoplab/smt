#ifndef _SMT_PLUMBING_IMPL_H
#define _SMT_PLUMBING_IMPL_H

/* TLS 1.2 AES-GCM-128 record framing: a 5-byte record header and an 8-byte
 * explicit nonce precede the data, a 16-byte tag follows it (smt_impl.h
 * checks these against <net/tls.h>).
 */
#define SMT_RECORD_EXTRA_PRE_LENGTH 13
#define SMT_RECORD_EXTRA_POST_LENGTH 16
#define SMT_RECORD_EXTRA_LENGTH \
	(SMT_RECORD_EXTRA_PRE_LENGTH + SMT_RECORD_EXTRA_POST_LENGTH)

/* Most packets in one record (homa_copy_to_user decrypts a record from at
 * most MAX_SKBS packets).
 */
#define SMT_MAX_RECORD_SEGS 20

/* Extra linear bytes an outgoing DATA skb needs: an SMT packet carries the
 * record header where homa_data_hdr's homa_seg_hdr would be.
 */
#ifdef CONFIG_SMT
#define SMT_SKB_LINEAR_EXTRA \
	(SMT_RECORD_EXTRA_PRE_LENGTH - sizeof(struct homa_seg_hdr))
#else
#define SMT_SKB_LINEAR_EXTRA 0
#endif

struct smt_rx_logical_info {
	int start;
	int length;
	int end;
	int record_data_len;
	int record_data_offset;
	bool trailer_only;
};

#define SMT_RX_INFO(skb) ((struct smt_rx_logical_info *)(skb)->cb)

#endif /* _SMT_PLUMBING_IMPL_H */
