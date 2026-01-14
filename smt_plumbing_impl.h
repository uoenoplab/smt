#ifndef _SMT_PLUMBING_IMPL_H
#define _SMT_PLUMBING_IMPL_H

struct homa_smt_padding_info {
	int hdr_len;
	int trl_len;
};

struct smt_rx_logical_info {
	int start;
	int length;
	int end;
	int record_data_len;
	int record_data_offset;
	bool trailer_only;
};

#endif /* _SMT_PLUMBING_IMPL_H */
