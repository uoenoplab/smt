/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

/* Copyright (c) 2019-2022 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _SMT_H_
#define _SMT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stdint.h>
#include <sys/mbuf.h>

#include "smt_common.h"

enum smt_pkt_type {
	SMT_DATA = 0x10,
	SMT_GRANT = 0x11,
	SMT_RESEND = 0x12,
	SMT_UNKNOWN = 0x13,
	SMT_BUSY = 0x14,
	SMT_CUTOFFS = 0x15,
	SMT_FREEZE = 0x16,
	SMT_NEED_ACK = 0x17,
	SMT_ACK = 0x18,
};

enum smt_optname {
	SMT_TXTLS_ENABLE = 31,
	SMT_RXTLS_ENABLE = 32,
};

struct smt_sendmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
};

struct smt_recvmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
	int flags;
	uint32_t num_bpages;
	uint32_t _pad[2];
	uint32_t bpage_offsets[SMT_MAX_BPAGES];
};

struct smt_common_header {
	uint16_t sport_be;
	uint16_t dport_be;
	uint32_t sequence_be; /* TCP header sequence number */
	char ack[3];	      /* unused */
	uint8_t type;
	uint8_t d_off;
	uint8_t flags;
	uint16_t window_be;   /* unused */
	uint16_t checksum_be; /* unused */
	uint16_t urgent_be;
	uint64_t sender_id_be;
} __attribute__((packed));

struct smt_ack {
	uint64_t client_id_be;
	uint16_t server_port_be;
} __attribute__((packed));

struct smt_data_segment {
	uint32_t offset_be;
} __attribute__((packed));

struct smt_data_header {
	struct smt_common_header common;
	uint32_t message_length_be;
	uint32_t incoming_be;
	struct smt_ack ack;
	uint16_t cutoff_version_be;
	uint8_t retransmit;
	char padding[3];
	struct smt_data_segment data_segment; /* first of many data segments */
} __attribute__((packed));
CTASSERT(sizeof(struct smt_data_header) <= SMT_MAX_HEADER);
CTASSERT(sizeof(struct smt_data_header) >= SMT_MIN_PKT_LENGTH);
CTASSERT(((sizeof(struct smt_data_header) - sizeof(struct smt_data_segment)) &
	     0x3) == 0);

struct smt_grant_header {
	struct smt_common_header common;
	uint32_t offset_be;
	uint8_t priority;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_grant_header) <= SMT_MAX_HEADER);

struct smt_resend_header {
	struct smt_common_header common;
	uint32_t offset_be;
	uint32_t length_be;
	uint8_t priority;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_resend_header) <= SMT_MAX_HEADER);

struct smt_unknown_header {
	struct smt_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_unknown_header) <= SMT_MAX_HEADER);

struct smt_busy_header {
	struct smt_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_busy_header) <= SMT_MAX_HEADER);

struct smt_cutoffs_header {
	struct smt_common_header common;
	uint32_t unsched_cutoffs_be[SMT_MAX_PRIORITIES];
	uint16_t cutoff_version_be;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_cutoffs_header) <= SMT_MAX_HEADER);

struct smt_freeze_header {
	struct smt_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_freeze_header) <= SMT_MAX_HEADER);

struct smt_need_ack_header {
	struct smt_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct smt_need_ack_header) <= SMT_MAX_HEADER);

struct smt_ack_header {
	struct smt_common_header common;
	uint16_t num_acks_be;
	struct smt_ack acks[NUM_PEER_UNACKED_IDS];
} __attribute__((packed));
CTASSERT(sizeof(struct smt_cutoffs_header) <= SMT_MAX_HEADER);

#define SMT_SET_DOFF(HEADERP)                                               \
	do {                                                                 \
		(HEADERP)->common.d_off = (sizeof(struct smt_data_header) - \
					      sizeof(                        \
						  struct smt_data_segment)) \
		    << 2;                                                    \
	} while (0)

#define IP_SMT_HEADER_SIZE(PCB, TYPE) ((PCB)->iphlen + sizeof(TYPE))

extern int smt_header_lengths[];

#define SMT_MTOD(MBUF, T, OFFSET) \
	((T)(mtod((MBUF), char *) + (OFFSET)))

static inline int
smt_payload_len(struct mbuf *m, int iphlen)
{
	KASSERT(m->m_len >= sizeof(struct smt_data_header) + iphlen,
	 ("%s: header must be at least %lu, instead %d", __func__,
	 sizeof(struct smt_data_header) + iphlen, m->m_len));
	KASSERT(m->m_flags & M_PKTHDR, ("mbuf must be a header mbuf"));
	KASSERT(iphlen > 0, ("iphlen must be positive"));

#ifdef INVARIANTS
	struct smt_common_header *header = SMT_MTOD(m, struct smt_common_header *, iphlen);
	KASSERT(header->type == SMT_DATA, ("mbuf must be DATA type"));
#endif

	return m->m_pkthdr.len - sizeof(struct smt_data_header) - iphlen;
}

#endif
