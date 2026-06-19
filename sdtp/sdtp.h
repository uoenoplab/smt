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

#ifndef _SDTP_H_
#define _SDTP_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stdint.h>
#include <sys/mbuf.h>

#include "sdtp_common.h"

enum sdtp_pkt_type {
	SDTP_DATA = 0x10,
	SDTP_GRANT = 0x11,
	SDTP_RESEND = 0x12,
	SDTP_UNKNOWN = 0x13,
	SDTP_BUSY = 0x14,
	SDTP_CUTOFFS = 0x15,
	SDTP_FREEZE = 0x16,
	SDTP_NEED_ACK = 0x17,
	SDTP_ACK = 0x18,
};

enum sdtp_optname {
	SDTP_TXTLS_ENABLE = 31,
	SDTP_RXTLS_ENABLE = 32,
};

struct sdtp_sendmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
};

struct sdtp_recvmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
	int flags;
	uint32_t num_bpages;
	uint32_t _pad[2];
	uint32_t bpage_offsets[SDTP_MAX_BPAGES];
};

struct sdtp_common_header {
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

struct sdtp_ack {
	uint64_t client_id_be;
	uint16_t server_port_be;
} __attribute__((packed));

struct sdtp_data_segment {
	uint32_t offset_be;
} __attribute__((packed));

struct sdtp_data_header {
	struct sdtp_common_header common;
	uint32_t message_length_be;
	uint32_t incoming_be;
	struct sdtp_ack ack;
	uint16_t cutoff_version_be;
	uint8_t retransmit;
	char padding[3];
	struct sdtp_data_segment data_segment; /* first of many data segments */
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_data_header) <= SDTP_MAX_HEADER);
CTASSERT(sizeof(struct sdtp_data_header) >= SDTP_MIN_PKT_LENGTH);
CTASSERT(((sizeof(struct sdtp_data_header) - sizeof(struct sdtp_data_segment)) &
	     0x3) == 0);

struct sdtp_grant_header {
	struct sdtp_common_header common;
	uint32_t offset_be;
	uint8_t priority;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_grant_header) <= SDTP_MAX_HEADER);

struct sdtp_resend_header {
	struct sdtp_common_header common;
	uint32_t offset_be;
	uint32_t length_be;
	uint8_t priority;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_resend_header) <= SDTP_MAX_HEADER);

struct sdtp_unknown_header {
	struct sdtp_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_unknown_header) <= SDTP_MAX_HEADER);

struct sdtp_busy_header {
	struct sdtp_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_busy_header) <= SDTP_MAX_HEADER);

struct sdtp_cutoffs_header {
	struct sdtp_common_header common;
	uint32_t unsched_cutoffs_be[SDTP_MAX_PRIORITIES];
	uint16_t cutoff_version_be;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_cutoffs_header) <= SDTP_MAX_HEADER);

struct sdtp_freeze_header {
	struct sdtp_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_freeze_header) <= SDTP_MAX_HEADER);

struct sdtp_need_ack_header {
	struct sdtp_common_header common;
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_need_ack_header) <= SDTP_MAX_HEADER);

struct sdtp_ack_header {
	struct sdtp_common_header common;
	uint16_t num_acks_be;
	struct sdtp_ack acks[NUM_PEER_UNACKED_IDS];
} __attribute__((packed));
CTASSERT(sizeof(struct sdtp_cutoffs_header) <= SDTP_MAX_HEADER);

#define SDTP_SET_DOFF(HEADERP)                                               \
	do {                                                                 \
		(HEADERP)->common.d_off = (sizeof(struct sdtp_data_header) - \
					      sizeof(                        \
						  struct sdtp_data_segment)) \
		    << 2;                                                    \
	} while (0)

#define IP_SDTP_HEADER_SIZE(PCB, TYPE) ((PCB)->iphlen + sizeof(TYPE))

extern int sdtp_header_lengths[];

#define SDTP_MTOD(MBUF, T, OFFSET) \
	((T)(mtod((MBUF), char *) + (OFFSET)))

static inline int
sdtp_payload_len(struct mbuf *m, int iphlen)
{
	KASSERT(m->m_len >= sizeof(struct sdtp_data_header) + iphlen,
	 ("%s: header must be at least %lu, instead %d", __func__,
	 sizeof(struct sdtp_data_header) + iphlen, m->m_len));
	KASSERT(m->m_flags & M_PKTHDR, ("mbuf must be a header mbuf"));
	KASSERT(iphlen > 0, ("iphlen must be positive"));

#ifdef INVARIANTS
	struct sdtp_common_header *header = SDTP_MTOD(m, struct sdtp_common_header *, iphlen);
	KASSERT(header->type == SDTP_DATA, ("mbuf must be DATA type"));
#endif

	return m->m_pkthdr.len - sizeof(struct sdtp_data_header) - iphlen;
}

#endif
