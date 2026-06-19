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

#ifndef _SDTP_OUTPUT_H_
#define _SDTP_OUTPUT_H_

#include "sdtp.h"
#include "sdtp_rpc.h"

int sdtp_packet_insert_list(struct sdtp_rpc *rpc, struct mbuf *m, struct sdtp_packet_slist_entry **prev);
void sdtp_fill_data_header(struct sdtp_rpc *rpc, struct mbuf *m, int offset);

void sdtp_resend_data(struct sdtp_rpc *rpc, int start, int end, int priority);
void sdtp_send_unknown(struct sdtp_inpcb *pcb, struct sdtp_common_header *header,
    struct in6_addr *source);
int sdtp_send_control(struct sdtp_rpc *rpc, enum sdtp_pkt_type type, void *data,
    size_t len);
int sdtp_message_out(struct sdtp_rpc *rpc, struct uio *uio,
    bool immediate_send);
int sdtp_send_control_buf(struct sdtp_inpcb *pcb, struct sdtp_peer *peer,
    void *data, size_t len);

#endif
