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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "sdtp.h"
#include "sdtp_debug.h"
#include "sdtp_input.h"
#include "sdtp_pcb.h"
#include "sdtp_structs.h"
#include "sdtp_test.h"

#ifdef INET6
#include <netinet6/icmp6.h>
#endif

extern struct sdtp *sdtp;

static bool
sdtp_check_header_conditions(const struct sdtp_common_header *const header,
    const struct mbuf *const m, int iphlen)
{
	KASSERT(header != NULL, ("header must be valid"));
	KASSERT(m != NULL, ("m must be valid"));
	KASSERT(m != NULL, ("m must be valid"));
	MBUF_LEN_AT_LEAST(m, sizeof(header) + iphlen);

	if (header->type < SDTP_DATA || header->type > SDTP_ACK) {
		return (false);
	}

	if (m->m_pkthdr.len < sdtp_header_lengths[header->type - SDTP_DATA]) {
		return (false);
	}

	return (true);
}

static struct sdtp_inpcb *
sdtp_get_pcb(struct sdtp *sdtp_struct,
    const struct sdtp_common_header *const header, int offset)
{
	KASSERT(header != NULL, ("header must be valid"));
	KASSERT(sdtp_struct != NULL, ("sdtp struct must be valid"));

	uint16_t dport;
	struct sdtp_inpcb *pcb;

	dport = ntohs(header->dport_be);

	mtx_lock_spin(&sdtp_struct->port_map.write_spinlock);
	pcb = sdtp_find_inpcb(&sdtp_struct->port_map, dport);
	if (pcb == NULL) {
		mtx_unlock_spin(&sdtp_struct->port_map.write_spinlock);
		return (NULL);
	}
	sdtp_pcb_hold(pcb);
	mtx_unlock_spin(&sdtp_struct->port_map.write_spinlock);

	sdtp_pcb_lock(pcb);
	if (pcb->shutdown || sdtp_so(pcb) == NULL || pcb->iphlen != offset) {
		sdtp_pcb_unlock(pcb);
		sdtp_pcb_put(pcb);
		return (NULL);
	}
	sdtp_pcb_unlock(pcb);

	return pcb;
}

static void
check_pcb_locks(struct sdtp_inpcb *pcb)
{
	KASSERT(pcb != NULL, ("pcb must be valid"));

	PCB_LOCK_NOTOWNED(pcb);
	mtx_assert(&pcb->sdtp->port_map.write_spinlock, MA_NOTOWNED);
	mtx_assert(&pcb->sdtp->peers.write_spinlock, MA_NOTOWNED);
}

static void
sdtp_parse_header_and_src_addr(struct mbuf *m, int iphlen,
    struct sdtp_common_header **sdtp_header, struct in6_addr *addr)
{
	KASSERT(m != NULL, ("m must be valid"));
	KASSERT(sdtp_header != NULL, ("sdtp_header must be valid"));
	KASSERT(addr != NULL, ("addr must be valid"));
	MUST_POSITIVE(iphlen);

	struct ip *ip_header = mtod(m, struct ip *);

	*sdtp_header = (struct sdtp_common_header *)((caddr_t)ip_header +
	    iphlen);
	*addr = ipv4_to_ipv6(&ip_header->ip_src);
}

int
sdtp_input(struct mbuf **mp, int *offp, int proto)
{
	struct sdtp_common_header *header;
	struct in6_addr src_addr;
	struct sdtp_inpcb *pcb = NULL;
	struct mbuf *m = *mp;
	uint64_t start_cycles = get_cyclecount();

	/* We want to access at least the common header */
	if ((m = m_pullup(m, *offp + sizeof(struct sdtp_common_header))) ==
	    NULL) {
		sdtp_debug("%s: failed pullup common header", __func__);
		goto sdtp_input_done;
	}

	sdtp_parse_header_and_src_addr(m, *offp, &header, &src_addr);

	if (!sdtp_check_header_conditions(header, m, *offp)) {
		m_freem(m);
		sdtp_debug("%s: failed header conditions: header type: %d, mbuf total length: %d",
			__func__, header->type, m->m_pkthdr.len);
		goto sdtp_input_done;
	}

	if ((pcb = sdtp_get_pcb(sdtp, header, *offp)) == NULL) {
		sdtp_debug("%s: can't find pcb\n", __func__);
		icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
		goto sdtp_input_done;
	}

	if ((m = m_pullup(m, *offp + sdtp_header_lengths[header->type - SDTP_DATA])) ==
	    NULL) {
		sdtp_debug("%s: failed pullup typed header", __func__);
		goto sdtp_input_done;
	}

	sdtp_handle_packet(m, &src_addr, pcb);

sdtp_input_done:
	if (pcb) {
		check_pcb_locks(pcb);
		sdtp_pcb_put(pcb);
	}
	SDTP_LATENCY(sdtp, lat_input_cycles, lat_input_count, start_cycles);
	return (IPPROTO_DONE);
}

int
sdtp6_input(struct mbuf **mp, int *offp, int proto)
{
	/*
	 * #ifdef INET6
	 * 	if (ip_header->ip_v == (IPV6_VERSION >> 4)) {
	 * 	    icmp6_error(m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT,
	 * 0, 0);
	 * 	}
	 * #endif
	 */

	return (IPPROTO_DONE);
}

void
sdtp_ctlinput(struct icmp *icmp)
{
	return;
}

void
sdtp6_ctlinput(struct ip6ctlparam *ip6cp)
{
	return;
}
