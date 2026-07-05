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

#include "smt.h"
#include "smt_debug.h"
#include "smt_input.h"
#include "smt_pcb.h"
#include "smt_structs.h"
#include "smt_test.h"

#ifdef INET6
#include <netinet6/icmp6.h>
#endif

extern struct smt *smt;

static bool
smt_check_header_conditions(const struct smt_common_header *const header,
    const struct mbuf *const m, int iphlen)
{
	KASSERT(header != NULL, ("header must be valid"));
	KASSERT(m != NULL, ("m must be valid"));
	KASSERT(m != NULL, ("m must be valid"));
	MBUF_LEN_AT_LEAST(m, sizeof(header) + iphlen);

	if (header->type < SMT_DATA || header->type > SMT_ACK) {
		return (false);
	}

	if (m->m_pkthdr.len < smt_header_lengths[header->type - SMT_DATA]) {
		return (false);
	}

	return (true);
}

static struct smt_inpcb *
smt_get_pcb(struct smt *smt_struct,
    const struct smt_common_header *const header, int offset)
{
	KASSERT(header != NULL, ("header must be valid"));
	KASSERT(smt_struct != NULL, ("smt struct must be valid"));

	uint16_t dport;
	struct smt_inpcb *pcb;

	dport = ntohs(header->dport_be);

	mtx_lock_spin(&smt_struct->port_map.write_spinlock);
	pcb = smt_find_inpcb(&smt_struct->port_map, dport);
	if (pcb == NULL) {
		mtx_unlock_spin(&smt_struct->port_map.write_spinlock);
		return (NULL);
	}
	smt_pcb_hold(pcb);
	mtx_unlock_spin(&smt_struct->port_map.write_spinlock);

	smt_pcb_lock(pcb);
	if (pcb->shutdown || smt_so(pcb) == NULL || pcb->iphlen != offset) {
		smt_pcb_unlock(pcb);
		smt_pcb_put(pcb);
		return (NULL);
	}
	smt_pcb_unlock(pcb);

	return pcb;
}

static void
check_pcb_locks(struct smt_inpcb *pcb)
{
	KASSERT(pcb != NULL, ("pcb must be valid"));

	PCB_LOCK_NOTOWNED(pcb);
	mtx_assert(&pcb->smt->port_map.write_spinlock, MA_NOTOWNED);
	mtx_assert(&pcb->smt->peers.write_spinlock, MA_NOTOWNED);
}

static void
smt_parse_header_and_src_addr(struct mbuf *m, int iphlen,
    struct smt_common_header **smt_header, struct in6_addr *addr)
{
	KASSERT(m != NULL, ("m must be valid"));
	KASSERT(smt_header != NULL, ("smt_header must be valid"));
	KASSERT(addr != NULL, ("addr must be valid"));
	MUST_POSITIVE(iphlen);

	struct ip *ip_header = mtod(m, struct ip *);

	*smt_header = (struct smt_common_header *)((caddr_t)ip_header +
	    iphlen);
	*addr = ipv4_to_ipv6(&ip_header->ip_src);
}

int
smt_input(struct mbuf **mp, int *offp, int proto)
{
	struct smt_common_header *header;
	struct in6_addr src_addr;
	struct smt_inpcb *pcb = NULL;
	struct mbuf *m = *mp;
	uint64_t start_cycles = get_cyclecount();

	/* We want to access at least the common header */
	if ((m = m_pullup(m, *offp + sizeof(struct smt_common_header))) ==
	    NULL) {
		smt_debug("%s: failed pullup common header", __func__);
		goto smt_input_done;
	}

	smt_parse_header_and_src_addr(m, *offp, &header, &src_addr);

	if (!smt_check_header_conditions(header, m, *offp)) {
		m_freem(m);
		smt_debug("%s: failed header conditions: header type: %d, mbuf total length: %d",
			__func__, header->type, m->m_pkthdr.len);
		goto smt_input_done;
	}

	if ((pcb = smt_get_pcb(smt, header, *offp)) == NULL) {
		smt_debug("%s: can't find pcb\n", __func__);
		icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
		goto smt_input_done;
	}

	if ((m = m_pullup(m, *offp + smt_header_lengths[header->type - SMT_DATA])) ==
	    NULL) {
		smt_debug("%s: failed pullup typed header", __func__);
		goto smt_input_done;
	}

	smt_handle_packet(m, &src_addr, pcb);

smt_input_done:
	if (pcb) {
		check_pcb_locks(pcb);
		smt_pcb_put(pcb);
	}
	SMT_LATENCY(smt, lat_input_cycles, lat_input_count, start_cycles);
	return (IPPROTO_DONE);
}

int
smt6_input(struct mbuf **mp, int *offp, int proto)
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
smt_ctlinput(struct icmp *icmp)
{
	return;
}

void
smt6_ctlinput(struct ip6ctlparam *ip6cp)
{
	return;
}
