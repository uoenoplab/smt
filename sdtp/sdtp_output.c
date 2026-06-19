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
#include <sys/epoch.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/if_types.h>
#include <net/route/nhop.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>

#include <machine/in_cksum.h>

#include "sdtp.h"
#include "sdtp_debug.h"
#include "sdtp_os.h"
#include "sdtp_output.h"
#include "sdtp_pcb.h"
#include "sdtp_peer.h"
#include "sdtp_rpc.h"
#include "sdtp_structs.h"
#include "sdtp_test.h"

extern struct sdtp_zones zones;

int
sdtp_send_control_buf(struct sdtp_inpcb *pcb, struct sdtp_peer *peer,
    void *data, size_t len)
{
	VALID_PCB_ASSERT(pcb);
	VALID_PEER_ASSERT(peer);

	KASSERT(data != NULL, ("data must be valid"));
	MUST_POSITIVE(len);

	struct mbuf *m;
	struct inpcb *inp = &pcb->inp;
	struct epoch_tracker et;
	int error = 0, family = sdtp_so(pcb)->so_proto->pr_domain->dom_family;
	size_t iphlen = pcb->iphlen;
	uint64_t ip_output_start;

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (!m) {
		error = ENOBUFS;
		goto sdtp_send_control_buf_error;
	}
	memset(mtod(m, char *), 0, MHLEN);
	memcpy(mtod(m, char *) + iphlen, data, len);

	m->m_pkthdr.len = iphlen + len;
	m->m_len = iphlen + len;

	switch (family) {
	case AF_INET: {
		struct ip *ip_header = mtod(m, struct ip *);

		INP_WLOCK(inp);
		NET_EPOCH_ENTER(et);

		memset(ip_header, 0, sizeof(struct ip));

		ip_header->ip_v = IPVERSION;
		ip_header->ip_hl = sizeof(struct ip) >> 2;
		ip_header->ip_off = htons(IP_DF);
		ip_header->ip_tos = inp->inp_ip_tos;
		ip_header->ip_len = htons(m->m_pkthdr.len);
		ip_header->ip_ttl = 64;
		ip_header->ip_p = IPPROTO_SDTP;
		ipv6_to_ipv4(&peer->addr, &ip_header->ip_dst);
		ip_header->ip_src = inp->inp_laddr;
		ip_header->ip_sum = in_cksum_hdr(ip_header);

		ip_output_start = get_cyclecount();
		error = ip_output(m, NULL, &inp->inp_route, 0, NULL, inp);
		SDTP_LATENCY(pcb->sdtp, lat_ip_output_cycles,
		    lat_ip_output_count, ip_output_start);
		NET_EPOCH_EXIT(et);
		INP_WUNLOCK(inp);
		sdtp_pcb_debug(pcb, "ip_output return error: %d", error);

		break;
	}
	case AF_INET6: {
		KASSERT(0, ("not implemented yet"));
		break;
	}
	default: {
		KASSERT(0, ("unreachable"));
		__unreachable();
	}
	}

	return error;

sdtp_send_control_buf_error:
	if (m) {
		sdtp_free_mbuf(m);
	}
	return error;
}

int
sdtp_send_control(struct sdtp_rpc *rpc, enum sdtp_pkt_type type, void *data,
    size_t len)
{
	KASSERT(len >= sizeof(struct sdtp_common_header),
	    ("The buffer of size %lu should have at least size of common header (%lu bytes)",
		len, sizeof(struct sdtp_common_header)));

	struct sdtp_common_header *header = (struct sdtp_common_header *)data;
	header->type = type;
	header->sport_be = htons(rpc->sdtpcb->port);
	header->dport_be = htons(rpc->dport);
	header->sender_id_be = htobe64(rpc->id);
	return sdtp_send_control_buf(rpc->sdtpcb, rpc->peer, data, len);
}

void
sdtp_send_unknown(struct sdtp_inpcb *pcb, struct sdtp_common_header *header,
    struct in6_addr *source)
{
	struct sdtp_peer *peer;
	struct sdtp_unknown_header unknown;
	int error = 0;

	unknown.common.sport_be = header->dport_be;
	unknown.common.dport_be = header->sport_be;
	unknown.common.type = SDTP_UNKNOWN;
	unknown.common.sender_id_be = htobe64(
	    sdtp_local_id(header->sender_id_be));
	peer = sdtp_find_peer(&pcb->sdtp->peers, source, &error);
	if (error == 0 && peer != NULL) {
		sdtp_send_control_buf(pcb, peer, &unknown, sizeof(unknown));
		sdtp_peer_put(peer);
	}
}

static void
sdtp_msgout_init(struct sdtp_rpc *rpc, struct uio *uio)
{
	KASSERT(uio != NULL, ("uio must be valid"));
	MUST_POSITIVE(uio->uio_resid);

	rpc->msgout.length = uio->uio_resid;
	rpc->msgout.num_bufs = 0;
	rpc->msgout.next_xmit = NULL;
	rpc->msgout.next_xmit_offset = 0;
	atomic_store_int(&rpc->msgout.active_xmits_atomic, 0);
	rpc->msgout.sched_priority = 0;
}

static int
calc_unscheduled(struct sdtp_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);

	MUST_POSITIVE(rpc->msgout.length);
	MUST_POSITIVE(rpc->sdtpcb->sdtp->unsched_bytes);
	MUST_POSITIVE(rpc->msgout.pkt_data);

	int unsched;
	int length = rpc->msgout.length;
	int unsched_allow = rpc->sdtpcb->sdtp->unsched_bytes;
	int pkt_data = rpc->msgout.pkt_data;

	unsched = (unsched_allow + pkt_data) - (unsched_allow % pkt_data) - 1;
	if (unsched > length) {
		unsched = length;
	}

	MUST_POSITIVE(unsched);
	return unsched;
}

struct packet_mbuf_result {
	struct mbuf *buf;

	/*
	 * if there is an error, it is an error code, otherwise it
	 * is how many bytes were copied from the mbuf.
	 */
	int result;
};

static int
sdtp_uio_to_mbuf(struct sdtp_rpc *rpc, struct mbuf **mp, struct uio *uio, int m_size, int header_len)
{
	struct mchain mc;
	struct mbuf *m;
	int error;

	error = mc_uiotomc(&mc, uio, m_size - header_len, header_len, M_NOWAIT, M_PKTHDR);
	if (error != 0) {
		return (error);
	}

	m = mc_first(&mc);
	KASSERT(m != NULL, ("m must be valid"));

	m->m_pkthdr.len = mc.mc_len;
	m->m_pkthdr.memlen = mc.mc_mlen;

	m->m_data -= header_len;
	m->m_len += header_len;
	m->m_pkthdr.len += header_len;

	*mp = m;
	return (0);
}

void
sdtp_fill_data_header(struct sdtp_rpc *rpc, struct mbuf *m, int offset)
{
	struct sdtp_data_header *header;

	header = SDTP_MTOD(m, struct sdtp_data_header *, rpc->sdtpcb->iphlen);

	header->common.sport_be = htons(rpc->sdtpcb->port);
	header->common.dport_be = htons(rpc->dport);
	SDTP_SET_DOFF(header);
	header->common.type = SDTP_DATA;
	header->common.sender_id_be = htobe64(rpc->id);
	header->message_length_be = htonl(rpc->msgout.length);
	// I'm not sure if this is correct?
	header->incoming_be = htonl(rpc->msgout.length);
	header->cutoff_version_be = rpc->peer->cutoff_version_be;
	header->retransmit = 0;

	if (is_encrypted_rpc(rpc)) {
		header->padding[0] = (offset >> 16) & 0xFF;
		header->padding[1] = (offset >> 8) & 0xFF;
		header->padding[2] = offset & 0xFF;
	} else {
		header->data_segment.offset_be = htonl(offset);
	}

	header->ack.client_id_be = htobe64(rpc->id ^ 1);
	header->ack.server_port_be = htons(rpc->dport);
}

/*
 * m_size represents maximum size of packet INCLUDING header
 */
static struct packet_mbuf_result
sdtp_create_packet_mbuf(struct sdtp_rpc *rpc, struct uio *uio, int m_size,
    int offset)
{
	VALID_RPC_ASSERT(rpc);

	CTASSERT(MLEN >= MHLEN);
	KASSERT(IP_SDTP_HEADER_SIZE(rpc->sdtpcb, struct sdtp_data_header) <=
		MHLEN,
	    ("packet head buffer should contain ip header and sdtp data header"));

	MUST_POSITIVE(m_size);

	KASSERT(uio != NULL, ("uio must be valid"));
	MUST_POSITIVE(uio->uio_resid);

	struct mbuf *m;
	struct packet_mbuf_result res = {0};
	int error = 0;
	int header_len = IP_SDTP_HEADER_SIZE(rpc->sdtpcb, struct sdtp_data_header);

	error = sdtp_uio_to_mbuf(rpc, &m, uio, m_size, header_len);
	if (error != 0) {
		res.result = -error;
		goto sdtp_create_packet_mbuf_error;
	}

	sdtp_fill_data_header(rpc, m, offset);

	res.buf = m;
	res.result = m->m_pkthdr.len - header_len;

	MUST_POSITIVE(m->m_pkthdr.len);
	KASSERT(res.buf != NULL, ("res buf must be valid"));
	MUST_POSITIVE(res.result);

	sdtp_rpc_debug(rpc, "offset: %d, length: %d",
	    offset, res.result);

	return res;

sdtp_create_packet_mbuf_error:
	if (m) {
		m_freem(m);
	}
	KASSERT(res.buf == NULL,
	    ("res buf must be NULL when there is an error"));
	KASSERT(res.result < 0,
	    ("res result must be negative when there is an error"));
	return res;
}

static int
sdtp_fill_packets(struct sdtp_rpc *rpc, struct uio *uio,
    int max_packet_size)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);

	KASSERT(uio != NULL, ("uio must be valid"));
	MUST_POSITIVE(uio->uio_resid);

	MUST_POSITIVE(max_packet_size);

	int bytes_left, offset = 0, error = 0;
	struct sdtp_packet_slist_entry *prev = NULL;
	uint64_t start_cycles = get_cyclecount();

	sdtp_rpc_debug(rpc, "total message length to send: %d",
	    rpc->msgout.length);

	for (bytes_left = rpc->msgout.length; bytes_left > 0;) {
		struct packet_mbuf_result res;
		struct sdtp_packet_slist_entry *entry;
		int packet_size, m_size;

		packet_size = min(bytes_left, max_packet_size);
		m_size = IP_SDTP_HEADER_SIZE(rpc->sdtpcb,
			     struct sdtp_data_header) +
		    packet_size;

		sdtp_rpc_unlock(rpc);

		res = sdtp_create_packet_mbuf(rpc, uio, m_size, offset);
		if (res.result < 0) {
			error = -res.result;
			goto sdtp_fill_packets_slist_error;
		}
		bytes_left -= res.result;
		offset += res.result;

		entry = SDTP_ZONE_GET(zones.sdtp_zone_packet_slist_entry,
		    struct sdtp_packet_slist_entry);
		if (entry == NULL) {
			sdtp_rpc_debug(rpc,
			    "no entry left in zones.sdtp_zone_packet_slist_entry");
			sdtp_free_mbuf(res.buf);
			error = -ENOBUFS;
			goto sdtp_fill_packets_slist_error;
		}
		entry->data = res.buf;
		KASSERT(entry->data->m_pkthdr.len <= max_packet_size +
			    IP_SDTP_HEADER_SIZE(rpc->sdtpcb,
				struct sdtp_data_header),
		    ("buf size (%d) must be less or equal to MTU %lu",
			entry->data->m_pkthdr.len,
			max_packet_size +
			    IP_SDTP_HEADER_SIZE(rpc->sdtpcb,
				struct sdtp_data_header)));
		sdtp_rpc_debug(rpc, "buffer slist: offset %d, length %d",
		    ntohl(
			((struct sdtp_data_header *)(mtod(entry->data, char *) +
			     rpc->sdtpcb->iphlen))
			    ->data_segment.offset_be),
		    entry->data->m_pkthdr.len);

		sdtp_rpc_lock(rpc);
		if (prev == NULL) {
			SLIST_INSERT_HEAD(&rpc->msgout.packets, entry, link);
			rpc->msgout.next_xmit = &rpc->msgout.packets.slh_first;
		} else {
			SLIST_INSERT_AFTER(prev, entry, link);
		}
		prev = entry;
		++rpc->msgout.num_bufs;
	}

	SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_fill_packets_cycles,
	    lat_fill_packets_count, start_cycles);
	return 0;

sdtp_fill_packets_slist_error:
	sdtp_rpc_lock(rpc);
	SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_fill_packets_cycles,
	    lat_fill_packets_count, start_cycles);
	return error;
}

int
sdtp_packet_insert_list(struct sdtp_rpc *rpc, struct mbuf *m, struct sdtp_packet_slist_entry **prev)
{
	struct sdtp_packet_slist_entry *entry;

	entry = SDTP_ZONE_GET(zones.sdtp_zone_packet_slist_entry,
		struct sdtp_packet_slist_entry);
	if (entry == NULL) {
		sdtp_rpc_lock(rpc);
		return (ENOBUFS);
	}

	entry->data = m;

	sdtp_rpc_lock(rpc);
	if (*prev == NULL) {
		SLIST_INSERT_HEAD(&rpc->msgout.packets, entry, link);
		rpc->msgout.next_xmit = &rpc->msgout.packets.slh_first;
	} else {
		SLIST_INSERT_AFTER(*prev, entry, link);
	}
	*prev = entry;
	++rpc->msgout.num_bufs;

	return (0);
}

static void
sdtp_send_data(struct sdtp_rpc *rpc, struct mbuf *buf, int priority, bool overwrite_id)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_NOTOWNED(rpc);

	KASSERT(buf != 0, ("buf must be valid"));
	KASSERT(buf->m_flags & M_PKTHDR, ("buf must have packet header"));
	KASSERT(buf->m_pkthdr.len >=
		IP_SDTP_HEADER_SIZE(rpc->sdtpcb, struct sdtp_data_header),
	    ("buf must at least contain sdtp_data_header and ip header"));

	VALID_PEER_ASSERT(rpc->peer);

	struct epoch_tracker et;
	struct sdtp_data_header *header;
	// struct nhop_object *nh;
	struct inpcb *inp = &rpc->sdtpcb->inp;
	int family = sdtp_so(rpc->sdtpcb)->so_proto->pr_domain->dom_family;
	uint64_t ip_output_start;

	// nh = rpc->peer->nh;
	header = (struct sdtp_data_header *)(mtod(buf, char *) +
	    rpc->sdtpcb->iphlen);
	header->cutoff_version_be = rpc->peer->cutoff_version_be;

	buf->m_pkthdr.csum_flags = CSUM_IP;
	buf->m_pkthdr.csum_data = 0;

	switch (family) {
	case AF_INET: {
		struct ip *ip_header = mtod(buf, struct ip *);

		INP_WLOCK(inp);
		NET_EPOCH_ENTER(et);

		//memset(ip_header, 0, sizeof(struct ip));

		ip_header->ip_v = IPVERSION;
		ip_header->ip_hl = sizeof(struct ip) >> 2;
		ip_header->ip_tos = inp->inp_ip_tos;
		ip_header->ip_len = htons(buf->m_pkthdr.len);
		if (overwrite_id) {
			ip_fillid(ip_header, false);
		}
		ip_header->ip_off = htons(IP_DF);
		ip_header->ip_ttl = 64;
		ip_header->ip_p = IPPROTO_SDTP;
		ipv6_to_ipv4(&rpc->peer->addr, &ip_header->ip_dst);
		ip_header->ip_src = inp->inp_laddr;
		ip_header->ip_sum = 0;

		ip_output_start = get_cyclecount();
		int res = ip_output(buf, NULL, &inp->inp_route, IP_RAWOUTPUT, NULL, inp);
		SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_ip_output_cycles,
		    lat_ip_output_count, ip_output_start);
		NET_EPOCH_EXIT(et);
		INP_WUNLOCK(inp);
		sdtp_rpc_debug(rpc, "ip_output return error: %d", res);

		break;
	}
	case AF_INET6: {
		/*
		struct route_in6 ro6;
		memset(&ro6, 0, sizeof(ro6));
		ro6.ro_nh = nh;

		ip6_output(buf, NULL, &ro6, 0, NULL, &rpc->sdtpcb->inp);
		*/
		KASSERT(0, ("not implemented yet"));
		break;
	}
	default: {
		KASSERT(0, ("unreachable"));
		break;
	}
	}

	SDTP_METRIC(rpc->sdtpcb->sdtp, send_pkts_atomic, 1);
}

static void
sdtp_send_next_data(struct sdtp_rpc *rpc, bool force)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);

	struct sdtp *sdtp = rpc->sdtpcb->sdtp;
	struct mbuf *txm;

#ifdef SDTP_TEST
	static int i = 0;
	struct sdtp_data_header *header;
	int dropped = atomic_load_int(&test_state.drop_next_rpc_pkt_idx_atomic);
#endif

	atomic_add_int(&rpc->msgout.active_xmits_atomic, 1);
	while (rpc->msgout.next_xmit && *rpc->msgout.next_xmit) {
		int priority;
		struct mbuf *buf = (*rpc->msgout.next_xmit)->data;

		KASSERT(buf->m_flags & M_PKTHDR,
		    ("First packet buf need to contain a header"));
		sdtp_rpc_debug(rpc, "packet length: %d", buf->m_pkthdr.len);

#ifdef SDTP_TEST
		header = (struct sdtp_data_header *)(mtod(buf, char *) +
		    rpc->sdtpcb->iphlen);
		if (header->data_segment.offset_be == 0) {
			i = 0;
		}
#endif

		if (rpc->msgout.next_xmit_offset > rpc->msgout.granted) {
			sdtp_rpc_debug(rpc,
			    "rpc trying to send %d bytes over granted bytes %d",
			    rpc->msgout.next_xmit_offset, rpc->msgout.granted);
			break;
		}

		/*
		 * TODO: remember to fix this
		if ((rpc->msgout.length - rpc->msgout.next_xmit_offset)
					>= homa->throttle_min_bytes) {

			}
		*/

		if (rpc->msgout.next_xmit_offset < rpc->msgout.unscheduled) {
			priority = sdtp_unsched_priority(sdtp, rpc->peer,
			    rpc->msgout.length);
		} else {
			priority = rpc->msgout.sched_priority;
		}

		rpc->msgout.next_xmit = &(
		    (*rpc->msgout.next_xmit)->link.sle_next);
		rpc->msgout.next_xmit_offset += rpc->msgout.pkt_data;
		if (rpc->msgout.next_xmit_offset > rpc->msgout.length) {
			rpc->msgout.next_xmit_offset = rpc->msgout.length;
		}

#ifdef SDTP_TEST
		if (dropped == i++) {
			atomic_store_int(
			    &test_state.drop_next_rpc_pkt_idx_atomic, -1);
			continue;
		}
#endif

		sdtp_rpc_unlock(rpc);

		txm = m_copypacket(buf, M_NOWAIT);
		if (txm != NULL && (!M_WRITABLE(txm) || txm->m_len < rpc->sdtpcb->iphlen)) {
			txm = m_pullup(txm, rpc->sdtpcb->iphlen);
		}
		if (txm == NULL) {
			break;
		}

		KASSERT(txm != NULL, ("txm must be valid"));
		sdtp_send_data(rpc, txm, priority, !is_encrypted_rpc(rpc));
		force = false;

		sdtp_rpc_lock(rpc);
	}
	atomic_add_int(&rpc->msgout.active_xmits_atomic, -1);
}

int
sdtp_message_out(struct sdtp_rpc *rpc, struct uio *uio, bool immediate_send)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);

	KASSERT(uio != NULL, ("uio must be valid"));
	MUST_POSITIVE(uio->uio_resid);

	int max_packet_size, error = 0;
	//, overlap_xmit;
	uint16_t mtu;
	uint64_t start_cycles = get_cyclecount();

	// sdtp_debug_print_pcb_rpcs(rpc->sdtpcb, rpc);

	sdtp_msgout_init(rpc, uio);

	if (rpc->msgout.length > SDTP_MAX_MESSAGE_LENGTH ||
	    rpc->msgout.length == 0) {
		error = EINVAL;
		sdtp_rpc_debug(rpc, "message length invalid");
		goto sdtp_message_out_error;
	}

	KASSERT(NH_IS_VALID(rpc->peer->nh), ("nh must be valid"));
	mtu = rpc->peer->nh->nh_mtu;
	sdtp_debug("ifp=%s mtu=%d\n", rpc->peer->nh->nh_ifp->if_xname,
	    rpc->peer->nh->nh_ifp->if_mtu);
	max_packet_size = mtu -
	    IP_SDTP_HEADER_SIZE(rpc->sdtpcb, struct sdtp_data_header);
	MUST_POSITIVE(max_packet_size);
	sdtp_rpc_debug(rpc, "mtu: %d, max_packet_size: %d", mtu,
	    max_packet_size);

	if (max_packet_size < 0) {
		error = EINVAL;
		goto sdtp_message_out_error;
	}

	rpc->msgout.pkt_data = rpc->msgout.length;
	rpc->msgout.unscheduled = calc_unscheduled(rpc);
	rpc->msgout.granted = rpc->msgout.unscheduled;

	// overlap_xmit = rpc->msgout.length > 2 * max_packet_size;
	atomic_set_32(&rpc->flags_atomic, RPC_COPYING_FROM_USER);

	if (is_encrypted_rpc(rpc)) {
		error = sdtp_tls_fill_packets(rpc, uio, max_packet_size);
	} else {
		error = sdtp_fill_packets(rpc, uio, max_packet_size);
	}
	if (error) {
		goto sdtp_message_out_error;
	}

	atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_FROM_USER);
	if (immediate_send) {
		sdtp_send_next_data(rpc, false);
	}

	SDTP_METRIC(rpc->sdtpcb->sdtp, send_rpcs_atomic, 1);
	SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_message_out_cycles,
	    lat_message_out_count, start_cycles);
	return 0;

sdtp_message_out_error:
	atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_FROM_USER);
	SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_message_out_cycles,
	    lat_message_out_count, start_cycles);
	return error;
}

void
sdtp_resend_data(struct sdtp_rpc *rpc, int start, int end, int priority)
{
	VALID_RPC_ASSERT(rpc);
	MUST_NOT_NEGATIVE(start);
	MUST_NOT_NEGATIVE(end);
	KASSERT(end >= start,
	    ("end must be more than start: %d, %d", end, start));

	struct sdtp_packet_slist_entry *packet;
	struct sdtp_data_header *header;
	struct mbuf *txm;
	int offset, dbytes;

	SLIST_FOREACH(packet, &rpc->msgout.packets, link) {
		header = ((
		    struct sdtp_data_header *)(mtod(packet->data, char *) +
		    rpc->sdtpcb->iphlen));
		offset = ntohl(header->data_segment.offset_be);
		dbytes = packet->data->m_pkthdr.len -
		    sizeof(struct sdtp_data_header) -
		    rpc->sdtpcb->iphlen;

		if (offset >= end) {
			break;
		}
		if (start >= (offset + dbytes)) {
			continue;
		}

		txm = m_dup(packet->data, M_NOWAIT);
		KASSERT(txm != NULL, ("txm must be valid"));
		sdtp_rpc_debug(rpc, "resend data from %d to %d", offset,
		    offset + dbytes);
		sdtp_send_data(rpc, txm, priority, !is_encrypted_rpc(rpc));
	}
}
