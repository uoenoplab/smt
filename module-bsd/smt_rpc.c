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
#include <sys/endian.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <machine/atomic.h>

#include "smt.h"
#include "smt_debug.h"
#include "smt_os.h"
#include "smt_output.h"
#include "smt_peer.h"
#include "smt_rpc.h"
#include "smt_structs.h"
#include "smt_test.h"

extern struct smt_zones zones;

void
smt_rpc_lock(struct smt_rpc *rpc)
{
	// smt_rpc_debug(rpc, "locked by %#lx", (uintptr_t)curthread);
	mtx_lock_spin(rpc->spinlock_p);
}

void
smt_rpc_unlock(struct smt_rpc *rpc)
{
	mtx_unlock_spin(rpc->spinlock_p);
	// smt_rpc_debug(rpc, "unlocked by %#lx", (uintptr_t)curthread);
}

void
insert_ready_rpc(struct smt_inpcb *pcb, struct smt_rpc_list *list,
	struct smt_rpc *rpc)
{
	PCB_LOCK_OWNED(pcb);
	MPASS(atomic_load_int(&rpc->is_ready_atomic) == false);

	atomic_store_int(&rpc->is_ready_atomic, true);
	LIST_INSERT_HEAD(list, rpc, ready_links);
}

void
remove_ready_rpc(struct smt_inpcb *pcb, struct smt_rpc *rpc)
{
	PCB_LOCK_OWNED(pcb);
	MPASS(atomic_load_int(&rpc->is_ready_atomic) == true);

	LIST_REMOVE(rpc, ready_links);
	atomic_store_int(&rpc->is_ready_atomic, false);
}

void
smt_free_mbuf(struct mbuf *buf)
{
	KASSERT(buf != NULL, ("mbuf should be valid"));
	KASSERT(buf->m_len > 0, ("mbuf size should be at least 0"));

	smt_debug("buf %#lx free'd\n", (uintptr_t)buf);
	m_freem(buf);
}

bool
smt_is_client(uint64_t id)
{
	return (id & 1) == 0;
}

static inline struct smt_rpc *
smt_rpc_zone_get(struct smt_inpcb *pcb)
{
	struct smt_rpc *rpc = SMT_ZONE_GET(zones.smt_zone_rpc,
	    struct smt_rpc);
	if (rpc) {
		SMT_METRIC(pcb->smt, allocated_rpcs_atomic, 1);
	}
	return rpc;
}

static inline void
smt_rpc_zone_free(struct smt_inpcb *pcb, struct smt_rpc *rpc)
{
	if (rpc->crypto.ctx != NULL) {
		smt_ctx_put(rpc->crypto.ctx);
		rpc->crypto.ctx = NULL;
	}
	SMT_ZONE_FREE(zones.smt_zone_rpc, rpc);
	SMT_METRIC(pcb->smt, freed_rpcs_atomic, 1);
}

static void
smt_handoff_rpc(struct smt_inpcb *pcb, struct smt_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_NOTOWNED(pcb);

	struct smt_interest *interest;

	smt_rpc_debug(rpc, "handing off");

	smt_pcb_lock(pcb);
	if (pcb->shutdown || rpc->state == SMT_RPC_DEAD) {
		smt_pcb_unlock(pcb);
		return;
	}

	if ((atomic_load_32(&rpc->flags_atomic) & RPC_HANDING_OFF) ||
	    atomic_load_int(&rpc->is_ready_atomic)) {
		smt_rpc_debug(rpc, "already handing off");
		smt_pcb_unlock(pcb);
		return;
	}

	if (rpc->interest) {
		smt_rpc_debug(rpc, "already has interest");
		interest = rpc->interest;
		goto smt_handoff_rpc_waiting;
	}

	if (smt_is_client(rpc->id)) {
		smt_rpc_debug(rpc, "check if thread is waiting for response");
		interest = TAILQ_FIRST(&pcb->response_interests);
		if (interest) {
			goto smt_handoff_rpc_waiting;
		}
		insert_ready_rpc(pcb, &pcb->ready_responses, rpc);
	} else {
		smt_rpc_debug(rpc, "check if thread is waiting for request");
		interest = TAILQ_FIRST(&pcb->request_interests);
		if (interest) {
			goto smt_handoff_rpc_waiting;
		}
		insert_ready_rpc(pcb, &pcb->ready_requests, rpc);
	}

	smt_pcb_unlock(pcb);
	smt_rpc_unlock(rpc);
	smt_rpc_debug(rpc, "wake up pcb");
	smt_sorwakeup(pcb);
	smt_rpc_lock(rpc);
	return;

smt_handoff_rpc_waiting:
	mtx_lock_spin(&interest->spinlock);
	smt_rpc_debug(rpc, "there is a thread waiting");
	atomic_set_32(&rpc->flags_atomic, RPC_HANDING_OFF);

	smt_rpc_hold(rpc);

	if (interest->reg_rpc) {
		rpc->interest = NULL;
		interest->reg_rpc = NULL;
		smt_rpc_put(rpc);
	}

	if (atomic_load_int(&interest->is_request_atomic)) {
		remove_request_interest(pcb, interest);
	}
	if (atomic_load_int(&interest->is_response_atomic)) {
		remove_response_interest(pcb, interest);
	}

	atomic_store_rel_ptr(&interest->ready_rpc_atomic, (uintptr_t)rpc);
	smt_rpc_debug(rpc, "waking up thread: %#x", interest->thread);
	INTEREST_NOT_LINKED(interest);

	wakeup(&interest->spinlock);
	mtx_unlock_spin(&interest->spinlock);
	smt_pcb_unlock(pcb);
}

struct smt_rpc *
smt_find_client_rpc(struct smt_inpcb *pcb, uint64_t id)
{
	struct smt_rpc *rpc = NULL;
	struct smt_rpc_bucket *bucket = smt_client_rpc_bucket(pcb, id);

	smt_pcb_debug(pcb, "finding client rpc");

	mtx_lock_spin(&bucket->spinlock);
	LIST_FOREACH(rpc, &bucket->rpcs, hash_links) {
		if (rpc->id == id) {
			return rpc;
		}
	}
	mtx_unlock_spin(&bucket->spinlock);
	return NULL;
}

struct smt_rpc *
smt_find_server_rpc(struct smt_inpcb *pcb, struct in6_addr *source,
    uint16_t port, uint64_t id)
{
	struct smt_rpc *rpc = NULL;
	struct smt_rpc_bucket *bucket = smt_server_rpc_bucket(pcb, id);

	smt_pcb_debug(pcb, "finding server rpc");

	mtx_lock_spin(&bucket->spinlock);
	LIST_FOREACH(rpc, &bucket->rpcs, hash_links) {
		if (rpc->id == id && rpc->dport == port &&
		    is_ipv6_same(&rpc->peer->addr, source)) {
			return rpc;
		}
	}
	mtx_unlock_spin(&bucket->spinlock);
	return NULL;
}

struct smt_rpc *
smt_new_client_rpc(struct smt_inpcb *pcb, struct in6_addr *dest,
    uint16_t port, int *error)
{
	struct smt_rpc_bucket *bucket;
	struct smt_rpc *rpc;
	*error = 0;

	smt_pcb_debug(pcb, "creating new client rpc");
	rpc = smt_rpc_zone_get(pcb);
	if (!rpc) {
		*error = ENOMEM;
		smt_pcb_debug(pcb, "not enough memory for new client rpc");
		goto smt_new_client_rpc_error;
	}

	rpc->smtcb = pcb;
	rpc->id = atomic_fetchadd_64(&pcb->smt->next_out_id_atomic, 2);
	rpc->state = SMT_RPC_OUTGOING;

	bucket = smt_client_rpc_bucket(pcb, rpc->id);
	rpc->peer = smt_find_peer(&pcb->smt->peers, dest, error);
	if (*error != 0) {
		smt_pcb_debug(pcb, "new client rpc can't find peer");
		goto smt_new_client_rpc_error;
	}
	rpc->dport = port;
	rpc->msgin.total_length = -1;
	rpc->msgout.length = -1;
	atomic_store_int(&rpc->is_ready_atomic, false);
	TAILQ_INIT(&rpc->grantable_links);
	TAILQ_INIT(&rpc->throttled_links);
	rpc->resend_timer_ticks = pcb->smt->timer_ticks;
	rpc->magic = SMT_RPC_MAGIC;
	rpc->start_cycles = get_cyclecount();
	refcount_init(&rpc->refs, 1);

	rpc->spinlock_p = &bucket->spinlock;
	smt_rpc_lock(rpc);
	smt_pcb_lock(pcb);
	if (pcb->shutdown) {
		smt_pcb_unlock(pcb);
		smt_rpc_unlock(rpc);
		*error = ESHUTDOWN;
		goto smt_new_client_rpc_error;
	}

	if (pcb->ctx_map.active) {
		*error = smt_rpc_ctx_init(pcb, rpc);
		if (*error != 0) {
			smt_pcb_unlock(pcb);
			smt_rpc_unlock(rpc);
			goto smt_new_client_rpc_error;
		}
	}

	LIST_INSERT_HEAD(&bucket->rpcs, rpc, hash_links);
	TAILQ_INSERT_TAIL(&pcb->active_rpcs, rpc, active_links);
	smt_pcb_unlock(pcb);

	return rpc;

smt_new_client_rpc_error:
	if (rpc) {
		if (rpc->peer) {
			smt_peer_put(rpc->peer);
		}
		smt_rpc_zone_free(pcb, rpc);
	}
	return NULL;
}

static inline void
smt_set_header_offset(struct smt_data_header *header)
{
	if (ntohl(header->data_segment.offset_be) == -1) {
		header->data_segment.offset_be = header->common.sequence_be;
	}
}

static void
smt_message_in_init(struct smt_message_in *msgin, int length, int incoming)
{
	KASSERT(msgin->total_length == -1, ("msgin must not be initialized: length: %d",
		msgin->total_length));

	msgin->total_length = length;
	TAILQ_INIT(&msgin->packets);
	msgin->num_bufs = 0;
	msgin->bytes_remaining = length;
	msgin->gsoseg_offset = 0;
	msgin->decrypt_offset = 0;
	msgin->gsoseg_bufs = &msgin->packets;
	msgin->decrypt_bufs = &msgin->packets;
	msgin->max_pkt_data = 0;
	msgin->nextgsoseg_length = 0;
	msgin->nextgsoseg_received = 0;
	msgin->incoming = (incoming > length) ? length : incoming;
	msgin->priority = 0;
	msgin->scheduled = length > incoming;
	msgin->copied_out = 0;
	msgin->num_bpages = 0;
}

static void
smt_init_server_rpc_fields(struct smt_inpcb *pcb, struct smt_rpc *rpc,
    struct smt_data_header *header, uint64_t id)
{
	rpc->smtcb = pcb;
	rpc->state = SMT_RPC_INCOMING;
	atomic_store_32(&rpc->flags_atomic, 0);
	atomic_store_32(&rpc->grants_in_progress_atomic, 0);
	rpc->dport = ntohs(header->common.sport_be);
	rpc->id = id;
	rpc->completion_cookie = 0;
	rpc->error = 0;
	atomic_store_int(&rpc->is_ready_atomic, false);
	rpc->msgin.total_length = -1;
	rpc->msgin.num_bufs = 0;
	rpc->msgin.num_bpages = 0;
	memset(&rpc->msgout, 0, sizeof(rpc->msgout));
	rpc->msgout.length = -1;
	rpc->interest = NULL;
	TAILQ_INIT(&rpc->grantable_links);
	TAILQ_INIT(&rpc->throttled_links);
	rpc->silent_ticks = 0;
	rpc->resend_timer_ticks = pcb->smt->timer_ticks;
	rpc->done_timer_ticks = 0;
	rpc->magic = SMT_RPC_MAGIC;
	rpc->start_cycles = get_cyclecount();
	refcount_init(&rpc->refs, 1);
	memset(&rpc->crypto, 0, sizeof(rpc->crypto));
}

static struct smt_expected_rpc_ptr
smt_new_server_rpc(struct smt_data_header *header,
		    struct smt_inpcb *pcb, struct in6_addr *source, int payload_size)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_NOTOWNED(pcb);
	MUST_POSITIVE(payload_size);

	struct smt_rpc_bucket *bucket;
	struct smt_rpc *existing, *rpc;
	int error = 0;
	uint64_t id;

	id = smt_local_id(header->common.sender_id_be);

	rpc = smt_find_server_rpc(pcb, source, ntohs(header->common.sport_be), id);
	if (rpc) {
		smt_pcb_debug(pcb, "no need for new rpc, found old one");
		return SMT_MAKE_EXPECTED(struct smt_expected_rpc_ptr, rpc);
	}

	smt_pcb_debug(pcb, "creating new server rpc");
	rpc = smt_rpc_zone_get(pcb);
	if (!rpc) {
		error = ENOMEM;
		smt_pcb_debug(pcb, "not enough memory for new server rpc");
		goto smt_new_server_rpc_error;
	}

	smt_set_header_offset(header);
	smt_init_server_rpc_fields(pcb, rpc, header, id);
	smt_message_in_init(&rpc->msgin,
		    ntohl(header->message_length_be),
		    ntohl(header->incoming_be));

	rpc->peer = smt_find_peer(&pcb->smt->peers, source, &error);
	if (error != 0) {
		smt_pcb_debug(pcb, "new server rpc can't find peer");
		goto smt_new_server_rpc_error;
	}

	bucket = smt_server_rpc_bucket(pcb, id);
	rpc->spinlock_p = &bucket->spinlock;
	smt_rpc_lock(rpc);

	// Another CPU may have created this RPC in the meantime.
	LIST_FOREACH(existing, &bucket->rpcs, hash_links) {
		if (existing->id == id && existing->dport == rpc->dport &&
		    is_ipv6_same(&existing->peer->addr, source)) {
			smt_rpc_hold(existing);
			smt_rpc_unlock(rpc);
			smt_peer_put(rpc->peer);
			rpc->peer = NULL;
			smt_rpc_zone_free(pcb, rpc);

			smt_rpc_lock(existing);
			if (existing->state == SMT_RPC_DEAD) {
				smt_rpc_put(existing);
				smt_rpc_unlock(existing);
				return smt_new_server_rpc(header, pcb, source,
				    payload_size);
			}
			smt_rpc_put(existing);
			return SMT_MAKE_EXPECTED(
			    struct smt_expected_rpc_ptr, existing);
		}
	}

	smt_pcb_lock(pcb);
	if (pcb->shutdown) {
		error = ESHUTDOWN;
		smt_pcb_unlock(pcb);
		smt_rpc_unlock(rpc);
		goto smt_new_server_rpc_error;
	}

	if (pcb->ctx_map.active) {
		error = smt_rpc_ctx_init(pcb, rpc);
		if (error != 0) {
			smt_pcb_unlock(pcb);
			smt_rpc_unlock(rpc);
			goto smt_new_server_rpc_error;
		}
	}

	LIST_INSERT_HEAD(&bucket->rpcs, rpc, hash_links);
	TAILQ_INSERT_TAIL(&pcb->active_rpcs, rpc, active_links);
	smt_pcb_unlock(pcb);

	return SMT_MAKE_EXPECTED(struct smt_expected_rpc_ptr, rpc);

smt_new_server_rpc_error:
	if (rpc) {
		if (rpc->peer) {
			smt_peer_put(rpc->peer);
		}
		smt_rpc_zone_free(pcb, rpc);
	}
	return SMT_MAKE_UNEXPECTED(struct smt_expected_rpc_ptr, error);
}

static bool
smt_add_packet(struct mbuf *m, struct smt_rpc *rpc,
    struct smt_data_header *header, int iphlen)
{
	KASSERT(m != NULL, ("m must be valid"));
	MBUF_LEN_AT_LEAST(m, sizeof(struct smt_data_header) + iphlen);
	KASSERT(m->m_flags & M_PKTHDR, ("mbuf must be a header mbuf"));
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	KASSERT(header != NULL, ("header must be valid"));
	MUST_POSITIVE(iphlen);

	struct smt_packet_tailq_entry *packet, *new;
	struct smt_rx_logical_info rx_info;
	int offset, data_bytes;
	int floor = rpc->msgin.copied_out;
	int ceiling = rpc->msgin.total_length;

	if (is_encrypted_rpc(rpc)) {
		rx_info = smt_calc_rx_logical_info(rpc, m);
		offset = rx_info.start;
		data_bytes = rx_info.length;
	} else {
		offset = ntohl(header->data_segment.offset_be);
		data_bytes = smt_payload_len(m, iphlen);
	}
	smt_data_header_debug(header, "size: %d", data_bytes);
	MUST_POSITIVE(data_bytes);

	TAILQ_FOREACH_REVERSE(packet, &rpc->msgin.packets, smt_packet_tailq,
	    link) {
		KASSERT(packet->data->m_flags & M_PKTHDR,
		    ("packet must be a header mbuf"));

		int tmp_off, tmp_dbytes;

		if (is_encrypted_rpc(rpc)) {
			struct smt_rx_logical_info *ri = &packet->rx_info;
			tmp_off = ri->start;
			tmp_dbytes = ri->length;
		} else {
			struct smt_data_header *h = SMT_MTOD(packet->data,
				struct smt_data_header *, iphlen);
			tmp_off = ntohl(h->data_segment.offset_be);
			tmp_dbytes = smt_payload_len(packet->data, iphlen);
		}

		MUST_POSITIVE(tmp_dbytes);

		if (tmp_off < offset) {
			floor = tmp_off + tmp_dbytes;
			break;
		}
		ceiling = tmp_off;
	}

	if ((offset < floor) || (offset + data_bytes > ceiling)) {
		smt_rpc_debug(rpc, "drop packet");
		return false;
	}

	if (header->retransmit) {
		// TODO: homa_freeze()
	}

	new = smt_pool_alloc_packet_tailq_entry();
	new->data = m;
	new->rx_info = rx_info;

	if (packet) {
		TAILQ_INSERT_AFTER(&rpc->msgin.packets, packet, new, link);
	} else {
		TAILQ_INSERT_TAIL(&rpc->msgin.packets, new, link);
	}

	rpc->msgin.bytes_remaining -= data_bytes;
	rpc->msgin.num_bufs++;
	smt_rpc_debug(rpc, "new packet added");
	return true;
}

static void
smt_rpc_acked(struct smt_inpcb *pcb, struct in6_addr *source_addr,
    struct smt_ack *ack)
{
	uint16_t server_port = ntohs(ack->server_port_be);
	uint64_t id = smt_local_id(ack->client_id_be);
	struct smt_inpcb *tmp = pcb;
	struct smt_rpc_bucket *bucket;
	struct smt_rpc *rpc;
	bool target_held = false;

	if (tmp->port != server_port) {
		mtx_lock_spin(&pcb->smt->port_map.write_spinlock);
		tmp = smt_find_inpcb(&pcb->smt->port_map, server_port);
		if (tmp != NULL) {
			smt_pcb_hold(tmp);
			target_held = true;
		}
		mtx_unlock_spin(&pcb->smt->port_map.write_spinlock);
		if (tmp == NULL) {
			return;
		}
	}

	bucket = smt_server_rpc_bucket(tmp, id);
	mtx_lock_spin(&bucket->spinlock);
	LIST_FOREACH(rpc, &bucket->rpcs, hash_links) {
		if (rpc->id == id &&
		    is_ipv6_same(&rpc->peer->addr, source_addr)) {
			break;
		}
	}
	if (rpc == NULL) {
		mtx_unlock_spin(&bucket->spinlock);
	}
	if (rpc) {
		smt_rpc_free(rpc);
		smt_rpc_unlock(rpc);
	}
	if (target_held) {
		smt_pcb_put(tmp);
	}
}

/* return true if RPC is alive, otherwise false. We need to check because we
 * drop the RPC lock */
static bool
smt_ack_client(struct smt_inpcb *pcb, struct smt_rpc *rpc,
    struct smt_data_header *header, struct in6_addr *source)
{
	if (header->ack.client_id_be == 0) {
		return true;
	}

	smt_rpc_unlock(rpc);
	smt_rpc_acked(pcb, source, &header->ack);
	smt_rpc_lock(rpc);

	return rpc->state != SMT_RPC_DEAD;
}

/* return false if the RPC isn't in the correct state */
static bool
smt_prepare_rpc_for_data(struct smt_rpc *rpc, struct smt_data_header *header)
{
	bool is_client = smt_is_client(rpc->id);

	if (rpc->state == SMT_RPC_INCOMING) {
		return true;
	}

	if (!is_client && rpc->msgin.total_length >= 0) {
		return false;
	}

	// if server RPC, msgin should be already initialized
	// in smt_new_server_rpc().
	if (is_client) {
		if (rpc->state != SMT_RPC_OUTGOING) {
			return false;
		}

		rpc->state = SMT_RPC_INCOMING;
		smt_message_in_init(&rpc->msgin,
		    ntohl(header->message_length_be),
		    ntohl(header->incoming_be));

		if (is_encrypted_rpc(rpc)) {
			/* TODO: Set smt_max_pkt_data for first data packet */
		}
	}

	return true;
}

static void
smt_debug_msgin_packets(struct smt_rpc *rpc)
{
	struct smt_packet_tailq_entry *entry;
	if (is_encrypted_rpc(rpc)) {
		TAILQ_FOREACH(entry, &rpc->msgin.packets, link) {
			struct smt_rx_logical_info *rx_info = &entry->rx_info;
			smt_debug_rx_info(rpc, rx_info);
		}
	}
}

static bool
smt_data_packet(struct smt *smt, struct mbuf *m, struct smt_rpc *rpc,
    struct smt_inpcb *pcb, struct in6_addr *source)
{
	KASSERT(smt != NULL, ("smt must be valid"));
	KASSERT(m != NULL, ("m must be valid"));
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	VALID_PCB_ASSERT(pcb);
	KASSERT(source != NULL, ("source must be valid"));

	struct smt_data_header *header = SMT_MTOD(m, struct smt_data_header *, pcb->iphlen);
	uint64_t start_cycles = get_cyclecount();
	smt_set_header_offset(header);
	smt_data_header_debug(header, NULL);

	if (!smt_ack_client(pcb, rpc, header, source)) {
		goto smt_data_packet_error;
	}

	if (!smt_prepare_rpc_for_data(rpc, header)) {
		goto smt_data_packet_error;
	}

	if (!smt_add_packet(m, rpc, header, pcb->iphlen)) {
		goto smt_data_packet_error;
	}

	smt_debug_msgin_packets(rpc);

	if (!TAILQ_EMPTY(&rpc->msgin.packets) &&
		(!(atomic_load_32(&rpc->flags_atomic) & RPC_PKTS_READY))) {

		// Temporary solution, because we don't have memory pools,
		// we can only handoff when the message is complete.
		if ((is_encrypted_rpc(rpc) && smt_ctx_record_complete(rpc))
			|| (!is_encrypted_rpc(rpc) && rpc->msgin.bytes_remaining == 0)) {

			atomic_set_32(&rpc->flags_atomic, RPC_PKTS_READY);
			smt_handoff_rpc(pcb, rpc);
		}
	}

	if (rpc->msgin.scheduled) {
		// TODO: homa_check_grantable(homa, rpc);
	}

	if (ntohs(header->cutoff_version_be) != smt->cutoff_version) {
		// TODO: The sender has out-of-date cutoffs
	}

	SMT_LATENCY(smt, lat_data_packet_cycles, lat_data_packet_count,
	    start_cycles);
	return true;

smt_data_packet_error:
	SMT_LATENCY(smt, lat_data_packet_cycles, lat_data_packet_count,
	    start_cycles);
	return false;
}

int
smt_rpc_reap(struct smt_inpcb *pcb, bool reap_all)
{
#define BATCH_MAX 10
	struct smt_rpc *rpcs[BATCH_MAX];
	struct smt_packet_slist_entry *out_pkts[BATCH_MAX];
	struct smt_packet_tailq_entry *in_pkts[BATCH_MAX];
	bool checked_all_rpcs = false;
	int bufs_to_reap, batch_size, num_out_pkts, num_in_pkts, num_rpcs;
	struct smt_rpc *rpc, *tmp;

	smt_pcb_debug(pcb, "reap dead rpcs");

	bufs_to_reap = pcb->smt->reap_limit;
	while (!checked_all_rpcs) {
		batch_size = BATCH_MAX;
		if (!reap_all) {
			if (bufs_to_reap <= 0) {
				smt_pcb_debug(pcb, "bufs_to_reap: %d",
				    bufs_to_reap);
				break;
			}
			if (batch_size > bufs_to_reap) {
				batch_size = bufs_to_reap;
			}
		}
		num_out_pkts = 0;
		num_in_pkts = 0;
		num_rpcs = 0;

		smt_pcb_debug(pcb, "reap batch size: %d", batch_size);

		smt_pcb_lock(pcb);
		if (atomic_load_32(&pcb->protect_count_atomic)) {
			smt_pcb_unlock(pcb);
			return 0;
		}

		TAILQ_FOREACH_SAFE(rpc, &pcb->dead_rpcs, dead_links, tmp) {
			u_int refs;

			// if holding the PCB lock, we don't want to spin
			// infinitely on RPC.
			if (!mtx_trylock_spin(rpc->spinlock_p)) {
				checked_all_rpcs = false;
				goto smt_reap_rpc_release;
			}
			refs = refcount_load(&rpc->refs);

			if (refs > 1) {
				smt_rpc_unlock(rpc);
				continue;
			}

			if (rpc->msgout.length >= 0) {
				while (!SLIST_EMPTY(&rpc->msgout.packets)) {
					out_pkts[num_out_pkts] = SLIST_FIRST(
					    &rpc->msgout.packets);
					SLIST_REMOVE_HEAD(&rpc->msgout.packets,
					    link);
					++num_out_pkts;
					--rpc->msgout.num_bufs;
					if (num_out_pkts >= batch_size) {
						smt_rpc_unlock(rpc);
						checked_all_rpcs = false;
						goto smt_reap_rpc_release;
					}
				}
			}

			if (rpc->msgin.total_length >= 0) {
				while (!TAILQ_EMPTY(&rpc->msgin.packets)) {
					in_pkts[num_in_pkts] = TAILQ_FIRST(
					    &rpc->msgin.packets);
					TAILQ_REMOVE_HEAD(&rpc->msgin.packets,
					    link);
					++num_in_pkts;
					--rpc->msgin.num_bufs;
					if (num_in_pkts >= batch_size) {
						smt_rpc_unlock(rpc);
						checked_all_rpcs = false;
						goto smt_reap_rpc_release;
					}
				}
			}

			rpcs[num_rpcs] = rpc;
			++num_rpcs;
			TAILQ_REMOVE(&pcb->dead_rpcs, rpc, dead_links);
			smt_rpc_unlock(rpc);
			if (num_rpcs >= batch_size) {
				checked_all_rpcs = TAILQ_EMPTY(&pcb->dead_rpcs);
				goto smt_reap_rpc_release;
			}
		}
		checked_all_rpcs = true;

	smt_reap_rpc_release:
		pcb->dead_bufs -= num_out_pkts + num_in_pkts;
		smt_pcb_unlock(pcb);
		if (!reap_all) {
			bufs_to_reap -= num_out_pkts + num_in_pkts + num_rpcs;
		}

		smt_pcb_debug(pcb, "reap %d out packets", num_out_pkts);
		for (int i = 0; i < num_out_pkts; ++i) {
			m_freem(out_pkts[i]->data);
			SMT_ZONE_FREE(zones.smt_zone_packet_slist_entry,
			    out_pkts[i]);
			SMT_METRIC(pcb->smt, freed_send_pkts_atomic, 1);
		}

		smt_pcb_debug(pcb, "reap %d in packets", num_in_pkts);
		for (int i = 0; i < num_in_pkts; ++i) {
			m_freem(in_pkts[i]->data);
			smt_pool_free_packet_tailq_entry(in_pkts[i]);
			SMT_METRIC(pcb->smt, freed_recv_pkts_atomic, 1);
		}

		smt_pcb_debug(pcb, "reap %d rpcs", num_rpcs);
		for (int i = 0; i < num_rpcs; ++i) {
			rpc = rpcs[i];

			if (rpc->peer) {
				smt_peer_put(rpc->peer);
				rpc->peer = NULL;
			}
			rpc->magic = 0;
			rpc->state = 0;
			smt_rpc_zone_free(pcb, rpc);
		}

		if (!checked_all_rpcs && num_out_pkts == 0 &&
		    num_in_pkts == 0 && num_rpcs == 0) {
			pause("smtreap", 1);
		}
	}

	return !checked_all_rpcs;
}

static struct smt_expected_rpc_ptr
smt_get_rpc(struct smt_inpcb *pcb, struct smt_common_header *header,
	     struct in6_addr *source, int payload_size)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_NOTOWNED(pcb);
	KASSERT(header != NULL, ("header must be valid"));
	KASSERT(source != NULL, ("source must be valid"));

	uint64_t id = smt_local_id(header->sender_id_be);
	bool is_client = smt_is_client(id);
	struct smt_rpc *rpc;
	struct smt_expected_rpc_ptr expected_rpc;

	smt_header_debug(header, "id: %x, is_client: %d", id,
	    smt_is_client(id));

	if (!is_client && header->type == SMT_DATA) {
		/* We are the RPC server and it's a DATA packet */
		MUST_POSITIVE(payload_size);

		expected_rpc = smt_new_server_rpc((struct smt_data_header *) header,
				     pcb, source, payload_size);
		if (!SMT_IS_ERROR(expected_rpc) &&
		    SMT_GET_VAL(expected_rpc) != NULL) {
			VALID_RPC_ASSERT(SMT_GET_VAL(expected_rpc));
			RPC_LOCK_OWNED(SMT_GET_VAL(expected_rpc));
		}
		return expected_rpc;
	}

	rpc = is_client ?
	    smt_find_client_rpc(pcb, id) :
	    smt_find_server_rpc(pcb, source, ntohs(header->sport_be), id);
	if (rpc) {
		VALID_RPC_ASSERT(rpc);
		RPC_LOCK_OWNED(rpc);
	}
	return SMT_MAKE_EXPECTED(struct smt_expected_rpc_ptr, rpc);
}

static bool
smt_preprocess_rpc(struct smt_rpc *rpc, struct smt_common_header *header)
{
	KASSERT(header != NULL, ("header must be valid"));

	if (rpc) {
		VALID_RPC_ASSERT(rpc);
		RPC_LOCK_OWNED(rpc);

		if (header->type == SMT_DATA || header->type == SMT_GRANT ||
		    header->type == SMT_BUSY) {
			rpc->silent_ticks = 0;
		}
		rpc->peer->outstanding_resends = 0;
		return true;

	} else if (header->type != SMT_CUTOFFS &&
	    header->type != SMT_NEED_ACK && header->type != SMT_ACK &&
	    header->type != SMT_RESEND) {
		return false;
	}

	return true;
}

/*
static void
smt_request_retrans(struct smt_rpc *rpc)
{
    struct smt_resend_header resend;


}
*/

static void
smt_need_ack_packet(struct smt_inpcb *pcb, struct smt_rpc *rpc,
    struct smt_common_header *header, struct in6_addr *source)
{
	struct smt_ack_header ack;
	struct smt_peer *peer;
	uint64_t id = smt_local_id(header->sender_id_be);
	int error = 0;

	smt_pcb_unlock(pcb);
	if (rpc != NULL &&
	    (rpc->state != SMT_RPC_INCOMING ||
		rpc->msgin.bytes_remaining > 0)) {
		// TODO: implement this
		// smt_request_retrans(rpc);
		smt_pcb_debug(pcb, "need_ack: request retransmit");
		smt_pcb_lock(pcb);
		return;
	} else {
		peer = smt_find_peer(&pcb->smt->peers, source, &error);
		if (peer == NULL || error != 0) {
			smt_pcb_debug(pcb, "need_ack: failed to find peer: %d",
			    error);
			smt_pcb_lock(pcb);
			return;
		}
	}

	ack.common.type = SMT_ACK;
	ack.common.sport_be = header->dport_be;
	ack.common.dport_be = header->sport_be;
	ack.common.sender_id_be = htobe64(id);
	ack.num_acks_be = htons(
	    smt_peer_get_acks(peer, NUM_PEER_UNACKED_IDS, ack.acks));
	smt_pcb_debug(pcb, "need_ack: send %d acks", ntohs(ack.num_acks_be));

	smt_send_control_buf(pcb, peer, &ack, sizeof(ack));
	smt_peer_put(peer);
	if (rpc) {
		smt_rpc_lock(rpc);
	}
}

static void
smt_ack_packet(struct smt_inpcb *pcb, struct smt_rpc *rpc,
		struct smt_ack_header *header, struct in6_addr *source)
{
	int n = ntohs(header->num_acks_be);

	if (rpc) {
		smt_rpc_free(rpc);
	}

	if (n > 0) {
		if (rpc) {
			smt_rpc_unlock(rpc);
		}

		for (int i = 0; i < n; ++i) {
			smt_rpc_acked(pcb, source, &header->acks[i]);
		}

		if (rpc) {
			smt_rpc_lock(rpc);
		}
	}
}

static void
smt_resend_packet(struct smt_inpcb *pcb, struct smt_rpc *rpc,
		   struct smt_resend_header *header, struct in6_addr *source)
{
	struct smt_busy_header busy;

	int header_offset = ntohl(header->offset_be);
	int header_length = ntohl(header->length_be);
	int offset, length, end;

	if (rpc == NULL) {
		smt_pcb_debug(pcb, "resend_packet: unknown rpc");
		smt_send_unknown(pcb, &header->common, source);
		return;
	}

	offset = header_offset != -1 ? header_offset :
				       ntohl(header->common.sequence_be);
	length = header_length != -1 ? header_length : rpc->msgout.length;
	end = offset + length;

	if ((!smt_is_client(rpc->id) &&
		rpc->state != SMT_RPC_OUTGOING) /* 1. we are the server but
						    don't have a response yet */
	    || (rpc->msgout.next_xmit_offset <
		   rpc->msgout.granted)) /* 2. we chose not send this message */
	{
		smt_pcb_debug(pcb, "resend_packet: send busy");
		smt_rpc_unlock(rpc);
		smt_send_control(rpc, SMT_BUSY, &busy, sizeof(busy));
		smt_rpc_lock(rpc);
		return;
	}

	smt_pcb_debug(pcb, "resend_packet: send data (offset: %d, end: %d)",
	    offset, end);

	smt_rpc_unlock(rpc);
	smt_resend_data(rpc, offset, end, header->priority);
	smt_rpc_lock(rpc);
}

static void
smt_cutoffs_packet(struct smt_inpcb *pcb, struct smt_cutoffs_header *header,
    struct in6_addr *source)
{
	struct smt_peer *peer;
	int i, error;

	peer = smt_find_peer(&pcb->smt->peers, source, &error);
	if (peer == NULL) {
		return;
	}

	peer->unsched_cutoffs[0] = INT_MAX;
	for (i = 1; i < SMT_MAX_PRIORITIES; ++i) {
		peer->unsched_cutoffs[i] = ntohl(header->unsched_cutoffs_be[i]);
	}
	peer->cutoff_version_be = header->cutoff_version_be;
	smt_peer_put(peer);
}

void
smt_handle_packet(struct mbuf *m, struct in6_addr *source,
    struct smt_inpcb *pcb)
{
	KASSERT(m != NULL, ("m must be valid"));
	MBUF_LEN_AT_LEAST(m, sizeof(struct smt_common_header) + pcb->iphlen);
	KASSERT(m->m_flags & M_PKTHDR, ("mbuf must be a header mbuf"));
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_NOTOWNED(pcb);
	KASSERT(source != NULL, ("source must be valid"));

	struct smt_common_header *header = SMT_MTOD(m, struct smt_common_header *, pcb->iphlen);

	KASSERT(header->type >= SMT_DATA && header->type <= SMT_ACK,
	    ("header type must be valid (%#x)", header->type));
	KASSERT(m->m_pkthdr.len >= pcb->iphlen +
		smt_header_lengths[header->type - SMT_DATA],
	    ("mbuf must be at least the size of its type header"));
	KASSERT(m->m_len >= pcb->iphlen + smt_header_lengths[header->type - SMT_DATA],
	    ("mbuf must contain its type header"));

	bool consumed = false;
	bool reap_dead_rpcs;
	struct smt_rpc *rpc = NULL;
	struct smt_expected_rpc_ptr expected_rpc;
	int payload_size = (header->type == SMT_DATA) ? smt_payload_len(m, pcb->iphlen) : -1;
	uint64_t start_cycles = get_cyclecount();

	expected_rpc = smt_get_rpc(pcb, header, source, payload_size);
	if (SMT_IS_ERROR(expected_rpc)) {
		goto smt_handle_packet_error;
	}
	rpc = SMT_GET_VAL(expected_rpc);

	if (rpc) {
		smt_rpc_hold(rpc);

		/* if RPC is encrypted, more data need to be pulled up for the TLS record header */
		if (is_encrypted_rpc(rpc) && header->type == SMT_DATA) {
			int pullup_size = pcb->iphlen + SMT_TLS_DATA_OFFSET;

			smt_rpc_unlock(rpc);
			m = m_pullup(m, pullup_size);
			smt_rpc_lock(rpc);
			if (m == NULL) {
				goto smt_handle_packet_error;
			}
			if (rpc->state == SMT_RPC_DEAD) {
				goto smt_handle_packet_error;
			}
			header = SMT_MTOD(m, struct smt_common_header *,
			    pcb->iphlen);
		}
	}

	if (!smt_preprocess_rpc(rpc, header)) {
		goto smt_handle_packet_error;
	}

	SMT_METRIC(pcb->smt, received_pkts[header->type - SMT_DATA], 1);

	switch (header->type) {
	case SMT_DATA: {
		consumed = smt_data_packet(pcb->smt, m, rpc, pcb, source);
		break;
	}

	case SMT_RESEND:
		smt_resend_packet(pcb, rpc,
		     (struct smt_resend_header *) header, source);
		break;

	case SMT_CUTOFFS:
		smt_cutoffs_packet(pcb,
		      (struct smt_cutoffs_header *) header, source);
		break;

	case SMT_NEED_ACK:
		smt_need_ack_packet(pcb, rpc, header, source);
		break;

	case SMT_ACK:
		smt_ack_packet(pcb, rpc,
		  (struct smt_ack_header *) header, source);
		break;

	case SMT_GRANT:
	case SMT_UNKNOWN:
	case SMT_BUSY:
	case SMT_FREEZE:
		break;

	default:
		KASSERT(0,
		    ("switch statement: header type must be valid (%#x)",
			header->type));
		__unreachable();
	}

	if (rpc) {
		smt_rpc_put(rpc);
		smt_rpc_unlock(rpc);
	}

	smt_pcb_lock(pcb);
	reap_dead_rpcs =
	    pcb->dead_bufs >= 2 * pcb->smt->dead_buffs_limit;
	smt_pcb_unlock(pcb);
	if (reap_dead_rpcs) {
		smt_rpc_reap(pcb, /* reap_all */ false);
	}

	if (!consumed) {
		smt_free_mbuf(m);
	}
	SMT_LATENCY(pcb->smt, lat_handle_packet_cycles,
	    lat_handle_packet_count, start_cycles);
	return;

smt_handle_packet_error:
	if (rpc) {
		smt_rpc_put(rpc);
		smt_rpc_unlock(rpc);
	}
	if (m != NULL) {
		smt_free_mbuf(m);
	}
	SMT_LATENCY(pcb->smt, lat_handle_packet_cycles,
	    lat_handle_packet_count, start_cycles);
}

void
smt_rpc_free(struct smt_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);

	struct smt_inpcb *pcb = rpc->smtcb;

	smt_pcb_lock(pcb);
	smt_rpc_free_locked(rpc);
	smt_pcb_unlock(pcb);
}

void
smt_rpc_free_locked(struct smt_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	PCB_LOCK_OWNED(rpc->smtcb);

	int delta;

	if (rpc->state == SMT_RPC_DEAD) {
		return;
	}

	rpc->state = SMT_RPC_DEAD;
	// TODO: smt_remove_from_grantable

	LIST_REMOVE(rpc, hash_links);
	TAILQ_REMOVE(&rpc->smtcb->active_rpcs, rpc, active_links);
	TAILQ_INSERT_TAIL(&rpc->smtcb->dead_rpcs, rpc, dead_links);
	rpc->smtcb->dead_bufs += rpc->msgin.num_bufs + rpc->msgout.num_bufs;
	if (atomic_load_int(&rpc->is_ready_atomic)) {
		remove_ready_rpc(rpc->smtcb, rpc);
	}
	if (rpc->interest != NULL) {
		struct smt_interest *interest = rpc->interest;

		mtx_lock_spin(&interest->spinlock);
		if (interest->reg_rpc) {
			interest->reg_rpc = NULL;
			smt_rpc_put(rpc);
		}
		rpc->interest = NULL;
		wakeup(&interest->spinlock);
		mtx_unlock_spin(&interest->spinlock);
	}

	delta = (rpc->msgin.total_length < 0) ?
	    0 :
	    (rpc->msgin.incoming -
		(rpc->msgin.total_length - rpc->msgin.bytes_remaining));
	if (delta != 0) {
		atomic_add_64(&rpc->smtcb->smt->total_incoming_atomic, delta);
	}
	// TODO: smt_remove_from_throttled
}
