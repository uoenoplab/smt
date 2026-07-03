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

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/eventhandler.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/sleepqueue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stdint.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif

#include "sdtp.h"
#include "sdtp_ctx.h"
#include "sdtp_debug.h"
#include "sdtp_os.h"
#include "sdtp_output.h"
#include "sdtp_structs.h"

extern struct sdtp *sdtp;
extern struct sdtp_zones zones;

static int
sdtp_msleep_spin_sig(const void *ident, struct mtx *mtx, const char *wmesg)
{
	int error;
	WITNESS_SAVE_DECL(mtx);

	if (SCHEDULER_STOPPED()) {
		return (0);
	}

	sleepq_lock(ident);
	DROP_GIANT();
	mtx_assert(mtx, MA_OWNED | MA_NOTRECURSED);
	WITNESS_SAVE(&mtx->lock_object, mtx);
	mtx_unlock_spin(mtx);

	sleepq_add(ident, &mtx->lock_object, wmesg,
	    SLEEPQ_SLEEP | SLEEPQ_INTERRUPTIBLE, 0);
#ifdef WITNESS
	sleepq_release(ident);
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
	    "Sleeping on \"%s\"", wmesg);
	sleepq_lock(ident);
#endif
	error = sleepq_wait_sig(ident, 0);

	PICKUP_GIANT();
	mtx_lock_spin(mtx);
	WITNESS_RESTORE(&mtx->lock_object, mtx);
	return (error);
}

#ifdef INET

static int
sdtp_attach(struct socket *so, int proto, struct thread *p)
{
	int error;
	struct sdtp_inpcb *inp;

	inp = sdtp_so_pcb(so);
	if (inp != NULL) {
		return EINVAL;
	}

	error = sdtp_inpcb_alloc(so, sdtp);

	if (error == 0) {
		SDTP_METRIC(sdtp, opened_sockets, 1);
	}
	return error;
}

static int
sdtp_register_interest(struct sdtp_interest *interest, struct sdtp_inpcb *pcb,
    int flags, uint64_t id)
{
	bool more_ready;
	int error = 0;
	struct sdtp_rpc *rpc = NULL, *ready_rpc = NULL;

	sdtp_interest_init(interest);
	if (id != 0) {
		if (!sdtp_is_client(id)) {
			error = EINVAL;
			goto sdtp_register_interest_error;
		}

		rpc = sdtp_find_client_rpc(pcb, id);
		if (rpc == NULL) {
			error = EINVAL;
			goto sdtp_register_interest_error;
		}

		sdtp_pcb_lock(pcb);
		if (pcb->shutdown) {
			sdtp_pcb_unlock(pcb);
			error = ESHUTDOWN;
			goto sdtp_register_interest_error;
		}
		if (rpc->state == SDTP_RPC_DEAD ||
		    (rpc->interest != NULL && rpc->interest != interest)) {
			sdtp_pcb_unlock(pcb);
			error = EINVAL;
			goto sdtp_register_interest_error;
		}
		if ((atomic_load_32(&rpc->flags_atomic) & RPC_PKTS_READY) ||
		    rpc->error) {
			ready_rpc = rpc;
			if (atomic_load_int(&rpc->is_ready_atomic)) {
				remove_ready_rpc(pcb, rpc);
			}
			goto sdtp_register_interest_claim_locked_rpc;
		}

		rpc->interest = interest;
		interest->reg_rpc = rpc;
		sdtp_rpc_hold(rpc);
		sdtp_pcb_unlock(pcb);
		sdtp_rpc_unlock(rpc);
		return 0;
	}

retry_generic:
	sdtp_pcb_lock(pcb);
	if (pcb->shutdown) {
		sdtp_pcb_unlock(pcb);
		return ESHUTDOWN;
	}

	if (flags & SDTP_RECVMSG_RESPONSE) {
		sdtp_pcb_debug(pcb, "Check if there are response RPCs");
		if (!LIST_EMPTY(&pcb->ready_responses)) {
			sdtp_pcb_debug(pcb,
			    "There are response RPCs in PCB list");
			ready_rpc = LIST_FIRST(&pcb->ready_responses);
		}
	}
	if (ready_rpc == NULL && (flags & SDTP_RECVMSG_REQUEST)) {
		sdtp_pcb_debug(pcb, "Check if there are request RPCs");
		if (!LIST_EMPTY(&pcb->ready_requests)) {
			sdtp_pcb_debug(pcb,
			    "There are request RPCs in PCB list");
			ready_rpc = LIST_FIRST(&pcb->ready_requests);
		}
	}

	if (ready_rpc != NULL) {
		if (!mtx_trylock_spin(ready_rpc->spinlock_p)) {
			sdtp_pcb_unlock(pcb);
			pause("sdtpclaim", 1);
			ready_rpc = NULL;
			goto retry_generic;
		}
		if (ready_rpc->state == SDTP_RPC_DEAD ||
		    !atomic_load_int(&ready_rpc->is_ready_atomic)) {
			sdtp_rpc_unlock(ready_rpc);
			sdtp_pcb_unlock(pcb);
			ready_rpc = NULL;
			goto retry_generic;
		}
		remove_ready_rpc(pcb, ready_rpc);
		goto sdtp_register_interest_claim_locked_rpc;
	}

	if (flags & SDTP_RECVMSG_RESPONSE) {
		insert_response_interest(pcb, interest);
	}
	if (flags & SDTP_RECVMSG_REQUEST) {
		insert_request_interest(pcb, interest);
	}
	sdtp_pcb_unlock(pcb);
	return 0;

sdtp_register_interest_claim_locked_rpc:
	atomic_set_32(&ready_rpc->flags_atomic, RPC_HANDING_OFF);
	sdtp_rpc_hold(ready_rpc);
	atomic_store_rel_ptr(&interest->ready_rpc_atomic,
	    (uintptr_t)ready_rpc);
	more_ready = !LIST_EMPTY(&pcb->ready_requests) ||
	    !LIST_EMPTY(&pcb->ready_responses);
	sdtp_pcb_unlock(pcb);
	sdtp_rpc_unlock(ready_rpc);
	if (more_ready) {
		sdtp_sorwakeup(pcb);
	}
	return 0;

sdtp_register_interest_error:
	if (rpc) {
		sdtp_rpc_unlock(rpc);
	}
	return error;
}

#define MAX_BUFS 20

static int
sdtp_collect_bufs(struct sdtp_rpc *rpc, struct mbuf *bufs[MAX_BUFS], int iphlen)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	MUST_POSITIVE(iphlen);

	int n = 0, segment_offset = 0;
	struct sdtp_packet_tailq_entry *entry;
	struct sdtp_data_header *header;
	struct mbuf *m;

	for (int i = 0; i < MAX_BUFS; ++i) {
		if (rpc->msgin.copied_out >= rpc->msgin.total_length) {
			break;
		}

		entry = TAILQ_FIRST(&rpc->msgin.packets);
		if (entry == NULL) {
			break;
		}

		m = entry->data;

		KASSERT(m->m_flags & M_PKTHDR, ("buf must have packet header"));
		KASSERT(m->m_pkthdr.len >= sizeof(struct sdtp_data_header) + iphlen,
			("buf %d (size: %d) must contain within its mbuf chain the headers\n",
			n, m->m_pkthdr.len));
		KASSERT(m->m_len >= sizeof(struct sdtp_data_header) + iphlen,
			("buf %d (size: %d) must be the headers\n", n, m->m_len));

		header = SDTP_MTOD(m, struct sdtp_data_header *, iphlen);
		segment_offset = ntohl(header->data_segment.offset_be);

		if (rpc->msgin.copied_out < segment_offset) {
			break;
		}

		bufs[n++] = m;
		TAILQ_REMOVE(&rpc->msgin.packets, entry, link);
		sdtp_pool_free_packet_tailq_entry(entry);

		--rpc->msgin.num_bufs;
		rpc->msgin.copied_out = segment_offset + sdtp_payload_len(m, iphlen);
	}

	MUST_NOT_NEGATIVE(n);
	return (n);
}

static int
__sdtp_copy_to_user(struct uio *uio, struct sdtp_rpc *rpc, struct mbuf *bufs[MAX_BUFS], int n, int iphlen)
{
	KASSERT(uio != 0, ("uio must be valid"));
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	KASSERT(!(rpc->flags_atomic & RPC_COPYING_TO_USER), ("RPC_COPYING_TO_USER flag must be off"));
	MUST_POSITIVE(n);
	MUST_POSITIVE(iphlen);

	int error = 0, rem, buf_header_rem;
	struct mbuf *m;
	struct sdtp_data_header *header;

	atomic_set_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);
	sdtp_rpc_unlock(rpc);

	for (int i = 0; i < n; ++i) {
		m = bufs[i];

		KASSERT(m->m_len >= sizeof(struct sdtp_data_header) + iphlen,
			("buf %d (%d) must contain the size of headers\n",
			n, m->m_len));

		header = SDTP_MTOD(m, struct sdtp_data_header *, iphlen);
		rem = sdtp_payload_len(m, iphlen);
		buf_header_rem = m->m_len - sizeof(*header) - iphlen;
		MUST_POSITIVE(rem);
		MUST_POSITIVE(buf_header_rem);

		error = uiomove((char *)(header + 1), buf_header_rem, uio);
		if (error != 0) {
			break;
		}

		rem -= buf_header_rem;
		m = m->m_next;
		for (; m != NULL && uio->uio_resid > 0 && rem > 0; m = m->m_next) {
			int len = min(m->m_len, uio->uio_resid);
			len = min(len, rem);

			sdtp_rpc_debug(rpc, "copying %d length to userspace", len);
			error = uiomove(mtod(m, char *), len, uio);
			if (error) {
				break;
			}
			sdtp_rpc_debug(rpc, "uio->uio_resid: %d, len: %d, rem: %d\n", uio->uio_resid, len, rem);
			rem -= len;
		}
		if (error) {
			break;
		}

		KASSERT(uio->uio_resid == 0 || rem == 0, ("uio_resid (%zd) or rem (%d) must be 0",
			uio->uio_resid, rem));
		SDTP_METRIC(rpc->sdtpcb->sdtp, recv_pkts_atomic, 1);
	}

	for (int i = 0; i < n; ++i) {
		// TODO: buffer should be free'd here?
		// TODO: sdtp_handle_acks(rpc, bufs[i]);
		sdtp_free_mbuf(bufs[i]);
		SDTP_METRIC(rpc->sdtpcb->sdtp, freed_recv_pkts_atomic, 1);
	}

	sdtp_rpc_lock(rpc);
	atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);

	return (error);
}

static int
sdtp_copy_to_user(struct uio *uio, struct sdtp_rpc *rpc)
{
	MUST_POSITIVE(rpc->msgin.num_bufs);

	int error = 0, n = 0, iphlen = rpc->sdtpcb->iphlen;
	struct mbuf *bufs[MAX_BUFS];
	uint64_t start_cycles = get_cyclecount();

	while (true) {
		n = sdtp_collect_bufs(rpc, bufs, iphlen);
		if (n == 0) {
			break;
		}

		error = __sdtp_copy_to_user(uio, rpc, bufs, n, iphlen);
		if (error != 0) {
			break;
		}
	}

	SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_copy_to_user_cycles,
	    lat_copy_to_user_count, start_cycles);
	return (error);
}

static int
sdtp_get_record_entries(struct sdtp_rpc *rpc, struct sdtp_packet_tailq_entry *entries[MAX_BUFS],
		     int rec_start, int rec_len)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	MUST_NOT_NEGATIVE(rec_start);
	MUST_POSITIVE(rec_len);

	struct sdtp_packet_tailq_entry *entry;
	struct sdtp_rx_logical_info *rx_info;
	int n = 0, seg_end = rec_start;

	TAILQ_FOREACH(entry, &rpc->msgin.packets, link) {
		rx_info = &entry->rx_info;

		if (rx_info->start != seg_end) {
			sdtp_rpc_debug(rpc, "rx_info->start: %d, seg_end: %d",
				rx_info->start, seg_end);
			break;
		}
		++n;
		seg_end = rx_info->end;
		if (seg_end - rec_start >= rec_len) {
			break;
		}
	}

	if (seg_end - rec_start < rec_len) {
		sdtp_rpc_debug(rpc, "seg_len: %d, rec_len: %d",
			seg_end - rec_start, rec_len);
		return (0);
	}
	if (n > MAX_BUFS) {
		return (-EINVAL);
	}

	for (int i = 0; i < n; ++i) {
		entries[i] = TAILQ_FIRST(&rpc->msgin.packets);
		TAILQ_REMOVE(&rpc->msgin.packets, entries[i], link);
	}
	rpc->msgin.copied_out = rec_start + rec_len;

	return (n);
}

static int
sdtp_get_record_window(struct sdtp_rpc *rpc, int *rec_start, int *rec_end)
{
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);

	struct sdtp_packet_tailq_entry *entry;
	struct sdtp_rx_logical_info *rx_info;

	entry = TAILQ_FIRST(&rpc->msgin.packets);
	if (entry == NULL) {
		sdtp_rpc_debug(rpc, "failed to get entry");
		return (-1);
	}

	rx_info = &entry->rx_info;
	sdtp_debug_rx_info(rpc, rx_info);

	if (rx_info->record_data_offset == -1
	    || rx_info->record_data_offset > rpc->crypto.offset) {

		sdtp_rpc_debug(rpc, "%s: rx info incorrect: record_data_offset: %d, rpc offset: %d",
			__func__, rx_info->record_data_offset, rpc->crypto.offset);
		return (-1);
	}

	*rec_start = rx_info->record_data_offset;
	*rec_end = rx_info->record_data_len;
	return (0);
}

static int
__sdtp_ctx_copy_to_user(struct uio *uio, struct sdtp_rpc *rpc, struct sdtp_packet_tailq_entry *entries[MAX_BUFS], int n, int trailer_len)
{
	KASSERT(uio != 0, ("uio must be valid"));
	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	KASSERT(!(rpc->flags_atomic & RPC_COPYING_TO_USER), ("RPC_COPYING_TO_USER flag must be off"));
	MUST_POSITIVE(n);
	KASSERT(n < MAX_BUFS, ("n (%d) must be less than MAX_BUFS (%d)", n, MAX_BUFS));
	KASSERT(entries != NULL && *entries != NULL, ("entries must be valid"));
	MUST_NOT_NEGATIVE(trailer_len);

	struct mbuf *m = entries[0]->data;
	KASSERT(m->m_flags & M_PKTHDR, ("m must be a packet header"));

	struct sdtp_rx_logical_info *rx_info = &entries[0]->rx_info;
	int error = 0, offset, rem, pre_len, post_len;

	atomic_set_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);
	sdtp_rpc_unlock(rpc);

	pre_len = sdtp_pre_len(rpc);
	post_len = sdtp_post_len(rpc);
	rem = rx_info->record_data_len;
	offset = pre_len;
	for (int i = 0; i < n; ++i) {
		int seg_rem = entries[i]->rx_info.length;
		if (i == 0) {
			seg_rem += trailer_len;
		} else if (i == n - 1) {
			seg_rem -= trailer_len;
		}

		sdtp_rpc_debug(rpc, "seg_rem: %d, trailer_len: %d, pre_len: %d post_len: %d, offset: %d, rem: %d",
			seg_rem, trailer_len, pre_len, post_len, offset, rem);

		offset += sizeof(struct sdtp_data_segment);
		while (seg_rem > 0 && m != NULL && uio->uio_resid > 0) {
			int mlen = m->m_len;
			if (m->m_next == NULL) {
				mlen -= post_len;
			}
			MUST_POSITIVE(mlen);
			sdtp_rpc_debug(rpc, "mlen: %d, offset: %d, uio->uio_resid: %d, rem: %d, seg_rem: %d",
		  mlen, offset, uio->uio_resid, rem, seg_rem);

			int len = min(mlen - offset, uio->uio_resid);
			len = min(len, rem);
			len = min(len, seg_rem);
			MUST_POSITIVE(len);

			error = uiomove(SDTP_MTOD(m, char *, offset), len, uio);
			if (error) {
				goto __sdtp_ctx_copy_to_user_out;
			}

			rem -= len;
			seg_rem -= len;
			offset += len;
			KASSERT(offset <= mlen, ("offset must be less than mlen: %d < %d", offset, mlen));
			if (mlen == offset) {
				m = m->m_next;
				offset = 0;
			}
		}
	}

	KASSERT(uio->uio_resid == 0 || rem == 0, ("uio_resid (%zd) or rem (%d) must be 0", uio->uio_resid, rem));
	// SDTP_METRIC(rpc->sdtpcb->sdtp, recv_pkts_atomic, 1);

__sdtp_ctx_copy_to_user_out:
	// TODO: buffer should be free'd here?
	// TODO: sdtp_handle_acks(rpc, bufs[i]);
	sdtp_free_mbuf(entries[0]->data);
	// SDTP_METRIC(rpc->sdtpcb->sdtp, freed_recv_pkts_atomic, 1);

	sdtp_rpc_lock(rpc);
	atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);

	return (error);
}

static void
sdtp_free_entries(struct sdtp_packet_tailq_entry *entries[MAX_BUFS], int n)
{
	for (int i = 0; i < n; ++i) {
		sdtp_pool_free_packet_tailq_entry(entries[i]);
	}
}

static int
sdtp_ctx_copy_to_user(struct uio *uio, struct sdtp_rpc *rpc)
{
	MUST_POSITIVE(rpc->msgin.num_bufs);

	int error = 0, iphlen = rpc->sdtpcb->iphlen, rec_start = -1, rec_len = -1, n = 0;
	int trailer_len = -1;
	struct sdtp_packet_tailq_entry *entries[MAX_BUFS];
	uint64_t start_cycles = get_cyclecount();

	while (true) {
		if (sdtp_get_record_window(rpc, &rec_start, &rec_len)) {
			sdtp_rpc_debug(rpc, "failed to get window");
			break;
		}

		n = sdtp_get_record_entries(rpc, entries, rec_start, rec_len);
		if (n <= 0) {
			error = -n;
			n = 0;
			sdtp_rpc_debug(rpc, "failed to get records: %d", error);
			break;
		}

		for (int i = 0; i < n; ++i) {
			sdtp_debug_mbuf(rpc, entries[i]->data);
		}
		error = sdtp_ctx_decrypt(rpc, iphlen, entries, n, &trailer_len);
		if (error != 0) {
			sdtp_rpc_debug(rpc, "failed decryption");
			break;
		}
		MUST_NOT_NEGATIVE(trailer_len);

		sdtp_debug_mbuf(rpc, entries[0]->data);
		error = __sdtp_ctx_copy_to_user(uio, rpc, entries, n, trailer_len);
		if (error != 0) {
			sdtp_rpc_debug(rpc, "failed copy to user");
			break;
		}

		sdtp_free_entries(entries, n);
		n = 0;
	}

	sdtp_free_entries(entries, n);
	SDTP_LATENCY(rpc->sdtpcb->sdtp, lat_copy_to_user_cycles,
	    lat_copy_to_user_count, start_cycles);
	return (error);
}

static void
sdtp_unregister_interest(struct sdtp_inpcb *pcb,
    struct sdtp_interest *interest)
{
	struct sdtp_rpc *rpc = interest->reg_rpc;

	if (rpc != NULL) {
		sdtp_rpc_lock(rpc);
	}
	sdtp_pcb_lock(pcb);
	if (rpc != NULL && interest->reg_rpc == rpc &&
	    rpc->interest == interest) {
		rpc->interest = NULL;
		interest->reg_rpc = NULL;
		sdtp_rpc_put(rpc);
	}
	if (atomic_load_int(&interest->is_response_atomic)) {
		remove_response_interest(pcb, interest);
	}
	if (atomic_load_int(&interest->is_request_atomic)) {
		remove_request_interest(pcb, interest);
	}
	sdtp_pcb_unlock(pcb);
	if (rpc != NULL) {
		sdtp_rpc_unlock(rpc);
	}
}

static struct sdtp_rpc *
sdtp_wait_for_message(struct sdtp_inpcb *pcb, int flags, uint64_t id,
    struct uio *uio, int *error)
{
	struct sdtp_rpc *rpc = NULL;
	struct sdtp_interest interest;
	uint64_t poll_start, now;
	uint64_t start_cycles = get_cyclecount();
	int sleep_error, more_rpcs_to_reap = true;

	while (1) {
		sdtp_pcb_debug(pcb, "check if there is waiting interest");
		*error = sdtp_register_interest(&interest, pcb, flags, id);
		rpc = (struct sdtp_rpc *)atomic_load_ptr(
		    &interest.ready_rpc_atomic);
		if (rpc != NULL || *error != 0) {
			goto sdtp_wait_for_message_found_rpc;
		}

		while (more_rpcs_to_reap) {
			rpc = (struct sdtp_rpc *)atomic_load_ptr(
			    &interest.ready_rpc_atomic);
			if (rpc != NULL) {
				goto sdtp_wait_for_message_found_rpc;
			}

			more_rpcs_to_reap = sdtp_rpc_reap(pcb,
			    /* reap_all */ false);
		}

		if (flags & SDTP_RECVMSG_NONBLOCKING) {
			*error = EAGAIN;
			goto sdtp_wait_for_message_found_rpc;
		}

		poll_start = now = get_cyclecount();
		sdtp_pcb_debug(pcb, "spin and check");
		while (1) {
			rpc = (struct sdtp_rpc *)atomic_load_ptr(
			    &interest.ready_rpc_atomic);
			if (rpc) {
				goto sdtp_wait_for_message_found_rpc;
			}

			if (pcb->sdtp->poll_cycles == 0 ||
			    now - poll_start >= pcb->sdtp->poll_cycles) {
				break;
			}

			cpu_spinwait();
			now = get_cyclecount();
		}

		sdtp_pcb_debug(pcb, "going to sleep with thread: %#x",
		    interest.thread);
		sdtp_pcb_debug(pcb, "sleep channel: %#x", &interest.spinlock);
		mtx_assert(&interest.spinlock, MA_NOTOWNED);

		mtx_lock_spin(&interest.spinlock);
		rpc = (struct sdtp_rpc *)atomic_load_ptr(
		    &interest.ready_rpc_atomic);
		if (rpc == NULL && !pcb->shutdown) {
			sleep_error = sdtp_msleep_spin_sig(&interest.spinlock,
			    &interest.spinlock, "sdtp_recv");
			sdtp_pcb_debug(pcb, "sleep result: %d", sleep_error);
			rpc = (struct sdtp_rpc *)atomic_load_ptr(
			    &interest.ready_rpc_atomic);
			if (rpc != NULL) {
				INTEREST_NOT_LINKED(&interest);
			} else if (sleep_error != 0) {
				*error = sleep_error;
			}
		}
		mtx_unlock_spin(&interest.spinlock);
		sdtp_pcb_debug(pcb, "waking up");

	sdtp_wait_for_message_found_rpc:
		sdtp_unregister_interest(pcb, &interest);
		mtx_destroy(&interest.spinlock);

		rpc = (struct sdtp_rpc *)atomic_load_ptr(
		    &interest.ready_rpc_atomic);
		sdtp_pcb_debug(pcb, "new rpc after waking: %llu",
		    (uintptr_t)rpc);
		if (rpc == NULL && *error != 0) {
			SDTP_LATENCY(pcb->sdtp, lat_wait_for_message_cycles,
			    lat_wait_for_message_count, start_cycles);
			return (NULL);
		}
		if (rpc) {
			*error = 0;
			sdtp_rpc_lock(rpc);

			RPC_REFS_ASSERT(rpc, 1);
			// We are holding the reference from
			// interest.ready_rpc_atomic sdtp_rpc_hold(rpc);

			atomic_clear_32(&rpc->flags_atomic, RPC_HANDING_OFF);
			if (rpc->state == SDTP_RPC_DEAD) {
				sdtp_rpc_unlock(rpc);
				sdtp_rpc_put(rpc);
				sdtp_pcb_debug(pcb, "dead RPC");
				continue;
			}

			if (rpc->error == 0 && rpc->msgin.num_bufs > 0) {
				sdtp_pcb_debug(pcb, "copy to user");
				rpc->error = (is_encrypted_rpc(rpc))
					? sdtp_ctx_copy_to_user(uio, rpc)
					: sdtp_copy_to_user(uio, rpc);
			}
			if (rpc->error != 0) {
				goto sdtp_wait_for_message_done;
			}

			atomic_clear_32(&rpc->flags_atomic, RPC_PKTS_READY);

			sdtp_rpc_debug(rpc,
			    "rpc->msgin.copied_out: %d, rpc->msgin.total_length: %d",
			    rpc->msgin.copied_out, rpc->msgin.total_length);
			if (rpc->msgin.copied_out == rpc->msgin.total_length) {
				SDTP_METRIC(rpc->sdtpcb->sdtp, recv_rpcs_atomic, 1);
				SDTP_LATENCY(rpc->sdtpcb->sdtp,
				    lat_rpc_lifetime_cycles,
				    lat_rpc_lifetime_count, rpc->start_cycles);
				goto sdtp_wait_for_message_done;
			}
			sdtp_rpc_put(rpc);
			sdtp_rpc_unlock(rpc);
		}
	}

sdtp_wait_for_message_done:
	SDTP_LATENCY(pcb->sdtp, lat_wait_for_message_cycles,
	    lat_wait_for_message_count, start_cycles);
	return rpc;
}

static struct mbuf *
sdtp_fill_rcv_control(struct sdtp_rpc *rpc, struct mbuf *buf)
{
	struct cmsghdr *header;

	VALID_RPC_ASSERT(rpc);
	RPC_LOCK_OWNED(rpc);
	MBUF_LEN_AT_LEAST(buf, CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)));

	header = mtod(buf, struct cmsghdr *);
	memset(header, 0, CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)));

	header->cmsg_len = CMSG_LEN(sizeof(struct sdtp_recvmsg_args));
	header->cmsg_level = IPPROTO_SDTP;
	header->cmsg_type = 1; // placeholder

	struct sdtp_recvmsg_args *args = (struct sdtp_recvmsg_args *)CMSG_DATA(
	    header);
	args->id = rpc->id;
	args->completion_cookie = rpc->completion_cookie;
	if (rpc->msgin.total_length >= 0) {
		args->num_bpages = rpc->msgin.num_bpages;
		memcpy(args->bpage_offsets, rpc->msgin.bpage_offsets,
		    sizeof(args->bpage_offsets));
	}

	return buf;
}

static void
sdtp_fill_sockaddr(struct sdtp_rpc *rpc, struct sockaddr_in *sin)
{
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_port = htons(rpc->dport);
	ipv6_to_ipv4(&rpc->peer->addr, &sin->sin_addr);
}

static void
sdtp_fill_sockaddr6(struct sdtp_rpc *rpc, struct sockaddr_in6 *sin)
{
	sin->sin6_family = AF_INET6;
	sin->sin6_len = sizeof(struct sockaddr_in6);
	sin->sin6_port = htons(rpc->dport);
	sin->sin6_addr = rpc->peer->addr;
}

// TODO: read options through controlp, but controlp is NULL? Maybe setsockopt()
// is better
static int
sdtp_soreceive(struct socket *so, struct sockaddr **psa, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	int res = 0, family = so->so_proto->pr_domain->dom_family;
	struct sdtp_inpcb *inp;
	struct sdtp_rpc *rpc = NULL;
	struct mbuf *control_buf = NULL;
	uint8_t sockbuf[256];

	inp = sdtp_so_pcb(so);
	if (inp == NULL) {
		return EINVAL;
	}

	if (controlp != NULL) {
		KASSERT(CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)) <= MLEN,
		    ("control msg header + sdtp_recvmsg_args size (%lu) should be less than MHLEN %d",
			CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)), MLEN));

		control_buf = m_get2(CMSG_SPACE(
					 sizeof(struct sdtp_recvmsg_args)),
		    M_NOWAIT, MT_DATA, 0);
		if (!control_buf) {
			res = ENOBUFS;
			goto sdtp_soreceive_done;
		}

		control_buf->m_len = CMSG_SPACE(
		    sizeof(struct sdtp_recvmsg_args));
	}

	// TODO: we don't use sdtp_pool_release_bpages?

	rpc = sdtp_wait_for_message(inp, (flagsp != NULL) ? *flagsp : 0, 0, uio,
	    &res);
	if (res) {
		goto sdtp_soreceive_done;
	}

	// TODO: freeze_type = SLOW_RPC

	if (controlp != NULL) {
		*controlp = sdtp_fill_rcv_control(rpc, control_buf);
	}
	if (psa != NULL) {
		switch (family) {
		case AF_INET: {
			sdtp_fill_sockaddr(rpc, (struct sockaddr_in *)sockbuf);
			break;
		}
		case AF_INET6: {
			sdtp_fill_sockaddr6(rpc,
			    (struct sockaddr_in6 *)sockbuf);
			break;
		}
		default: {
			res = EAFNOSUPPORT;
			goto sdtp_soreceive_done;
		}
		}
	}

sdtp_soreceive_done:
	if (rpc) {
		rpc->msgin.num_bufs = 0;

		if (sdtp_is_client(rpc->id)) {
			sdtp_peer_ack(rpc);
			sdtp_rpc_free(rpc);
		} else {
			if (res >= 0) {
				rpc->state = SDTP_RPC_IN_SERVICE;
			} else {
				sdtp_rpc_free(rpc);
			}
		}
		sdtp_rpc_put(rpc);
		sdtp_rpc_unlock(rpc);
	}
	if (control_buf != NULL && res != 0) {
		m_freem(control_buf);
		*controlp = NULL;
	}
	if (psa != NULL) {
		*psa = (res == 0) ?
		    sodupsockaddr((struct sockaddr *)sockbuf, M_NOWAIT) :
		    NULL;
	}
	return res;
}

static void
sdtp_close(struct socket *so)
{
	struct sdtp_inpcb *pcb;

	pcb = sdtp_so_pcb(so);
	KASSERT(pcb != NULL, ("pcb must be valid"));

	sdtp_inpcb_shutdown(pcb);
	SDTP_METRIC(sdtp, closed_sockets, 1);
}

static void
sdtp_detach(struct socket *so)
{
	struct sdtp_inpcb *pcb;

	pcb = sdtp_so_pcb(so);
	KASSERT(pcb != NULL, ("pcb must be valid"));

	if (!pcb->shutdown) {
		sdtp_inpcb_shutdown(pcb);
		SDTP_METRIC(sdtp, closed_sockets, 1);
	}
	sdtp_pcb_free(pcb);
	SDTP_METRIC(sdtp, destroyed_sockets, 1);
}

static int
sdtp_bind(struct socket *so, struct sockaddr *addr, struct thread *p)
{
	struct sdtp_inpcb *inp;
	uint16_t port;

	inp = sdtp_so_pcb(so);
	if (inp == NULL) {
		return EINVAL;
	}

	if (addr == NULL) {
		return EINVAL;
	}

	if (addr->sa_family != so->so_proto->pr_domain->dom_family) {
		return EAFNOSUPPORT;
	}

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		port = ntohs(sin->sin_port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		port = ntohs(sin6->sin6_port);
		break;
	}
	default:
		return EAFNOSUPPORT;
	}

	return sdtp_inpcb_bind(&inp->sdtp->port_map, port, inp);
}

static struct sdtp_sendmsg_args *
sdtp_read_control_buf(struct mbuf *buf)
{
	struct cmsghdr *cmsg;

	if (buf == NULL || buf->m_len < sizeof(struct cmsghdr)) {
		return NULL;
	}

	cmsg = mtod(buf, struct cmsghdr *);

	if (cmsg->cmsg_level != IPPROTO_SDTP) {
		return NULL;
	}
	if (cmsg->cmsg_len > buf->m_len ||
	    cmsg->cmsg_len < CMSG_LEN(sizeof(struct sdtp_sendmsg_args))) {
		return NULL;
	}

	return (struct sdtp_sendmsg_args *)CMSG_DATA(cmsg);
}

static int
sdtp_send_request(struct sdtp_inpcb *pcb, struct uio *uio,
    struct sockaddr *sockaddr, struct sdtp_sendmsg_args *args)
{
	int error = 0;
	struct sdtp_rpc *rpc = NULL;
	struct in6_addr addr;
	uint16_t port;

	switch (sockaddr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;
		addr = ipv4_to_ipv6(&sin->sin_addr);
		port = ntohs(sin->sin_port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;
		addr = sin6->sin6_addr;
		port = ntohs(sin6->sin6_port);
		break;
	}
	default: {
		error = EAFNOSUPPORT;
		goto sdtp_send_request_error;
	}
	}

	rpc = sdtp_new_client_rpc(pcb, &addr, port, &error);
	if (rpc == NULL || error != 0) {
		goto sdtp_send_request_error;
	}
	sdtp_rpc_hold(rpc);

	// TODO: args flags & HOMA_SENDMSG_PRIVATE

	rpc->completion_cookie = args->completion_cookie;
	error = sdtp_message_out(rpc, uio, true);
	if (error != 0) {
		goto sdtp_send_request_error;
	}
	args->id = rpc->id;
	sdtp_rpc_put(rpc);
	sdtp_rpc_unlock(rpc);

	// copy msg control to user

	return 0;

sdtp_send_request_error:
	if (rpc) {
		sdtp_rpc_free(rpc);

		sdtp_rpc_put(rpc);
		sdtp_rpc_unlock(rpc);
	}
	return error;
}

static int
sdtp_send_response(struct sdtp_inpcb *pcb, struct uio *uio,
    struct sockaddr *sockaddr, struct sdtp_sendmsg_args *args)
{
	int error = 0;
	struct sdtp_rpc *rpc = NULL;
	struct in6_addr addr;
	uint16_t port;

	if (args->completion_cookie != 0) {
		error = EINVAL;
		goto sdtp_send_response_error;
	}

	switch (sockaddr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;
		addr = ipv4_to_ipv6(&sin->sin_addr);
		port = ntohs(sin->sin_port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;
		addr = sin6->sin6_addr;
		port = ntohs(sin6->sin6_port);
		break;
	}
	default: {
		error = EAFNOSUPPORT;
		goto sdtp_send_response_error;
	}
	}

	rpc = sdtp_find_server_rpc(pcb, &addr, port, args->id);
	if (!rpc) {
		/* valid output */
		return 0;
	}
	sdtp_rpc_hold(rpc);

	if (rpc->error) {
		error = rpc->error;
		goto sdtp_send_response_error;
	}

	if (rpc->state != SDTP_RPC_IN_SERVICE) {
		error = EINVAL;
		goto sdtp_send_response_error_no_free_rpc;
	}

	sdtp_rpc_debug(rpc, "sending response");

	rpc->state = SDTP_RPC_OUTGOING;
	// TODO: implement homals part
	error = sdtp_message_out(rpc, uio, true);
	if (error) {
		goto sdtp_send_response_error;
	}

	sdtp_rpc_put(rpc);
	sdtp_rpc_unlock(rpc);
	return 0;

sdtp_send_response_error:
	if (rpc != NULL) {
		sdtp_rpc_free(rpc);
	}

sdtp_send_response_error_no_free_rpc:
	if (rpc != NULL) {
		sdtp_rpc_put(rpc);
		sdtp_rpc_unlock(rpc);
	}
	return error;
}

static int
sdtp_sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags, struct thread *p)
{
	KASSERT(uio != NULL, ("uio must be valid"));
	KASSERT(top == NULL, ("top must be null"));

	int error = 0;
	struct sdtp_inpcb *pcb = NULL;
	struct sdtp_sendmsg_args *args;
	uint64_t start_cycles = get_cyclecount();

	sdtp_debug("sosend\n");

	pcb = sdtp_so_pcb(so);
	if (pcb == NULL) {
		sdtp_debug("invalid pcb\n");
		error = EINVAL;
		goto sdtp_sosend_error;
	}

	args = sdtp_read_control_buf(control);
	if (args == NULL) {
		sdtp_debug("invalid control\n");
		error = EINVAL;
		goto sdtp_sosend_error;
	}

	if (addr->sa_family != so->so_proto->pr_domain->dom_family) {
		sdtp_debug(
		    "not supported addr family, addr->sa_family: %d, so->dom_family: %d\n",
		    addr->sa_family, so->so_proto->pr_domain->dom_family);
		error = EAFNOSUPPORT;
		goto sdtp_sosend_error;
	}

	if ((addr->sa_len < sizeof(struct sockaddr_in)) ||
	    ((addr->sa_len < sizeof(struct sockaddr_in6)) &&
		(addr->sa_family == AF_INET6))) {
		sdtp_debug("invalid addr\n");
		error = EINVAL;
		goto sdtp_sosend_error;
	}

	if (args->id == 0) {
		error = sdtp_send_request(pcb, uio, addr, args);
	} else {
		error = sdtp_send_response(pcb, uio, addr, args);
	}

	if (error != 0) {
		goto sdtp_sosend_error;
	}

sdtp_sosend_error:
	if (control != NULL) {
		sdtp_free_mbuf(control);
	}

	if (pcb != NULL) {
		SDTP_LATENCY(pcb->sdtp, lat_sosend_cycles,
		    lat_sosend_count, start_cycles);
	} else {
		SDTP_LATENCY(sdtp, lat_sosend_cycles, lat_sosend_count,
		    start_cycles);
	}
	return error;
}

static int
sdtp_setsockopt(struct sdtp_inpcb *pcb, struct sockopt *sopt)
{
	VALID_PCB_ASSERT(pcb);

	int error = 0;

	if (sopt->sopt_level != IPPROTO_SDTP) {
		return ENOPROTOOPT;
	}

	switch (sopt->sopt_name) {
	case SDTP_TXTLS_ENABLE:
	case SDTP_RXTLS_ENABLE:
		error = sdtp_ctx_enable(pcb, sopt,
		    sopt->sopt_name == SDTP_TXTLS_ENABLE);
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	return error;
}

static int
sdtp_getsockopt(void)
{
	return ENOPROTOOPT;
}

static int
sdtp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	struct sdtp_inpcb *pcb = sdtp_so_pcb(so);

	VALID_PCB_ASSERT(pcb);

	// TODO: lock pcb here?
	if (sopt->sopt_level != so->so_proto->pr_protocol) {
#ifdef INET6
		if (INP_CHECK_SOCKAF(so, AF_INET6)) {
			error = ip6_ctloutput(so, sopt);
		}
#endif
#if defined(INET) && defined(INET6)
		else
#endif
#ifdef INET
		{
			error = ip_ctloutput(so, sopt);
		}
#endif
		return (error);
	}

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		error = sdtp_setsockopt(pcb, sopt);
		break;

	case SOPT_GET:
		error = sdtp_getsockopt();
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	return error;
}

struct protosw sdtp_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_attach = sdtp_attach,
	.pr_soreceive = sdtp_soreceive,
	.pr_bind = sdtp_bind,
	.pr_close = sdtp_close,
	.pr_sosend = sdtp_sosend,
	.pr_ctloutput = sdtp_ctloutput,
	.pr_detach =	sdtp_detach,
	/*
	.pr_connect =	sdtp_connect,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_control =	sdtp_control,
	.pr_detach =	sctp_close,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	*/
};

#endif
#ifdef INET6

struct protosw sdtp6_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_attach = sdtp_attach,
	.pr_soreceive = sdtp_soreceive,
	.pr_bind = sdtp_bind,
	.pr_close = sdtp_close,
	.pr_sosend = sdtp_sosend,
	.pr_ctloutput = sdtp_ctloutput,
	.pr_detach =	sdtp_detach,
	/*
	.pr_connect =	sdtp_connect,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_control =	sdtp_control,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	*/
};

#endif
