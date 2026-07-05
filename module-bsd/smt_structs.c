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

#include "smt.h"
#include "smt_ctx.h"
#include "smt_debug.h"
#include "smt_os.h"
#include "smt_structs.h"

#ifdef SMT_TEST
#include "smt_test.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/socketvar.h>

#include <machine/atomic.h>
#include <machine/cpu.h>

#ifdef SMT_TEST
struct smt_test_state test_state;
#endif

MALLOC_DEFINE(M_SMT_PEERMAP, "smt peermap", "SMT peermap buckets");
DPCPU_DEFINE(struct smt_core, smt_cores);
struct smt_zones zones;

int smt_header_lengths[] = {
	sizeof(struct smt_data_header), /* TODO: allow only trailer */
	sizeof(struct smt_grant_header), sizeof(struct smt_resend_header),
	sizeof(struct smt_unknown_header), sizeof(struct smt_busy_header),
	sizeof(struct smt_cutoffs_header), sizeof(struct smt_freeze_header),
	sizeof(struct smt_need_ack_header), sizeof(struct smt_ack_header)
};

uint64_t
smt_usecs_to_cycles(uint64_t usecs)
{
	uint64_t tickrate;

	tickrate = cpu_tickrate();
	return ((usecs / 1000000) * tickrate +
	    ((usecs % 1000000) * tickrate) / 1000000);
}

static int
smt_packet_tailq_pool_init(struct smt_packet_tailq_pool *pool)
{
	struct smt_packet_tailq_entry *entry, *tmp;
	int i;

	SMT_ZONE_INIT(pool->zone, "smt_packet_tailq_entry",
		sizeof(struct smt_packet_tailq_entry), MAX_SMT_PACKET_TAILQ_ENTRY);
	TAILQ_INIT(&pool->entries);
	mtx_init(&pool->spinlock, "smt packet tailq spinlock",
	    NULL, MTX_SPIN);

	for (i = 0; i < MAX_SMT_PACKET_TAILQ_ENTRY; ++i) {
		entry = SMT_ZONE_GET(pool->zone, struct smt_packet_tailq_entry);
		if (entry == NULL) {
			goto smt_packet_tailq_init_error;
		}
		TAILQ_INSERT_HEAD(&pool->entries, entry, link);
	}

	return (0);

smt_packet_tailq_init_error:
	TAILQ_FOREACH_SAFE(entry, &pool->entries, link, tmp) {
		TAILQ_REMOVE(&pool->entries, entry, link);
		SMT_ZONE_FREE(pool->zone, entry);
	}
	mtx_destroy(&pool->spinlock);
	return (ENOMEM);
}

static int
smt_ctx_pool_init(struct smt_ctx_pool *pool)
{
        struct smt_ctx *ctx;
        int i;

        SMT_ZONE_INIT(pool->zone, "smt_ctx",
            sizeof(struct smt_ctx), MAX_SMT_CONTEXT);
        LIST_INIT(&pool->entries);
        mtx_init(&pool->spinlock, "smt ctx pool spinlock",
            NULL, MTX_SPIN);

        for (i = 0; i < MAX_SMT_CONTEXT; ++i) {
                ctx = SMT_ZONE_GET(pool->zone, struct smt_ctx);
                if (ctx == NULL) {
                        goto smt_ctx_pool_init_error;
		}

                LIST_INSERT_HEAD(&pool->entries, ctx, hash_links);
        }

        return (0);

smt_ctx_pool_init_error:
	while ((ctx = LIST_FIRST(&pool->entries)) != NULL) {
                LIST_REMOVE(ctx, hash_links);
                SMT_ZONE_FREE(pool->zone, ctx);
        }
        mtx_destroy(&pool->spinlock);
        return (ENOMEM);
}

static int
smt_zone_init(void)
{
	int error;

	SMT_ZONE_INIT(zones.smt_zone_rpc, "smt_rpc", sizeof(struct smt_rpc),
	    MAX_SMT_RPC);
	SMT_ZONE_INIT(zones.smt_zone_peer, "smt_peer",
	    sizeof(struct smt_peer), MAX_SMT_PEER);
	SMT_ZONE_INIT(zones.smt_zone_packet_slist_entry,
	    "smt_packet_slist_entry", sizeof(struct smt_packet_slist_entry),
	    MAX_SMT_PACKET_SLIST_ENTRY);

	error = smt_packet_tailq_pool_init(&zones.packet_tailq_pool);
	if (error != 0) {
		return (error);
	}
	error = smt_ctx_pool_init(&zones.ctx_pool);
	if (error != 0) {
		return (error);
	}

	return error;
}

struct smt_packet_tailq_entry *
smt_pool_alloc_packet_tailq_entry(void)
{
	struct smt_packet_tailq_entry *entry;

	mtx_lock_spin(&zones.packet_tailq_pool.spinlock);
	entry = TAILQ_FIRST(&zones.packet_tailq_pool.entries);
	if (entry != NULL) {
		TAILQ_REMOVE(&zones.packet_tailq_pool.entries, entry, link);
	}
	mtx_unlock_spin(&zones.packet_tailq_pool.spinlock);

	return entry;
}

void
smt_pool_free_packet_tailq_entry(struct smt_packet_tailq_entry *entry)
{
	KASSERT(entry != NULL, ("%s: entry must be valid", __func__));

	mtx_lock_spin(&zones.packet_tailq_pool.spinlock);
	memset(entry, 0, sizeof(struct smt_packet_tailq_entry));
	TAILQ_INSERT_HEAD(&zones.packet_tailq_pool.entries, entry, link);
	mtx_unlock_spin(&zones.packet_tailq_pool.spinlock);
}

struct smt_ctx *
smt_pool_alloc_ctx(void)
{
	struct smt_ctx *ctx;

	mtx_lock_spin(&zones.ctx_pool.spinlock);
	ctx = LIST_FIRST(&zones.ctx_pool.entries);
	if (ctx != NULL) {
		LIST_REMOVE(ctx, hash_links);
	}
	mtx_unlock_spin(&zones.ctx_pool.spinlock);

	return ctx;
}

void
smt_pool_free_ctx(struct smt_ctx *ctx)
{
	KASSERT(ctx != NULL, ("%s: ctx must be valid", __func__));

	mtx_lock_spin(&zones.ctx_pool.spinlock);
	memset(ctx, 0, sizeof(struct smt_ctx));
	LIST_INSERT_HEAD(&zones.ctx_pool.entries, ctx, hash_links);
	mtx_unlock_spin(&zones.ctx_pool.spinlock);
}

static int
smt_core_init(void)
{
	int cpu;
	struct smt_core *core;

	CPU_FOREACH(cpu) {
		core = DPCPU_ID_PTR(cpu, smt_cores);

		core->last_active = 0;
		core->last_gro = 0;
		core->held_packet = NULL;
		core->held_bucket = 0;
	}

	return 0;
}

static void
smt_pcbmap_init(struct smt_pcbmap *pcbmap)
{
	int i;
	mtx_init(&pcbmap->write_spinlock, "smt pcbmap write spinlock", NULL,
	    MTX_SPIN);
	for (i = 0; i < SMT_PCBMAP_BUCKETS; i++) {
		LIST_INIT(&pcbmap->buckets[i]);
	}
}

static int
smt_peermap_init(struct smt_peermap *peermap)
{
	int i;

	mtx_init(&peermap->write_spinlock, "smt peermap write spinlock", NULL,
	    MTX_SPIN);
	TAILQ_INIT(&peermap->dead_dsts);

	peermap->buckets = (struct smt_peer_list *)
	    malloc(SMT_PEERTAB_BUCKETS * sizeof(*peermap->buckets),
		M_SMT_PEERMAP, M_WAITOK);
	if (!peermap->buckets)
		return ENOMEM;

	for (i = 0; i < SMT_PEERTAB_BUCKETS; i++) {
		LIST_INIT(&peermap->buckets[i]);
	}
	return 0;
}

static int
smt_metrics_init(struct smt *smt)
{
	int err;

	err = sysctl_ctx_init(&smt->metrics.sysctl_ctx);
	if (err != 0) {
		return err;
	}

	smt->metrics.sysctl_tree = SYSCTL_ADD_NODE(&smt->metrics.sysctl_ctx,
	    SYSCTL_STATIC_CHILDREN(_net), OID_AUTO, "smt",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "SMT");
	if (smt->metrics.sysctl_tree == NULL) {
		sysctl_ctx_free(&smt->metrics.sysctl_ctx);
	}

	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO, "send_rpcs",
	    CTLFLAG_RW, &smt->metrics.send_rpcs_atomic, 0, "send_rpcs");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO, "send_pkts",
	    CTLFLAG_RW, &smt->metrics.send_pkts_atomic, 0, "send_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO, "recv_rpcs",
	    CTLFLAG_RW, &smt->metrics.recv_rpcs_atomic, 0, "recv_rpcs");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO, "recv_pkts",
	    CTLFLAG_RW, &smt->metrics.recv_pkts_atomic, 0, "recv_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "recv_rpc_acks", CTLFLAG_RW, &smt->metrics.recv_rpc_acks_atomic, 0,
	    "recv_rpc_acks");

	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO, "freed_rpcs",
	    CTLFLAG_RW, &smt->metrics.freed_rpcs_atomic, 0, "freed_rpcs");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "allocated_rpcs", CTLFLAG_RW, &smt->metrics.allocated_rpcs_atomic,
	    0, "allocated_rpcs");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "freed_recv_pkts", CTLFLAG_RW,
	    &smt->metrics.freed_recv_pkts_atomic, 0, "freed_recv_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "freed_send_pkts", CTLFLAG_RW,
	    &smt->metrics.freed_send_pkts_atomic, 0, "freed_send_pkts");

	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_data_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_DATA - SMT_DATA], 0,
	    "received_data_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_grant_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_GRANT - SMT_DATA], 0,
	    "received_grant_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_resend_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_RESEND - SMT_DATA], 0,
	    "received_resend_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_unknown_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_UNKNOWN - SMT_DATA], 0,
	    "received_unknown_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_busy_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_BUSY - SMT_DATA], 0,
	    "received_busy_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_cutoffs_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_CUTOFFS - SMT_DATA], 0,
	    "received_cutoffs_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_freeze_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_FREEZE - SMT_DATA], 0,
	    "received_freeze_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_need_ack_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_NEED_ACK - SMT_DATA], 0,
	    "received_need_ack_pkts");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "received_ack_pkts", CTLFLAG_RW,
	    &smt->metrics.received_pkts[SMT_ACK - SMT_DATA], 0,
	    "received_ack_pkts");

	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "opened_sockets", CTLFLAG_RW,
	    &smt->metrics.opened_sockets, 0,
	    "opened_sockets");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "closed_sockets", CTLFLAG_RW,
	    &smt->metrics.closed_sockets, 0,
	    "closed_sockets");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "destroyed_sockets", CTLFLAG_RW,
	    &smt->metrics.destroyed_sockets, 0,
	    "destroyed_sockets");

	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_input_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_input_cycles, 0,
	    "cycles spent in smt_input");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_input_count", CTLFLAG_RW,
	    &smt->metrics.lat_input_count, 0,
	    "smt_input latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_handle_packet_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_handle_packet_cycles, 0,
	    "cycles spent in smt_handle_packet");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_handle_packet_count", CTLFLAG_RW,
	    &smt->metrics.lat_handle_packet_count, 0,
	    "smt_handle_packet latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_data_packet_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_data_packet_cycles, 0,
	    "cycles spent processing DATA packets");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_data_packet_count", CTLFLAG_RW,
	    &smt->metrics.lat_data_packet_count, 0,
	    "DATA packet latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_message_out_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_message_out_cycles, 0,
	    "cycles spent preparing outbound messages");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_message_out_count", CTLFLAG_RW,
	    &smt->metrics.lat_message_out_count, 0,
	    "outbound message latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_fill_packets_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_fill_packets_cycles, 0,
	    "cycles spent copying user data into packet mbufs");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_fill_packets_count", CTLFLAG_RW,
	    &smt->metrics.lat_fill_packets_count, 0,
	    "packet fill latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_ip_output_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_ip_output_cycles, 0,
	    "cycles spent in IP output");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_ip_output_count", CTLFLAG_RW,
	    &smt->metrics.lat_ip_output_count, 0,
	    "IP output latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_copy_to_user_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_copy_to_user_cycles, 0,
	    "cycles spent copying received data to user space");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_copy_to_user_count", CTLFLAG_RW,
	    &smt->metrics.lat_copy_to_user_count, 0,
	    "copy-to-user latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_wait_for_message_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_wait_for_message_cycles, 0,
	    "cycles spent waiting for receive messages");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_wait_for_message_count", CTLFLAG_RW,
	    &smt->metrics.lat_wait_for_message_count, 0,
	    "wait-for-message latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_sosend_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_sosend_cycles, 0,
	    "cycles spent in smt_sosend");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_sosend_count", CTLFLAG_RW,
	    &smt->metrics.lat_sosend_count, 0,
	    "smt_sosend latency samples");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_rpc_lifetime_cycles", CTLFLAG_RW,
	    &smt->metrics.lat_rpc_lifetime_cycles, 0,
	    "cycles from RPC creation to complete receive");
	SYSCTL_ADD_U64(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO,
	    "lat_rpc_lifetime_count", CTLFLAG_RW,
	    &smt->metrics.lat_rpc_lifetime_count, 0,
	    "RPC lifetime latency samples");


	return err;
}

static int
smt_struct_init(struct smt *smt)
{
	int err, i;

	/* fix pacer thread */
	smt->pacer_kthread = NULL;

	atomic_store_64(&smt->next_out_id_atomic, 2);
	atomic_store_64(&smt->link_idle_time_atomic, get_cyclecount());
	mtx_init(&smt->grantable_spinlock, "smt grantable spinlock", NULL,
	    MTX_SPIN);
	TAILQ_INIT(&smt->grantable_rpcs);
	smt->num_grantable_rpcs = 0;
	smt->last_grantable_change = get_cyclecount();
	smt->max_grantable_rpcs = 0;
	smt->grant_nonfifo = 0;
	smt->grant_nonfifo_left = 0;
	mtx_init(&smt->pacer_spinlock, "smt pacer spinlock", NULL, MTX_SPIN);
	smt->pacer_fifo_fraction = 50;
	smt->pacer_fifo_count = 1;
	smt->pacer_wake_time = 0;
	mtx_init(&smt->throttle_spinlock, "smt throttle spinlock", NULL,
	    MTX_SPIN);
	TAILQ_INIT(&smt->throttled_rpcs);
	smt->throttle_add = 0;
	smt->throttle_min_bytes = 1000;
	atomic_store_64(&smt->total_incoming_atomic, 0);
	smt->next_client_port = SMT_MIN_DEFAULT_PORT;
	smt_pcbmap_init(&smt->port_map);
	err = smt_peermap_init(&smt->peers);
	if (err) {
		return err;
	}

	smt->unsched_bytes = 10000;
	smt->link_mbps = 10000;
	smt->poll_usecs = 50;
	smt->poll_cycles = smt_usecs_to_cycles(smt->poll_usecs);
	smt->num_priorities = SMT_MAX_PRIORITIES;
	for (i = 0; i < SMT_MAX_PRIORITIES; i++)
		smt->priority_map[i] = i;
	smt->max_sched_prio = SMT_MAX_PRIORITIES - 5;
	smt->unsched_cutoffs[SMT_MAX_PRIORITIES - 1] = 200;
	smt->unsched_cutoffs[SMT_MAX_PRIORITIES - 2] = 2800;
	smt->unsched_cutoffs[SMT_MAX_PRIORITIES - 3] = 15000;
	smt->unsched_cutoffs[SMT_MAX_PRIORITIES - 4] =
	    SMT_MAX_MESSAGE_LENGTH;

	smt->cutoff_version = 1;
	smt->fifo_grant_increment = 10000;
	smt->grant_fifo_fraction = 50;
	smt->max_overcommit = 8;
	smt->max_incoming = 400000;
	smt->max_rpcs_per_peer = 1;
	smt->dynamic_windows = 0;
	smt->resend_ticks = 15;
	smt->resend_interval = 10;
	smt->timeout_resends = 5;
	smt->request_ack_ticks = 2;
	smt->reap_limit = 10;
	smt->dead_buffs_limit = 5000;
	smt->max_dead_buffs = 0;

	// TODO: pacer thread initialization

	smt->pacer_exit = false;
	smt->max_nic_queue_ns = 2000;
	smt->cycles_per_kbyte = 0;
	smt->verbose = 0;
	smt->max_gso_size = 10000;
	smt->max_gro_skbs = 20;
	smt->gso_force_software = 0;
	smt->gro_policy = SMT_GRO_NORMAL;
	smt->gro_busy_usecs = 10;
	smt->timer_ticks = 0;
	smt->flags = 0;
	smt->freeze_type = 0;
	smt->sync_freeze = 0;
	smt->bpage_lease_usecs = 10000;
	smt->hardware_state_threshold = 1;
	strncpy(smt->hardware_interface, "enp1s0f0np0",
	    sizeof(smt->hardware_interface) - 1);

	err = smt_metrics_init(smt);

	return err;
}

int
smt_init(struct smt *smt)
{
	CTASSERT(SMT_MAX_PRIORITIES >= 8);

	int err;

	if ((err = smt_zone_init()) != 0) {
		return err;
	}
	if ((err = smt_core_init()) != 0) {
		return err;
	}
	if ((err = smt_struct_init(smt)) != 0) {
		return err;
	}

#ifdef SMT_TEST
	err = smt_test_state_init(&test_state, smt);
#endif

	return err;
}

void
smt_interest_init(struct smt_interest *interest)
{
	memset(interest, 0, sizeof(struct smt_interest));

	interest->thread = curthread;
	atomic_store_ptr(&interest->ready_rpc_atomic, 0);

	mtx_init(&interest->spinlock, "interest sleep lock", NULL, MTX_SPIN);

	interest->reg_rpc = NULL;
	atomic_store_int(&interest->is_response_atomic, false);
	atomic_store_int(&interest->is_request_atomic, false);
}

// TODO: fix uninit
int
smt_exit(struct smt *smt)
{
	SMT_ZONE_DESTROY(zones.smt_zone_rpc);
	SMT_ZONE_DESTROY(zones.smt_zone_peer);
	SMT_ZONE_DESTROY(zones.packet_tailq_pool.zone);
	SMT_ZONE_DESTROY(zones.smt_zone_packet_slist_entry);
	SMT_ZONE_DESTROY(zones.ctx_pool.zone);

	sysctl_ctx_free(&smt->metrics.sysctl_ctx);

	return 0;
}
