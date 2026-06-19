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

#ifndef _SDTP_STRUCTS_H_
#define _SDTP_STRUCTS_H_

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <vm/uma.h>

#include <netinet/in.h>

#include "sdtp.h"
#include "sdtp_common.h"
#include "sdtp_pcb.h"
#include "sdtp_peer.h"
#include "sdtp_rpc.h"

struct sdtp_core {
	uint64_t last_active;
	uint64_t last_gro;
	/*
	 * atomic_t softirq_backlog;
	 * int softirq_offset;
	 */

	struct sdtp_packet *held_packet;
	int held_bucket;
	struct thread *thread;
	uint64_t syscall_end_time;
};

struct sdtp_metrics {
	struct sysctl_ctx_list sysctl_ctx;
	struct sysctl_oid *sysctl_tree;

	uint64_t send_rpcs_atomic;
	uint64_t send_pkts_atomic;
	uint64_t recv_rpcs_atomic;
	uint64_t recv_pkts_atomic;
	uint64_t recv_rpc_acks_atomic;

	uint64_t freed_rpcs_atomic;
	uint64_t allocated_rpcs_atomic;
	uint64_t freed_recv_pkts_atomic;
	uint64_t freed_send_pkts_atomic;

	uint64_t received_pkts[SDTP_ACK - SDTP_DATA + 1];

	uint64_t opened_sockets;
	uint64_t closed_sockets;
	uint64_t destroyed_sockets;

	uint64_t lat_input_cycles;
	uint64_t lat_input_count;
	uint64_t lat_handle_packet_cycles;
	uint64_t lat_handle_packet_count;
	uint64_t lat_data_packet_cycles;
	uint64_t lat_data_packet_count;
	uint64_t lat_message_out_cycles;
	uint64_t lat_message_out_count;
	uint64_t lat_fill_packets_cycles;
	uint64_t lat_fill_packets_count;
	uint64_t lat_ip_output_cycles;
	uint64_t lat_ip_output_count;
	uint64_t lat_copy_to_user_cycles;
	uint64_t lat_copy_to_user_count;
	uint64_t lat_wait_for_message_cycles;
	uint64_t lat_wait_for_message_count;
	uint64_t lat_sosend_cycles;
	uint64_t lat_sosend_count;
	uint64_t lat_rpc_lifetime_cycles;
	uint64_t lat_rpc_lifetime_count;
};

struct sdtp_dead_dst {
	struct nhop_object *nh;
	uint64_t gc_time;
	struct sdtp_dead_dst_tailq dst_links;
};

enum sdtp_freeze_type {
	RESTART_RPC = 1,
	PEER_TIMEOUT = 2,
	SLOW_RPC = 3,
	SOCKET_CLOSE = 4,
	PACKET_LOST = 5,
};

struct sdtp {
	uint64_t next_out_id_atomic;
	uint64_t link_idle_time_atomic __aligned(SDTP_CACHE_LINE_SIZE);

	struct mtx grantable_spinlock __aligned(SDTP_CACHE_LINE_SIZE);
	struct sdtp_rpc_tailq grantable_rpcs;
	int num_grantable_rpcs;
	uint64_t last_grantable_change;
	int max_grantable_rpcs;
	int grant_nonfifo;
	int grant_nonfifo_left;

	/* only try */
	struct mtx pacer_spinlock __aligned(SDTP_CACHE_LINE_SIZE);
	int pacer_fifo_fraction;
	int pacer_fifo_count;
	uint64_t pacer_wake_time;

	struct mtx throttle_spinlock;
	struct sdtp_rpc_tailq throttled_rpcs;
	uint64_t throttle_add;
	int throttle_min_bytes;
	uint64_t total_incoming_atomic __aligned(CACHE_LINE_SIZE);
	uint16_t next_client_port __aligned(CACHE_LINE_SIZE);

	struct sdtp_pcbmap port_map __aligned(CACHE_LINE_SIZE);
	struct sdtp_peermap peers;

	int unsched_bytes;
	int link_mbps;
	int poll_usecs;
	uint64_t poll_cycles;
	int num_priorities;
	int priority_map[SDTP_MAX_PRIORITIES];
	int max_sched_prio;
	int unsched_cutoffs[SDTP_MAX_PRIORITIES];
	int cutoff_version;
	int fifo_grant_increment;
	int grant_fifo_fraction;
	int max_overcommit;
	int max_incoming;
	int max_rpcs_per_peer;
	int dynamic_windows;
	int resend_ticks;
	int resend_interval;
	int timeout_resends;
	int request_ack_ticks;
	int reap_limit;
	int dead_buffs_limit;
	int max_dead_buffs;

	struct thread *pacer_kthread;

	bool pacer_exit;
	int max_nic_queue_ns;
	int max_nic_queue_cycles;
	uint32_t cycles_per_kbyte;
	int verbose;
	int max_gso_size;
	int max_gro_skbs;
	int gso_force_software;
	int gro_policy;

#define SDTP_GRO_BYPASS	      0x1
#define SDTP_GRO_SAME_CORE    0x2
#define SDTP_GRO_IDLE	      0x4
#define SDTP_GRO_NEXT	      0x8
#define SDTP_GRO_IDLE_NEW     0x10
#define SDTP_GRO_FAST_GRANTS  0x20
#define SDTP_GRO_SHORT_BYPASS 0x40
#define SDTP_GRO_NORMAL \
	(SDTP_GRO_SAME_CORE | SDTP_GRO_IDLE_NEW | SDTP_GRO_SHORT_BYPASS)

	int gro_busy_usecs;
	int gro_busy_cycles;
	uint32_t timer_ticks;

	struct sdtp_metrics metrics;

	int metrics_active_opens;
	int flags;
	enum sdtp_freeze_type freeze_type;
	int sync_freeze;
	int bpage_lease_usecs;
	int hardware_state_threshold;
	char hardware_interface[32];
	int bpage_lease_cycles;
	int temp[4];
};

typedef struct uma_zone *sdtp_zone_t;

#define DEFINE_SDTP_POOL(NAME, HEAD_TYPE)    \
struct NAME {                                \
        sdtp_zone_t zone;                    \
        HEAD_TYPE entries;                   \
        struct mtx spinlock;                 \
}

DEFINE_SDTP_POOL(sdtp_packet_tailq_pool, struct sdtp_packet_tailq);
DEFINE_SDTP_POOL(sdtp_ctx_pool, struct sdtp_ctx_list);

struct sdtp_zones {
	sdtp_zone_t sdtp_zone_rpc;
	sdtp_zone_t sdtp_zone_peer;
	sdtp_zone_t sdtp_zone_packet_slist_entry;

	struct sdtp_packet_tailq_pool packet_tailq_pool;
	struct sdtp_ctx_pool          ctx_pool;
};

static inline struct sdtp_rpc_bucket *
sdtp_client_rpc_bucket(struct sdtp_inpcb *pcb, uint64_t id)
{
	return &pcb->client_rpc_buckets[(id >> 1) &
	    (SDTP_CLIENT_RPC_BUCKETS - 1)];
}

static inline struct sdtp_rpc_bucket *
sdtp_server_rpc_bucket(struct sdtp_inpcb *pcb, uint64_t id)
{
	return &pcb->server_rpc_buckets[(id >> 1) &
	    (SDTP_SERVER_RPC_BUCKETS - 1)];
}

static inline int
sdtp_port_hash(uint16_t port)
{
	return port & (SDTP_PCBMAP_BUCKETS - 1);
}

int sdtp_init(struct sdtp *sdtp);
int sdtp_exit(struct sdtp *sdtp);
void sdtp_interest_init(struct sdtp_interest *interest);
uint64_t sdtp_usecs_to_cycles(uint64_t usecs);

struct sdtp_packet_tailq_entry *sdtp_pool_alloc_packet_tailq_entry(void);
void sdtp_pool_free_packet_tailq_entry(struct sdtp_packet_tailq_entry *entry);

struct sdtp_ctx *sdtp_pool_alloc_ctx(void);
void sdtp_pool_free_ctx(struct sdtp_ctx *ctx);

#define SDTP_METRIC(S, FIELD, VAL)                                 \
	do {                                                       \
		atomic_add_64(&((S)->metrics.FIELD), VAL); \
	} while (0)

#ifdef SDTP_LATENCY_ALLOW

#define SDTP_LATENCY(S, CYCLES_FIELD, COUNT_FIELD, START)          \
	do {                                                       \
		SDTP_METRIC((S), CYCLES_FIELD, get_cyclecount() - (START)); \
		SDTP_METRIC((S), COUNT_FIELD, 1);                   \
	} while (0)

#else

#define SDTP_LATENCY(S, CYCLES_FIELD, COUNT_FIELD, START) \
	do { (void)(START); } while (0)

#endif

VNET_DECLARE(struct inpcbinfo, sdtp_pcbinfo);
#define V_sdtp_pcbinfo	VNET(sdtp_pcbinfo)

#endif
