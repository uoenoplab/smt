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

#include "smt_test.h"

int
smt_test_state_init(struct smt_test_state *state, struct smt *smt)
{
	state->sysctl_tree = SYSCTL_ADD_NODE(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(smt->metrics.sysctl_tree), OID_AUTO, "test",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "SMT test state");

	if (state->sysctl_tree == NULL) {
		return ENOMEM;
	}

	atomic_store_int(&state->drop_next_rpc_pkt_idx_atomic, -1);

	SYSCTL_ADD_INT(&smt->metrics.sysctl_ctx,
	    SYSCTL_CHILDREN(state->sysctl_tree), OID_AUTO,
	    "drop_next_rpc_pkt_idx", CTLFLAG_RW | CTLFLAG_MPSAFE,
	    &state->drop_next_rpc_pkt_idx_atomic, 0, "drop_next_rpc_pkt_idx");

	return 0;
}
