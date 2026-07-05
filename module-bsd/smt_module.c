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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/module.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>

#include "smt_input.h"
#include "smt_structs.h"

struct smt smt_data;
struct smt *smt = &smt_data;

extern struct protosw smt_protosw;
extern struct protosw smt6_protosw;

static volatile bool existing = false;

INPCBSTORAGE_DEFINE(smtcbstor, smt_inpcb,
    "smt_inp", "smt_inpcb", "smt_hash");
VNET_DEFINE(struct inpcbinfo, smt_pcbinfo);

static void
smt_vnet_init(void *arg __unused)
{
	in_pcbinfo_init(&V_smt_pcbinfo, &smtcbstor,
		 SMT_HASHSIZE, SMT_HASHSIZE, SMT_HASHSIZE);
}
VNET_SYSINIT(smt_vnet_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_FOURTH,
	smt_vnet_init, NULL);

static int
smt_module_load(void)
{
	int error = 0;

#ifdef INET
	error = protosw_register(&inetdomain, &smt_protosw);
	if (error != 0)
		return (error);
	error = ipproto_register(IPPROTO_SMT, smt_input, smt_ctlinput);
	if (error != 0)
		return (error);
#endif
/*
#ifdef INET6
	error = protosw_register(&inet6domain, &smt6_protosw);
	if (error != 0)
		return (error);
	error = ip6proto_register(IPPROTO_SMT, smt6_input, smt6_ctlinput);
	if (error != 0)
		return (error);
#endif
*/

	/*
	 * error = kthread_add(&smt_timer_main, NULL, NULL, &timer_kthread, 0, 0,
	 * "smt_timer"); if (error != 0) { timer_kthread = NULL; return (error);
	 * }
	 */
	// sched_add(timer_kthread, SRQ_BORING);

	error = smt_init(smt);
	// error = smt_syscalls_init();
	return (error);
}

static int
smt_module_unload(void)
{
	int error = 0;
	existing = true;

	error = smt_exit(smt);
#ifdef INET
	(void)ipproto_unregister(IPPROTO_SMT);
	(void)protosw_unregister(&smt_protosw);
#endif
/*
#ifdef INET6
	(void)ip6proto_unregister(IPPROTO_SMT);
	(void)protosw_unregister(&smt6_protosw);
#endif
*/

	return (error);
}

static int
smt_modload(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = smt_module_load();
		break;
	case MOD_UNLOAD:
		error = smt_module_unload();
		break;
	default:
		error = 0;
		break;
	}
	return (error);
}

static moduledata_t smt_mod = {
	"smt",
	&smt_modload,
	NULL,
};

DECLARE_MODULE(smt, smt_mod, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_VERSION(smt, 1);
