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

#include "sdtp_input.h"
#include "sdtp_structs.h"

struct sdtp sdtp_data;
struct sdtp *sdtp = &sdtp_data;

extern struct protosw sdtp_protosw;
extern struct protosw sdtp6_protosw;

static volatile bool existing = false;

INPCBSTORAGE_DEFINE(sdtpcbstor, sdtp_inpcb,
    "sdtp_inp", "sdtp_inpcb", "sdtp_hash");
VNET_DEFINE(struct inpcbinfo, sdtp_pcbinfo);

static void
sdtp_vnet_init(void *arg __unused)
{
	in_pcbinfo_init(&V_sdtp_pcbinfo, &sdtpcbstor,
		 SDTP_HASHSIZE, SDTP_HASHSIZE, SDTP_HASHSIZE);
}
VNET_SYSINIT(sdtp_vnet_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_FOURTH,
	sdtp_vnet_init, NULL);

static int
sdtp_module_load(void)
{
	int error = 0;

#ifdef INET
	error = protosw_register(&inetdomain, &sdtp_protosw);
	if (error != 0)
		return (error);
	error = ipproto_register(IPPROTO_SDTP, sdtp_input, sdtp_ctlinput);
	if (error != 0)
		return (error);
#endif
/*
#ifdef INET6
	error = protosw_register(&inet6domain, &sdtp6_protosw);
	if (error != 0)
		return (error);
	error = ip6proto_register(IPPROTO_SDTP, sdtp6_input, sdtp6_ctlinput);
	if (error != 0)
		return (error);
#endif
*/

	/*
	 * error = kthread_add(&sdtp_timer_main, NULL, NULL, &timer_kthread, 0, 0,
	 * "sdtp_timer"); if (error != 0) { timer_kthread = NULL; return (error);
	 * }
	 */
	// sched_add(timer_kthread, SRQ_BORING);

	error = sdtp_init(sdtp);
	// error = sdtp_syscalls_init();
	return (error);
}

static int
sdtp_module_unload(void)
{
	int error = 0;
	existing = true;

	error = sdtp_exit(sdtp);
#ifdef INET
	(void)ipproto_unregister(IPPROTO_SDTP);
	(void)protosw_unregister(&sdtp_protosw);
#endif
/*
#ifdef INET6
	(void)ip6proto_unregister(IPPROTO_SDTP);
	(void)protosw_unregister(&sdtp6_protosw);
#endif
*/

	return (error);
}

static int
sdtp_modload(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = sdtp_module_load();
		break;
	case MOD_UNLOAD:
		error = sdtp_module_unload();
		break;
	default:
		error = 0;
		break;
	}
	return (error);
}

static moduledata_t sdtp_mod = {
	"sdtp",
	&sdtp_modload,
	NULL,
};

DECLARE_MODULE(sdtp, sdtp_mod, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_VERSION(sdtp, 1);
