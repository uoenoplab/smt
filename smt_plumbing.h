/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* What Homa calls in SMT. */

#ifndef _SMT_PLUMBING_H
#define _SMT_PLUMBING_H

#include "homa_impl.h"
#include "homa_rpc.h"

#include "smt_plumbing_impl.h"

/* helpers */

#ifdef CONFIG_SMT_DEBUG
#define CONFIG_SMT_INFO
#define smt_pr_devel(fmt, arg...) pr_info(fmt, ##arg)
#else
#define smt_pr_devel(fmt, arg...) {}
#endif

#define SMT_TRACE_FUNC_ENTER() smt_pr_devel("%s: Enter\n", __func__)

#ifdef CONFIG_SMT_INFO
#define smt_pr_info(fmt, arg...) pr_info(fmt, ##arg)
#else
#define smt_pr_info(fmt, arg...) {}
#endif

#define smt_pr_err(fmt, arg...) pr_err(fmt, ##arg)

#endif /* _SMT_PLUMBING_H */
