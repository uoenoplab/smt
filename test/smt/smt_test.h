/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* Included first in every file of the SMT unit tests. net/tls.h (through
 * smt_uapi.h) sizes arrays by MAX_SKB_FRAGS, which mock.h turns into a
 * variable, so it comes here with the kernel's value.
 */

#include "homa_impl.h"

#pragma push_macro("MAX_SKB_FRAGS")
#undef MAX_SKB_FRAGS
#define MAX_SKB_FRAGS CONFIG_MAX_SKB_FRAGS
#include <net/tls.h>
#pragma pop_macro("MAX_SKB_FRAGS")
