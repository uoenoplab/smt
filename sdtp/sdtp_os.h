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

#ifndef _SDTP_OS_H_
#define _SDTP_OS_H_

#include <vm/uma.h>

#include "sdtp_structs.h"

#define SDTP_ZONE_INIT(zone, name, size, number)                       \
	{                                                              \
		zone = uma_zcreate(name, size, NULL, NULL, NULL, NULL, \
		    UMA_ALIGN_PTR, 0);                                 \
		uma_zone_set_max(zone, number);                        \
	}

#define SDTP_ZONE_DESTROY(zone)	      uma_zdestroy(zone)

#define SDTP_ZONE_GET(zone, type)     (type *)uma_zalloc(zone, M_NOWAIT | M_ZERO);

#define SDTP_ZONE_FREE(zone, element) uma_zfree(zone, element);

#endif
