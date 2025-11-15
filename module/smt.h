/* Copyright (c) 2022-2025, Tianyi Gao, University of Edinburgh
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

#ifndef _SMT_H
#define _SMT_H

#include <linux/tls.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct smt_crypto_info {
	struct tls12_crypto_info_aes_gcm_128 crypto_info_aes_gcm_128;

	uint32_t addr; // network order
	uint16_t port; // network order

	uint8_t reuse;

	uint8_t padding;
};

extern void set_crypto_info(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server);
extern void set_crypto_info_alter(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server); // for 2 echo client with different keys
extern void set_crypto_info_tls12(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server);

extern int smt_setsockopt_wrapper(int sockfd, uint32_t addr, uint16_t port, int server, int tls13);
extern int tcpktls_setsockopt_wrapper(int sockfd, int server, int tls13);

#ifdef __cplusplus
}
#endif

#endif /* _SMT_H */
