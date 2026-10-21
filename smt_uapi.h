/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* SMT setsockopt interface (kernel and user space). */

#ifndef _UAPI_LINUX_SMT_H
#define _UAPI_LINUX_SMT_H

#ifdef __KERNEL__
#include <net/tls.h>
#else
#define _GNU_SOURCE
#include <stdint.h>
#include <linux/tls.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @smt_info: the peer a key is for, in network order: its address and Homa
 * port. A setsockopt(SOL_TLS, TLS_TX or TLS_RX) for a peer that has a key
 * replaces it; RPCs that already use the old key finish with it. Both 0
 * is refused. local_addr is not used.
 */
struct smt_info {
	uint32_t peer_addr;
	uint16_t peer_port;
	uint32_t local_addr;
} __attribute__((packed));

struct smt_aes_gcm_128_info {
	struct smt_info smt;
	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128;
} __attribute__((packed));

struct smt_aes_gcm_256_info {
	struct smt_info smt;
	struct tls12_crypto_info_aes_gcm_256 aes_gcm_256;
} __attribute__((packed));

#ifdef __KERNEL__
struct smt_tls_info {
	struct smt_info smt;
	struct tls_crypto_info tls;
} __attribute__((packed));

union smt_info_union {
	struct smt_info smt;
	struct smt_tls_info smt_tls;
	struct smt_aes_gcm_128_info smt_aes_gcm_128;
	struct smt_aes_gcm_256_info smt_aes_gcm_256;
};

#else
/* key_size: 128 or 256 (AES-GCM). */
int tcpktls_setsockopt_hardcodekey_helper(int sockfd, int server, int tls13, int key_size);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _UAPI_LINUX_SMT_H */
