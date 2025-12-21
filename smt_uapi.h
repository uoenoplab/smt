// Userspace SMT header
#ifndef _UAPI_LINUX_SMT_H
#define _UAPI_LINUX_SMT_H

#ifdef __KERNEL__
#include <net/tls.h>
#else
#include <stdint.h>
#include <linux/tls.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @smt_info: common struct for differnt crypto size
 *
 * To reuse this crypto info based on 2-tuple (local_port + protocol),
 * set peer_addr, peer_port and local_addr to 0;
 * To reuse this crypto info based on 3-tuple (local_addr + local_port + protocol),
 * set peer_addr, peer_port to 0, local_addr to a valid IP address;
 * All fields in this struct is in Network Order.
 */
struct smt_info {
	uint32_t peer_addr;
	uint16_t peer_port;
	uint32_t local_addr;
};

struct smt_aes_gcm_128_info {
	struct smt_info smt;
	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128;
};

struct smt_aes_gcm_256_info {
	struct smt_info smt;
	struct tls12_crypto_info_aes_gcm_256 aes_gcm_256;
};

#ifdef __KERNEL__
struct smt_tls_info {
	struct smt_info smt;
	struct tls_crypto_info tls;
};

union smt_info_union
{
	struct smt_info smt;
	struct smt_tls_info smt_tls;
	struct smt_aes_gcm_128_info smt_aes_gcm_128;
	struct smt_aes_gcm_256_info smt_aes_gcm_256;
};

#else
int smt_aes_gcm_128_setsockopt_hardcodekey_helper(int sockfd, int tls13, uint32_t peer_addr, uint16_t peer_port, uint32_t local_addr, int server);
int tcpktls_aes_gcm_128_setsockopt_hardcodekey_helper(int sockfd, int server, int tls13);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _UAPI_LINUX_SMT_H */
