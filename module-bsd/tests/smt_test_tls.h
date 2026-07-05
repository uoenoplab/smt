#ifndef _SMT_TEST_TLS_H_
#define _SMT_TEST_TLS_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ktls.h>

#include <crypto/cryptodev.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IPPROTO_SMT		146
#define SMT_TXTLS_ENABLE	31
#define SMT_RXTLS_ENABLE	32

struct smt_tls_enable {
	uint32_t peer_addr_be;
	uint16_t peer_port_be;
	uint32_t local_addr_be;
	struct tls_enable tls;
};

static int
smt_enable_test_tls(int fd, bool server)
{
	static const uint8_t client_key[16] = {
		0x8d, 0xd2, 0x30, 0xa7, 0x7a, 0x05, 0xeb, 0x71,
		0x15, 0x91, 0x29, 0xbc, 0xbc, 0xf6, 0x42, 0x30
	};
	static const uint8_t server_key[16] = {
		0x6c, 0xcf, 0x62, 0xff, 0x4b, 0xe6, 0x14, 0x85,
		0xd8, 0xba, 0x29, 0xfe, 0x2e, 0x84, 0x7a, 0x7f
	};
	static const uint8_t client_iv[TLS_AEAD_GCM_LEN] = {
		0x87, 0xc6, 0x35, 0xc8
	};
	static const uint8_t server_iv[TLS_AEAD_GCM_LEN] = {
		0xb9, 0xfa, 0x55, 0x83
	};
	struct smt_tls_enable rx, tx;

	memset(&rx, 0, sizeof(rx));
	memset(&tx, 0, sizeof(tx));

	tx.tls.cipher_algorithm = CRYPTO_AES_NIST_GCM_16;
	tx.tls.cipher_key = server ? server_key : client_key;
	tx.tls.cipher_key_len = sizeof(client_key);
	tx.tls.iv = server ? server_iv : client_iv;
	tx.tls.iv_len = TLS_AEAD_GCM_LEN;
	tx.tls.tls_vmajor = TLS_MAJOR_VER_ONE;
	tx.tls.tls_vminor = TLS_MINOR_VER_TWO;

	rx.tls.cipher_algorithm = CRYPTO_AES_NIST_GCM_16;
	rx.tls.cipher_key = server ? client_key : server_key;
	rx.tls.cipher_key_len = sizeof(client_key);
	rx.tls.iv = server ? client_iv : server_iv;
	rx.tls.iv_len = TLS_AEAD_GCM_LEN;
	rx.tls.tls_vmajor = TLS_MAJOR_VER_ONE;
	rx.tls.tls_vminor = TLS_MINOR_VER_TWO;

	if (setsockopt(fd, IPPROTO_SMT, SMT_TXTLS_ENABLE, &tx,
	    sizeof(tx)) < 0) {
		perror("setsockopt(SMT_TXTLS_ENABLE)");
		return (-1);
	}
	if (setsockopt(fd, IPPROTO_SMT, SMT_RXTLS_ENABLE, &rx,
	    sizeof(rx)) < 0) {
		perror("setsockopt(SMT_RXTLS_ENABLE)");
		return (-1);
	}

	return (0);
}

#endif
