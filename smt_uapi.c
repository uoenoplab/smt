#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "smt_uapi.h"

static int set_tls_crypto_info(void *crypto_info_send_ptr, void *crypto_info_read_ptr, int tls13, int server, int key_size, int alter) {
    uint8_t client_key_hardcode[32] = {0x8D, 0xD2, 0x30, 0xA7, 0x7A, 0x05, 0xEB, 0x71, 0x15, 0x91, 0x29, 0xBC, 0xBC, 0xF6, 0x42, 0x30, 0x8D, 0xD2, 0x30, 0xA7, 0x7A, 0x05, 0xEB, 0x71, 0x15, 0x91, 0x29, 0xBC, 0xBC, 0xF6, 0x42, 0x30};
    uint8_t client_iv_hardcode[12] = {0x87, 0xC6, 0x35, 0xC8, 0x17, 0x87, 0xDE, 0x4A, 0x88, 0x1D, 0xD2, 0xD5};
    uint8_t server_key_hardcode[32] = {0x6C, 0xCF, 0x62, 0xFF, 0x4B, 0xE6, 0x14, 0x85, 0xD8, 0xBA, 0x29, 0xFE, 0x2E, 0x84, 0x7A, 0x7F, 0x6C, 0xCF, 0x62, 0xFF, 0x4B, 0xE6, 0x14, 0x85, 0xD8, 0xBA, 0x29, 0xFE, 0x2E, 0x84, 0x7A, 0x7F};
    uint8_t server_iv_hardcode[12] = {0xB9, 0xFA, 0x55, 0x83, 0xD5, 0x8F, 0x85, 0x18, 0xFF, 0xA6, 0x3E, 0x66};

    uint8_t client_key_hardcode_alter[32] = {0xE0, 0x47, 0x0E, 0x9F, 0x09, 0x48, 0x27, 0x9B, 0xE9, 0x8B, 0xF3, 0xB1, 0x18, 0x58, 0x4F, 0xB6, 0xE0, 0x47, 0x0E, 0x9F, 0x09, 0x48, 0x27, 0x9B, 0xE9, 0x8B, 0xF3, 0xB1, 0x18, 0x58, 0x4F, 0xB6};
    uint8_t client_iv_hardcode_alter[12] = {0x39, 0x00, 0x8E, 0x2E, 0xFE, 0x3E, 0x37, 0x81, 0xCF, 0x71, 0x66, 0x69};
    uint8_t server_key_hardcode_alter[32] = {0x6A, 0x0D, 0xF9, 0x6B, 0xDD, 0x28, 0x08, 0xF8, 0x3C, 0x4D, 0x70, 0x07, 0x43, 0x4C, 0xE0, 0x38, 0x6A, 0x0D, 0xF9, 0x6B, 0xDD, 0x28, 0x08, 0xF8, 0x3C, 0x4D, 0x70, 0x07, 0x43, 0x4C, 0xE0, 0x38};
    uint8_t server_iv_hardcode_alter[12] = {0xBE, 0x9D, 0x1C, 0xEA, 0xF8, 0xE9, 0x54, 0x23, 0x32, 0x8E, 0xD4, 0x20};

    uint8_t *local_key, *local_iv, *remote_key, *remote_iv;
    uint64_t local_sequence_number = 0, remote_sequence_number = 0;

    if (!alter) {
        local_key = server ? server_key_hardcode : client_key_hardcode;
        local_iv = server ? server_iv_hardcode : client_iv_hardcode;
        remote_key = server ? client_key_hardcode : server_key_hardcode;
        remote_iv = server ? client_iv_hardcode : server_iv_hardcode;
    } else {
        local_key = server ? server_key_hardcode_alter : client_key_hardcode_alter;
        local_iv = server ? server_iv_hardcode_alter : client_iv_hardcode_alter;
        remote_key = server ? client_key_hardcode_alter : server_key_hardcode_alter;
        remote_iv = server ? client_iv_hardcode_alter : server_iv_hardcode_alter;
    }

    if (key_size == 128) {
        struct tls12_crypto_info_aes_gcm_128 *crypto_info_send = (struct tls12_crypto_info_aes_gcm_128 *)crypto_info_send_ptr;
        uint64_t local_seq_be = htobe64(local_sequence_number);
        crypto_info_send->info.version = tls13 ? TLS_1_3_VERSION : TLS_1_2_VERSION;
        crypto_info_send->info.cipher_type = TLS_CIPHER_AES_GCM_128;
        if (tls13) {
            memcpy(crypto_info_send->iv, local_iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        } else {
            memcpy(crypto_info_send->iv, &local_seq_be, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        }
        memcpy(crypto_info_send->key, local_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        memcpy(crypto_info_send->salt, local_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
        memcpy(crypto_info_send->rec_seq, &local_seq_be, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
        struct tls12_crypto_info_aes_gcm_128 *crypto_info_read = (struct tls12_crypto_info_aes_gcm_128 *)crypto_info_read_ptr;
        uint64_t remote_seq_be = htobe64(remote_sequence_number);
        crypto_info_read->info.version = tls13 ? TLS_1_3_VERSION : TLS_1_2_VERSION;
        crypto_info_read->info.cipher_type = TLS_CIPHER_AES_GCM_128;
        if (tls13) {
            memcpy(crypto_info_read->iv, remote_iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        } else {
            memcpy(crypto_info_read->iv, &remote_seq_be, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        }
        memcpy(crypto_info_read->key, remote_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        memcpy(crypto_info_read->salt, remote_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
        memcpy(crypto_info_read->rec_seq, &remote_seq_be, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    } else if (key_size == 256) {
        struct tls12_crypto_info_aes_gcm_256 *crypto_info_send = (struct tls12_crypto_info_aes_gcm_256 *)crypto_info_send_ptr;
        uint64_t local_seq_be = htobe64(local_sequence_number);
        crypto_info_send->info.version = tls13 ? TLS_1_3_VERSION : TLS_1_2_VERSION;
        crypto_info_send->info.cipher_type = TLS_CIPHER_AES_GCM_256;
        if (tls13) {
            memcpy(crypto_info_send->iv, local_iv + 4, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        } else {
            memcpy(crypto_info_send->iv, &local_seq_be, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        }
        memcpy(crypto_info_send->key, local_key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
        memcpy(crypto_info_send->salt, local_iv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
        memcpy(crypto_info_send->rec_seq, &local_seq_be, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
        struct tls12_crypto_info_aes_gcm_256 *crypto_info_read = (struct tls12_crypto_info_aes_gcm_256 *)crypto_info_read_ptr;
        uint64_t remote_seq_be = htobe64(remote_sequence_number);
        crypto_info_read->info.version = tls13 ? TLS_1_3_VERSION : TLS_1_2_VERSION;
        crypto_info_read->info.cipher_type = TLS_CIPHER_AES_GCM_256;
        if (tls13) {
            memcpy(crypto_info_read->iv, remote_iv + 4, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        } else {
            memcpy(crypto_info_read->iv, &local_seq_be, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        }
        memcpy(crypto_info_read->key, remote_key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
        memcpy(crypto_info_read->salt, remote_iv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
        memcpy(crypto_info_read->rec_seq, &remote_seq_be, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
    } else {
        return -1;
    }

    return 0;
}

int smt_aes_gcm_128_setsockopt_hardcodekey_helper(int sockfd, int tls13, uint32_t peer_addr, uint16_t peer_port, uint32_t local_addr, int server) {
    int ret;
    struct smt_aes_gcm_128_info info_send, info_read;

    info_send.smt.peer_addr = peer_addr;
    info_send.smt.peer_port = peer_port;
    info_send.smt.local_addr = local_addr;

    info_read.smt.peer_addr = peer_addr;
    info_read.smt.peer_port = peer_port;
    info_read.smt.local_addr = local_addr;

    if (tls13)
        set_tls_crypto_info(&info_send.aes_gcm_128, &info_read.aes_gcm_128, 1, server, 128, 0);
    else
        set_tls_crypto_info(&info_send.aes_gcm_128, &info_read.aes_gcm_128, 0, server, 128, 0);

    ret = setsockopt(sockfd, SOL_TLS, TLS_TX, &info_send, sizeof(info_send));
    if (ret < 0) {
        printf("Couldn't set TLS_TX option on smt: %d %s\n", ret, strerror(errno));
        return ret;
    }

    ret = setsockopt(sockfd, SOL_TLS, TLS_RX, &info_read, sizeof(info_read));
    if (ret < 0) {
        printf("Couldn't set TLS_RX option values on smt: %d %s\n", ret, strerror(errno));
        return ret;
    }

    return 0;
}

int tcpktls_aes_gcm_128_setsockopt_hardcodekey_helper(int sockfd, int server, int tls13) {
    int ret;
    struct tls12_crypto_info_aes_gcm_128 info_send, info_read;

    if (tls13)
        set_tls_crypto_info(&info_send, &info_read, 1, server, 128, 0);
    else
        set_tls_crypto_info(&info_send, &info_read, 0, server, 128, 0);

    ret = setsockopt(sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret < 0) {
        printf("KTLS fail: %s\n", strerror(errno));
        return ret;
    }

    ret = setsockopt(sockfd, SOL_TLS, TLS_TX, &info_send, sizeof(info_send));
    if (ret < 0) {
        printf("Couldn't set TLS_TX option on tcp tls module: %d %s\n", ret, strerror(errno));
        return ret;
    }

    ret = setsockopt(sockfd, SOL_TLS, TLS_RX, &info_read, sizeof(info_read));
    if (ret < 0) {
        printf("Couldn't set TLS_RX option values on tcp tls module: %d %s\n", ret, strerror(errno));
        return ret;
    }

    return 0;
}
