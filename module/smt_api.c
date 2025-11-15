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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "smt.h"

void set_crypto_info(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server) {
    unsigned char client_key_hardcode[16] = {0x8D, 0xD2, 0x30, 0xA7, 0x7A, 0x05, 0xEB, 0x71, 0x15, 0x91, 0x29, 0xBC, 0xBC, 0xF6, 0x42, 0x30};
    unsigned char client_iv_hardcode[12] = {0x87, 0xC6, 0x35, 0xC8, 0x17, 0x87, 0xDE, 0x4A, 0x88, 0x1D, 0xD2, 0xD5};
    unsigned char server_key_hardcode[16] = {0x6C, 0xCF, 0x62, 0xFF, 0x4B, 0xE6, 0x14, 0x85, 0xD8, 0xBA, 0x29, 0xFE, 0x2E, 0x84, 0x7A, 0x7F};
    unsigned char server_iv_hardcode[12] = {0xB9, 0xFA, 0x55, 0x83, 0xD5, 0x8F, 0x85, 0x18, 0xFF, 0xA6, 0x3E, 0x66};
    // SERVER_HANDSHAKE_TRAFFIC_SECRET 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c 362e38b385ae1fd42f52c9bd2bec1504fa533e920fba65d45cd17bd4fa56bfbf
    // CLIENT_HANDSHAKE_TRAFFIC_SECRET 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c 81ae4d383eaaf193b3f87e45fc74f175d6e771c8448175a5ee09a72f6f2dadd8
    // SERVER_TRAFFIC_SECRET_0 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c d0f12781a4b5d275645cd2d31e94d58f79f07f0aa87e9dfeb055a8809cc092d2
    // CLIENT_TRAFFIC_SECRET_0 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c 7c15eefb93991b9419999d04abf2174852dc0033bcd4c635aa3111311125c272

    unsigned char *local_iv = server ? server_iv_hardcode : client_iv_hardcode;
    unsigned char *local_key = server ? server_key_hardcode : client_key_hardcode;
    unsigned char *remote_iv = server ? client_iv_hardcode : server_iv_hardcode;
    unsigned char *remote_key = server ? client_key_hardcode : server_key_hardcode;
    uint64_t local_sequence_number = 0;
    uint64_t remote_sequence_number = 0;

    crypto_info_send->info.version = TLS_1_3_VERSION;
    crypto_info_send->info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info_send->iv, local_iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info_send->rec_seq, &local_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info_send->key, local_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info_send->salt, local_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    crypto_info_read->info.version = TLS_1_3_VERSION;
    crypto_info_read->info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info_read->iv, remote_iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info_read->rec_seq, &remote_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info_read->key, remote_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info_read->salt, remote_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
}

void set_crypto_info_alter(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server) {
    unsigned char client_key_hardcode[16] = {0xE0, 0x47, 0x0E, 0x9F, 0x09, 0x48, 0x27, 0x9B, 0xE9, 0x8B, 0xF3, 0xB1, 0x18, 0x58, 0x4F, 0xB6};
    unsigned char client_iv_hardcode[12] = {0x39, 0x00, 0x8E, 0x2E, 0xFE, 0x3E, 0x37, 0x81, 0xCF, 0x71, 0x66, 0x69};
    unsigned char server_key_hardcode[16] = {0x6A, 0x0D, 0xF9, 0x6B, 0xDD, 0x28, 0x08, 0xF8, 0x3C, 0x4D, 0x70, 0x07, 0x43, 0x4C, 0xE0, 0x38};
    unsigned char server_iv_hardcode[12] = {0xBE, 0x9D, 0x1C, 0xEA, 0xF8, 0xE9, 0x54, 0x23, 0x32, 0x8E, 0xD4, 0x20};

    // CLIENT_HANDSHAKE_TRAFFIC_SECRET (32): A0 C7 C1 3D A3 47 FF 77 9B 1A 14 FC 19 73 93 71 18 0B D3 D3 C5 AA 08 69 AB 8B D6 84 B8 C0 67 63
    // SERVER_HANDSHAKE_TRAFFIC_SECRET (32): C3 B7 53 80 A0 EE 67 4D FF 22 C2 A3 C9 5F 61 3C 0B B5 80 F3 89 01 4D 3A 5C DA FF 1D 1C 5F FA CD
    // CLIENT_TRAFFIC_SECRET_0 (32): 31 AF 3A FA 49 C9 AD AC 6A C0 56 E9 31 95 47 B8 A3 12 04 AC 8A 3A 18 0E 18 54 F4 AC 98 6F 0E D4
    // SERVER_TRAFFIC_SECRET_0 (32): 06 C8 18 9E A7 EB E9 36 F5 5B 63 54 2E 48 87 9E 75 13 E0 28 12 3D F9 58 D6 58 D4 5C 46 58 3B B3
    // CLIENT KEY (16): E0 47 0E 9F 09 48 27 9B E9 8B F3 B1 18 58 4F B6
    // CLIENT IV (12): 39 00 8E 2E FE 3E 37 81 CF 71 66 69
    // SERVER KEY (16): 6A 0D F9 6B DD 28 08 F8 3C 4D 70 07 43 4C E0 38
    // SERVER IV (12): BE 9D 1C EA F8 E9 54 23 32 8E D4 20

    unsigned char *local_iv = server ? server_iv_hardcode : client_iv_hardcode;
    unsigned char *local_key = server ? server_key_hardcode : client_key_hardcode;
    unsigned char *remote_iv = server ? client_iv_hardcode : server_iv_hardcode;
    unsigned char *remote_key = server ? client_key_hardcode : server_key_hardcode;
    uint64_t local_sequence_number = 0;
    uint64_t remote_sequence_number = 0;

    crypto_info_send->info.version = TLS_1_3_VERSION;
    crypto_info_send->info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info_send->iv, local_iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info_send->rec_seq, &local_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info_send->key, local_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info_send->salt, local_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    crypto_info_read->info.version = TLS_1_3_VERSION;
    crypto_info_read->info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info_read->iv, remote_iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info_read->rec_seq, &remote_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info_read->key, remote_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info_read->salt, remote_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
}

void set_crypto_info_tls12(struct tls12_crypto_info_aes_gcm_128 *crypto_info_send, struct tls12_crypto_info_aes_gcm_128 *crypto_info_read, int server) {
    unsigned char client_key_hardcode[16] = {0x8D, 0xD2, 0x30, 0xA7, 0x7A, 0x05, 0xEB, 0x71, 0x15, 0x91, 0x29, 0xBC, 0xBC, 0xF6, 0x42, 0x30};
    unsigned char client_iv_hardcode[4] = {0x87, 0xC6, 0x35, 0xC8};
    unsigned char server_key_hardcode[16] = {0x6C, 0xCF, 0x62, 0xFF, 0x4B, 0xE6, 0x14, 0x85, 0xD8, 0xBA, 0x29, 0xFE, 0x2E, 0x84, 0x7A, 0x7F};
    unsigned char server_iv_hardcode[4] = {0xB9, 0xFA, 0x55, 0x83};
    // SERVER_HANDSHAKE_TRAFFIC_SECRET 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c 362e38b385ae1fd42f52c9bd2bec1504fa533e920fba65d45cd17bd4fa56bfbf
    // CLIENT_HANDSHAKE_TRAFFIC_SECRET 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c 81ae4d383eaaf193b3f87e45fc74f175d6e771c8448175a5ee09a72f6f2dadd8
    // SERVER_TRAFFIC_SECRET_0 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c d0f12781a4b5d275645cd2d31e94d58f79f07f0aa87e9dfeb055a8809cc092d2
    // CLIENT_TRAFFIC_SECRET_0 62b0c35c27be5f002ac005a910360682adebe3697cf47df70f9541f3fa43072c 7c15eefb93991b9419999d04abf2174852dc0033bcd4c635aa3111311125c272

    unsigned char *local_iv = server ? server_iv_hardcode : client_iv_hardcode;
    unsigned char *local_key = server ? server_key_hardcode : client_key_hardcode;
    unsigned char *remote_iv = server ? client_iv_hardcode : server_iv_hardcode;
    unsigned char *remote_key = server ? client_key_hardcode : server_key_hardcode;
    uint64_t local_sequence_number = 0;
    uint64_t remote_sequence_number = 0;

    crypto_info_send->info.version = TLS_1_2_VERSION;
    crypto_info_send->info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info_send->iv, &local_sequence_number, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info_send->rec_seq, &local_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info_send->key, local_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info_send->salt, local_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    crypto_info_read->info.version = TLS_1_2_VERSION;
    crypto_info_read->info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info_read->iv, &remote_sequence_number, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info_read->rec_seq, &remote_sequence_number, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(crypto_info_read->key, remote_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info_read->salt, remote_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
}

int smt_setsockopt_wrapper(int sockfd, uint32_t addr, uint16_t port, int server, int tls13) {
    int ret;
    struct smt_crypto_info smt_info_send, smt_info_read;

    smt_info_send.addr = addr;
    smt_info_read.addr = addr;

    smt_info_send.port = port;
    smt_info_read.port = port;

    if (addr == 0 && port == 0) {
        smt_info_send.reuse = 1;
        smt_info_read.reuse = 1;
    }

    if (tls13)
        set_crypto_info(&(smt_info_send.crypto_info_aes_gcm_128), &(smt_info_read.crypto_info_aes_gcm_128), server);
    else
        set_crypto_info_tls12(&(smt_info_send.crypto_info_aes_gcm_128), &(smt_info_read.crypto_info_aes_gcm_128), server);

    ret = setsockopt(sockfd, SOL_TLS, TLS_TX, &smt_info_send, sizeof(smt_info_send));
    if (ret < 0) {
        printf("Couldn't set TLS_TX option on smt: %d %s\n", ret, strerror(errno));
        return ret;
    }

    ret = setsockopt(sockfd, SOL_TLS, TLS_RX, &smt_info_read, sizeof(smt_info_read));
    if (ret < 0) {
        printf("Couldn't set TLS_RX option values on smt: %d %s\n", ret, strerror(errno));
        return ret;
    }

    return 0;
}

int tcpktls_setsockopt_wrapper(int sockfd, int server, int tls13) {
    int ret;
    struct tls12_crypto_info_aes_gcm_128 crypto_info_send, crypto_info_read;

    if (tls13)
        set_crypto_info(&crypto_info_send, &crypto_info_read, server);
    else
        set_crypto_info_tls12(&crypto_info_send, &crypto_info_read, server);

    ret = setsockopt(sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret) {
        printf("KTLS fail: %s\n", strerror(errno));
        return 1;
    }

    ret = setsockopt(sockfd, SOL_TLS, TLS_TX, &crypto_info_send, sizeof(crypto_info_send));
    if (ret < 0) {
        printf("Couldn't set TLS_TX option on tcp tls module: %d %s\n", ret, strerror(errno));
        return ret;
    }

    ret = setsockopt(sockfd, SOL_TLS, TLS_RX, &crypto_info_read, sizeof(crypto_info_read));
    if (ret < 0) {
        printf("Couldn't set TLS_RX option values on tcp tls module: %d %s\n", ret, strerror(errno));
        return ret;
    }

    return 0;
}
