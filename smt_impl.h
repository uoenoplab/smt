/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+ */

/* SMT internals. */

#ifndef _SMT_IMPL_H
#define _SMT_IMPL_H

#include <crypto/aead.h>
#include <linux/bits.h>
#include <linux/refcount.h>
#include <linux/scatterlist.h>
#include <linux/unaligned.h>

#include "smt_plumbing.h"
#include "smt_uapi.h"

/* helpers */

#if defined(CONFIG_SMT_HEXDUMP) && !defined(CONFIG_SMT_DEBUG)
#error "CONFIG_SMT_HEXDUMP requires CONFIG_SMT_DEBUG (use: make debug SMT_CFLAGS=-DCONFIG_SMT_HEXDUMP)"
#endif

#if defined(CONFIG_SMT_DEBUG) && defined(CONFIG_SMT_HEXDUMP)
static inline void smt_hexdump(const char *title, const unsigned char *buf,
			       unsigned int len)
{
	char line[16 * 3 + 1];
	unsigned int i, j, n;

	for (i = 0; i < len; i += 16) {
		n = min_t(unsigned int, 16, len - i);
		for (j = 0; j < n; j++)
			snprintf(line + j * 3, 4, "%02x ", buf[i + j]);
		line[n * 3] = '\0';
		pr_info("%s[%04x] %s\n", title, i, line);
	}
}
#else
#define smt_hexdump(...) do {} while (0)
#endif

/* smt structs and macros */

/* Both ciphers share every size but the key's, so the code uses the 128-bit
 * names for them.
 */
static_assert(TLS_CIPHER_AES_GCM_128_IV_SIZE == TLS_CIPHER_AES_GCM_256_IV_SIZE);
static_assert(TLS_CIPHER_AES_GCM_128_SALT_SIZE ==
	      TLS_CIPHER_AES_GCM_256_SALT_SIZE);
static_assert(TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE ==
	      TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
static_assert(TLS_CIPHER_AES_GCM_128_TAG_SIZE == TLS_CIPHER_AES_GCM_256_TAG_SIZE);
static_assert(SMT_RECORD_PRE_MAX ==
	      TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE);
static_assert(SMT_RECORD_POST_MAX == 1 + TLS_CIPHER_AES_GCM_128_TAG_SIZE);

#define SMT_MAX_CRYPT_SG 128

/* Per-ctx (5-tuple) software crypto pool: borrowed/returned per RPC. */
struct smt_sw_crypto {
	struct crypto_aead *tfm;
	struct aead_request *aead_req;
	int aead_req_size;
	/* AAD for one TX record; the sg list can't point at the stack. */
	u8 aad[SMT_RECORD_PRE_MAX];
	struct scatterlist crypt_sg[SMT_MAX_CRYPT_SG];
	struct list_head list;
};

struct smt_sw_context {
	struct list_head crypto_list;
	spinlock_t crypto_list_lock;
	/* The ctx that allocated it plus the ctxs that replace it and keep it. */
	refcount_t refs;
};

/* A direction's key fields; only the key's length differs between
 * AES-GCM-128 and -256, so salt and rec_seq move with it.
 */
static inline bool smt_crypto_256(const union tls_crypto_context *c)
{
	return c->info.cipher_type == TLS_CIPHER_AES_GCM_256;
}

static inline const u8 *smt_crypto_key(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.key : c->aes_gcm_128.key;
}

static inline int smt_crypto_key_size(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? TLS_CIPHER_AES_GCM_256_KEY_SIZE :
				   TLS_CIPHER_AES_GCM_128_KEY_SIZE;
}

static inline const u8 *smt_crypto_iv(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.iv : c->aes_gcm_128.iv;
}

static inline const u8 *smt_crypto_salt(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.salt : c->aes_gcm_128.salt;
}

static inline const u8 *smt_crypto_rec_seq(const union tls_crypto_context *c)
{
	return smt_crypto_256(c) ? c->aes_gcm_256.rec_seq :
				   c->aes_gcm_128.rec_seq;
}

/* smt_sw.c */

struct smt_sw_context *
smt_sw_ctx_alloc(const union tls_crypto_context *info, int n);
void smt_sw_ctx_put(struct smt_sw_context *sw_ctx);

static inline struct smt_sw_context *
smt_sw_ctx_get(struct smt_sw_context *sw_ctx)
{
	refcount_inc(&sw_ctx->refs);
	return sw_ctx;
}

#endif /* _SMT_IMPL_H */
