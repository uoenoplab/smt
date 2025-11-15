#include "smt_impl.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

#define KSELFTEST_NOT_MAIN 1m
#include "kselftest_harness.h"

/* It isn't safe to include some header files, such as stdlib, because
 * they conflict with kernel header files. The explicit declarations
 * below replace those header files.
 */

extern void       free(void *ptr);
extern void      *malloc(size_t size);
extern void      *memcpy(void *dest, const void *src, size_t n);

void kfree_sensitive(const void *) {
	return;
}

void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags) {
	return NULL;
}

struct crypto_aead *crypto_alloc_aead(const char *alg_name, u32 type, u32 mask) {
	return NULL;
}

int crypto_aead_setkey(struct crypto_aead *tfm, const u8 *key, unsigned int keylen) {
	return 0;
}

int crypto_aead_setauthsize(struct crypto_aead *tfm, unsigned int authsize) {
	return 0;
}

void sg_init_one(struct scatterlist *, const void *, unsigned int) {
	return;
}

void crypto_req_done(struct crypto_async_request *req, int err) {
	return;
}

int crypto_aead_encrypt(struct aead_request *req) {
	return 0;
}

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len) {
	return 0;
}

void crypto_destroy_tfm(void *mem, struct crypto_tfm *tfm) {
	return;
}

void kmem_cache_free(struct kmem_cache *, void *) {
	return;
}

struct kmem_cache *kmem_cache_create_usercopy(const char *name,
			unsigned int size, unsigned int align,
			slab_flags_t flags,
			unsigned int useroffset, unsigned int usersize,
			void (*ctor)(void *)) {
	return NULL;
}

struct kmem_cache *kmem_cache_create(const char *name, unsigned int size,
			unsigned int align, slab_flags_t flags,
			void (*ctor)(void *)) {
	return NULL;
}

void kmem_cache_destroy(struct kmem_cache *) {
	return;
}

int crypto_aead_decrypt(struct aead_request *req) {
	return 0;
}
