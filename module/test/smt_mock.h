
void kfree_sensitive(const void *);

void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags);

struct crypto_aead *crypto_alloc_aead(const char *alg_name, u32 type, u32 mask);

int crypto_aead_setkey(struct crypto_aead *tfm, 
						const u8 *key, unsigned int keylen);

int crypto_aead_setauthsize(struct crypto_aead *tfm, unsigned int authsize);

void sg_init_one(struct scatterlist *, const void *, unsigned int);

void crypto_req_done(struct crypto_async_request *req, int err);

int crypto_aead_encrypt(struct aead_request *req);

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);

void crypto_destroy_tfm(void *mem, struct crypto_tfm *tfm);

void kmem_cache_free(struct kmem_cache *, void *);

struct kmem_cache *kmem_cache_create_usercopy(const char *name,
			unsigned int size, unsigned int align,
			slab_flags_t flags,
			unsigned int useroffset, unsigned int usersize,
			void (*ctor)(void *));

struct kmem_cache *kmem_cache_create(const char *name, unsigned int size,
			unsigned int align, slab_flags_t flags,
			void (*ctor)(void *));

void kmem_cache_destroy(struct kmem_cache *);

int crypto_aead_decrypt(struct aead_request *req);
