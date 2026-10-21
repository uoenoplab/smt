// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0+

/* Mocks for the SMT unit tests: the kernel functions that SMT uses and the
 * Homa mocks lack, and smt_sw.c, which these tests leave out: its pools hold
 * no AEAD requests, and encryption and decryption change nothing.
 */

#include "smt_impl.h"
#include "mock.h"

struct kmem_cache {
	unsigned int size;
};

static struct kmem_cache mock_smt_cache;

struct kmem_cache *__kmem_cache_create_args(const char *name,
					    unsigned int object_size,
					    struct kmem_cache_args *args,
					    slab_flags_t flags)
{
	mock_smt_cache.size = object_size;
	return &mock_smt_cache;
}

void kmem_cache_destroy(struct kmem_cache *s)
{
}

void *kmem_cache_alloc_noprof(struct kmem_cache *s, gfp_t flags)
{
	return mock_malloc(s->size, flags, "kfree");
}

void kmem_cache_free(struct kmem_cache *s, void *objp)
{
	mock_free(objp, "kfree");
}

/* SMT's workqueue (smt_wq) runs each work at once: a ctx is freed when its
 * last reference goes. The link wraps queue_work_on (see the Makefile).
 */
static struct workqueue_struct *mock_smt_wq = (struct workqueue_struct *)1;

struct workqueue_struct *alloc_workqueue_noprof(const char *fmt,
						unsigned int flags,
						int max_active, ...)
{
	return mock_smt_wq;
}

void destroy_workqueue(struct workqueue_struct *wq)
{
}

bool __real_queue_work_on(int cpu, struct workqueue_struct *wq,
			  struct work_struct *work);
bool __wrap_queue_work_on(int cpu, struct workqueue_struct *wq,
			  struct work_struct *work)
{
	if (wq != mock_smt_wq)
		return __real_queue_work_on(cpu, wq, work);
	work->func(work);
	return true;
}

/* A pool without AEAD requests, with the reference count of the real one. */
struct smt_sw_context *smt_sw_ctx_alloc(const union tls_crypto_context *info,
					int n)
{
	struct smt_sw_context *sw_ctx = kmalloc(sizeof(*sw_ctx), GFP_KERNEL);

	if (!sw_ctx)
		return ERR_PTR(-ENOMEM);
	refcount_set(&sw_ctx->refs, 1);
	return sw_ctx;
}

void smt_sw_ctx_put(struct smt_sw_context *sw_ctx)
{
	if (sw_ctx && refcount_dec_and_test(&sw_ctx->refs))
		kfree(sw_ctx);
}

int smt_sw_init_rpc(struct homa_rpc *rpc, int tx)
{
	return 0;
}

int smt_sw_encrypt(struct homa_rpc *rpc, u32 rec,
		   const struct homa_frag_filler *pos, int payload_len)
{
	return 0;
}

int smt_sw_decrypt(struct homa_rpc *rpc, struct sk_buff **skbs, int n)
{
	return 0;
}
