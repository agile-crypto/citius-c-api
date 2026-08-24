/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_internal.h — cross-translation-unit internals. NOT a public header:
 * not installed, not part of agilecrypto.h, and carries no ABI stability
 * guarantee. Included only by files under src/.
 */
#ifndef AGC_INTERNAL_H
#define AGC_INTERNAL_H

#include "agc_core.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Error reporting: populates the thread-local record that agc_last_error()
 * reads. Every service function that returns a non-OK agc_rc should call
 * this first so the detail record and the return code never disagree.
 * Any pointer argument may be NULL.
 * -------------------------------------------------------------------------- */
void agc__set_error(agc_rc rc, const char *message, const char *domain,
                     const char *reason, const char *provider_id,
                     int64_t provider_code, const char *failed_check);

void agc__clear_error_for_call(void);

/* --------------------------------------------------------------------------
 * Session internals (public shell declared in agc_core.h). A "family"
 * implementation (agc_stream.h, commit 9) owns an opaque impl_state and a
 * destructor; agc_session_free()/_cancel() call the destructor without core
 * knowing anything about encrypt/sign/digest state machines.
 * -------------------------------------------------------------------------- */
struct agc_session_ops {
    /* Called at most once, when the session is freed or cancelled. May be
     * NULL if impl_state needs no cleanup. */
    void (*destroy)(void *impl_state);
};

agc_rc agc__session_create(agc_ctx *ctx, agc_crypto_operation op,
                            const char *caller_operation_id /* may be NULL */,
                            void *impl_state, const struct agc_session_ops *ops,
                            agc_session **out);

void  *agc__session_impl_state(agc_session *s);
void   agc__session_set_selected_template(agc_session *s, const char *tmpl);
agc_ctx *agc__session_ctx(agc_session *s);
/* True if the session has already been cancelled/finalised; family code
 * should reject a second Update/Final with AGC_ERR_CRYPTO_INVALID_OPERATION_STATE. */
int    agc__session_is_open(const agc_session *s);
void   agc__session_mark_closed(agc_session *s);
/* Calls the family destructor (if any) and marks closed, without unlinking
 * from the owning context's registry or freeing the handle itself. Used by
 * agc_ctx_close() to force-close every outstanding session before freeing
 * the array that tracks them. */
void   agc__session_force_close(agc_session *s);

/* --------------------------------------------------------------------------
 * Context-owned session registry, used by session.c so agc_ctx_close() can
 * find and force-close every session derived from a context (D18: "handles
 * derived from a context become invalid when the context is closed").
 * -------------------------------------------------------------------------- */
agc_rc     agc__ctx_register_session(agc_ctx *ctx, agc_session *s);
void       agc__ctx_unregister_session(agc_ctx *ctx, agc_session *s);
agc_session *agc__ctx_find_session(agc_ctx *ctx, const char *operation_id);

/* True if `ctx` was poisoned by a fork() in this process since it was
 * opened. Service entry points landing in later commits should check this
 * before doing any work and fail with AGC_ERR_INVALID_HANDLE if true. */
int agc__ctx_is_poisoned(const agc_ctx *ctx);

/* --------------------------------------------------------------------------
 * Generic snapshot iterator. EMBEDDED mode has no network to page lazily
 * over, so the concrete iterators (agc_key_iter etc., commits 7/11) wrap this
 * rather than reimplementing paging five times: the backing store enumerates
 * its full matching set once at open time, and agc__iter_next() walks it.
 * This is a deliberate simplification over a true lazy per-page fetch; see
 * RECONCILIATION_PLAN.md D12 for why iterators exist at the public API at
 * all (hiding page_token bookkeeping), which holds regardless of how the
 * pages are actually produced underneath.
 * -------------------------------------------------------------------------- */
typedef struct agc_generic_iter agc_generic_iter;
typedef void (*agc_generic_item_free_fn)(void *item);

/* Takes ownership of `items` (an array of `count` owned pointers) and of
 * each item; frees both with `free_fn` (per item) and free() (the array)
 * when the iterator is freed or exhausted-and-freed. */
agc_rc agc__iter_create(void **items, size_t count, agc_generic_item_free_fn free_fn,
                         agc_generic_iter **out);

/* On AGC_OK, *out_item is the next item and ownership transfers to the
 * caller (the iterator no longer frees it). Returns AGC_ERR_ITERATOR_EXHAUSTED
 * at the end. */
agc_rc agc__iter_next(agc_generic_iter *it, void **out_item);

void   agc__iter_free(agc_generic_iter *it);

#ifdef __cplusplus
}
#endif
#endif /* AGC_INTERNAL_H */
