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
 * Per-context extension slots: lets each service's backing store (the
 * in-memory key/template/policy/provider stores, commits 7 and 11) attach
 * its own state to a context lazily, without agc_ctx (defined in ctx.c)
 * needing to know any of those types exist. agc_ctx_close() calls every
 * registered destructor exactly once.
 * -------------------------------------------------------------------------- */
typedef enum agc_ctx_ext_slot {
    AGC_CTX_EXT_KEYSTORE = 0,
    AGC_CTX_EXT_TEMPLATESTORE = 1,
    AGC_CTX_EXT_POLICYSTORE = 2,
    AGC_CTX_EXT_PROVIDERSTORE = 3,
    AGC_CTX_EXT_SLOT_COUNT
} agc_ctx_ext_slot;

void  agc__ctx_set_ext(agc_ctx *ctx, agc_ctx_ext_slot slot, void *state, void (*destroy)(void *));
void *agc__ctx_get_ext(agc_ctx *ctx, agc_ctx_ext_slot slot);

/* Atomic get-or-lazily-create: the correct way for a store to attach itself
 * to a context, since checking agc__ctx_get_ext() and then calling
 * agc__ctx_set_ext() as two separate steps races if two threads do it on
 * the same ctx concurrently. */
void *agc__ctx_get_or_create_ext(agc_ctx *ctx, agc_ctx_ext_slot slot,
                                  void *(*create)(void), void (*destroy)(void *));

/* --------------------------------------------------------------------------
 * Stub randomness (src/stub/stub_random.c): a REAL CSPRNG (the OS's, via
 * getrandom()) used for generated key material and GenerateRandom (commit
 * 8). "Stub" describes the cryptographic ALGORITHMS in src/stub/ (AEAD,
 * signing, ...), never the entropy source -- there is no reason to fake
 * that, and every stub key/nonce below depends on it being real.
 * -------------------------------------------------------------------------- */
agc_rc agc__stub_random(uint8_t *out, size_t n);

/* --------------------------------------------------------------------------
 * Key store (src/store/keystore.c), backing agc_key.h (commit 7). One
 * store per context (lazily created via the extension-slot mechanism);
 * every function is internally synchronized and safe to call concurrently
 * from multiple threads on the same ctx (D18).
 * -------------------------------------------------------------------------- */
struct agc_scope_spec; /* fwd decl to avoid pulling in agc_scope.h here */

char *agc__derive_stub_template_id(const struct agc_scope_spec *scope_spec);

agc_rc agc__keystore_create_key(agc_ctx *ctx, const char *name, const char *policy,
                                 const struct agc_scope_spec *scope_spec, const char *template_id,
                                 agc_key_info **out_key);
agc_rc agc__keystore_read(agc_ctx *ctx, const char *name, uint32_t version, agc_key_info **out_key);
agc_rc agc__keystore_list(agc_ctx *ctx, agc_key_lifecycle_state filter_state,
                           agc_key_info ***out_items, size_t *out_count);
agc_rc agc__keystore_delete(agc_ctx *ctx, const char *name);
agc_rc agc__keystore_rotate(agc_ctx *ctx, const char *name, agc_key_info **out_new_key);
agc_rc agc__keystore_transform(agc_ctx *ctx, const char *name, int retain_key_bytes,
                                const struct agc_scope_spec *scope_spec, const char *template_id,
                                agc_key_info **out_key);
agc_rc agc__keystore_update_policy(agc_ctx *ctx, const char *name, const char *new_policy,
                                    agc_key_info **out_key);
agc_rc agc__keystore_update_state(agc_ctx *ctx, const char *name, agc_key_lifecycle_state target,
                                   agc_key_info **out_key);
agc_rc agc__keystore_export(agc_ctx *ctx, const char *name, uint8_t **out_material, size_t *out_len);
agc_rc agc__keystore_import(agc_ctx *ctx, const char *name, const char *policy,
                             agc_slice key_material, const char *template_id, agc_key_info **out_key);

/* Returns an OWNED COPY of the named key's secret material (version 0 =
 * latest), for a service implementation's immediate, transient use in a
 * crypto operation (src/services/crypto.c, commit 8) -- never returned to
 * an external caller directly. The caller of this function must
 * agc_secure_zero() and free() the copy as soon as the operation completes.
 * Fails with AGC_ERR_CRYPTO_KEY_OPERATION_NOT_ALLOWED if the key has been
 * destroyed. */
agc_rc agc__keystore_get_secret(agc_ctx *ctx, const char *name, uint32_t version,
                                 uint8_t **out_secret, size_t *out_len, uint32_t *out_actual_version);

/* --------------------------------------------------------------------------
 * Metadata construction. The public API never lets a caller assemble
 * OperationMetadata field-by-field (it is always "the core's copy of a
 * provider response", per messages/metadata.proto's own framing) -- this is
 * the internal constructor a provider backend (src/stub/, commit 8 onward)
 * uses to hand off a freshly-produced result before it is wrapped in the
 * opaque agc_metadata handle.
 * -------------------------------------------------------------------------- */
typedef struct agc__metadata_build {
    uint32_t     key_version;
    const char  *api_version;    /* borrowed for the call; copied internally, may be NULL */
    agc_kv_list  user_context;   /* borrowed for the call; copied internally */
    const char  *encoding;       /* borrowed for the call; copied internally, may be NULL */

    agc_algorithm_output_kind kind; /* must not be AGC_ALGORITHM_OUTPUT_NONE */
    union {
        struct { agc_slice nonce; uint32_t tag_length_bytes; }      aead;
        struct { agc_slice iv; }                                    block_cipher;
        struct { agc_slice counter_block; uint32_t counter_bits; }  counter_mode;
        struct { agc_slice nonce; agc_slice block_counter; }        stream_cipher;
        struct { agc_slice salt; agc_slice iv; }                    kdf;
        struct { const agc_kb *items; size_t count; }               vendor;
    } out;
} agc__metadata_build;

/* Fails with AGC_ERR_INVALID_ARGUMENT if b->kind == AGC_ALGORITHM_OUTPUT_NONE
 * -- the internal constructor enforces the same "provider must always set
 * the oneof" contract that decode() enforces on stored bytes. */
agc_rc agc__metadata_create(const agc__metadata_build *b, agc_metadata **out_md);

/* Convenience used by every service whose response's metadata is always
 * "no system-generated parameters" (signatures, MACs, key establishment
 * results, ...): builds and wraps an AGC_ALGORITHM_OUTPUT_NO_OUTPUT
 * metadata in one call instead of every call site repeating the same
 * six-line agc__metadata_build boilerplate. */
agc_rc agc__build_no_output_metadata(uint32_t key_version, agc_kv_list user_context, agc_metadata **out_md);

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

/* --------------------------------------------------------------------------
 * Provider store (src/store/providerstore.c), backing agc_provider.h
 * (commit 11). One static ProviderInfo ("stub") plus a real, per-context,
 * mutable store of ProviderInstance registrations.
 * -------------------------------------------------------------------------- */
struct agc_provider_instance_spec;

int agc__provider_is_known(const char *provider_id);
agc_provider_info *agc__make_stub_provider_info(void);
agc_impl_props    *agc__make_stub_impl_props(void);

agc_rc agc__providerstore_register(agc_ctx *ctx, const struct agc_provider_instance_spec *spec,
                                    agc_provider_instance **out_instance);
agc_rc agc__providerstore_get(agc_ctx *ctx, const char *instance_id, agc_provider_instance **out);
agc_rc agc__providerstore_update(agc_ctx *ctx, const struct agc_provider_instance_spec *spec,
                                  agc_provider_instance **out_instance);
agc_rc agc__providerstore_delete(agc_ctx *ctx, const char *instance_id);
agc_rc agc__providerstore_list(agc_ctx *ctx, const char *provider_id_filter, int enabled_only,
                                agc_provider_instance ***out_items, size_t *out_count);

#ifdef __cplusplus
}
#endif
#endif /* AGC_INTERNAL_H */
