/* SPDX-License-Identifier: Apache-2.0
 *
 * policystore.c — in-memory policy document store backing agc_policy.h.
 * The document itself is opaque (D-plan §4.5): stored and returned as an
 * uninterpreted string, exactly as the proto's own governance model
 * requires.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_policy.h"
#include "agc_key.h" /* agc_key_info_policy, for the delete referential-integrity check */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct policy_entry {
    char         *name;
    char         *document;
    agc_timestamp created_at;
    agc_timestamp updated_at;
} policy_entry;

struct agc_policystore {
    pthread_mutex_t  mutex;
    policy_entry   **items;
    size_t           count;
    size_t           cap;
};

static agc_timestamp now_timestamp(void)
{
    agc_timestamp ts;
    ts.seconds = (int64_t)time(NULL);
    ts.nanos = 0;
    ts.present = 1;
    return ts;
}

static void free_entry(policy_entry *e)
{
    if (!e) return;
    free(e->name);
    free(e->document);
    free(e);
}

static void *policystore_create(void)
{
    struct agc_policystore *ps = calloc(1, sizeof(*ps));
    if (ps) pthread_mutex_init(&ps->mutex, NULL);
    return ps;
}

static void policystore_destroy(void *p)
{
    struct agc_policystore *ps = p;
    if (!ps) return;
    for (size_t i = 0; i < ps->count; i++) free_entry(ps->items[i]);
    free(ps->items);
    pthread_mutex_destroy(&ps->mutex);
    free(ps);
}

static struct agc_policystore *store_for(agc_ctx *ctx)
{
    return agc__ctx_get_or_create_ext(ctx, AGC_CTX_EXT_POLICYSTORE, policystore_create, policystore_destroy);
}

static policy_entry *find_locked(struct agc_policystore *ps, const char *name)
{
    for (size_t i = 0; i < ps->count; i++) {
        if (strcmp(ps->items[i]->name, name) == 0) return ps->items[i];
    }
    return NULL;
}

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

agc_rc agc_create_policy(agc_ctx *ctx, const char *name, const char *policy_document)
{
    if (!ctx_usable(ctx) || !name || !*name || !policy_document) return AGC_ERR_INVALID_ARGUMENT;
    struct agc_policystore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;

    pthread_mutex_lock(&ps->mutex);
    if (find_locked(ps, name)) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_ALREADY_EXISTS; }

    policy_entry *e = calloc(1, sizeof(*e));
    if (!e) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_OUT_OF_MEMORY; }
    e->name = strdup(name);
    e->document = strdup(policy_document);
    e->created_at = e->updated_at = now_timestamp();

    if (ps->count == ps->cap) {
        size_t new_cap = ps->cap ? ps->cap * 2 : 8;
        policy_entry **grown = realloc(ps->items, new_cap * sizeof(*grown));
        if (!grown) { free_entry(e); pthread_mutex_unlock(&ps->mutex); return AGC_ERR_OUT_OF_MEMORY; }
        ps->items = grown;
        ps->cap = new_cap;
    }
    ps->items[ps->count++] = e;
    pthread_mutex_unlock(&ps->mutex);
    return AGC_OK;
}

agc_rc agc_read_policy(agc_ctx *ctx, const char *name, agc_policy_document *out)
{
    if (!ctx_usable(ctx) || !name || !*name || !out || out->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    struct agc_policystore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;

    pthread_mutex_lock(&ps->mutex);
    policy_entry *e = find_locked(ps, name);
    if (!e) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_CRYPTO_POLICY_NOT_FOUND; }

    char *name_copy = strdup(e->name);
    char *doc_copy = strdup(e->document);
    pthread_mutex_unlock(&ps->mutex);
    if (!name_copy || !doc_copy) { free(name_copy); free(doc_copy); return AGC_ERR_OUT_OF_MEMORY; }

    if (AGC_FIELD_FITS(out, name)) out->name = name_copy; else free((void *)name_copy);
    if (AGC_FIELD_FITS(out, policy_document)) out->policy_document = doc_copy; else free((void *)doc_copy);
    return AGC_OK;
}

void agc_policy_document_release(agc_policy_document *doc)
{
    if (!doc) return;
    free((void *)doc->name);
    free((void *)doc->policy_document);
    doc->name = NULL;
    doc->policy_document = NULL;
}

agc_rc agc_update_policy(agc_ctx *ctx, const char *name, const char *policy_document)
{
    if (!ctx_usable(ctx) || !name || !*name || !policy_document) return AGC_ERR_INVALID_ARGUMENT;
    struct agc_policystore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;

    pthread_mutex_lock(&ps->mutex);
    policy_entry *e = find_locked(ps, name);
    if (!e) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_CRYPTO_POLICY_NOT_FOUND; }
    free(e->document);
    e->document = strdup(policy_document);
    e->updated_at = now_timestamp();
    pthread_mutex_unlock(&ps->mutex);
    return AGC_OK;
}

agc_rc agc_delete_policy(agc_ctx *ctx, const char *name)
{
    if (!ctx_usable(ctx) || !name || !*name) return AGC_ERR_INVALID_ARGUMENT;
    struct agc_policystore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;

    /* Referential integrity: refuse while any live (non-destroyed) key still
     * names this policy. A destroyed key's material is already zeroized and
     * irrecoverable (agc_delete_key's own contract), so its tombstone
     * retaining the policy name for audit purposes must not permanently
     * block deletion of a policy nothing live still governs. */
    agc_key_info **keys = NULL; size_t key_count = 0;
    agc_rc rc = agc__keystore_list(ctx, AGC_KEY_LIFECYCLE_STATE_UNSPECIFIED, &keys, &key_count);
    if (rc == AGC_OK) {
        for (size_t i = 0; i < key_count; i++) {
            agc_key_lifecycle_state state = agc_key_info_lifecycle_state(keys[i]);
            if (state != AGC_KEY_LIFECYCLE_STATE_DESTROYED &&
                state != AGC_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED &&
                strcmp(agc_key_info_policy(keys[i]), name) == 0) {
                rc = AGC_ERR_CRYPTO_POLICY_VIOLATION;
            }
            agc_key_info_free(keys[i]);
        }
        free(keys);
    }
    if (rc == AGC_ERR_CRYPTO_POLICY_VIOLATION) {
        agc__set_error(rc, "policy is still bound to at least one key", "caas.crypto.v1", NULL, NULL, 0, NULL);
        return rc;
    }

    pthread_mutex_lock(&ps->mutex);
    for (size_t i = 0; i < ps->count; i++) {
        if (strcmp(ps->items[i]->name, name) == 0) {
            free_entry(ps->items[i]);
            ps->items[i] = ps->items[ps->count - 1];
            ps->count--;
            pthread_mutex_unlock(&ps->mutex);
            return AGC_OK;
        }
    }
    pthread_mutex_unlock(&ps->mutex);
    return AGC_ERR_CRYPTO_POLICY_NOT_FOUND;
}

/* NOT built on the generic snapshot iterator (agc__iter_*): that one hands
 * ownership of each item OUT to the caller as it is consumed, which fits
 * the opaque-handle iterators (agc_key_iter et al., each item freed with
 * agc_key_info_free()). agc_policy_summary is a plain value struct with no
 * free function of its own, and its documented contract ("strings owned by
 * the iterator, invalidated by the next call") is the opposite ownership
 * direction -- so it gets its own small, direct implementation instead of
 * being forced through a mechanism designed for the other shape. */
struct agc_policy_iter {
    agc_policy_summary *items; /* owned array; each .name is an owned string */
    size_t               count;
    size_t               index;
};

agc_rc agc_list_policies(agc_ctx *ctx, const char *name_prefix, uint32_t page_size, agc_policy_iter **out_iter)
{
    (void)page_size;
    if (!ctx_usable(ctx) || !out_iter) return AGC_ERR_INVALID_ARGUMENT;
    *out_iter = NULL;
    struct agc_policystore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;

    pthread_mutex_lock(&ps->mutex);
    agc_policy_summary *items = ps->count ? calloc(ps->count, sizeof(*items)) : NULL;
    size_t n = 0;
    for (size_t i = 0; i < ps->count; i++) {
        if (name_prefix && strncmp(ps->items[i]->name, name_prefix, strlen(name_prefix)) != 0) continue;
        items[n].name = strdup(ps->items[i]->name);
        items[n].created_at = ps->items[i]->created_at;
        items[n].updated_at = ps->items[i]->updated_at;
        n++;
    }
    pthread_mutex_unlock(&ps->mutex);

    struct agc_policy_iter *it = calloc(1, sizeof(*it));
    if (!it) {
        for (size_t i = 0; i < n; i++) free((void *)items[i].name);
        free(items);
        return AGC_ERR_OUT_OF_MEMORY;
    }
    it->items = items;
    it->count = n;
    *out_iter = it;
    return AGC_OK;
}

agc_rc agc_policy_iter_next(agc_policy_iter *it, agc_policy_summary *out)
{
    if (!it || !out) return AGC_ERR_INVALID_ARGUMENT;
    if (it->index >= it->count) return AGC_ERR_ITERATOR_EXHAUSTED;
    *out = it->items[it->index]; /* borrowed: valid until the next call or agc_policy_iter_free() */
    it->index++;
    return AGC_OK;
}

void agc_policy_iter_free(agc_policy_iter *it)
{
    if (!it) return;
    for (size_t i = 0; i < it->count; i++) free((void *)it->items[i].name);
    free(it->items);
    free(it);
}
