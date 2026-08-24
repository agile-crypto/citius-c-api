/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L /* strdup (POSIX.1-2008), mlock/pthread_atfork (POSIX.1-2001) */
#include "agc_internal.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#define AGC_HAVE_MLOCK 1
#endif

struct agc_ctx {
    agc_mode      mode;
    atomic_int    poisoned;
    pthread_mutex_t mutex;

    char         *endpoint;
    char         *catalog_path;
    char         *default_policy;
    char         *provider_config_path;
    uint32_t      session_idle_ttl_seconds;
    int           require_locked_memory;
    int           fips_mode;
    uint8_t      *caller_identity;
    size_t        caller_identity_len;

    agc_session **sessions;
    size_t        session_count;
    size_t        session_cap;

    struct agc_ctx *fork_prev;
    struct agc_ctx *fork_next;
};

/* --------------------------------------------------------------------------
 * Global fork registry (D18 / RECONCILIATION_PLAN.md commit 5 scope).
 *
 * fork(2) duplicates the whole address space into the child, including every
 * open agc_ctx. The child must not go on using any of them as if nothing
 * happened -- a DRBG (once one exists, commit 8) reused post-fork by both
 * processes is a real cryptographic hazard, and provider connections may not
 * even be valid in the child. The pthread_atfork child handler below marks
 * every registered context POISONED; every future operation on it must check
 * that flag first and fail with AGC_ERR_INVALID_HANDLE. Recovery is
 * agc_ctx_reinit_after_fork(), which builds a brand-new context (fresh mutex,
 * fresh session list) from the poisoned one's configuration.
 * -------------------------------------------------------------------------- */

static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct agc_ctx *g_registry_head = NULL;
static pthread_once_t  g_atfork_once = PTHREAD_ONCE_INIT;

static void atfork_prepare(void) { pthread_mutex_lock(&g_registry_mutex); }
static void atfork_parent(void) { pthread_mutex_unlock(&g_registry_mutex); }

static void atfork_child(void)
{
    for (struct agc_ctx *c = g_registry_head; c; c = c->fork_next) {
        atomic_store(&c->poisoned, 1);
    }
    /* Do not touch any ctx->mutex here: whichever thread held it (if any) no
     * longer exists in the child, and every future access to a poisoned
     * context is required to check the flag before ever attempting the
     * lock (see agc__ctx_is_poisoned() calls below), so the stale mutex is
     * simply never touched again. */
    pthread_mutex_unlock(&g_registry_mutex);
}

static void install_atfork(void) { pthread_atfork(atfork_prepare, atfork_parent, atfork_child); }
static void ensure_atfork_installed(void) { pthread_once(&g_atfork_once, install_atfork); }

static void registry_add(struct agc_ctx *ctx)
{
    pthread_mutex_lock(&g_registry_mutex);
    ctx->fork_next = g_registry_head;
    ctx->fork_prev = NULL;
    if (g_registry_head) g_registry_head->fork_prev = ctx;
    g_registry_head = ctx;
    pthread_mutex_unlock(&g_registry_mutex);
}

static void registry_remove(struct agc_ctx *ctx)
{
    pthread_mutex_lock(&g_registry_mutex);
    if (ctx->fork_prev) ctx->fork_prev->fork_next = ctx->fork_next;
    else g_registry_head = ctx->fork_next;
    if (ctx->fork_next) ctx->fork_next->fork_prev = ctx->fork_prev;
    pthread_mutex_unlock(&g_registry_mutex);
}

static int ctx_is_poisoned(const struct agc_ctx *ctx)
{
    return atomic_load(&((struct agc_ctx *)ctx)->poisoned);
}

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

static char *dup_or_null(const char *s) { return s ? strdup(s) : NULL; }

agc_rc agc_ctx_open(const agc_ctx_config *cfg, agc_ctx **out_ctx)
{
    if (!cfg || !out_ctx) return AGC_ERR_INVALID_ARGUMENT;
    *out_ctx = NULL;
    if (cfg->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;

    if (cfg->mode != AGC_MODE_EMBEDDED) {
        agc__set_error(AGC_ERR_NOT_IMPLEMENTED,
                        "only AGC_MODE_EMBEDDED is implemented in this build",
                        NULL, NULL, NULL, 0, NULL);
        return AGC_ERR_NOT_IMPLEMENTED;
    }

    struct agc_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return AGC_ERR_OUT_OF_MEMORY;

    ctx->mode = cfg->mode;
    atomic_init(&ctx->poisoned, 0);

    if (AGC_FIELD_FITS(cfg, endpoint))              ctx->endpoint = dup_or_null(cfg->endpoint);
    if (AGC_FIELD_FITS(cfg, catalog_path))           ctx->catalog_path = dup_or_null(cfg->catalog_path);
    if (AGC_FIELD_FITS(cfg, default_policy))         ctx->default_policy = dup_or_null(cfg->default_policy);
    if (AGC_FIELD_FITS(cfg, provider_config_path))   ctx->provider_config_path = dup_or_null(cfg->provider_config_path);
    if (AGC_FIELD_FITS(cfg, session_idle_ttl_seconds)) ctx->session_idle_ttl_seconds = cfg->session_idle_ttl_seconds;
    if (AGC_FIELD_FITS(cfg, require_locked_memory))  ctx->require_locked_memory = cfg->require_locked_memory;
    if (AGC_FIELD_FITS(cfg, fips_mode))               ctx->fips_mode = cfg->fips_mode;
    if (AGC_FIELD_FITS(cfg, caller_identity) && cfg->caller_identity.data && cfg->caller_identity.len > 0) {
        ctx->caller_identity = malloc(cfg->caller_identity.len);
        if (!ctx->caller_identity) { free(ctx); return AGC_ERR_OUT_OF_MEMORY; }
        memcpy(ctx->caller_identity, cfg->caller_identity.data, cfg->caller_identity.len);
        ctx->caller_identity_len = cfg->caller_identity.len;
    }

#if defined(AGC_HAVE_MLOCK)
    if (ctx->require_locked_memory) {
        void *probe = malloc(4096);
        if (!probe || mlock(probe, 4096) != 0) {
            free(probe);
            agc__set_error(AGC_ERR_INTERNAL, "require_locked_memory requested but mlock() is unavailable",
                            NULL, NULL, NULL, 0, NULL);
            free(ctx->endpoint); free(ctx->catalog_path); free(ctx->default_policy);
            free(ctx->provider_config_path); free(ctx->caller_identity);
            free(ctx);
            return AGC_ERR_INTERNAL;
        }
        munlock(probe, 4096);
        free(probe);
    }
#else
    if (ctx->require_locked_memory) {
        agc__set_error(AGC_ERR_INTERNAL, "require_locked_memory requested but mlock() is not available on this platform",
                        NULL, NULL, NULL, 0, NULL);
        free(ctx->endpoint); free(ctx->catalog_path); free(ctx->default_policy);
        free(ctx->provider_config_path); free(ctx->caller_identity);
        free(ctx);
        return AGC_ERR_INTERNAL;
    }
#endif

    pthread_mutex_init(&ctx->mutex, NULL);
    ensure_atfork_installed();
    registry_add(ctx);

    *out_ctx = ctx;
    return AGC_OK;
}

void agc_ctx_close(agc_ctx *ctx)
{
    if (!ctx) return;
    registry_remove(ctx);

    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->session_count; i++) {
        agc__session_force_close(ctx->sessions[i]);
        /* The session handle itself is caller-owned; if the caller never
         * called agc_session_free() it leaks the handle (not the crypto
         * state, which agc__session_force_close already released) -- the
         * same tradeoff every opaque-handle API makes when a context
         * outlives its handles. */
    }
    free(ctx->sessions);
    ctx->sessions = NULL;
    ctx->session_count = ctx->session_cap = 0;
    pthread_mutex_unlock(&ctx->mutex);
    pthread_mutex_destroy(&ctx->mutex);

    free(ctx->endpoint);
    free(ctx->catalog_path);
    free(ctx->default_policy);
    free(ctx->provider_config_path);
    if (ctx->caller_identity) {
        agc_secure_zero(ctx->caller_identity, ctx->caller_identity_len);
        free(ctx->caller_identity);
    }
    free(ctx);
}

agc_rc agc_ctx_reinit_after_fork(agc_ctx *poisoned, agc_ctx **out_ctx)
{
    if (!poisoned || !out_ctx) return AGC_ERR_INVALID_ARGUMENT;
    *out_ctx = NULL;
    if (!ctx_is_poisoned(poisoned)) return AGC_ERR_INVALID_ARGUMENT;

    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = poisoned->mode;
    cfg.endpoint = poisoned->endpoint;
    cfg.catalog_path = poisoned->catalog_path;
    cfg.default_policy = poisoned->default_policy;
    cfg.provider_config_path = poisoned->provider_config_path;
    cfg.session_idle_ttl_seconds = poisoned->session_idle_ttl_seconds;
    cfg.require_locked_memory = poisoned->require_locked_memory;
    cfg.fips_mode = poisoned->fips_mode;
    cfg.caller_identity.data = poisoned->caller_identity;
    cfg.caller_identity.len = poisoned->caller_identity_len;

    agc_rc rc = agc_ctx_open(&cfg, out_ctx);
    if (rc != AGC_OK) return rc;

    /* The poisoned context's own mutex/session list are never touched again
     * (see atfork_child's comment); it is simply abandoned. A caller that
     * still holds it should stop using it, which agc_ctx_mode()/every other
     * function on it now refuses via AGC_ERR_INVALID_HANDLE. */
    return AGC_OK;
}

agc_mode agc_ctx_mode(const agc_ctx *ctx)
{
    if (!ctx) return AGC_MODE_EMBEDDED;
    return ctx->mode;
}

/* --------------------------------------------------------------------------
 * Internal: poisoning check for later commits' service entry points, and the
 * session registry backing session.c.
 * -------------------------------------------------------------------------- */

int agc__ctx_is_poisoned(const agc_ctx *ctx)
{
    return ctx_is_poisoned(ctx);
}

agc_rc agc__ctx_register_session(agc_ctx *ctx, agc_session *s)
{
    if (!ctx || !s) return AGC_ERR_INVALID_ARGUMENT;
    if (ctx_is_poisoned(ctx)) return AGC_ERR_INVALID_HANDLE;

    pthread_mutex_lock(&ctx->mutex);
    if (ctx->session_count == ctx->session_cap) {
        size_t new_cap = ctx->session_cap ? ctx->session_cap * 2 : 8;
        agc_session **grown = realloc(ctx->sessions, new_cap * sizeof(*grown));
        if (!grown) {
            pthread_mutex_unlock(&ctx->mutex);
            return AGC_ERR_OUT_OF_MEMORY;
        }
        ctx->sessions = grown;
        ctx->session_cap = new_cap;
    }
    ctx->sessions[ctx->session_count++] = s;
    pthread_mutex_unlock(&ctx->mutex);
    return AGC_OK;
}

void agc__ctx_unregister_session(agc_ctx *ctx, agc_session *s)
{
    if (!ctx || !s) return;
    pthread_mutex_lock(&ctx->mutex);
    for (size_t i = 0; i < ctx->session_count; i++) {
        if (ctx->sessions[i] == s) {
            ctx->sessions[i] = ctx->sessions[ctx->session_count - 1];
            ctx->session_count--;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);
}

agc_session *agc__ctx_find_session(agc_ctx *ctx, const char *operation_id)
{
    if (!ctx || !operation_id) return NULL;
    pthread_mutex_lock(&ctx->mutex);
    agc_session *found = NULL;
    for (size_t i = 0; i < ctx->session_count; i++) {
        const char *id = agc_session_id(ctx->sessions[i]);
        if (id && strcmp(id, operation_id) == 0) {
            found = ctx->sessions[i];
            break;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);
    return found;
}
