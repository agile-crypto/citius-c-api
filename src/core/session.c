/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct agc_session {
    agc_ctx              *ctx;
    char                  *operation_id;       /* owned, always non-NULL once created */
    agc_crypto_operation   operation;
    char                  *selected_template;  /* owned, optional */
    void                  *impl_state;
    struct agc_session_ops ops;
    int                    is_open;             /* 0 once cancelled/finalised: gates further
                                                  * Update/Final-shaped calls */
    int                    destroyed;           /* 0 until ops.destroy(impl_state) has actually
                                                  * run: gates the destructor, independently of
                                                  * is_open -- see agc__session_force_close() */
};

static atomic_ullong g_session_counter = 0;

static char *generate_operation_id(void)
{
    unsigned long long n = atomic_fetch_add(&g_session_counter, 1);
    char *buf = malloc(48);
    if (!buf) return NULL;
    snprintf(buf, 48, "agc-sess-%llu-%p", n, (void *)buf);
    return buf;
}

agc_rc agc__session_create(agc_ctx *ctx, agc_crypto_operation op,
                            const char *caller_operation_id, void *impl_state,
                            const struct agc_session_ops *ops, agc_session **out)
{
    if (!ctx || !out) return AGC_ERR_INVALID_ARGUMENT;
    *out = NULL;

    struct agc_session *s = calloc(1, sizeof(*s));
    if (!s) return AGC_ERR_OUT_OF_MEMORY;

    s->ctx = ctx;
    s->operation = op;
    s->impl_state = impl_state;
    if (ops) s->ops = *ops;
    s->is_open = 1;
    s->operation_id = caller_operation_id ? strdup(caller_operation_id) : generate_operation_id();
    if (!s->operation_id) {
        free(s);
        return AGC_ERR_OUT_OF_MEMORY;
    }

    agc_rc rc = agc__ctx_register_session(ctx, s);
    if (rc != AGC_OK) {
        free(s->operation_id);
        free(s);
        return rc;
    }

    *out = s;
    return AGC_OK;
}

void *agc__session_impl_state(agc_session *s)
{
    return s ? s->impl_state : NULL;
}

void agc__session_set_selected_template(agc_session *s, const char *tmpl)
{
    if (!s) return;
    free(s->selected_template);
    s->selected_template = tmpl ? strdup(tmpl) : NULL;
}

agc_ctx *agc__session_ctx(agc_session *s)
{
    return s ? s->ctx : NULL;
}

int agc__session_is_open(const agc_session *s)
{
    return s ? s->is_open : 0;
}

void agc__session_mark_closed(agc_session *s)
{
    if (s) s->is_open = 0;
}

void agc__session_force_close(agc_session *s)
{
    if (!s) return;
    /* Gated on `destroyed`, not `is_open`: a family's successful Final call
     * (e.g. agc_encrypt_final) marks the session closed via
     * agc__session_mark_closed() well before agc_session_free() runs, and
     * that must NOT skip the destructor -- it would leak the impl_state's
     * key material and buffers on every cleanly-finalised session, which is
     * the common case, not the exception. `destroyed` makes running the
     * destructor idempotent regardless of how many times force_close is
     * invoked (agc_session_cancel() then agc_session_free(), or
     * agc_ctx_close() sweeping a session the caller never freed). */
    if (!s->destroyed && s->ops.destroy) {
        s->ops.destroy(s->impl_state);
    }
    s->destroyed = 1;
    s->is_open = 0;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

const char *agc_session_id(const agc_session *s)
{
    return s ? s->operation_id : NULL;
}

agc_crypto_operation agc_session_operation(const agc_session *s)
{
    return s ? s->operation : AGC_CRYPTO_OPERATION_UNSPECIFIED;
}

const char *agc_session_selected_template_id(const agc_session *s)
{
    return s ? s->selected_template : NULL;
}

agc_rc agc_session_cancel(agc_session *s, const char *reason)
{
    /* reason is recorded in the audit trail on a real deployment; EMBEDDED
     * mode has no audit sink yet (RECONCILIATION_PLAN.md §9.4), so it is
     * accepted and currently discarded rather than silently dropped from
     * the signature. */
    (void)reason;
    if (!s) return AGC_OK; /* cancelling nothing is not an error */
    agc__session_force_close(s);
    return AGC_OK;
}

void agc_session_free(agc_session *s)
{
    if (!s) return;
    agc__session_force_close(s);
    agc__ctx_unregister_session(s->ctx, s);
    free(s->operation_id);
    free(s->selected_template);
    free(s);
}

agc_rc agc_session_attach(agc_ctx *ctx, const char *operation_id, agc_session **out_session)
{
    if (!ctx || !operation_id || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    agc_session *found = agc__ctx_find_session(ctx, operation_id);
    if (!found) {
        agc__set_error(AGC_ERR_CRYPTO_OPERATION_EXPIRED, "no session with that operation_id",
                        "caas.crypto.v1", "CRYPTO_ERROR_OPERATION_EXPIRED", NULL, 0, NULL);
        return AGC_ERR_CRYPTO_OPERATION_EXPIRED;
    }
    *out_session = found;
    return AGC_OK;
}
