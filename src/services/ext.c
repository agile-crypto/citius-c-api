/* SPDX-License-Identifier: Apache-2.0
 *
 * ext.c -- implementations behind agc_ext.h (commit 13, D16). Compiled only
 * when AGC_ENABLE_PROPOSED_EXTENSIONS is on (see CMakeLists.txt); excluded
 * from conformance/rpc_manifest.yaml and both Tier 1b/1c checks by
 * construction (they scan the 7 real service headers, never this one).
 */
#include "agc_internal.h"
#include "agc_ext.h"
#include "../stub/stub_crypto.h"

#include <stdlib.h>
#include <string.h>

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

/* --------------------------------------------------------------------------
 * RFC-01: UpdateKeyState
 * -------------------------------------------------------------------------- */

agc_rc agc_ext_update_key_state(agc_ctx *ctx, const char *name, agc_key_lifecycle_state target,
                                 const char *reason, agc_key_info **out_key)
{
    if (out_key) *out_key = NULL;
    if (!ctx_usable(ctx) || !name || !*name || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    if (target == AGC_KEY_LIFECYCLE_STATE_UNSPECIFIED) return AGC_ERR_INVALID_ARGUMENT;
    if (target == AGC_KEY_LIFECYCLE_STATE_COMPROMISED && (!reason || !*reason)) {
        agc__set_error(AGC_ERR_INVALID_ARGUMENT, "reason is required for a transition into COMPROMISED",
                        "caas.crypto.v1", NULL, NULL, 0, NULL);
        return AGC_ERR_INVALID_ARGUMENT;
    }
    /* reason is otherwise accepted and currently discarded, same posture as
     * agc_session_cancel()'s reason parameter (core, commit 5): there is no
     * audit sink in EMBEDDED mode yet (RECONCILIATION_PLAN.md §9.4). */
    (void)reason;
    return agc__keystore_update_state(ctx, name, target, out_key);
}

/* --------------------------------------------------------------------------
 * RFC-14: CancelOperation
 * -------------------------------------------------------------------------- */

agc_rc agc_ext_cancel_operation(agc_ctx *ctx, const char *operation_id, const char *reason)
{
    if (!ctx_usable(ctx) || !operation_id || !*operation_id) return AGC_ERR_INVALID_ARGUMENT;
    agc_session *s = NULL;
    agc_rc rc = agc_session_attach(ctx, operation_id, &s);
    if (rc != AGC_OK) return rc;
    return agc_session_cancel(s, reason);
}

/* --------------------------------------------------------------------------
 * RFC-13: MAC streaming
 * -------------------------------------------------------------------------- */

typedef struct byte_accum {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} byte_accum;

static agc_rc accum_append(byte_accum *a, const uint8_t *p, size_t n)
{
    if (n == 0) return AGC_OK;
    if (a->len + n > a->cap) {
        size_t new_cap = a->cap ? a->cap * 2 : 64;
        while (new_cap < a->len + n) new_cap *= 2;
        uint8_t *grown = realloc(a->data, new_cap);
        if (!grown) return AGC_ERR_OUT_OF_MEMORY;
        a->data = grown;
        a->cap = new_cap;
    }
    memcpy(a->data + a->len, p, n);
    a->len += n;
    return AGC_OK;
}

typedef struct ext_mac_state {
    int         is_verify;
    uint8_t    *key;
    size_t      key_len;
    uint32_t    key_version;
    uint8_t    *cctx;
    size_t      cctx_len;
    byte_accum  msg_accum;
} ext_mac_state;

static void ext_mac_state_destroy(void *p)
{
    ext_mac_state *st = p;
    if (!st) return;
    if (st->key) { agc_secure_zero(st->key, st->key_len); free(st->key); }
    free(st->cctx);
    free(st->msg_accum.data);
    free(st);
}

static agc_rc mac_customization_bytes(const agc_mac_params *p, const uint8_t **out_ctx, size_t *out_len)
{
    switch (p->kind) {
    case AGC_MAC_PARAMS_NO_PARAMS: *out_ctx = NULL; *out_len = 0; return AGC_OK;
    case AGC_MAC_PARAMS_CUSTOMIZABLE:
        *out_ctx = p->u.customizable.customization.data;
        *out_len = p->u.customizable.customization.len;
        return AGC_OK;
    case AGC_MAC_PARAMS_VENDOR:
        *out_ctx = p->u.vendor.raw_params.data;
        *out_len = p->u.vendor.raw_params.len;
        return AGC_OK;
    default:
        return AGC_ERR_INVALID_ARGUMENT;
    }
}

static agc_rc mac_init(agc_ctx *ctx, const agc_ext_mac_init_params *p, int is_verify,
                        agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name || !p->params) return AGC_ERR_INVALID_ARGUMENT;
    if (p->params->kind == AGC_MAC_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *cctx_borrowed; size_t cctx_len;
    agc_rc rc = mac_customization_bytes(p->params, &cctx_borrowed, &cctx_len);
    if (rc != AGC_OK) return rc;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    ext_mac_state *st = calloc(1, sizeof(*st));
    if (!st) { agc_secure_zero(secret, secret_len); free(secret); return AGC_ERR_OUT_OF_MEMORY; }
    st->is_verify = is_verify;
    st->key = secret;
    st->key_len = secret_len;
    st->key_version = version;
    if (cctx_len > 0) {
        st->cctx = malloc(cctx_len);
        if (!st->cctx) { ext_mac_state_destroy(st); return AGC_ERR_OUT_OF_MEMORY; }
        memcpy(st->cctx, cctx_borrowed, cctx_len);
        st->cctx_len = cctx_len;
    }

    static const struct agc_session_ops ops = { .destroy = ext_mac_state_destroy };
    rc = agc__session_create(ctx, is_verify ? AGC_CRYPTO_OPERATION_VERIFY_MAC : AGC_CRYPTO_OPERATION_GENERATE_MAC,
                              p->operation_id, st, &ops, out_session);
    if (rc != AGC_OK) { ext_mac_state_destroy(st); return rc; }
    return AGC_OK;
}

agc_rc agc_ext_generate_mac_init(agc_ctx *ctx, const agc_ext_mac_init_params *p, agc_session **out_session)
{
    return mac_init(ctx, p, 0, out_session);
}

agc_rc agc_ext_verify_mac_init(agc_ctx *ctx, const agc_ext_mac_init_params *p, agc_session **out_session)
{
    return mac_init(ctx, p, 1, out_session);
}

static agc_rc mac_update(agc_session *s, agc_slice data_chunk, int is_verify)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    ext_mac_state *st = agc__session_impl_state(s);
    if (!st || st->is_verify != is_verify || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    return accum_append(&st->msg_accum, data_chunk.data, data_chunk.len);
}

agc_rc agc_ext_generate_mac_update(agc_session *s, agc_slice data_chunk) { return mac_update(s, data_chunk, 0); }
agc_rc agc_ext_verify_mac_update(agc_session *s, agc_slice data_chunk) { return mac_update(s, data_chunk, 1); }

agc_rc agc_ext_generate_mac_final(agc_session *s, agc_buf out_mac, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    ext_mac_state *st = agc__session_impl_state(s);
    if (!st || st->is_verify || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    *out_len = AGC_STUB_MAC_LEN;
    if (out_mac.data == NULL) return AGC_OK;
    if (out_mac.cap < AGC_STUB_MAC_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_mac(st->key, st->key_len, st->cctx, st->cctx_len,
                  st->msg_accum.data, st->msg_accum.len, out_mac.data);
    uint32_t key_version = st->key_version;
    agc__session_mark_closed(s);
    if (out_md) return agc__build_no_output_metadata(key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

agc_rc agc_ext_verify_mac_final(agc_session *s, agc_slice mac, int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0;
    if (out_md) *out_md = NULL;
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    ext_mac_state *st = agc__session_impl_state(s);
    if (!st || !st->is_verify || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    int ok = agc__stub_mac_verify(st->key, st->key_len, st->cctx, st->cctx_len,
                                   st->msg_accum.data, st->msg_accum.len, mac.data, mac.len);
    uint32_t key_version = st->key_version;
    agc__session_mark_closed(s);
    if (!ok) return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;
    if (out_valid) *out_valid = 1;
    if (out_md) return agc__build_no_output_metadata(key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}
