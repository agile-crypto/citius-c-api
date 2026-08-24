/* SPDX-License-Identifier: Apache-2.0
 *
 * stream.c — StreamingCryptoService (43 RPCs) against the stub backend.
 *
 * All families share one state struct and one accumulator idiom:
 *   - AEAD-shaped (encrypt/decrypt, multi-part and message-based) emit
 *     ciphertext incrementally per chunk via the offset-addressable
 *     keystream (stub_crypto.h), while buffering ciphertext bytes purely so
 *     the tag can be computed once, at Final -- which is what naturally
 *     produces the proto's own "unauthenticated until Final" contract
 *     rather than requiring separate enforcement of it.
 *   - sign/verify/digest/xof buffer the whole message and process it once
 *     at Final, since none of those responses have incremental output to
 *     produce along the way.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_stream.h"
#include "../stub/stub_crypto.h"

#include <stdlib.h>
#include <string.h>

typedef enum stream_family {
    FAMILY_ENCRYPT,
    FAMILY_DECRYPT,
    FAMILY_ENCRYPT_MSG,
    FAMILY_DECRYPT_MSG,
    FAMILY_SIGN,
    FAMILY_VERIFY,
    FAMILY_SIGN_MSG,
    FAMILY_VERIFY_MSG,
    FAMILY_DIGEST,
    FAMILY_XOF
} stream_family;

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

static void accum_free(byte_accum *a)
{
    free(a->data);
    a->data = NULL;
    a->len = a->cap = 0;
}

typedef struct agc_stream_state {
    stream_family family;
    agc_ctx      *ctx;

    uint8_t      *key;
    size_t        key_len;
    uint32_t      key_version;

    /* encrypt/decrypt (AEAD-shaped; NO_PARAMS/XTS/ASYMMETRIC/VENDOR share
     * the same mechanics minus authentication -- see encrypt_params_kind) */
    agc_encrypt_params_kind enc_kind;
    uint8_t      *aad;      size_t aad_len;      /* owned copy: caller's slice is borrowed only for the Init call */
    uint8_t      *label;    size_t label_len;
    uint8_t       tweak[16];
    uint8_t       nonce[16]; size_t nonce_len;    /* current message's nonce/iv */
    uint64_t      offset;                          /* keystream position within the current message */
    byte_accum    ct_accum;                        /* full ciphertext-so-far, for the Final tag computation */
    size_t        released_len;                    /* decrypt only: plaintext bytes already handed to the
                                                      * caller via Update -- see the holdback design note on
                                                      * agc_decrypt_update() below */
    int           message_open;                    /* message-based only: Begin called, not yet finalised */

    /* sign/verify (multi-part and message-based) */
    agc_sign_params_kind sign_kind;
    uint8_t       sign_ctx[255]; uint8_t sign_ctx_len;
    byte_accum    msg_accum;

    /* digest/xof */
    uint32_t      xof_len;
} agc_stream_state;

static void stream_state_destroy(void *p)
{
    agc_stream_state *st = p;
    if (!st) return;
    if (st->key) { agc_secure_zero(st->key, st->key_len); free(st->key); }
    free(st->aad);
    free(st->label);
    accum_free(&st->ct_accum);
    accum_free(&st->msg_accum);
    free(st);
}

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

static agc_rc create_session(agc_ctx *ctx, agc_crypto_operation op, const char *operation_id,
                              stream_family family, agc_stream_state **out_st, agc_session **out_s)
{
    agc_stream_state *st = calloc(1, sizeof(*st));
    if (!st) return AGC_ERR_OUT_OF_MEMORY;
    st->ctx = ctx;
    st->family = family;

    struct agc_session_ops ops = { .destroy = stream_state_destroy };
    agc_rc rc = agc__session_create(ctx, op, operation_id, st, &ops, out_s);
    if (rc != AGC_OK) { free(st); return rc; }
    *out_st = st;
    return AGC_OK;
}

static agc_rc dup_bytes_owned(const uint8_t *p, size_t n, uint8_t **out)
{
    *out = NULL;
    if (n == 0) return AGC_OK;
    *out = malloc(n);
    if (!*out) return AGC_ERR_OUT_OF_MEMORY;
    memcpy(*out, p, n);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * 1. Multi-part encrypt / decrypt
 * -------------------------------------------------------------------------- */

static agc_rc setup_encrypt_common(agc_stream_state *st, const agc_encrypt_params *params)
{
    if (!params || params->kind == AGC_ENCRYPT_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    st->enc_kind = params->kind;
    agc_rc rc = AGC_OK;
    switch (params->kind) {
    case AGC_ENCRYPT_PARAMS_AEAD:
        rc = dup_bytes_owned(params->u.aead.aad.data, params->u.aead.aad.len, &st->aad);
        st->aad_len = params->u.aead.aad.len;
        break;
    case AGC_ENCRYPT_PARAMS_XTS:
        memcpy(st->tweak, params->u.xts.tweak, 16);
        break;
    case AGC_ENCRYPT_PARAMS_ASYMMETRIC:
        rc = dup_bytes_owned(params->u.asymmetric.label.data, params->u.asymmetric.label.len, &st->label);
        st->label_len = params->u.asymmetric.label.len;
        break;
    case AGC_ENCRYPT_PARAMS_NO_PARAMS:
    case AGC_ENCRYPT_PARAMS_VENDOR:
        break;
    default:
        return AGC_ERR_INVALID_ARGUMENT;
    }
    return rc;
}

/* Returns the "nonce-equivalent" bytes to key the stub keystream for the
 * current scope kind (AEAD nonce / block IV / XTS tweak / asymmetric label /
 * empty for vendor), so Update logic is written once and shared. */
static void nonce_equivalent(const agc_stream_state *st, const uint8_t **out_p, size_t *out_len)
{
    switch (st->enc_kind) {
    case AGC_ENCRYPT_PARAMS_AEAD:
    case AGC_ENCRYPT_PARAMS_NO_PARAMS:
        *out_p = st->nonce; *out_len = st->nonce_len; break;
    case AGC_ENCRYPT_PARAMS_XTS:
        *out_p = st->tweak; *out_len = 16; break;
    case AGC_ENCRYPT_PARAMS_ASYMMETRIC:
        *out_p = st->label; *out_len = st->label_len; break;
    default:
        *out_p = NULL; *out_len = 0; break;
    }
}

agc_rc agc_encrypt_init(agc_ctx *ctx, const agc_encrypt_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_ENCRYPT, p->operation_id, FAMILY_ENCRYPT, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }

    st->key = secret; st->key_len = secret_len; st->key_version = version;
    rc = setup_encrypt_common(st, p->params);
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }

    if (p->params->kind == AGC_ENCRYPT_PARAMS_AEAD || p->params->kind == AGC_ENCRYPT_PARAMS_NO_PARAMS) {
        st->nonce_len = (p->params->kind == AGC_ENCRYPT_PARAMS_AEAD) ? AGC_STUB_NONCE_LEN : 16;
        rc = agc__stub_random(st->nonce, st->nonce_len);
        if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }
    }
    return AGC_OK;
}

agc_rc agc_encrypt_update(agc_session *s, agc_slice plaintext_chunk, agc_buf out, size_t *out_len)
{
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_ENCRYPT || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    *out_len = plaintext_chunk.len;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < plaintext_chunk.len) return AGC_ERR_BUFFER_TOO_SMALL;

    const uint8_t *nz; size_t nzl;
    nonce_equivalent(st, &nz, &nzl);
    agc__stub_aead_encrypt_at(st->key, st->key_len, nz, nzl, st->offset,
                               plaintext_chunk.data, plaintext_chunk.len, out.data);
    st->offset += plaintext_chunk.len;

    if (st->enc_kind == AGC_ENCRYPT_PARAMS_AEAD) {
        agc_rc rc = accum_append(&st->ct_accum, out.data, plaintext_chunk.len);
        if (rc != AGC_OK) return rc;
    }
    return AGC_OK;
}

static agc_rc build_no_output_metadata(uint32_t key_version, agc_kv_list user_context, agc_metadata **out_md)
{
    agc__metadata_build mb;
    memset(&mb, 0, sizeof(mb));
    mb.key_version = key_version;
    mb.api_version = AGC_API_VERSION_STRING;
    mb.user_context = user_context;
    mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
    return agc__metadata_create(&mb, out_md);
}

agc_rc agc_encrypt_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_ENCRYPT || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    size_t tag_len = (st->enc_kind == AGC_ENCRYPT_PARAMS_AEAD) ? AGC_STUB_TAG_LEN : 0;
    *out_len = tag_len;
    if (out.data != NULL) {
        if (out.cap < tag_len) return AGC_ERR_BUFFER_TOO_SMALL;
        if (tag_len) {
            agc__stub_tag_from_parts(st->key, st->key_len, st->nonce, st->nonce_len,
                                      st->aad, st->aad_len, st->ct_accum.data, st->ct_accum.len, out.data);
        }
    } else {
        return AGC_OK;
    }

    agc_rc rc = AGC_OK;
    if (out_md) {
        if (st->enc_kind == AGC_ENCRYPT_PARAMS_AEAD) {
            agc__metadata_build mb;
            memset(&mb, 0, sizeof(mb));
            mb.key_version = st->key_version;
            mb.api_version = AGC_API_VERSION_STRING;
            mb.kind = AGC_ALGORITHM_OUTPUT_AEAD;
            mb.out.aead.nonce = (agc_slice){st->nonce, st->nonce_len};
            mb.out.aead.tag_length_bytes = AGC_STUB_TAG_LEN;
            rc = agc__metadata_create(&mb, out_md);
        } else if (st->enc_kind == AGC_ENCRYPT_PARAMS_NO_PARAMS) {
            agc__metadata_build mb;
            memset(&mb, 0, sizeof(mb));
            mb.key_version = st->key_version;
            mb.api_version = AGC_API_VERSION_STRING;
            mb.kind = AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER;
            mb.out.block_cipher.iv = (agc_slice){st->nonce, st->nonce_len};
            rc = agc__metadata_create(&mb, out_md);
        } else {
            rc = build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
        }
    }
    agc__session_mark_closed(s);
    return rc;
}

agc_rc agc_decrypt_init(agc_ctx *ctx, const agc_decrypt_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name || !p->metadata) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint32_t want_version = agc_metadata_key_version(p->metadata);
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, want_version, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_DECRYPT, p->operation_id, FAMILY_DECRYPT, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }

    st->key = secret; st->key_len = secret_len; st->key_version = version;
    rc = setup_encrypt_common(st, p->params);
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }

    if (p->params->kind == AGC_ENCRYPT_PARAMS_AEAD) {
        st->nonce_len = sizeof(st->nonce);
        rc = agc_metadata_aead_nonce(p->metadata, (agc_buf){st->nonce, sizeof(st->nonce)}, &st->nonce_len);
    } else if (p->params->kind == AGC_ENCRYPT_PARAMS_NO_PARAMS) {
        st->nonce_len = sizeof(st->nonce);
        rc = agc_metadata_block_iv(p->metadata, (agc_buf){st->nonce, sizeof(st->nonce)}, &st->nonce_len);
    }
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }
    return AGC_OK;
}

/* AEAD decrypt cannot know which trailing bytes are the tag until the
 * stream ends ("Ciphertext || Tag", and DecryptFinalRequest carries no
 * ciphertext of its own -- verified against messages/encryption.proto, so
 * every byte must already have been submitted via Update by the time Final
 * is called). This mirrors how a real incremental AEAD implementation
 * behaves (e.g. OpenSSL's EVP GCM path): Update releases everything it can
 * be sure is not part of the tag, holding back the last AGC_STUB_TAG_LEN
 * bytes seen so far; Final almost always then has zero new plaintext to
 * release (DecryptFinalResponse.plaintext_final is legitimately empty in
 * the common case) and exists to perform the tag check. */
agc_rc agc_decrypt_update(agc_session *s, agc_slice ciphertext_chunk, agc_buf out, size_t *out_len)
{
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DECRYPT || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    if (st->enc_kind != AGC_ENCRYPT_PARAMS_AEAD) {
        /* No tag to hold back: release everything immediately. */
        *out_len = ciphertext_chunk.len;
        if (out.data == NULL) return AGC_OK;
        if (out.cap < ciphertext_chunk.len) return AGC_ERR_BUFFER_TOO_SMALL;
        const uint8_t *nz; size_t nzl;
        nonce_equivalent(st, &nz, &nzl);
        agc__stub_aead_decrypt_at(st->key, st->key_len, nz, nzl, st->offset,
                                   ciphertext_chunk.data, ciphertext_chunk.len, out.data);
        st->offset += ciphertext_chunk.len;
        return AGC_OK;
    }

    agc_rc rc = accum_append(&st->ct_accum, ciphertext_chunk.data, ciphertext_chunk.len);
    if (rc != AGC_OK) return rc;

    size_t safe_len = (st->ct_accum.len > AGC_STUB_TAG_LEN) ? st->ct_accum.len - AGC_STUB_TAG_LEN : 0;
    size_t releasable = safe_len - st->released_len; /* safe_len >= released_len is a loop invariant */

    *out_len = releasable;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < releasable) return AGC_ERR_BUFFER_TOO_SMALL;

    if (releasable) {
        agc__stub_aead_decrypt_at(st->key, st->key_len, st->nonce, st->nonce_len, st->released_len,
                                   st->ct_accum.data + st->released_len, releasable, out.data);
        st->released_len += releasable;
    }
    return AGC_OK; /* UNAUTHENTICATED OUTPUT until Final -- see agc_stream.h */
}

agc_rc agc_decrypt_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    (void)out; /* always 0 bytes to release here: see the holdback design note above agc_decrypt_update() */
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DECRYPT || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    if (st->enc_kind != AGC_ENCRYPT_PARAMS_AEAD) {
        *out_len = 0;
        agc__session_mark_closed(s);
        if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
        return AGC_OK;
    }

    size_t tail_len = st->ct_accum.len - st->released_len; /* the held-back candidate tag */
    if (tail_len != AGC_STUB_TAG_LEN) {
        agc__session_mark_closed(s);
        return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED; /* too little ciphertext to contain a valid tag */
    }

    uint8_t expected[AGC_STUB_TAG_LEN];
    agc__stub_tag_from_parts(st->key, st->key_len, st->nonce, st->nonce_len, st->aad, st->aad_len,
                              st->ct_accum.data, st->released_len, expected);
    const uint8_t *actual_tag = st->ct_accum.data + st->released_len;
    int ok = agc_ct_equal(expected, actual_tag, AGC_STUB_TAG_LEN);

    agc__session_mark_closed(s);
    *out_len = 0; /* everything decryptable was already released via Update */
    if (!ok) return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;

    if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * 2. Message-based AEAD
 *
 * "One message per session" here is the wire specification's own current
 * limit (no end-of-message marker on *MessageNext; see the agc_stream.h
 * comment on agc_encrypt_message_final()), not a simplification introduced
 * by this implementation. Multiple independent messages are still fully
 * supported via repeated single-shot agc_encrypt_message()/
 * agc_decrypt_message() calls, which need no session at all.
 * -------------------------------------------------------------------------- */

agc_rc agc_encrypt_message_init(agc_ctx *ctx, const agc_encrypt_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_ENCRYPT, p->operation_id, FAMILY_ENCRYPT_MSG, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }

    st->key = secret; st->key_len = secret_len; st->key_version = version;
    st->enc_kind = AGC_ENCRYPT_PARAMS_AEAD; /* this family is "message-based AEAD" by definition */
    (void)p->params; /* per-message associated_data (Begin/Message) governs, not Init-time params */
    return AGC_OK;
}

agc_rc agc_encrypt_message(agc_ctx *ctx, const agc_encrypt_message_request *req,
                            agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name) return AGC_ERR_INVALID_ARGUMENT;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    size_t needed = req->plaintext.len + AGC_STUB_TAG_LEN;
    *out_len = needed;
    if (out.data == NULL) { agc_secure_zero(secret, secret_len); free(secret); return AGC_OK; }
    if (out.cap < needed) {
        agc_secure_zero(secret, secret_len); free(secret);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t nonce[AGC_STUB_NONCE_LEN];
    rc = agc__stub_random(nonce, sizeof(nonce));
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }

    agc__stub_aead_encrypt_at(secret, secret_len, nonce, sizeof(nonce), 0,
                               req->plaintext.data, req->plaintext.len, out.data);
    agc__stub_tag_from_parts(secret, secret_len, nonce, sizeof(nonce),
                              req->associated_data.data, req->associated_data.len,
                              out.data, req->plaintext.len, out.data + req->plaintext.len);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_AEAD;
        mb.out.aead.nonce = (agc_slice){nonce, sizeof(nonce)};
        mb.out.aead.tag_length_bytes = AGC_STUB_TAG_LEN;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_encrypt_message_begin(agc_session *s, agc_slice associated_data, agc_metadata **out_partial_md)
{
    if (out_partial_md) *out_partial_md = NULL;
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_ENCRYPT_MSG || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    if (st->message_open) return AGC_ERR_CRYPTO_INVALID_OPERATION_STATE; /* one message per session, see above */

    free(st->aad);
    agc_rc rc = dup_bytes_owned(associated_data.data, associated_data.len, &st->aad);
    if (rc != AGC_OK) return rc;
    st->aad_len = associated_data.len;

    rc = agc__stub_random(st->nonce, AGC_STUB_NONCE_LEN);
    if (rc != AGC_OK) return rc;
    st->nonce_len = AGC_STUB_NONCE_LEN;
    st->offset = 0;
    accum_free(&st->ct_accum);
    st->message_open = 1;

    if (out_partial_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = st->key_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.kind = AGC_ALGORITHM_OUTPUT_AEAD;
        mb.out.aead.nonce = (agc_slice){st->nonce, st->nonce_len};
        mb.out.aead.tag_length_bytes = AGC_STUB_TAG_LEN;
        return agc__metadata_create(&mb, out_partial_md);
    }
    return AGC_OK;
}

agc_rc agc_encrypt_message_next(agc_session *s, agc_slice plaintext_chunk, agc_buf out, size_t *out_len)
{
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_ENCRYPT_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }

    *out_len = plaintext_chunk.len;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < plaintext_chunk.len) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_aead_encrypt_at(st->key, st->key_len, st->nonce, st->nonce_len, st->offset,
                               plaintext_chunk.data, plaintext_chunk.len, out.data);
    st->offset += plaintext_chunk.len;
    agc_rc rc = accum_append(&st->ct_accum, out.data, plaintext_chunk.len);
    if (rc != AGC_OK) return rc;
    return AGC_OK;
}

agc_rc agc_encrypt_message_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_ENCRYPT_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }

    *out_len = AGC_STUB_TAG_LEN;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < AGC_STUB_TAG_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_tag_from_parts(st->key, st->key_len, st->nonce, st->nonce_len, st->aad, st->aad_len,
                              st->ct_accum.data, st->ct_accum.len, out.data);

    agc_rc rc = AGC_OK;
    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = st->key_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.kind = AGC_ALGORITHM_OUTPUT_AEAD;
        mb.out.aead.nonce = (agc_slice){st->nonce, st->nonce_len};
        mb.out.aead.tag_length_bytes = AGC_STUB_TAG_LEN;
        rc = agc__metadata_create(&mb, out_md);
    }
    agc__session_mark_closed(s); /* tears down the session -- see the header comment */
    return rc;
}

agc_rc agc_decrypt_message_init(agc_ctx *ctx, const agc_decrypt_message_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_DECRYPT, p->operation_id, FAMILY_DECRYPT_MSG, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }

    st->key = secret; st->key_len = secret_len; st->key_version = version;
    st->enc_kind = AGC_ENCRYPT_PARAMS_AEAD;
    (void)p->params;
    return AGC_OK;
}

agc_rc agc_decrypt_message(agc_ctx *ctx, const agc_decrypt_message_request *req,
                            const agc_metadata *metadata, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len || !metadata) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name) return AGC_ERR_INVALID_ARGUMENT;
    if (req->ciphertext.len < AGC_STUB_TAG_LEN) return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;

    uint32_t want_version = agc_metadata_key_version(metadata);
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, req->key_name, want_version, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    size_t pt_len = req->ciphertext.len - AGC_STUB_TAG_LEN;
    *out_len = pt_len;
    if (out.data == NULL) { agc_secure_zero(secret, secret_len); free(secret); return AGC_OK; }
    if (out.cap < pt_len) {
        agc_secure_zero(secret, secret_len); free(secret);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t nonce[64]; size_t nonce_len = sizeof(nonce);
    rc = agc_metadata_aead_nonce(metadata, (agc_buf){nonce, sizeof(nonce)}, &nonce_len);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }

    uint8_t expected_tag[AGC_STUB_TAG_LEN];
    agc__stub_tag_from_parts(secret, secret_len, nonce, nonce_len,
                              req->associated_data.data, req->associated_data.len,
                              req->ciphertext.data, pt_len, expected_tag);
    int ok = agc_ct_equal(expected_tag, req->ciphertext.data + pt_len, AGC_STUB_TAG_LEN);
    agc__stub_aead_decrypt_at(secret, secret_len, nonce, nonce_len, 0, req->ciphertext.data, pt_len, out.data);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (!ok) {
        agc_secure_zero(out.data, pt_len);
        return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;
    }

    if (out_md) return build_no_output_metadata(version, req->user_context, out_md);
    return AGC_OK;
}

agc_rc agc_decrypt_message_begin(agc_session *s, agc_slice associated_data, const agc_metadata *partial_md)
{
    if (!s || !partial_md) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DECRYPT_MSG || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    if (st->message_open) return AGC_ERR_CRYPTO_INVALID_OPERATION_STATE;

    free(st->aad);
    agc_rc rc = dup_bytes_owned(associated_data.data, associated_data.len, &st->aad);
    if (rc != AGC_OK) return rc;
    st->aad_len = associated_data.len;

    st->nonce_len = sizeof(st->nonce);
    rc = agc_metadata_aead_nonce(partial_md, (agc_buf){st->nonce, sizeof(st->nonce)}, &st->nonce_len);
    if (rc != AGC_OK) return rc;

    st->offset = 0;
    st->released_len = 0;
    accum_free(&st->ct_accum);
    st->message_open = 1;
    return AGC_OK;
}

agc_rc agc_decrypt_message_next(agc_session *s, agc_slice ciphertext_chunk, agc_buf out, size_t *out_len)
{
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DECRYPT_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }

    agc_rc rc = accum_append(&st->ct_accum, ciphertext_chunk.data, ciphertext_chunk.len);
    if (rc != AGC_OK) return rc;

    size_t safe_len = (st->ct_accum.len > AGC_STUB_TAG_LEN) ? st->ct_accum.len - AGC_STUB_TAG_LEN : 0;
    size_t releasable = safe_len - st->released_len;

    *out_len = releasable;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < releasable) return AGC_ERR_BUFFER_TOO_SMALL;

    if (releasable) {
        agc__stub_aead_decrypt_at(st->key, st->key_len, st->nonce, st->nonce_len, st->released_len,
                                   st->ct_accum.data + st->released_len, releasable, out.data);
        st->released_len += releasable;
    }
    return AGC_OK; /* UNAUTHENTICATED OUTPUT until agc_decrypt_message_final() */
}

agc_rc agc_decrypt_message_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    (void)out; /* always 0 bytes to release: see agc_decrypt_final() */
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DECRYPT_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }

    size_t tail_len = st->ct_accum.len - st->released_len;
    if (tail_len != AGC_STUB_TAG_LEN) {
        agc__session_mark_closed(s);
        return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;
    }

    uint8_t expected[AGC_STUB_TAG_LEN];
    agc__stub_tag_from_parts(st->key, st->key_len, st->nonce, st->nonce_len, st->aad, st->aad_len,
                              st->ct_accum.data, st->released_len, expected);
    int ok = agc_ct_equal(expected, st->ct_accum.data + st->released_len, AGC_STUB_TAG_LEN);

    *out_len = 0;
    agc__session_mark_closed(s); /* tears down the session -- one message per session, see above */
    if (!ok) return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;

    if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * 3 & 4. Multi-part and message-based signing
 *
 * Neither Init nor Final for multi-part/message-based verify carries a
 * metadata field on the wire (unlike single-shot VerifyRequest) -- see
 * agc_stream.h's comments on agc_verify_init_params and
 * agc_verify_message(). Both therefore always verify against the key's
 * latest version.
 * -------------------------------------------------------------------------- */

static agc_rc sign_context_from_params(agc_stream_state *st, const agc_sign_params *params)
{
    if (!params) return AGC_ERR_INVALID_ARGUMENT;
    switch (params->kind) {
    case AGC_SIGN_PARAMS_NO_CONTEXT:
        st->sign_ctx_len = 0;
        return AGC_OK;
    case AGC_SIGN_PARAMS_DOMAIN_CONTEXT:
        memcpy(st->sign_ctx, params->u.domain_context.context, params->u.domain_context.context_len);
        st->sign_ctx_len = params->u.domain_context.context_len;
        return AGC_OK;
    case AGC_SIGN_PARAMS_VENDOR: {
        size_t n = params->u.vendor.raw_params.len;
        if (n > sizeof(st->sign_ctx)) n = sizeof(st->sign_ctx);
        if (n) memcpy(st->sign_ctx, params->u.vendor.raw_params.data, n);
        st->sign_ctx_len = (uint8_t)n;
        return AGC_OK;
    }
    default:
        return AGC_ERR_INVALID_ARGUMENT;
    }
}

agc_rc agc_sign_init(agc_ctx *ctx, const agc_sign_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name || !p->params) return AGC_ERR_INVALID_ARGUMENT;
    if (p->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_SIGN, p->operation_id, FAMILY_SIGN, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }
    st->key = secret; st->key_len = secret_len; st->key_version = version;

    rc = sign_context_from_params(st, p->params);
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }
    return AGC_OK;
}

agc_rc agc_sign_update(agc_session *s, agc_slice data_chunk)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_SIGN || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    return accum_append(&st->msg_accum, data_chunk.data, data_chunk.len);
}

agc_rc agc_sign_final(agc_session *s, agc_buf out_signature, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_SIGN || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    *out_len = AGC_STUB_SIG_LEN;
    if (out_signature.data == NULL) return AGC_OK;
    if (out_signature.cap < AGC_STUB_SIG_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_sign(st->key, st->key_len, st->sign_ctx, st->sign_ctx_len,
                   st->msg_accum.data, st->msg_accum.len, out_signature.data);
    agc__session_mark_closed(s);
    if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

agc_rc agc_verify_init(agc_ctx *ctx, const agc_verify_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name || !p->params) return AGC_ERR_INVALID_ARGUMENT;
    if (p->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_VERIFY, p->operation_id, FAMILY_VERIFY, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }
    st->key = secret; st->key_len = secret_len; st->key_version = version;

    rc = sign_context_from_params(st, p->params);
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }
    return AGC_OK;
}

agc_rc agc_verify_update(agc_session *s, agc_slice data_chunk)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_VERIFY || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    return accum_append(&st->msg_accum, data_chunk.data, data_chunk.len);
}

agc_rc agc_verify_final(agc_session *s, agc_slice signature, int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0; /* fail-closed (D9) */
    if (out_md) *out_md = NULL;
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_VERIFY || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    int ok = agc__stub_verify(st->key, st->key_len, st->sign_ctx, st->sign_ctx_len,
                               st->msg_accum.data, st->msg_accum.len, signature.data, signature.len);
    agc__session_mark_closed(s);
    if (!ok) return AGC_ERR_CRYPTO_SIGNATURE_INVALID;
    if (out_valid) *out_valid = 1;
    if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

agc_rc agc_sign_message_init(agc_ctx *ctx, const agc_sign_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name || !p->params) return AGC_ERR_INVALID_ARGUMENT;
    if (p->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_SIGN, p->operation_id, FAMILY_SIGN_MSG, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }
    st->key = secret; st->key_len = secret_len; st->key_version = version;

    rc = sign_context_from_params(st, p->params);
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }
    return AGC_OK;
}

agc_rc agc_sign_message(agc_ctx *ctx, const agc_sign_message_request *req,
                         agc_buf out_signature, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name) return AGC_ERR_INVALID_ARGUMENT;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    *out_len = AGC_STUB_SIG_LEN;
    if (out_signature.data == NULL) { agc_secure_zero(secret, secret_len); free(secret); return AGC_OK; }
    if (out_signature.cap < AGC_STUB_SIG_LEN) {
        agc_secure_zero(secret, secret_len); free(secret);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }
    agc__stub_sign(secret, secret_len, NULL, 0, req->message.data, req->message.len, out_signature.data);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (out_md) return build_no_output_metadata(version, req->user_context, out_md);
    return AGC_OK;
}

agc_rc agc_sign_message_begin(agc_session *s)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_SIGN_MSG || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    if (st->message_open) return AGC_ERR_CRYPTO_INVALID_OPERATION_STATE;
    accum_free(&st->msg_accum);
    st->message_open = 1;
    return AGC_OK;
}

agc_rc agc_sign_message_next(agc_session *s, agc_slice message_chunk)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_SIGN_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }
    return accum_append(&st->msg_accum, message_chunk.data, message_chunk.len);
}

agc_rc agc_sign_message_final(agc_session *s, agc_buf out_signature, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_SIGN_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }

    *out_len = AGC_STUB_SIG_LEN;
    if (out_signature.data == NULL) return AGC_OK;
    if (out_signature.cap < AGC_STUB_SIG_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_sign(st->key, st->key_len, NULL, 0, st->msg_accum.data, st->msg_accum.len, out_signature.data);
    agc__session_mark_closed(s); /* one message per session -- see the family header comment */
    if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

agc_rc agc_verify_message_init(agc_ctx *ctx, const agc_verify_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_name || !*p->key_name || !p->params) return AGC_ERR_INVALID_ARGUMENT;
    if (p->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    agc_stream_state *st = NULL;
    rc = create_session(ctx, AGC_CRYPTO_OPERATION_VERIFY, p->operation_id, FAMILY_VERIFY_MSG, &st, out_session);
    if (rc != AGC_OK) { agc_secure_zero(secret, secret_len); free(secret); return rc; }
    st->key = secret; st->key_len = secret_len; st->key_version = version;

    rc = sign_context_from_params(st, p->params);
    if (rc != AGC_OK) { agc_session_free(*out_session); *out_session = NULL; return rc; }
    return AGC_OK;
}

agc_rc agc_verify_message(agc_ctx *ctx, const agc_verify_message_request *req,
                           int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0;
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name) return AGC_ERR_INVALID_ARGUMENT;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;

    int ok = agc__stub_verify(secret, secret_len, NULL, 0,
                               req->message.data, req->message.len, req->signature.data, req->signature.len);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (!ok) return AGC_ERR_CRYPTO_SIGNATURE_INVALID;
    if (out_valid) *out_valid = 1;
    if (out_md) return build_no_output_metadata(version, req->user_context, out_md);
    return AGC_OK;
}

agc_rc agc_verify_message_begin(agc_session *s)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_VERIFY_MSG || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    if (st->message_open) return AGC_ERR_CRYPTO_INVALID_OPERATION_STATE;
    accum_free(&st->msg_accum);
    st->message_open = 1;
    return AGC_OK;
}

agc_rc agc_verify_message_next(agc_session *s, agc_slice message_chunk)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_VERIFY_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }
    return accum_append(&st->msg_accum, message_chunk.data, message_chunk.len);
}

agc_rc agc_verify_message_final(agc_session *s, agc_slice signature, int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0;
    if (out_md) *out_md = NULL;
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_VERIFY_MSG || !agc__session_is_open(s) || !st->message_open) {
        return AGC_ERR_INVALID_HANDLE;
    }

    int ok = agc__stub_verify(st->key, st->key_len, NULL, 0,
                               st->msg_accum.data, st->msg_accum.len, signature.data, signature.len);
    agc__session_mark_closed(s);
    if (!ok) return AGC_ERR_CRYPTO_SIGNATURE_INVALID;
    if (out_valid) *out_valid = 1;
    if (out_md) return build_no_output_metadata(st->key_version, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * 5. Multi-part digest (DigestInit/Update/Key/Final)
 * -------------------------------------------------------------------------- */

agc_rc agc_digest_init(agc_ctx *ctx, const agc_digest_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!p->scope_spec && !p->template_id) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    agc_stream_state *st = NULL;
    agc_rc rc = create_session(ctx, AGC_CRYPTO_OPERATION_DIGEST, p->operation_id, FAMILY_DIGEST, &st, out_session);
    if (rc != AGC_OK) return rc;

    char *tmpl = p->template_id ? strdup(p->template_id) : agc__derive_stub_template_id(p->scope_spec);
    if (tmpl) {
        agc__session_set_selected_template(*out_session, tmpl);
        free(tmpl);
    }
    return AGC_OK;
}

agc_rc agc_digest_update(agc_session *s, agc_slice data_chunk)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DIGEST || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    return accum_append(&st->msg_accum, data_chunk.data, data_chunk.len);
}

agc_rc agc_digest_key(agc_session *s, const char *key_name)
{
    if (!s || !key_name || !*key_name) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DIGEST || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    /* Folds the key's value into the digest without exposing it to the
     * caller (PKCS#11 C_DigestKey): the secret is absorbed directly into
     * the accumulator and zeroized immediately after, never returned. */
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t version = 0;
    agc_rc rc = agc__keystore_get_secret(agc__session_ctx(s), key_name, 0, &secret, &secret_len, &version);
    if (rc != AGC_OK) return rc;
    rc = accum_append(&st->msg_accum, secret, secret_len);
    agc_secure_zero(secret, secret_len);
    free(secret);
    return rc;
}

agc_rc agc_digest_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_DIGEST || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    *out_len = AGC_STUB_DIGEST_LEN;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < AGC_STUB_DIGEST_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_digest(st->msg_accum.data, st->msg_accum.len, out.data);
    agc__session_mark_closed(s);
    if (out_md) return build_no_output_metadata(0, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * 6. Multi-part XOF (XofInit/Update/Final)
 * -------------------------------------------------------------------------- */

agc_rc agc_xof_init(agc_ctx *ctx, const agc_xof_init_params *p, agc_session **out_session)
{
    if (!ctx_usable(ctx) || !p || !out_session) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || p->output_length_bytes == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!p->scope_spec && !p->template_id) return AGC_ERR_INVALID_ARGUMENT;
    *out_session = NULL;

    agc_stream_state *st = NULL;
    agc_rc rc = create_session(ctx, AGC_CRYPTO_OPERATION_UNSPECIFIED, p->operation_id, FAMILY_XOF, &st, out_session);
    if (rc != AGC_OK) return rc;
    st->xof_len = p->output_length_bytes;

    char *tmpl = p->template_id ? strdup(p->template_id) : agc__derive_stub_template_id(p->scope_spec);
    if (tmpl) {
        agc__session_set_selected_template(*out_session, tmpl);
        free(tmpl);
    }
    return AGC_OK;
}

agc_rc agc_xof_update(agc_session *s, agc_slice data_chunk)
{
    if (!s) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_XOF || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;
    return accum_append(&st->msg_accum, data_chunk.data, data_chunk.len);
}

agc_rc agc_xof_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!s || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *st = agc__session_impl_state(s);
    if (!st || st->family != FAMILY_XOF || !agc__session_is_open(s)) return AGC_ERR_INVALID_HANDLE;

    *out_len = st->xof_len;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < st->xof_len) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_xof(st->msg_accum.data, st->msg_accum.len, out.data, st->xof_len);
    agc__session_mark_closed(s);
    if (out_md) return build_no_output_metadata(0, (agc_kv_list){0}, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * 7. Dual-function operations
 *
 * Each takes two typed handles and validates both -- family, openness, and
 * (implicitly, since the states are strongly typed) that neither is some
 * other kind of session -- before touching either, turning "wrong kind" or
 * "already finalised" into one AGC_ERR_INVALID_HANDLE instead of a
 * confusing failure partway through.
 * -------------------------------------------------------------------------- */

agc_rc agc_digest_encrypt_update(agc_session *digest_session, agc_session *encrypt_session,
                                  agc_slice plaintext_chunk, agc_buf out_ciphertext, size_t *out_len)
{
    if (!digest_session || !encrypt_session || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *ds = agc__session_impl_state(digest_session);
    agc_stream_state *es = agc__session_impl_state(encrypt_session);
    if (!ds || ds->family != FAMILY_DIGEST || !agc__session_is_open(digest_session)) return AGC_ERR_INVALID_HANDLE;
    if (!es || es->family != FAMILY_ENCRYPT || !agc__session_is_open(encrypt_session)) return AGC_ERR_INVALID_HANDLE;

    agc_rc rc = accum_append(&ds->msg_accum, plaintext_chunk.data, plaintext_chunk.len);
    if (rc != AGC_OK) return rc;
    return agc_encrypt_update(encrypt_session, plaintext_chunk, out_ciphertext, out_len);
}

agc_rc agc_decrypt_digest_update(agc_session *decrypt_session, agc_session *digest_session,
                                  agc_slice ciphertext_chunk, agc_buf out_plaintext, size_t *out_len)
{
    if (!decrypt_session || !digest_session || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *ds = agc__session_impl_state(decrypt_session);
    agc_stream_state *gs = agc__session_impl_state(digest_session);
    if (!ds || ds->family != FAMILY_DECRYPT || !agc__session_is_open(decrypt_session)) return AGC_ERR_INVALID_HANDLE;
    if (!gs || gs->family != FAMILY_DIGEST || !agc__session_is_open(digest_session)) return AGC_ERR_INVALID_HANDLE;

    agc_rc rc = agc_decrypt_update(decrypt_session, ciphertext_chunk, out_plaintext, out_len);
    if (rc != AGC_OK) return rc;
    if (out_plaintext.data != NULL && *out_len > 0) {
        /* UNAUTHENTICATED OUTPUT: absorbed the same as it is released,
         * before the decrypt session's Final has verified anything. */
        rc = accum_append(&gs->msg_accum, out_plaintext.data, *out_len);
    }
    return rc;
}

agc_rc agc_sign_encrypt_update(agc_session *sign_session, agc_session *encrypt_session,
                                agc_slice plaintext_chunk, agc_buf out_ciphertext, size_t *out_len)
{
    if (!sign_session || !encrypt_session || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *ss = agc__session_impl_state(sign_session);
    agc_stream_state *es = agc__session_impl_state(encrypt_session);
    if (!ss || ss->family != FAMILY_SIGN || !agc__session_is_open(sign_session)) return AGC_ERR_INVALID_HANDLE;
    if (!es || es->family != FAMILY_ENCRYPT || !agc__session_is_open(encrypt_session)) return AGC_ERR_INVALID_HANDLE;

    agc_rc rc = accum_append(&ss->msg_accum, plaintext_chunk.data, plaintext_chunk.len);
    if (rc != AGC_OK) return rc;
    return agc_encrypt_update(encrypt_session, plaintext_chunk, out_ciphertext, out_len);
}

agc_rc agc_decrypt_verify_update(agc_session *decrypt_session, agc_session *verify_session,
                                  agc_slice ciphertext_chunk, agc_buf out_plaintext, size_t *out_len)
{
    if (!decrypt_session || !verify_session || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    agc_stream_state *ds = agc__session_impl_state(decrypt_session);
    agc_stream_state *vs = agc__session_impl_state(verify_session);
    if (!ds || ds->family != FAMILY_DECRYPT || !agc__session_is_open(decrypt_session)) return AGC_ERR_INVALID_HANDLE;
    if (!vs || vs->family != FAMILY_VERIFY || !agc__session_is_open(verify_session)) return AGC_ERR_INVALID_HANDLE;

    agc_rc rc = agc_decrypt_update(decrypt_session, ciphertext_chunk, out_plaintext, out_len);
    if (rc != AGC_OK) return rc;
    if (out_plaintext.data != NULL && *out_len > 0) {
        rc = accum_append(&vs->msg_accum, out_plaintext.data, *out_len);
    }
    return rc;
}
