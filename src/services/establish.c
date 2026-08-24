/* SPDX-License-Identifier: Apache-2.0
 *
 * establish.c — KeyEstablishmentService (6 RPCs). Every function here
 * produces a new named key via agc__keystore_import() (which stores
 * caller-supplied bytes under a name/template, exactly what "record the
 * result under a new name" means here regardless of whether the bytes came
 * from unwrapping, deriving, agreeing, or decapsulating).
 */
#define _POSIX_C_SOURCE 200809L /* strdup, unused directly but kept for consistency with siblings */
#include "agc_internal.h"
#include "agc_establish.h"
#include "agc_key.h"
#include "../stub/stub_crypto.h"

#include <stdlib.h>
#include <string.h>

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

/* --------------------------------------------------------------------------
 * WrapKey / UnwrapKey
 * -------------------------------------------------------------------------- */

static agc_rc wrap_context_bytes(const agc_wrap_params *p, const uint8_t **out_p, size_t *out_len)
{
    switch (p->kind) {
    case AGC_WRAP_PARAMS_NO_PARAMS: *out_p = NULL; *out_len = 0; return AGC_OK;
    case AGC_WRAP_PARAMS_KA_WRAP: *out_p = p->u.ka_wrap.shared_info.data; *out_len = p->u.ka_wrap.shared_info.len; return AGC_OK;
    case AGC_WRAP_PARAMS_GOST: *out_p = p->u.gost.ukm.data; *out_len = p->u.gost.ukm.len; return AGC_OK;
    case AGC_WRAP_PARAMS_VENDOR: *out_p = p->u.vendor.raw_params.data; *out_len = p->u.vendor.raw_params.len; return AGC_OK;
    default: return AGC_ERR_INVALID_ARGUMENT;
    }
}

agc_rc agc_wrap_key(agc_ctx *ctx, const agc_wrap_key_params *p, agc_buf out_wrapped, size_t *out_len,
                     agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !p || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (p->struct_size == 0 || !p->key_to_wrap_name || !*p->key_to_wrap_name ||
        !p->wrapping_key_name || !*p->wrapping_key_name || !p->params) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    if (p->params->kind == AGC_WRAP_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *wctx; size_t wctx_len;
    agc_rc rc = wrap_context_bytes(p->params, &wctx, &wctx_len);
    if (rc != AGC_OK) return rc;

    uint8_t *kek = NULL; size_t kek_len = 0; uint32_t kek_version = 0;
    rc = agc__keystore_get_secret(ctx, p->wrapping_key_name, 0, &kek, &kek_len, &kek_version);
    if (rc != AGC_OK) return rc;

    uint8_t *target = NULL; size_t target_len = 0; uint32_t target_version = 0;
    rc = agc__keystore_get_secret(ctx, p->key_to_wrap_name, 0, &target, &target_len, &target_version);
    if (rc != AGC_OK) { agc_secure_zero(kek, kek_len); free(kek); return rc; }

    size_t needed = target_len + AGC_STUB_TAG_LEN;
    *out_len = needed;
    if (out_wrapped.data == NULL) {
        agc_secure_zero(kek, kek_len); free(kek);
        agc_secure_zero(target, target_len); free(target);
        return AGC_OK;
    }
    if (out_wrapped.cap < needed) {
        agc_secure_zero(kek, kek_len); free(kek);
        agc_secure_zero(target, target_len); free(target);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t nonce[AGC_STUB_NONCE_LEN];
    rc = agc__stub_random(nonce, sizeof(nonce));
    if (rc == AGC_OK) {
        agc__stub_aead_encrypt(kek, kek_len, nonce, sizeof(nonce), wctx, wctx_len,
                                target, target_len, out_wrapped.data, out_wrapped.data + target_len);
    }
    agc_secure_zero(kek, kek_len); free(kek);
    agc_secure_zero(target, target_len); free(target);
    if (rc != AGC_OK) return rc;

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = kek_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = p->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_AEAD;
        mb.out.aead.nonce = (agc_slice){nonce, sizeof(nonce)};
        mb.out.aead.tag_length_bytes = AGC_STUB_TAG_LEN;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_unwrap_key(agc_ctx *ctx, const agc_unwrap_key_params *p, agc_key_info **out_key, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !p || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (p->struct_size == 0 || !p->wrapping_key_name || !*p->wrapping_key_name ||
        !p->unwrapped_key_name || !*p->unwrapped_key_name || !p->metadata || !p->params) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    if (p->params->kind == AGC_WRAP_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    if (p->wrapped_key.len < AGC_STUB_TAG_LEN) return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;

    const uint8_t *wctx; size_t wctx_len;
    agc_rc rc = wrap_context_bytes(p->params, &wctx, &wctx_len);
    if (rc != AGC_OK) return rc;

    uint32_t want_version = agc_metadata_key_version(p->metadata);
    uint8_t *kek = NULL; size_t kek_len = 0; uint32_t kek_version = 0;
    rc = agc__keystore_get_secret(ctx, p->wrapping_key_name, want_version, &kek, &kek_len, &kek_version);
    if (rc != AGC_OK) return rc;

    uint8_t nonce[64]; size_t nonce_len = sizeof(nonce);
    rc = agc_metadata_aead_nonce(p->metadata, (agc_buf){nonce, sizeof(nonce)}, &nonce_len);
    if (rc != AGC_OK) { agc_secure_zero(kek, kek_len); free(kek); return rc; }

    size_t plain_len = p->wrapped_key.len - AGC_STUB_TAG_LEN;
    uint8_t *recovered = malloc(plain_len ? plain_len : 1);
    if (!recovered) { agc_secure_zero(kek, kek_len); free(kek); return AGC_ERR_OUT_OF_MEMORY; }

    int ok = agc__stub_aead_decrypt(kek, kek_len, nonce, nonce_len, wctx, wctx_len,
                                     p->wrapped_key.data, plain_len,
                                     p->wrapped_key.data + plain_len, recovered);
    agc_secure_zero(kek, kek_len); free(kek);
    if (!ok) {
        agc_secure_zero(recovered, plain_len); free(recovered);
        return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;
    }

    rc = agc__keystore_import(ctx, p->unwrapped_key_name, NULL, (agc_slice){recovered, plain_len},
                               p->unwrapped_key_template_id ? p->unwrapped_key_template_id : "stub-unwrapped-v1",
                               out_key);
    agc_secure_zero(recovered, plain_len);
    free(recovered);
    if (rc != AGC_OK) return rc;

    if (out_md) return agc__build_no_output_metadata(kek_version, p->user_context, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * DeriveKey
 * -------------------------------------------------------------------------- */

/* Flattens whichever KDF params arm is set into a single context buffer for
 * the stub's keyed expansion. Not a real per-algorithm KDF construction
 * (HKDF-Extract-and-Expand, PBKDF2 iteration, Argon2 memory-hardness, ...)
 * -- see src/stub/stub_crypto.h's header comment on what is and is not
 * real here. */
static agc_rc kdf_context_bytes(const agc_kdf_params *p, uint8_t **out_buf, size_t *out_len)
{
    *out_buf = NULL; *out_len = 0;
    agc_slice a = {0}, b2 = {0};
    switch (p->kind) {
    case AGC_KDF_PARAMS_HKDF:
        a = p->u.hkdf.salt.present ? p->u.hkdf.salt.slice : (agc_slice){0};
        b2 = p->u.hkdf.info;
        break;
    case AGC_KDF_PARAMS_PBKDF2:
        a = p->u.pbkdf2.password;
        b2 = p->u.pbkdf2.salt.present ? p->u.pbkdf2.salt.slice : (agc_slice){0};
        break;
    case AGC_KDF_PARAMS_ARGON2:
        a = p->u.argon2.password;
        b2 = p->u.argon2.salt.present ? p->u.argon2.salt.slice : (agc_slice){0};
        break;
    case AGC_KDF_PARAMS_ECDH:
        a = p->u.ecdh.shared_info;
        break;
    case AGC_KDF_PARAMS_X942_DH:
        a = p->u.x942_dh.other_info;
        break;
    case AGC_KDF_PARAMS_TLS_PRF:
        a = p->u.tls_prf.label;
        b2 = p->u.tls_prf.seed;
        break;
    case AGC_KDF_PARAMS_TLS12:
        a = (agc_slice){p->u.tls12.client_random, 32};
        b2 = (agc_slice){p->u.tls12.server_random, 32};
        break;
    case AGC_KDF_PARAMS_SP800_108:
        break; /* repeated data_params: folded in as empty context for the stub */
    case AGC_KDF_PARAMS_GOST:
        a = p->u.gost.ukm;
        break;
    case AGC_KDF_PARAMS_X3DH:
        a = p->u.x3dh.context;
        break;
    case AGC_KDF_PARAMS_VENDOR:
        a = p->u.vendor.raw_params;
        break;
    default:
        return AGC_ERR_INVALID_ARGUMENT;
    }
    size_t total = a.len + b2.len;
    uint8_t *buf = total ? malloc(total) : NULL;
    if (total && !buf) return AGC_ERR_OUT_OF_MEMORY;
    if (a.len) memcpy(buf, a.data, a.len);
    if (b2.len) memcpy(buf + a.len, b2.data, b2.len);
    *out_buf = buf;
    *out_len = total;
    return AGC_OK;
}

agc_rc agc_derive_key(agc_ctx *ctx, const agc_derive_key_params *p, agc_key_info **out_key, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !p || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (p->struct_size == 0 || !p->base_key_name || !*p->base_key_name ||
        !p->derived_key_name || !*p->derived_key_name || !p->params) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    if (p->params->kind == AGC_KDF_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    uint8_t *base = NULL; size_t base_len = 0; uint32_t base_version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->base_key_name, 0, &base, &base_len, &base_version);
    if (rc != AGC_OK) return rc;

    uint8_t *kdf_ctx = NULL; size_t kdf_ctx_len = 0;
    rc = kdf_context_bytes(p->params, &kdf_ctx, &kdf_ctx_len);
    if (rc != AGC_OK) { agc_secure_zero(base, base_len); free(base); return rc; }

    uint8_t derived[32];
    agc__stub_expand(base, base_len, kdf_ctx, kdf_ctx_len, derived, sizeof(derived));
    free(kdf_ctx);
    agc_secure_zero(base, base_len);
    free(base);

    rc = agc__keystore_import(ctx, p->derived_key_name, p->policy,
                               (agc_slice){derived, sizeof(derived)}, "stub-derived-v1", out_key);
    agc_secure_zero(derived, sizeof(derived));
    if (rc != AGC_OK) return rc;

    if (out_md) return agc__build_no_output_metadata(base_version, p->user_context, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * KeyAgreement
 * -------------------------------------------------------------------------- */

agc_rc agc_key_agreement(agc_ctx *ctx, const agc_key_agreement_params *p,
                          agc_key_info **out_key, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !p || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (p->struct_size == 0 || !p->private_key_name || !*p->private_key_name ||
        !p->shared_secret_name || !*p->shared_secret_name || !p->params) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    /* agreement_params is a strict subset of kdf_params on the wire
     * (Ecdh/X942Dh/X3dh/Vendor) -- reject the rest at runtime rather than
     * duplicating a near-identical union (RECONCILIATION_PLAN.md §4.4). */
    switch (p->params->kind) {
    case AGC_KDF_PARAMS_ECDH:
    case AGC_KDF_PARAMS_X942_DH:
    case AGC_KDF_PARAMS_X3DH:
    case AGC_KDF_PARAMS_VENDOR:
        break;
    default:
        return AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS;
    }

    uint8_t *priv = NULL; size_t priv_len = 0; uint32_t priv_version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, p->private_key_name, 0, &priv, &priv_len, &priv_version);
    if (rc != AGC_OK) return rc;

    uint8_t *kdf_ctx = NULL; size_t kdf_ctx_len = 0;
    rc = kdf_context_bytes(p->params, &kdf_ctx, &kdf_ctx_len);
    if (rc != AGC_OK) { agc_secure_zero(priv, priv_len); free(priv); return rc; }

    /* Fold in the peer's public key material too: a real ECDH shared
     * secret depends on both sides' key material, not just ours. */
    size_t total_ctx_len = kdf_ctx_len + p->peer_public_key.len;
    uint8_t *combined = malloc(total_ctx_len ? total_ctx_len : 1);
    if (!combined) {
        free(kdf_ctx); agc_secure_zero(priv, priv_len); free(priv);
        return AGC_ERR_OUT_OF_MEMORY;
    }
    if (kdf_ctx_len) memcpy(combined, kdf_ctx, kdf_ctx_len);
    if (p->peer_public_key.len) memcpy(combined + kdf_ctx_len, p->peer_public_key.data, p->peer_public_key.len);
    free(kdf_ctx);

    uint8_t shared[32];
    agc__stub_expand(priv, priv_len, combined, total_ctx_len, shared, sizeof(shared));
    free(combined);
    agc_secure_zero(priv, priv_len);
    free(priv);

    rc = agc__keystore_import(ctx, p->shared_secret_name, NULL, (agc_slice){shared, sizeof(shared)},
                               p->shared_secret_template_id ? p->shared_secret_template_id : "stub-shared-secret-v1",
                               out_key);
    agc_secure_zero(shared, sizeof(shared));
    if (rc != AGC_OK) return rc;

    if (out_md) return agc__build_no_output_metadata(priv_version, p->user_context, out_md);
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * EncapsulateKey / DecapsulateKey
 *
 * The stub has no real KEM (no lattice math); it uses the recipient's
 * "public key" bytes (which, per keystore.c, are themselves just random
 * bytes generated for asymmetric-shaped scopes) as a shared secret seed
 * XORed against a fresh random value, transported as the "ciphertext". This
 * proves the API's shape and ownership rules -- a genuinely new key is
 * created on each side and neither returns raw key material -- without
 * claiming any post-quantum security property.
 * -------------------------------------------------------------------------- */

agc_rc agc_encapsulate_key(agc_ctx *ctx, const agc_encapsulate_params *p,
                            agc_buf out_ciphertext, size_t *out_len,
                            agc_key_info **out_key, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !p || !out_len || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (p->struct_size == 0 || !p->recipient_public_key_name || !*p->recipient_public_key_name ||
        !p->shared_secret_name || !*p->shared_secret_name) {
        return AGC_ERR_INVALID_ARGUMENT;
    }

    agc_key_info *recipient = NULL;
    agc_rc rc = agc__keystore_read(ctx, p->recipient_public_key_name, 0, &recipient);
    if (rc != AGC_OK) return rc;

    uint8_t pub[64]; size_t pub_len = sizeof(pub);
    rc = agc_key_info_public_key(recipient, (agc_buf){pub, sizeof(pub)}, &pub_len);
    agc_key_info_free(recipient);
    if (rc != AGC_OK) return rc; /* not an asymmetric-shaped key: no public key to encapsulate against */

    *out_len = AGC_STUB_NONCE_LEN; /* the "KEM ciphertext" -- a fresh random value, in this stub */
    if (out_ciphertext.data == NULL) return AGC_OK;
    if (out_ciphertext.cap < AGC_STUB_NONCE_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    rc = agc__stub_random(out_ciphertext.data, AGC_STUB_NONCE_LEN);
    if (rc != AGC_OK) return rc;

    uint8_t shared[32];
    agc__stub_expand(pub, pub_len, out_ciphertext.data, AGC_STUB_NONCE_LEN, shared, sizeof(shared));

    rc = agc__keystore_import(ctx, p->shared_secret_name, NULL, (agc_slice){shared, sizeof(shared)},
                               p->shared_secret_template_id ? p->shared_secret_template_id : "stub-shared-secret-v1",
                               out_key);
    agc_secure_zero(shared, sizeof(shared));
    if (rc != AGC_OK) return rc;

    if (out_md) return agc__build_no_output_metadata(0, p->user_context, out_md);
    return AGC_OK;
}

agc_rc agc_decapsulate_key(agc_ctx *ctx, const agc_decapsulate_params *p,
                            agc_key_info **out_key, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !p || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (p->struct_size == 0 || !p->private_key_name || !*p->private_key_name ||
        !p->shared_secret_name || !*p->shared_secret_name || !p->ciphertext.data) {
        return AGC_ERR_INVALID_ARGUMENT;
    }

    /* Deliberately does not take a KEM algorithm parameter (matching the
     * proto: metadata is unauthenticated, so the algorithm is resolved from
     * the private key's own template) -- in this stub, that resolution is a
     * no-op since there is only one "KEM" construction. */
    agc_key_info *me = NULL;
    agc_rc rc = agc__keystore_read(ctx, p->private_key_name, 0, &me);
    if (rc != AGC_OK) return rc;

    uint8_t pub[64]; size_t pub_len = sizeof(pub);
    rc = agc_key_info_public_key(me, (agc_buf){pub, sizeof(pub)}, &pub_len);
    agc_key_info_free(me);
    if (rc != AGC_OK) return rc;

    uint8_t shared[32];
    agc__stub_expand(pub, pub_len, p->ciphertext.data, p->ciphertext.len, shared, sizeof(shared));

    rc = agc__keystore_import(ctx, p->shared_secret_name, NULL, (agc_slice){shared, sizeof(shared)},
                               p->shared_secret_template_id ? p->shared_secret_template_id : "stub-shared-secret-v1",
                               out_key);
    agc_secure_zero(shared, sizeof(shared));
    if (rc != AGC_OK) return rc;

    if (out_md) return agc__build_no_output_metadata(0, p->user_context, out_md);
    return AGC_OK;
}
