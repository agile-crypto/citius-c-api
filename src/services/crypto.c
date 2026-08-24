/* SPDX-License-Identifier: Apache-2.0
 *
 * crypto.c — CryptoService (12 RPCs), against the stub backend
 * (src/stub/stub_crypto.c) and the key store (src/store/keystore.c).
 *
 * Two RPCs (Digest, Xof) and two more (GenerateRandom, SeedRandom) are
 * genuinely keyless on the wire -- DigestRequest/XofRequest carry
 * scope_spec/template_id, never key_name (verified directly against
 * messages/digest.proto and messages/random.proto) -- so they never touch
 * the key store at all.
 */
#include "agc_internal.h"
#include "agc_crypto.h"
#include "../stub/stub_crypto.h"

#include <stdlib.h>
#include <string.h>

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

/* --------------------------------------------------------------------------
 * Encrypt / Decrypt
 * -------------------------------------------------------------------------- */

agc_rc agc_encrypt(agc_ctx *ctx, const agc_encrypt_request *req,
                    agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_ENCRYPT_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    size_t pt_len = req->plaintext.len;
    agc__metadata_build mb;
    memset(&mb, 0, sizeof(mb));
    mb.key_version = actual_version;
    mb.api_version = AGC_API_VERSION_STRING;
    mb.user_context = req->user_context;

    size_t needed = 0;
    /* Declared at function scope, not inside a switch case: mb.out.*.nonce/
     * iv below borrow from these, and that borrow must still be valid at
     * the agc__metadata_create() call after the switch ends (a case-scoped
     * array would go out of scope first -- a real stack-use-after-scope
     * bug caught by ASan while verifying this commit; ct_encrypt_params
     * still narrows which one is actually used). */
    uint8_t nonce[AGC_STUB_NONCE_LEN];
    uint8_t iv[16];

    switch (req->params->kind) {
    case AGC_ENCRYPT_PARAMS_AEAD: {
        needed = pt_len + AGC_STUB_TAG_LEN;
        if (out.data != NULL) {
            if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
            rc = agc__stub_random(nonce, sizeof(nonce));
            if (rc != AGC_OK) break;
            uint8_t tag[AGC_STUB_TAG_LEN];
            agc__stub_aead_encrypt(secret, secret_len, nonce, sizeof(nonce),
                                    req->params->u.aead.aad.data, req->params->u.aead.aad.len,
                                    req->plaintext.data, pt_len, out.data, tag);
            memcpy(out.data + pt_len, tag, AGC_STUB_TAG_LEN);
            mb.kind = AGC_ALGORITHM_OUTPUT_AEAD;
            mb.out.aead.nonce = (agc_slice){nonce, sizeof(nonce)};
            mb.out.aead.tag_length_bytes = AGC_STUB_TAG_LEN;
        } else {
            mb.kind = AGC_ALGORITHM_OUTPUT_AEAD; /* size query: no metadata needed by the caller yet */
        }
        break;
    }
    case AGC_ENCRYPT_PARAMS_NO_PARAMS: {
        needed = pt_len;
        if (out.data != NULL) {
            if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
            rc = agc__stub_random(iv, sizeof(iv));
            if (rc != AGC_OK) break;
            /* XOR keystream directly into out via the AEAD helper's encrypt
             * path with a zero-length AAD/tag discarded -- reuse the same
             * primitive rather than a third implementation. */
            uint8_t discard_tag[AGC_STUB_TAG_LEN];
            agc__stub_aead_encrypt(secret, secret_len, iv, sizeof(iv), NULL, 0,
                                    req->plaintext.data, pt_len, out.data, discard_tag);
            mb.kind = AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER;
            mb.out.block_cipher.iv = (agc_slice){iv, sizeof(iv)};
        } else {
            mb.kind = AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER;
        }
        break;
    }
    case AGC_ENCRYPT_PARAMS_XTS: {
        needed = pt_len;
        if (out.data != NULL) {
            if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
            uint8_t discard_tag[AGC_STUB_TAG_LEN];
            agc__stub_aead_encrypt(secret, secret_len, req->params->u.xts.tweak, 16, NULL, 0,
                                    req->plaintext.data, pt_len, out.data, discard_tag);
        }
        /* "disk encryption (AES-XTS -- tweak is user-provided)" is
         * explicitly in NoAlgorithmOutput's covers-list in the proto
         * comment: no system-generated parameter exists to report. */
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        break;
    }
    case AGC_ENCRYPT_PARAMS_ASYMMETRIC: {
        needed = pt_len;
        if (out.data != NULL) {
            if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
            uint8_t discard_tag[AGC_STUB_TAG_LEN];
            agc__stub_aead_encrypt(secret, secret_len,
                                    req->params->u.asymmetric.label.data, req->params->u.asymmetric.label.len,
                                    NULL, 0, req->plaintext.data, pt_len, out.data, discard_tag);
        }
        /* "asymmetric encryption (RSA-OAEP, RSA-PKCS1v15)" is also in
         * NoAlgorithmOutput's covers-list. */
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        break;
    }
    case AGC_ENCRYPT_PARAMS_VENDOR: {
        needed = pt_len;
        if (out.data != NULL) {
            if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
            uint8_t discard_tag[AGC_STUB_TAG_LEN];
            agc__stub_aead_encrypt(secret, secret_len, NULL, 0, NULL, 0,
                                    req->plaintext.data, pt_len, out.data, discard_tag);
        }
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        break;
    }
    default:
        rc = AGC_ERR_INVALID_ARGUMENT;
        break;
    }

    agc_secure_zero(secret, secret_len);
    free(secret);
    /* AGC_ERR_BUFFER_TOO_SMALL still reports the required size (D5): an
     * undersized buffer must degrade into a size query, not a truncation.
     * Every other error leaves *out_len untouched -- there is no meaningful
     * size to report for e.g. AGC_ERR_CRYPTO_KEY_NOT_FOUND. */
    if (rc == AGC_ERR_BUFFER_TOO_SMALL) { *out_len = needed; return rc; }
    if (rc != AGC_OK) return rc;

    *out_len = needed;
    if (out.data == NULL) return AGC_OK; /* size query: no metadata yet either */

    if (out_md) {
        rc = agc__metadata_create(&mb, out_md);
        if (rc != AGC_OK) return rc;
    }
    return AGC_OK;
}

agc_rc agc_decrypt(agc_ctx *ctx, const agc_decrypt_request *req,
                    agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!req->key_name || !*req->key_name || !req->params || !req->metadata) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_ENCRYPT_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    uint32_t want_version = agc_metadata_key_version(req->metadata);
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    agc_rc rc = agc__keystore_get_secret(ctx, req->key_name, want_version, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    size_t ct_len = req->ciphertext.len;
    size_t needed = 0;

    switch (req->params->kind) {
    case AGC_ENCRYPT_PARAMS_AEAD: {
        if (ct_len < AGC_STUB_TAG_LEN) { rc = AGC_ERR_CRYPTO_AUTHENTICATION_FAILED; break; }
        needed = ct_len - AGC_STUB_TAG_LEN;
        if (out.data == NULL) break;
        if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }

        uint8_t nonce_buf[64]; size_t nonce_len = sizeof(nonce_buf);
        rc = agc_metadata_aead_nonce(req->metadata, (agc_buf){nonce_buf, sizeof(nonce_buf)}, &nonce_len);
        if (rc != AGC_OK) break;

        const uint8_t *tag = req->ciphertext.data + needed;
        int ok = agc__stub_aead_decrypt(secret, secret_len, nonce_buf, nonce_len,
                                         req->params->u.aead.aad.data, req->params->u.aead.aad.len,
                                         req->ciphertext.data, needed, tag, out.data);
        if (!ok) {
            agc_secure_zero(out.data, needed); /* never release tampered plaintext */
            rc = AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;
        }
        break;
    }
    case AGC_ENCRYPT_PARAMS_NO_PARAMS: {
        needed = ct_len;
        if (out.data == NULL) break;
        if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
        uint8_t iv_buf[64]; size_t iv_len = sizeof(iv_buf);
        rc = agc_metadata_block_iv(req->metadata, (agc_buf){iv_buf, sizeof(iv_buf)}, &iv_len);
        if (rc != AGC_OK) break;
        uint8_t discard_tag[AGC_STUB_TAG_LEN];
        agc__stub_aead_decrypt(secret, secret_len, iv_buf, iv_len, NULL, 0,
                                req->ciphertext.data, needed, discard_tag /* unchecked */, out.data);
        /* No authentication for this family (matches real AES-CBC/CTR: an
         * unauthenticated mode), so the tag comparison above is a
         * self-consistency artefact of reusing agc__stub_aead_decrypt and is
         * deliberately not checked here. */
        break;
    }
    case AGC_ENCRYPT_PARAMS_XTS: {
        needed = ct_len;
        if (out.data == NULL) break;
        if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
        uint8_t discard_tag[AGC_STUB_TAG_LEN];
        agc__stub_aead_decrypt(secret, secret_len, req->params->u.xts.tweak, 16, NULL, 0,
                                req->ciphertext.data, needed, discard_tag, out.data);
        break;
    }
    case AGC_ENCRYPT_PARAMS_ASYMMETRIC: {
        needed = ct_len;
        if (out.data == NULL) break;
        if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
        uint8_t discard_tag[AGC_STUB_TAG_LEN];
        agc__stub_aead_decrypt(secret, secret_len,
                                req->params->u.asymmetric.label.data, req->params->u.asymmetric.label.len,
                                NULL, 0, req->ciphertext.data, needed, discard_tag, out.data);
        break;
    }
    case AGC_ENCRYPT_PARAMS_VENDOR: {
        needed = ct_len;
        if (out.data == NULL) break;
        if (out.cap < needed) { rc = AGC_ERR_BUFFER_TOO_SMALL; break; }
        uint8_t discard_tag[AGC_STUB_TAG_LEN];
        agc__stub_aead_decrypt(secret, secret_len, NULL, 0, NULL, 0,
                                req->ciphertext.data, needed, discard_tag, out.data);
        break;
    }
    default:
        rc = AGC_ERR_INVALID_ARGUMENT;
        break;
    }

    agc_secure_zero(secret, secret_len);
    free(secret);
    if (rc == AGC_ERR_BUFFER_TOO_SMALL) { *out_len = needed; return rc; }
    if (rc != AGC_OK) return rc;

    *out_len = needed;
    if (out.data == NULL) return AGC_OK;

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = agc_metadata_output_kind(req->metadata);
        /* Decrypt's returned metadata echoes what was consumed; commit 9's
         * streaming family and commit 10 both need this same pattern, so it
         * is worth a helper if a third call site appears. */
        switch (mb.kind) {
        case AGC_ALGORITHM_OUTPUT_AEAD: {
            uint8_t nonce_buf[64]; size_t n = sizeof(nonce_buf);
            agc_metadata_aead_nonce(req->metadata, (agc_buf){nonce_buf, sizeof(nonce_buf)}, &n);
            mb.out.aead.nonce = (agc_slice){nonce_buf, n};
            agc_metadata_aead_tag_len(req->metadata, &mb.out.aead.tag_length_bytes);
            rc = agc__metadata_create(&mb, out_md);
            break;
        }
        default:
            mb.kind = mb.kind == AGC_ALGORITHM_OUTPUT_NONE ? AGC_ALGORITHM_OUTPUT_NO_OUTPUT : mb.kind;
            rc = agc__metadata_create(&mb, out_md);
            break;
        }
    }
    return rc;
}

/* --------------------------------------------------------------------------
 * Sign / Verify
 * -------------------------------------------------------------------------- */

static agc_rc sign_context_bytes(const agc_sign_params *p, const uint8_t **out_ctx, size_t *out_len)
{
    switch (p->kind) {
    case AGC_SIGN_PARAMS_NO_CONTEXT: *out_ctx = NULL; *out_len = 0; return AGC_OK;
    case AGC_SIGN_PARAMS_DOMAIN_CONTEXT:
        *out_ctx = p->u.domain_context.context;
        *out_len = p->u.domain_context.context_len;
        return AGC_OK;
    case AGC_SIGN_PARAMS_VENDOR:
        *out_ctx = p->u.vendor.raw_params.data;
        *out_len = p->u.vendor.raw_params.len;
        return AGC_OK;
    default:
        return AGC_ERR_INVALID_ARGUMENT;
    }
}

agc_rc agc_sign(agc_ctx *ctx, const agc_sign_request *req,
                 agc_buf out_signature, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *sctx; size_t sctx_len;
    agc_rc rc = sign_context_bytes(req->params, &sctx, &sctx_len);
    if (rc != AGC_OK) return rc;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    *out_len = AGC_STUB_SIG_LEN;
    if (out_signature.data == NULL) { agc_secure_zero(secret, secret_len); free(secret); return AGC_OK; }
    if (out_signature.cap < AGC_STUB_SIG_LEN) {
        agc_secure_zero(secret, secret_len); free(secret);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }

    agc__stub_sign(secret, secret_len, sctx, sctx_len, req->input.data, req->input.len, out_signature.data);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT; /* signatures: no system-generated params */
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_verify(agc_ctx *ctx, const agc_verify_request *req, int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0; /* fail-closed: cleared before any work (D9) */
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *sctx; size_t sctx_len;
    agc_rc rc = sign_context_bytes(req->params, &sctx, &sctx_len);
    if (rc != AGC_OK) return rc;

    uint32_t want_version = req->metadata ? agc_metadata_key_version(req->metadata) : 0;
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    rc = agc__keystore_get_secret(ctx, req->key_name, want_version, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    int ok = agc__stub_verify(secret, secret_len, sctx, sctx_len,
                               req->input.data, req->input.len, req->signature.data, req->signature.len);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (!ok) return AGC_ERR_CRYPTO_SIGNATURE_INVALID; /* fail-closed (D9): out_valid stays 0 */
    if (out_valid) *out_valid = 1;

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * DigestSign / DigestVerify
 * -------------------------------------------------------------------------- */

agc_rc agc_digest_sign(agc_ctx *ctx, const agc_digest_sign_request *req,
                        agc_buf out_signature, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    if (req->hash_algorithm == AGC_HASH_ALGORITHM_UNSPECIFIED) return AGC_ERR_INVALID_ARGUMENT;

    size_t expected_len = agc_hash_algorithm_output_len(req->hash_algorithm);
    if (expected_len != 0 && req->digest.len != expected_len) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *sctx; size_t sctx_len;
    agc_rc rc = sign_context_bytes(req->params, &sctx, &sctx_len);
    if (rc != AGC_OK) return rc;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    *out_len = AGC_STUB_SIG_LEN;
    if (out_signature.data == NULL) { agc_secure_zero(secret, secret_len); free(secret); return AGC_OK; }
    if (out_signature.cap < AGC_STUB_SIG_LEN) {
        agc_secure_zero(secret, secret_len); free(secret);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }
    agc__stub_sign(secret, secret_len, sctx, sctx_len, req->digest.data, req->digest.len, out_signature.data);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_digest_verify(agc_ctx *ctx, const agc_digest_verify_request *req, int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0;
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_SIGN_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;
    if (req->hash_algorithm == AGC_HASH_ALGORITHM_UNSPECIFIED) return AGC_ERR_INVALID_ARGUMENT;

    size_t expected_len = agc_hash_algorithm_output_len(req->hash_algorithm);
    if (expected_len != 0 && req->digest.len != expected_len) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *sctx; size_t sctx_len;
    agc_rc rc = sign_context_bytes(req->params, &sctx, &sctx_len);
    if (rc != AGC_OK) return rc;

    uint32_t want_version = req->metadata ? agc_metadata_key_version(req->metadata) : 0;
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    rc = agc__keystore_get_secret(ctx, req->key_name, want_version, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    int ok = agc__stub_verify(secret, secret_len, sctx, sctx_len,
                               req->digest.data, req->digest.len, req->signature.data, req->signature.len);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (!ok) return AGC_ERR_CRYPTO_SIGNATURE_INVALID;
    if (out_valid) *out_valid = 1;

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

size_t agc_hash_algorithm_output_len(agc_hash_algorithm h)
{
    switch (h) {
    case AGC_HASH_ALGORITHM_SHA256: return 32;
    case AGC_HASH_ALGORITHM_SHA384: return 48;
    case AGC_HASH_ALGORITHM_SHA512: return 64;
    case AGC_HASH_ALGORITHM_SHA512_256: return 32;
    case AGC_HASH_ALGORITHM_SHA224: return 28;
    case AGC_HASH_ALGORITHM_SHA512_224: return 28;
    case AGC_HASH_ALGORITHM_SHA3_256: return 32;
    case AGC_HASH_ALGORITHM_SHA3_384: return 48;
    case AGC_HASH_ALGORITHM_SHA3_512: return 64;
    case AGC_HASH_ALGORITHM_SHA3_224: return 28;
    case AGC_HASH_ALGORITHM_BLAKE2B_256: return 32;
    case AGC_HASH_ALGORITHM_BLAKE2B_384: return 48;
    case AGC_HASH_ALGORITHM_BLAKE2B_512: return 64;
    case AGC_HASH_ALGORITHM_BLAKE2S_256: return 32;
    case AGC_HASH_ALGORITHM_BLAKE2S_160: return 20;
    case AGC_HASH_ALGORITHM_BLAKE2S_224: return 28;
    case AGC_HASH_ALGORITHM_BLAKE3: return 32; /* default output length; BLAKE3 is an XOF */
    case AGC_HASH_ALGORITHM_GOST_R3411_94: return 32;
    case AGC_HASH_ALGORITHM_GOST_R3411_2012_256: return 32;
    case AGC_HASH_ALGORITHM_GOST_R3411_2012_512: return 64;
    case AGC_HASH_ALGORITHM_SHA1: return 20;  /* deprecated, retained for legacy artifacts */
    case AGC_HASH_ALGORITHM_MD5: return 16;   /* deprecated, retained for legacy artifacts */
    case AGC_HASH_ALGORITHM_SHAKE128:
    case AGC_HASH_ALGORITHM_SHAKE256:
    case AGC_HASH_ALGORITHM_OTHER:
    case AGC_HASH_ALGORITHM_UNSPECIFIED:
    default:
        return 0;
    }
}

/* --------------------------------------------------------------------------
 * GenerateMAC / VerifyMAC
 * -------------------------------------------------------------------------- */

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

agc_rc agc_generate_mac(agc_ctx *ctx, const agc_mac_request *req,
                         agc_buf out_mac, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_MAC_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *cctx; size_t cctx_len;
    agc_rc rc = mac_customization_bytes(req->params, &cctx, &cctx_len);
    if (rc != AGC_OK) return rc;

    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    rc = agc__keystore_get_secret(ctx, req->key_name, 0, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    *out_len = AGC_STUB_MAC_LEN;
    if (out_mac.data == NULL) { agc_secure_zero(secret, secret_len); free(secret); return AGC_OK; }
    if (out_mac.cap < AGC_STUB_MAC_LEN) {
        agc_secure_zero(secret, secret_len); free(secret);
        return AGC_ERR_BUFFER_TOO_SMALL;
    }
    agc__stub_mac(secret, secret_len, cctx, cctx_len, req->message.data, req->message.len, out_mac.data);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_verify_mac(agc_ctx *ctx, const agc_verify_mac_request *req, int *out_valid, agc_metadata **out_md)
{
    if (out_valid) *out_valid = 0;
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || !req->key_name || !*req->key_name || !req->params) return AGC_ERR_INVALID_ARGUMENT;
    if (req->params->kind == AGC_MAC_PARAMS_NONE) return AGC_ERR_INVALID_ARGUMENT;

    const uint8_t *cctx; size_t cctx_len;
    agc_rc rc = mac_customization_bytes(req->params, &cctx, &cctx_len);
    if (rc != AGC_OK) return rc;

    uint32_t want_version = req->metadata ? agc_metadata_key_version(req->metadata) : 0;
    uint8_t *secret = NULL; size_t secret_len = 0; uint32_t actual_version = 0;
    rc = agc__keystore_get_secret(ctx, req->key_name, want_version, &secret, &secret_len, &actual_version);
    if (rc != AGC_OK) return rc;

    int ok = agc__stub_mac_verify(secret, secret_len, cctx, cctx_len,
                                   req->message.data, req->message.len, req->mac.data, req->mac.len);
    agc_secure_zero(secret, secret_len);
    free(secret);

    if (!ok) return AGC_ERR_CRYPTO_AUTHENTICATION_FAILED;
    if (out_valid) *out_valid = 1;

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = actual_version;
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * Digest / Xof -- genuinely keyless on the wire
 * -------------------------------------------------------------------------- */

agc_rc agc_digest(agc_ctx *ctx, const agc_digest_request *req, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!req->scope_spec && !req->template_id) return AGC_ERR_INVALID_ARGUMENT;

    *out_len = AGC_STUB_DIGEST_LEN;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < AGC_STUB_DIGEST_LEN) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_digest(req->data.data, req->data.len, out.data);

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.key_version = 0; /* not applicable: proto's own documented meaning */
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_xof(agc_ctx *ctx, const agc_xof_request *req, agc_buf out, size_t *out_len, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (!ctx_usable(ctx) || !req || !out_len) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!req->scope_spec && !req->template_id) return AGC_ERR_INVALID_ARGUMENT;
    if (req->output_length_bytes == 0) return AGC_ERR_INVALID_ARGUMENT;

    *out_len = req->output_length_bytes;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < req->output_length_bytes) return AGC_ERR_BUFFER_TOO_SMALL;

    agc__stub_xof(req->data.data, req->data.len, out.data, req->output_length_bytes);

    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * Random
 * -------------------------------------------------------------------------- */

agc_rc agc_generate_random(agc_ctx *ctx, const agc_random_request *req,
                            agc_buf out, const char **out_provider_id, agc_metadata **out_md)
{
    if (out_md) *out_md = NULL;
    if (out_provider_id) *out_provider_id = NULL;
    if (!ctx_usable(ctx) || !req) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0 || req->num_bytes == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!out.data || out.cap < req->num_bytes) return AGC_ERR_INVALID_ARGUMENT;

    agc_rc rc = agc__stub_random(out.data, req->num_bytes);
    if (rc != AGC_OK) return rc;

    if (out_provider_id) *out_provider_id = "stub";
    if (out_md) {
        agc__metadata_build mb;
        memset(&mb, 0, sizeof(mb));
        mb.api_version = AGC_API_VERSION_STRING;
        mb.user_context = req->user_context;
        mb.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
        return agc__metadata_create(&mb, out_md);
    }
    return AGC_OK;
}

agc_rc agc_random_bytes(agc_ctx *ctx, uint8_t *out, size_t len)
{
    if (!ctx_usable(ctx) || !out || len == 0) return AGC_ERR_INVALID_ARGUMENT;
    return agc__stub_random(out, len);
}

agc_rc agc_seed_random(agc_ctx *ctx, const agc_seed_random_request *req,
                        int *out_accepted, const char **out_message)
{
    if (out_accepted) *out_accepted = 0;
    if (out_message) *out_message = NULL;
    if (!ctx_usable(ctx) || !req) return AGC_ERR_INVALID_ARGUMENT;
    if (req->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;

    /* Honest answer for this build: the RNG is the OS CSPRNG directly, with
     * no seedable DRBG state to mix caller-supplied entropy into. Declined,
     * not failed -- AGC_OK is still the return code (D-shaped: distinguish
     * "declined" from "failed", which a plain bool cannot). */
    if (out_message) *out_message = "this build's RNG has no seedable DRBG state to mix entropy into";
    return AGC_OK;
}
