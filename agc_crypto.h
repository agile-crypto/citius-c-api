/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_crypto.h — CryptoService (12 RPCs): single-shot, stateless operations.
 *
 * THE VERIFICATION CONTRACT
 * -------------------------
 * The proto returns `bool valid` in a successful VerifyResponse. A C binding
 * that copied that shape would create a well-known failure mode:
 *
 *     agc_verify(ctx, ..., &valid);      // rc ignored
 *     if (valid) { accept(); }           // valid is uninitialised on error
 *
 * So verification here is fail-closed twice over:
 *   1. *out_valid is set to 0 BEFORE any work is attempted, so an early error
 *      return can never leave it holding a stale or uninitialised true.
 *   2. A cryptographically invalid signature/MAC returns
 *      AGC_ERR_CRYPTO_SIGNATURE_INVALID / AGC_ERR_CRYPTO_AUTHENTICATION_FAILED
 *      AND sets *out_valid = 0.
 *
 * Both `if (rc != AGC_OK)` and `if (!valid)` are therefore individually
 * sufficient, and a caller who checks neither has written obviously wrong code
 * rather than subtly wrong code. out_valid may be NULL if the caller relies on
 * rc alone. This is a deliberate divergence from the proto's response shape; a
 * gRPC front-end maps AGC_ERR_CRYPTO_SIGNATURE_INVALID back to
 * VerifyResponse{valid:false} rather than to a transport error.
 *
 * BUFFER SIZING
 * -------------
 * Every byte output uses the two-call convention. For callers who cannot afford
 * the double call in a hot loop, agc_*_max_len() gives an upper bound derivable
 * from the key's template without touching the provider.
 */

#ifndef AGC_CRYPTO_H
#define AGC_CRYPTO_H

#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Encrypt / Decrypt
 * -------------------------------------------------------------------------- */

typedef struct agc_encrypt_request {
    size_t                    struct_size;
    const char               *key_name;      /* REQUIRED, 1..256 bytes */
    agc_slice                 plaintext;
    const agc_encrypt_params *params;        /* REQUIRED — the oneof is required */
    agc_kv_list               user_context;  /* optional audit enrichment */
} agc_encrypt_request;

/* *out_md receives the metadata that MUST be stored with the ciphertext; it
 * carries the system-generated nonce/IV without which decryption is impossible.
 * The caller frees it with agc_metadata_free after encoding it for storage. */
AGC_API agc_rc agc_encrypt(agc_ctx *ctx, const agc_encrypt_request *req,
                           agc_buf out, size_t *out_len,
                           agc_metadata **out_md);

typedef struct agc_decrypt_request {
    size_t                    struct_size;
    const char               *key_name;      /* REQUIRED */
    agc_slice                 ciphertext;
    const agc_metadata       *metadata;      /* REQUIRED — from the encrypt call */
    const agc_encrypt_params *params;        /* REQUIRED — must match encryption */
    agc_kv_list               user_context;
} agc_decrypt_request;

/* AEAD tag failure returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED and writes
 * nothing to out. Plaintext is never released on authentication failure. */
AGC_API agc_rc agc_decrypt(agc_ctx *ctx, const agc_decrypt_request *req,
                           agc_buf out, size_t *out_len,
                           agc_metadata **out_md);

/* Upper bound on ciphertext length for plaintext_len bytes under key_name's
 * current template, including any AEAD tag and padding. Lets a caller size a
 * buffer once and reuse it. */
AGC_API agc_rc agc_encrypt_max_len(agc_ctx *ctx, const char *key_name,
                                   size_t plaintext_len, size_t *out_max);

/* --------------------------------------------------------------------------
 * Sign / Verify
 * -------------------------------------------------------------------------- */

typedef struct agc_sign_request {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    agc_slice              input;         /* message; the service hashes it */
    const agc_sign_params *params;        /* REQUIRED — the oneof is required */
    agc_kv_list            user_context;
} agc_sign_request;

AGC_API agc_rc agc_sign(agc_ctx *ctx, const agc_sign_request *req,
                        agc_buf out_signature, size_t *out_len,
                        agc_metadata **out_md);

typedef struct agc_verify_request {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    agc_slice              input;
    agc_slice              signature;
    const agc_metadata    *metadata;      /* carries key_version; REQUIRED after rotation */
    const agc_sign_params *params;        /* REQUIRED — must match signing */
    agc_kv_list            user_context;
} agc_verify_request;

AGC_API agc_rc agc_verify(agc_ctx *ctx, const agc_verify_request *req,
                          int *out_valid, agc_metadata **out_md);

AGC_API agc_rc agc_signature_max_len(agc_ctx *ctx, const char *key_name, size_t *out_max);

/* --------------------------------------------------------------------------
 * DigestSign / DigestVerify — caller supplies a pre-computed digest
 * -------------------------------------------------------------------------- */

typedef struct agc_digest_sign_request {
    size_t                 struct_size;
    const char            *key_name;            /* REQUIRED */
    agc_slice              digest;              /* pre-computed */
    const agc_sign_params *params;              /* REQUIRED */

    /* REQUIRED. Declares which hash produced `digest`. The service validates
     * digest.len against agc_hash_algorithm_output_len(hash_algorithm), which
     * is what stops a SHA-1 digest from being presented as SHA-256 to bypass
     * policy. AGC_HASH_ALGORITHM_UNSPECIFIED is rejected. */
    agc_hash_algorithm     hash_algorithm;

    /* Optional OID. Required in practice when hash_algorithm is
     * AGC_HASH_ALGORITHM_OTHER. When both are given they must agree. */
    const char            *hash_algorithm_oid;

    agc_kv_list            user_context;
} agc_digest_sign_request;

AGC_API agc_rc agc_digest_sign(agc_ctx *ctx, const agc_digest_sign_request *req,
                               agc_buf out_signature, size_t *out_len,
                               agc_metadata **out_md);

typedef struct agc_digest_verify_request {
    size_t                 struct_size;
    const char            *key_name;
    agc_slice              digest;
    agc_slice              signature;
    const agc_metadata    *metadata;
    const agc_sign_params *params;
    agc_hash_algorithm     hash_algorithm;      /* REQUIRED; must match signing */
    const char            *hash_algorithm_oid;
    agc_kv_list            user_context;
} agc_digest_verify_request;

AGC_API agc_rc agc_digest_verify(agc_ctx *ctx, const agc_digest_verify_request *req,
                                 int *out_valid, agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * GenerateMAC / VerifyMAC
 * -------------------------------------------------------------------------- */

typedef struct agc_mac_request {
    size_t                struct_size;
    const char           *key_name;      /* REQUIRED */
    agc_slice             message;
    const agc_mac_params *params;        /* REQUIRED — the oneof is required */
    agc_kv_list           user_context;
} agc_mac_request;

AGC_API agc_rc agc_generate_mac(agc_ctx *ctx, const agc_mac_request *req,
                                agc_buf out_mac, size_t *out_len,
                                agc_metadata **out_md);

typedef struct agc_verify_mac_request {
    size_t                struct_size;
    const char           *key_name;
    agc_slice             message;
    agc_slice             mac;
    const agc_metadata   *metadata;
    const agc_mac_params *params;        /* REQUIRED — must match generation */
    agc_kv_list           user_context;
} agc_verify_mac_request;

/* Comparison is constant-time inside the library. Callers MUST NOT compare
 * MACs themselves; agc_ct_equal exists for the cases where they must. */
AGC_API agc_rc agc_verify_mac(agc_ctx *ctx, const agc_verify_mac_request *req,
                              int *out_valid, agc_metadata **out_md);

AGC_API agc_rc agc_mac_max_len(agc_ctx *ctx, const char *key_name, size_t *out_max);

/* --------------------------------------------------------------------------
 * Digest — keyless, template selected by intent
 * -------------------------------------------------------------------------- */

typedef struct agc_digest_request {
    size_t                struct_size;
    const agc_scope_spec *scope_spec;    /* hash scope; NULL only if template_id set */
    const char           *template_id;   /* explicit; NULL => policy selects */
    agc_slice             data;
    const char           *policy_name;   /* optional validation */
    agc_kv_list           user_context;
} agc_digest_request;

/* out_selected_template (optional) receives a borrowed pointer to the template
 * id the service chose, valid until the next call on this thread. */
AGC_API agc_rc agc_digest(agc_ctx *ctx, const agc_digest_request *req,
                          agc_buf out, size_t *out_len,
                          const char **out_selected_template,
                          agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * XOF — extendable output
 * -------------------------------------------------------------------------- */

typedef struct agc_xof_request {
    size_t                struct_size;
    const agc_scope_spec *scope_spec;           /* hash scope, XOF variant */
    const char           *template_id;
    agc_slice             data;
    uint32_t              output_length_bytes;  /* REQUIRED, 1..1048576 */
    const char           *policy_name;
    agc_kv_list           user_context;
} agc_xof_request;

/* The 1 MiB ceiling from the proto's buf.validate constraint is enforced here
 * too; larger requests return AGC_ERR_INVALID_ARGUMENT rather than being
 * silently truncated. Callers needing more should stream (see agc_xof_init). */
AGC_API agc_rc agc_xof(agc_ctx *ctx, const agc_xof_request *req,
                       agc_buf out, size_t *out_len,
                       const char **out_selected_template,
                       agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * Random
 * -------------------------------------------------------------------------- */

typedef struct agc_random_request {
    size_t      struct_size;
    uint32_t    num_bytes;      /* REQUIRED, 1..1048576 */
    const char *provider_id;    /* NULL => default RNG provider */
    const char *policy_name;    /* optional: governs which RNGs are permitted */
    agc_kv_list user_context;
} agc_random_request;

/* Unlike every other output in this API, the random buffer is exactly
 * num_bytes; no size query is needed and out.cap must be >= num_bytes.
 * out_provider_id (optional) receives the provider that actually served it,
 * which matters for FIPS evidence. */
AGC_API agc_rc agc_generate_random(agc_ctx *ctx, const agc_random_request *req,
                                   agc_buf out,
                                   const char **out_provider_id,
                                   agc_metadata **out_md);

/* Convenience wrapper for the overwhelmingly common case. */
AGC_API agc_rc agc_random_bytes(agc_ctx *ctx, uint8_t *out, size_t len);

typedef struct agc_seed_random_request {
    size_t      struct_size;
    agc_slice   seed;
    const char *provider_id;
    const char *policy_name;
    agc_kv_list user_context;
} agc_seed_random_request;

/* Seed material is MIXED into the DRBG, never used as its sole source
 * (NIST SP 800-90A §8.7.2). Providers that do not accept user entropy return
 * AGC_OK with *out_accepted = 0 and an explanatory message in out_message;
 * this distinguishes "declined" from "failed", which a plain bool would not. */
AGC_API agc_rc agc_seed_random(agc_ctx *ctx, const agc_seed_random_request *req,
                               int *out_accepted, const char **out_message);

#ifdef __cplusplus
}
#endif
#endif /* AGC_CRYPTO_H */
