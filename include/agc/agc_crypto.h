/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_crypto.h — CryptoService (12 RPCs; api/services/crypto_service.proto).
 * Single-shot, stateless operations. Streaming equivalents are agc_stream.h.
 *
 * Functions only. Every request and response type they name is defined in
 * agc_crypto_types.h, which also states the SIZE QUERY and METADATA rules
 * that govern them.
 *
 * SHAPE OF EVERY CALL
 * -------------------
 *     agc_rc agc_<op>(agc_ctx *ctx, const agc_<op>_request *req, agc_<op>_response *resp);
 *
 * One request struct, one response struct, both CALLER-ALLOCATED, both
 * beginning with struct_size (AGC_INIT). The library writes only into
 * regions the caller placed in the response; it allocates nothing the caller
 * sees and there is nothing to free. Rules: docs/agc_crypto.md.
 */

#ifndef AGC_CRYPTO_H
#define AGC_CRYPTO_H

#include "agc_core.h"
#include "agc_crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Encrypt / Decrypt
 * -------------------------------------------------------------------------- */

/* The metadata is not optional: it carries the system-generated nonce/IV
 * without which decryption is impossible. */
AGC_API agc_rc agc_encrypt(agc_ctx *ctx, const agc_encrypt_request *req,
                           agc_encrypt_response *resp);

/* AEAD tag failure returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED and writes
 * nothing to resp->plaintext. Plaintext is never released on authentication
 * failure. A NULL resp->metadata.data is NOT a size query here: it opts out
 * of the metadata output, since the caller already holds the input one. */
AGC_API agc_rc agc_decrypt(agc_ctx *ctx, const agc_decrypt_request *req,
                           agc_decrypt_response *resp);

/* --------------------------------------------------------------------------
 * Sign / Verify
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_sign(agc_ctx *ctx, const agc_sign_request *req, agc_sign_response *resp);

/* Fail-closed twice (D9): see agc_verify_response in agc_crypto_types.h. */
AGC_API agc_rc agc_verify(agc_ctx *ctx, const agc_verify_request *req, agc_verify_response *resp);

/* --------------------------------------------------------------------------
 * DigestSign / DigestVerify -- caller supplies a pre-computed digest
 * -------------------------------------------------------------------------- */

/* Shares agc_sign_response with agc_sign. */
AGC_API agc_rc agc_digest_sign(agc_ctx *ctx, const agc_digest_sign_request *req,
                               agc_sign_response *resp);

AGC_API agc_rc agc_digest_verify(agc_ctx *ctx, const agc_digest_verify_request *req,
                                 agc_verify_response *resp);

/* Digest length in bytes for a fixed-output hash. Returns 0 for XOFs and for
 * AGC_HASH_ALGORITHM_OTHER/UNSPECIFIED. Lets a caller pre-check the
 * DigestSign contract locally. */
AGC_API size_t agc_hash_algorithm_output_len(agc_hash_algorithm h);

/* --------------------------------------------------------------------------
 * GenerateMAC / VerifyMAC
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_generate_mac(agc_ctx *ctx, const agc_mac_request *req, agc_mac_response *resp);

/* Comparison is constant-time inside the library (agc_ct_equal). */
AGC_API agc_rc agc_verify_mac(agc_ctx *ctx, const agc_verify_mac_request *req,
                              agc_verify_response *resp);

/* --------------------------------------------------------------------------
 * Digest / Xof -- keyless, provider and template selected by policy
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_digest(agc_ctx *ctx, const agc_digest_request *req, agc_digest_response *resp);

/* Shares agc_digest_response with agc_digest. */
AGC_API agc_rc agc_xof(agc_ctx *ctx, const agc_xof_request *req, agc_digest_response *resp);

/* --------------------------------------------------------------------------
 * Random
 * -------------------------------------------------------------------------- */

/* Unlike every other output, the random buffer is exactly num_bytes; the
 * size query for `output` is therefore never needed. */
AGC_API agc_rc agc_generate_random(agc_ctx *ctx, const agc_random_request *req,
                                   agc_random_response *resp);

/* Convenience wrapper for the overwhelmingly common case: `len` bytes from
 * the default provider into a caller buffer, no metadata. */
AGC_API agc_rc agc_random_bytes(agc_ctx *ctx, uint8_t *out, size_t len);

/* A provider with no seedable DRBG state declines: AGC_OK with success = 0
 * and a message -- "declined" is distinct from "failed". */
AGC_API agc_rc agc_seed_random(agc_ctx *ctx, const agc_seed_random_request *req,
                               agc_seed_random_response *resp);

#ifdef __cplusplus
}
#endif
#endif /* AGC_CRYPTO_H */
