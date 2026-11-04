/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_establish.h — KeyEstablishmentService (6 RPCs;
 * api/services/key_establishment_service.proto).
 *
 * Functions only. Every request and response type they name is defined in
 * agc_establish_types.h, which also states the SIZE QUERY and METADATA rules
 * that govern them.
 *
 * Keys acting on keys. Five of the six functions produce a NEW NAMED KEY in
 * the key store, and none returns plaintext key material. That is the
 * invariant that makes the whole surface safe to expose from C: there is no
 * secret buffer for a caller to leak, forget to zeroize, or accidentally
 * log. The two byte outputs here -- the wrapped blob and the KEM
 * encapsulation -- are ciphertext, meant to be transported.
 *
 * SHAPE OF EVERY CALL
 * -------------------
 *     agc_rc agc_<op>(agc_ctx *ctx, const agc_<op>_request *req, agc_<op>_response *resp);
 *
 * One request struct, one response struct, both CALLER-ALLOCATED, both
 * beginning with struct_size (AGC_INIT). The library writes only into
 * regions the caller placed in the response; it allocates nothing the caller
 * sees and there is nothing to free. Rules: docs/agc_crypto.md.
 *
 * STATUS: declarations only. Implementation follows; see
 * docs/implementation_progress.md.
 */

#ifndef AGC_ESTABLISH_H
#define AGC_ESTABLISH_H

#include "agc_core.h"
#include "agc_establish_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * WrapKey / UnwrapKey (key transport)
 * -------------------------------------------------------------------------- */

/* Emits the wrapped blob, which is ciphertext+metadata and must be transportable.
 * Creates no key, so its response carries no key record. */
AGC_API agc_rc agc_wrap_key(agc_ctx *ctx, const agc_wrap_key_request *req,
                             agc_wrap_key_response *resp);

/* Unwraps a wrapped key. */
AGC_API agc_rc agc_unwrap_key(agc_ctx *ctx, const agc_unwrap_key_request *req,
                               agc_establish_key_response *resp);

/* --------------------------------------------------------------------------
 * DeriveKey / KeyAgreement
 * -------------------------------------------------------------------------- */

/* The derived key is always created in the base key's provider, which is
 * what keeps material inside one security domain. Shares
 * agc_establish_key_response with unwrap, key_agreement and decapsulate. */
AGC_API agc_rc agc_derive_key(agc_ctx *ctx, const agc_derive_key_request *req,
                               agc_establish_key_response *resp);

/* Takes agc_agreement_params, not agc_kdf_params: the proto's
 * agreement_params oneof has four arms (Ecdh/X942Dh/X3dh/Vendor) where
 * kdf_params has eleven, and a dedicated union makes that subset a
 * compile-time fact rather than a runtime AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS. */
AGC_API agc_rc agc_key_agreement(agc_ctx *ctx, const agc_key_agreement_request *req,
                                  agc_establish_key_response *resp);

/* --------------------------------------------------------------------------
 * EncapsulateKey / DecapsulateKey (post-quantum KEMs)
 * -------------------------------------------------------------------------- */

/* Both creates the shared-secret key and emits the KEM encapsulation, so it
 * has its own response type. */
AGC_API agc_rc agc_encapsulate_key(agc_ctx *ctx, const agc_encapsulate_key_request *req,
                                    agc_encapsulate_key_response *resp);

AGC_API agc_rc agc_decapsulate_key(agc_ctx *ctx, const agc_decapsulate_key_request *req,
                                    agc_establish_key_response *resp);

#ifdef __cplusplus
}
#endif
#endif /* AGC_ESTABLISH_H */
