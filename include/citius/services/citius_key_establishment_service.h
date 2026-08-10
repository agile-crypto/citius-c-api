/**
 * @file citius_key_establishment_service.h
 * @brief Key-to-key cryptographic operations (KeyEstablishmentService).
 *
 * C mirror of api/proto/services/key_establishment_service.proto —
 * KeyEstablishmentService.
 *
 * This service provides operations where keys act on keys — the output of
 * every RPC is a new key stored in the key store.
 *
 * Covers all four NIST key establishment categories:
 *   - Key Transport   (SP 800-56B):     WrapKey / UnwrapKey
 *   - Key Agreement   (SP 800-56A):     KeyAgreement (ECDH, X25519, X448, X3DH)
 *   - Key Encapsulation (SP 800-56C):   EncapsulateKey / DecapsulateKey (ML-KEM)
 *   - Key Derivation  (SP 800-56C §4,
 *                       SP 800-108):    DeriveKey (HKDF, PBKDF2, Argon2, …)
 *
 * Proto → C mapping
 * -----------------
 *   rpc WrapKey(WrapKeyRequest) → WrapKeyResponse
 *       citius_wrap_key(request*, response*)
 *
 *   rpc UnwrapKey(UnwrapKeyRequest) → UnwrapKeyResponse
 *       citius_unwrap_key(request*, response*)
 *
 *   rpc DeriveKey(DeriveKeyRequest) → DeriveKeyResponse
 *       citius_derive_key(request*, response*)
 *
 *   rpc KeyAgreement(KeyAgreementRequest) → KeyAgreementResponse
 *       citius_key_agreement(request*, response*)
 *
 *   rpc EncapsulateKey(EncapsulateKeyRequest) → EncapsulateKeyResponse
 *       citius_encapsulate_key(request*, response*)
 *
 *   rpc DecapsulateKey(DecapsulateKeyRequest) → DecapsulateKeyResponse
 *       citius_decapsulate_key(request*, response*)
 *
 * HTTP REST paths (from proto annotations):
 *   POST /v1/keys/{wrapping_key_name}/wrap           citius_wrap_key()
 *   POST /v1/keys/{wrapping_key_name}/unwrap         citius_unwrap_key()
 *   POST /v1/keys/{base_key_name}/derive             citius_derive_key()
 *   POST /v1/keys/{private_key_name}/agree           citius_key_agreement()
 *   POST /v1/keys/{recipient_public_key_name}/encapsulate  citius_encapsulate_key()
 *   POST /v1/keys/{private_key_name}/decapsulate     citius_decapsulate_key()
 */

#ifndef CITIUS_SERVICES_KEY_ESTABLISHMENT_SERVICE_H
#define CITIUS_SERVICES_KEY_ESTABLISHMENT_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/messages/citius_key_wrapping.h"
#include "citius/messages/citius_key_derivation.h"
#include "citius/messages/citius_key_encapsulation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Key wrapping / transport  (proto: WrapKey / UnwrapKey)
 * ========================================================================= */

CITIUS_RV citius_wrap_key(
    const citius_wrap_key_request_t   *request,
    citius_wrap_key_response_t        *response
);

CITIUS_RV citius_unwrap_key(
    const citius_unwrap_key_request_t  *request,
    citius_unwrap_key_response_t       *response
);

/* =========================================================================
 * Key derivation  (proto: DeriveKey)
 * ========================================================================= */

CITIUS_RV citius_derive_key(
    const citius_derive_key_request_t   *request,
    citius_derive_key_response_t        *response
);

/* =========================================================================
 * Key agreement  (proto: KeyAgreement)
 * ========================================================================= */

CITIUS_RV citius_key_agreement(
    const citius_key_agreement_request_t   *request,
    citius_key_agreement_response_t        *response
);

/* =========================================================================
 * Key encapsulation  (proto: EncapsulateKey / DecapsulateKey)
 * ========================================================================= */

CITIUS_RV citius_encapsulate_key(
    const citius_encapsulate_key_request_t  *request,
    citius_encapsulate_key_response_t       *response
);

CITIUS_RV citius_decapsulate_key(
    const citius_decapsulate_key_request_t  *request,
    citius_decapsulate_key_response_t       *response
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_KEY_ESTABLISHMENT_SERVICE_H */
