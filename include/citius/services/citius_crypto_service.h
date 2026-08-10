/**
 * @file citius_crypto_service.h
 * @brief Single-shot cryptographic operations (CryptoService).
 *
 * C mirror of api/proto/services/crypto_service.proto — CryptoService.
 *
 * Service family overview
 * -----------------------
 *   CryptoService (this file)       — stateless single-shot operations
 *   StreamingCryptoService          — stateful Init/Update/Final sessions
 *   KeyEstablishmentService         — key-to-key operations (derive, KEM, wrap)
 *   KeyManagementService            — key lifecycle (CRUD, rotate, migrate)
 *   CryptoPolicyService             — policy lifecycle and evaluation
 *   AlgorithmDiscoveryService       — template and scope discovery
 *   ProviderService                 — provider catalog and instance management
 *
 * Proto → C mapping
 * -----------------
 *   rpc Encrypt(EncryptRequest) → EncryptResponse
 *       citius_encrypt(request*, response*)
 *
 *   rpc Decrypt(DecryptRequest) → DecryptResponse
 *       citius_decrypt(request*, response*)
 *
 *   rpc Sign(SignRequest) → SignResponse
 *       citius_sign(request*, response*)
 *
 *   rpc Verify(VerifyRequest) → VerifyResponse
 *       citius_verify(request*, response*)
 *
 *   rpc DigestSign(DigestSignRequest) → DigestSignResponse
 *       citius_digest_sign(request*, response*)
 *
 *   rpc DigestVerify(DigestVerifyRequest) → DigestVerifyResponse
 *       citius_digest_verify(request*, response*)
 *
 *   rpc GenerateMAC(GenerateMACRequest) → GenerateMACResponse
 *       citius_generate_mac(request*, response*)
 *
 *   rpc VerifyMAC(VerifyMACRequest) → VerifyMACResponse
 *       citius_verify_mac(request*, response*)
 *
 *   rpc Digest(DigestRequest) → DigestResponse
 *       citius_digest(request*, response*)
 *
 *   rpc Xof(XofRequest) → XofResponse
 *       citius_xof(request*, response*)
 *
 *   rpc GenerateRandom(GenerateRandomRequest) → GenerateRandomResponse
 *       citius_generate_random(request*, response*)
 *
 *   rpc SeedRandom(SeedRandomRequest) → SeedRandomResponse
 *       citius_seed_random(request*, response*)
 *
 * HTTP REST paths (from proto annotations):
 *   POST /v1/encrypt/{key_name}          citius_encrypt()
 *   POST /v1/decrypt/{key_name}          citius_decrypt()
 *   POST /v1/sign/{key_name}             citius_sign()
 *   POST /v1/verify/{key_name}           citius_verify()
 *   POST /v1/sign/digest/{key_name}      citius_digest_sign()
 *   POST /v1/verify/digest/{key_name}    citius_digest_verify()
 *   POST /v1/mac/{key_name}/generate     citius_generate_mac()
 *   POST /v1/mac/{key_name}/verify       citius_verify_mac()
 *   POST /v1/digest                      citius_digest()
 *   POST /v1/xof                         citius_xof()
 *   POST /v1/random/generate             citius_generate_random()
 *   POST /v1/random/seed                 citius_seed_random()
 *
 * Output buffer (size-query) pattern
 * ------------------------------------
 * Every response struct that contains a citius_mutable_buffer_t output field
 * supports size-query mode:
 *   - Set output.data = NULL  OR  output.capacity = 0 to receive the
 *     required byte count in output.length without performing the operation.
 *   - Set output.data to a buffer with output.capacity >= required size to
 *     receive the actual output.
 */

#ifndef CITIUS_SERVICES_CRYPTO_SERVICE_H
#define CITIUS_SERVICES_CRYPTO_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/messages/citius_encryption.h"
#include "citius/messages/citius_signing.h"
#include "citius/messages/citius_mac.h"
#include "citius/messages/citius_digest.h"
#include "citius/messages/citius_random.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Symmetric / AEAD operations
 * ========================================================================= */

CITIUS_RV citius_encrypt(
    const citius_encrypt_request_t *request,
    citius_encrypt_response_t      *response
);

CITIUS_RV citius_decrypt(
    const citius_decrypt_request_t *request,
    citius_decrypt_response_t      *response
);

/* =========================================================================
 * Signature operations
 * ========================================================================= */

CITIUS_RV citius_sign(
    const citius_sign_request_t *request,
    citius_sign_response_t      *response
);

CITIUS_RV citius_verify(
    const citius_verify_request_t *request,
    citius_verify_response_t      *response
);

/** Sign a pre-computed digest. */
CITIUS_RV citius_digest_sign(
    const citius_digest_sign_request_t *request,
    citius_digest_sign_response_t      *response
);

/** Verify a signature over a pre-computed digest. */
CITIUS_RV citius_digest_verify(
    const citius_digest_verify_request_t *request,
    citius_digest_verify_response_t      *response
);

/* =========================================================================
 * MAC operations
 * ========================================================================= */

CITIUS_RV citius_generate_mac(
    const citius_generate_mac_request_t *request,
    citius_generate_mac_response_t      *response
);

CITIUS_RV citius_verify_mac(
    const citius_verify_mac_request_t  *request,
    citius_verify_mac_response_t       *response
);

/* =========================================================================
 * Digest / XOF operations
 * ========================================================================= */

CITIUS_RV citius_digest(
    const citius_digest_request_t  *request,
    citius_digest_response_t       *response
);

CITIUS_RV citius_xof(
    const citius_xof_request_t  *request,
    citius_xof_response_t       *response
);

/* =========================================================================
 * Random generation
 * ========================================================================= */

CITIUS_RV citius_generate_random(
    const citius_generate_random_request_t  *request,
    citius_generate_random_response_t       *response
);

CITIUS_RV citius_seed_random(
    const citius_seed_random_request_t   *request,
    citius_seed_random_response_t        *response
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_CRYPTO_SERVICE_H */
