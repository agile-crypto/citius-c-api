/**
 * @file citius_signing.h
 * @brief Sign / Verify / DigestSign / DigestVerify request and response structs.
 *
 * Mirrors api/proto/messages/signing.proto in full:
 *   - Single-shot Sign/Verify, DigestSign/DigestVerify
 *   - Multi-part SignInit/Update/Final, VerifyInit/Update/Final
 *   - Message-based SignMessageInit/Message/Begin/Next/Final and
 *     VerifyMessageInit/Message/Begin/Next/Final
 *
 * Proto correspondence
 * --------------------
 *  SignRequest                 → citius_sign_request_t
 *  SignResponse                → citius_sign_response_t
 *  VerifyRequest               → citius_verify_request_t
 *  VerifyResponse              → citius_verify_response_t
 *  DigestSignRequest           → citius_digest_sign_request_t
 *  DigestSignResponse          → citius_digest_sign_response_t
 *  DigestVerifyRequest         → citius_digest_verify_request_t
 *  DigestVerifyResponse        → citius_digest_verify_response_t
 *  SignInitRequest             → citius_sign_init_request_t
 *  SignInitResponse            → citius_sign_init_response_t
 *  SignUpdateRequest           → citius_sign_update_request_t
 *  SignUpdateResponse          → citius_sign_update_response_t
 *  SignFinalRequest            → citius_sign_final_request_t
 *  SignFinalResponse           → citius_sign_final_response_t
 *  VerifyInitRequest           → citius_verify_init_request_t
 *  VerifyInitResponse          → citius_verify_init_response_t
 *  VerifyUpdateRequest         → citius_verify_update_request_t
 *  VerifyUpdateResponse        → citius_verify_update_response_t
 *  VerifyFinalRequest          → citius_verify_final_request_t
 *  VerifyFinalResponse         → citius_verify_final_response_t
 *  SignMessageInitRequest      → citius_sign_message_init_request_t
 *  SignMessageInitResponse     → citius_sign_message_init_response_t
 *  SignMessageRequest          → citius_sign_message_request_t
 *  SignMessageResponse         → citius_sign_message_response_t
 *  SignMessageBeginRequest     → citius_sign_message_begin_request_t
 *  SignMessageBeginResponse    → citius_sign_message_begin_response_t
 *  SignMessageNextRequest      → citius_sign_message_next_request_t
 *  SignMessageNextResponse     → citius_sign_message_next_response_t
 *  SignMessageFinalRequest     → citius_sign_message_final_request_t
 *  SignMessageFinalResponse    → citius_sign_message_final_response_t
 *  VerifyMessageInitRequest    → citius_verify_message_init_request_t
 *  VerifyMessageInitResponse   → citius_verify_message_init_response_t
 *  VerifyMessageRequest        → citius_verify_message_request_t
 *  VerifyMessageResponse       → citius_verify_message_response_t
 *  VerifyMessageBeginRequest   → citius_verify_message_begin_request_t
 *  VerifyMessageBeginResponse  → citius_verify_message_begin_response_t
 *  VerifyMessageNextRequest    → citius_verify_message_next_request_t
 *  VerifyMessageNextResponse   → citius_verify_message_next_response_t
 *  VerifyMessageFinalRequest   → citius_verify_message_final_request_t
 *  VerifyMessageFinalResponse  → citius_verify_message_final_response_t
 */

#ifndef CITIUS_MESSAGES_SIGNING_H
#define CITIUS_MESSAGES_SIGNING_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_algorithm_params.h"
#include "citius/types/citius_operation_params.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Signature scope parameters tagged union
 * (proto: oneof scope_params in SignRequest / VerifyRequest / *InitRequest / …)
 * oneof: NoParams | SignatureDomainContext | VendorSignatureContext
 * ========================================================================= */

typedef enum {
    CITIUS_SIGN_PARAMS_NONE              = 0, /**< ECDSA, RSA-PSS, DSA, GOST R 34.10  */
    CITIUS_SIGN_PARAMS_DOMAIN_CONTEXT    = 1, /**< EdDSA, ML-DSA, SLH-DSA             */
    CITIUS_SIGN_PARAMS_VENDOR            = 2  /**< Vendor/custom scope                */
} citius_sign_params_type_t;

typedef struct {
    citius_sign_params_type_t type; /**< Discriminator — which union arm is valid.
                                         NONE means no domain context required
                                         (proto: NoParams); the params union is not read. */
    union {
        citius_signature_domain_context_t  domain_context; /**< CITIUS_SIGN_PARAMS_DOMAIN_CONTEXT */
        citius_vendor_signature_context_t  vendor;         /**< CITIUS_SIGN_PARAMS_VENDOR         */
    } params;
} citius_sign_params_t;

/** Convenience: explicit no-params (classical signatures). */
#define CITIUS_SIGN_PARAMS_NONE_INIT \
    ((citius_sign_params_t){ .type = CITIUS_SIGN_PARAMS_NONE })

/* =========================================================================
 * SignRequest / SignResponse  (single-shot)
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    citius_byte_buffer_t      input;
    citius_sign_params_t      scope_params; /**< REQUIRED — one of: NONE (ECDSA/RSA-PSS/DSA),
                                                 DOMAIN_CONTEXT (EdDSA/ML-DSA/SLH-DSA),
                                                 VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_sign_request_t;

typedef struct {
    citius_mutable_buffer_t      signature;
    citius_operation_metadata_t  metadata;
} citius_sign_response_t;

/* =========================================================================
 * VerifyRequest / VerifyResponse  (single-shot)
 * ========================================================================= */

typedef struct {
    const char                        *key_name;
    citius_byte_buffer_t               input;
    citius_byte_buffer_t               signature;
    citius_operation_metadata_t        metadata;
    citius_sign_params_t               scope_params; /**< REQUIRED — must match scope used during signing */
    const citius_map_t                *user_context; /**< nullable */
} citius_verify_request_t;

typedef struct {
    uint8_t                      valid;
    citius_operation_metadata_t  metadata;
} citius_verify_response_t;

/* =========================================================================
 * DigestSignRequest / DigestSignResponse
 * ========================================================================= */

/**
 * citius_digest_sign_request_t  (proto: DigestSignRequest)
 *
 * @field hash_algorithm  Hash algorithm used to produce the digest.
 *                        Required: validates digest size and enforces policy.
 * @field hash_algorithm_oid  Optional OID string; nullable.
 *                            When both fields are set the provider validates they agree.
 */
typedef struct {
    const char               *key_name;
    citius_byte_buffer_t      digest;
    citius_sign_params_t      scope_params;         /**< REQUIRED — one of: NONE, DOMAIN_CONTEXT, VENDOR */
    citius_hash_algorithm_t   hash_algorithm;
    const char               *hash_algorithm_oid; /**< nullable */
    const citius_map_t       *user_context;        /**< nullable */
} citius_digest_sign_request_t;

typedef struct {
    citius_mutable_buffer_t      signature;
    citius_operation_metadata_t  metadata;
} citius_digest_sign_response_t;

/* =========================================================================
 * DigestVerifyRequest / DigestVerifyResponse
 * ========================================================================= */

typedef struct {
    const char                        *key_name;
    citius_byte_buffer_t               digest;
    citius_byte_buffer_t               signature;
    citius_operation_metadata_t        metadata;
    citius_sign_params_t               scope_params;        /**< REQUIRED — must match scope used during signing */
    citius_hash_algorithm_t            hash_algorithm;
    const char                        *hash_algorithm_oid; /**< nullable */
    const citius_map_t                *user_context;        /**< nullable */
} citius_digest_verify_request_t;

typedef struct {
    uint8_t                      valid;
    citius_operation_metadata_t  metadata;
} citius_digest_verify_response_t;

/* =========================================================================
 * Multi-part signing  (SignInit / SignUpdate / SignFinal)
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_sign_params_t      scope_params; /**< REQUIRED — one of: NONE, DOMAIN_CONTEXT, VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_sign_init_request_t;

typedef struct {
    uint8_t success;
} citius_sign_init_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  data_chunk;
} citius_sign_update_request_t;

typedef struct {
    uint8_t success;
} citius_sign_update_response_t;

typedef struct {
    const char *operation_id;
} citius_sign_final_request_t;

typedef struct {
    citius_mutable_buffer_t      signature;
    citius_operation_metadata_t  metadata;
} citius_sign_final_response_t;

/* =========================================================================
 * Multi-part verification  (VerifyInit / VerifyUpdate / VerifyFinal)
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_sign_params_t      scope_params; /**< REQUIRED — must match scope used for SignInit */
    const citius_map_t       *user_context; /**< nullable */
} citius_verify_init_request_t;

typedef struct {
    uint8_t success;
} citius_verify_init_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  data_chunk;
} citius_verify_update_request_t;

typedef struct {
    uint8_t success;
} citius_verify_update_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  signature;
} citius_verify_final_request_t;

typedef struct {
    uint8_t                      valid;
    citius_operation_metadata_t  metadata;
} citius_verify_final_response_t;

/* =========================================================================
 * Message-based signing — SignMessageInit
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_sign_params_t      scope_params; /**< REQUIRED — one of: NONE, DOMAIN_CONTEXT, VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_sign_message_init_request_t;

typedef struct {
    uint8_t success;
} citius_sign_message_init_response_t;

/* =========================================================================
 * Message-based signing — single-message SignMessage
 * ========================================================================= */

typedef struct {
    const char           *key_name;
    citius_byte_buffer_t  message;
    const citius_map_t   *user_context; /**< nullable */
} citius_sign_message_request_t;

typedef struct {
    citius_mutable_buffer_t      signature;
    citius_operation_metadata_t  metadata;
} citius_sign_message_response_t;

/* =========================================================================
 * Message-based signing — streaming Begin/Next/Final
 * ========================================================================= */

typedef struct {
    const char *operation_id;
} citius_sign_message_begin_request_t;

typedef struct {
    uint8_t success;
} citius_sign_message_begin_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  message_chunk;
} citius_sign_message_next_request_t;

typedef struct {
    uint8_t success;
} citius_sign_message_next_response_t;

typedef struct {
    const char *operation_id;
} citius_sign_message_final_request_t;

typedef struct {
    citius_mutable_buffer_t      signature;
    citius_operation_metadata_t  metadata;
} citius_sign_message_final_response_t;

/* =========================================================================
 * Message-based verification — VerifyMessageInit
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_sign_params_t      scope_params; /**< REQUIRED — must match scope used for SignMessageInit */
    const citius_map_t       *user_context; /**< nullable */
} citius_verify_message_init_request_t;

typedef struct {
    uint8_t success;
} citius_verify_message_init_response_t;

/* =========================================================================
 * Message-based verification — single-message VerifyMessage
 * ========================================================================= */

typedef struct {
    const char           *key_name;
    citius_byte_buffer_t  message;
    citius_byte_buffer_t  signature;
    const citius_map_t   *user_context; /**< nullable */
} citius_verify_message_request_t;

typedef struct {
    uint8_t                      valid;
    citius_operation_metadata_t  metadata;
} citius_verify_message_response_t;

/* =========================================================================
 * Message-based verification — streaming Begin/Next/Final
 * ========================================================================= */

typedef struct {
    const char *operation_id;
} citius_verify_message_begin_request_t;

typedef struct {
    uint8_t success;
} citius_verify_message_begin_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  message_chunk;
} citius_verify_message_next_request_t;

typedef struct {
    uint8_t success;
} citius_verify_message_next_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  signature;
} citius_verify_message_final_request_t;

typedef struct {
    uint8_t                      valid;
    citius_operation_metadata_t  metadata;
} citius_verify_message_final_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_SIGNING_H */
