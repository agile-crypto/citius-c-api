/**
 * @file citius_key_derivation.h
 * @brief DeriveKey / KeyAgreement request and response structs.
 *
 * Mirrors api/proto/messages/key_derivation.proto.
 *
 * Proto correspondence
 * --------------------
 *  DeriveKeyRequest      → citius_derive_key_request_t
 *  DeriveKeyResponse     → citius_derive_key_response_t
 *  KeyAgreementRequest   → citius_key_agreement_request_t
 *  KeyAgreementResponse  → citius_key_agreement_response_t
 *
 * Design note (DeriveKey)
 * -----------------------
 * The base key's template specifies BOTH the KDF algorithm AND the output
 * key type.  No scope or template_id is provided at derive time — this
 * avoids conflicts (e.g. KDF outputs 256 bits but template wants 128) and
 * ensures all algorithm decisions are made at key-creation time.
 *
 * The derived key is ALWAYS created in the same provider as the base key to
 * keep key material within its security domain.  For cross-provider transfer
 * use WrapKey / UnwrapKey explicitly.
 *
 * Design note (KeyAgreement)
 * --------------------------
 * Key agreement is distinct from key derivation:
 *   - KeyAgreement: two parties each contribute a key (Diffie-Hellman model).
 *   - DeriveKey:    one party derives from existing key material + KDF params.
 */

#ifndef CITIUS_MESSAGES_KEY_DERIVATION_H
#define CITIUS_MESSAGES_KEY_DERIVATION_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_operation_params.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyMetadata is defined in messages/citius_key_management.h; forward-declare
 * the typedef here so this header can be included without that dependency. */
#ifndef CITIUS_KEY_METADATA_DEFINED
struct citius_key_metadata_s;
typedef struct citius_key_metadata_s citius_key_metadata_t;
#define CITIUS_KEY_METADATA_DEFINED 1
#endif

/* =========================================================================
 * KDF scope parameters tagged union
 * (proto: oneof kdf_params in DeriveKeyRequest)
 * oneof: HkdfOperationParams | Pbkdf2OperationParams | Argon2OperationParams |
 *        EcdhOperationParams | X942DhOperationParams | TlsPrfOperationParams |
 *        Tls12KdfOperationParams | Sp800108OperationParams |
 *        GostKdfOperationParams | X3dhOperationParams | VendorKdfParams
 * ========================================================================= */

typedef enum {
    CITIUS_KDF_PARAMS_HKDF      = 1,  /**< HKDF-SHA256, HKDF-SHA512, …      */
    CITIUS_KDF_PARAMS_PBKDF2    = 2,  /**< PBKDF2-HMAC-SHA*                  */
    CITIUS_KDF_PARAMS_ARGON2    = 3,  /**< Argon2id, Argon2i, Argon2d        */
    CITIUS_KDF_PARAMS_ECDH      = 4,  /**< ECDH, X25519, X448                */
    CITIUS_KDF_PARAMS_X942_DH   = 5,  /**< X9.42 DH                          */
    CITIUS_KDF_PARAMS_TLS_PRF   = 6,  /**< TLS 1.0/1.1 PRF                   */
    CITIUS_KDF_PARAMS_TLS12_KDF = 7,  /**< TLS 1.2 KDF                       */
    CITIUS_KDF_PARAMS_SP800_108 = 8,  /**< NIST SP 800-108 KDF               */
    CITIUS_KDF_PARAMS_GOST_KDF  = 9,  /**< GOST key derivation               */
    CITIUS_KDF_PARAMS_X3DH      = 10, /**< Signal X3DH protocol              */
    CITIUS_KDF_PARAMS_VENDOR    = 11  /**< Vendor/custom KDF                 */
} citius_kdf_params_type_t;

typedef struct {
    citius_kdf_params_type_t type; /**< Discriminator — which union arm is valid */
    union {
        citius_hkdf_operation_params_t      hkdf;      /**< CITIUS_KDF_PARAMS_HKDF      */
        citius_pbkdf2_operation_params_t    pbkdf2;    /**< CITIUS_KDF_PARAMS_PBKDF2    */
        citius_argon2_operation_params_t    argon2;    /**< CITIUS_KDF_PARAMS_ARGON2    */
        citius_ecdh_operation_params_t      ecdh;      /**< CITIUS_KDF_PARAMS_ECDH      */
        citius_x942_dh_operation_params_t   x942_dh;   /**< CITIUS_KDF_PARAMS_X942_DH   */
        citius_tls_prf_operation_params_t   tls_prf;   /**< CITIUS_KDF_PARAMS_TLS_PRF   */
        citius_tls12_kdf_operation_params_t tls12_kdf; /**< CITIUS_KDF_PARAMS_TLS12_KDF */
        citius_sp800_108_operation_params_t sp800_108; /**< CITIUS_KDF_PARAMS_SP800_108 */
        citius_gost_kdf_operation_params_t  gost_kdf;  /**< CITIUS_KDF_PARAMS_GOST_KDF  */
        citius_x3dh_operation_params_t      x3dh;      /**< CITIUS_KDF_PARAMS_X3DH      */
        citius_vendor_kdf_params_t          vendor;    /**< CITIUS_KDF_PARAMS_VENDOR    */
    } params;
} citius_kdf_params_t;

/* =========================================================================
 * Key-agreement scope parameters tagged union
 * (proto: oneof agreement_params in KeyAgreementRequest)
 * oneof: EcdhOperationParams | X942DhOperationParams |
 *        X3dhOperationParams | VendorKdfParams
 * ========================================================================= */

typedef enum {
    CITIUS_KEY_AGREEMENT_PARAMS_ECDH    = 1, /**< ECDH (P-256/P-384/P-521), X25519, X448 */
    CITIUS_KEY_AGREEMENT_PARAMS_X942_DH = 2, /**< X9.42 DH (MODP groups)                 */
    CITIUS_KEY_AGREEMENT_PARAMS_X3DH    = 3, /**< Signal X3DH protocol                   */
    CITIUS_KEY_AGREEMENT_PARAMS_VENDOR  = 4  /**< Vendor-specific KA algorithms           */
} citius_key_agreement_params_type_t;

typedef struct {
    citius_key_agreement_params_type_t type; /**< Discriminator — which union arm is valid */
    union {
        citius_ecdh_operation_params_t    ecdh;    /**< CITIUS_KEY_AGREEMENT_PARAMS_ECDH    */
        citius_x942_dh_operation_params_t x942_dh; /**< CITIUS_KEY_AGREEMENT_PARAMS_X942_DH */
        citius_x3dh_operation_params_t    x3dh;    /**< CITIUS_KEY_AGREEMENT_PARAMS_X3DH    */
        citius_vendor_kdf_params_t        vendor;  /**< CITIUS_KEY_AGREEMENT_PARAMS_VENDOR  */
    } params;
} citius_key_agreement_params_t;

/* =========================================================================
 * DeriveKeyRequest / DeriveKeyResponse
 * ========================================================================= */

typedef struct {
    const char               *base_key_name;
    const char               *derived_key_name; /**< must be unique in the key namespace */
    const char               *policy;            /**< nullable — inherits base key's policy if omitted */
    citius_kdf_params_t       kdf_params;        /**< REQUIRED — set the arm matching the KDF algorithm:
                                                       HKDF, PBKDF2, ARGON2, ECDH, X942_DH,
                                                       TLS_PRF, TLS12_KDF, SP800_108, GOST_KDF,
                                                       X3DH, VENDOR */
    const citius_map_t       *user_context;      /**< nullable */
} citius_derive_key_request_t;

typedef struct {
    uint8_t                      success;
    const char                  *message;      /**< nullable */
    citius_operation_metadata_t  metadata;
    citius_key_metadata_t        key_metadata;
} citius_derive_key_response_t;

/* =========================================================================
 * KeyAgreementRequest / KeyAgreementResponse
 * ========================================================================= */

/**
 * citius_key_agreement_request_t  (proto: KeyAgreementRequest)
 *
 * @field peer_public_key  Raw peer public-key bytes.
 *   Encoding is algorithm-specific:
 *     ECDH:  uncompressed (04 || X || Y) or compressed (02/03 || X)
 *     X25519/X448: raw 32/56-byte LE scalar
 *     X9.42 DH: DER SubjectPublicKeyInfo
 */
typedef struct {
    const char                         *private_key_name;
    citius_byte_buffer_t                peer_public_key;
    const char                         *shared_secret_name;        /**< must be unique; non-null */
    const char                         *shared_secret_template_id; /**< nullable */
    citius_key_agreement_params_t       agreement_params;          /**< REQUIRED — one of: ECDH, X942_DH, X3DH, VENDOR */
    const citius_map_t                 *user_context;               /**< nullable */
} citius_key_agreement_request_t;

typedef struct {
    uint8_t                      success;
    const char                  *message;      /**< nullable */
    citius_operation_metadata_t  metadata;
    citius_key_metadata_t        key_metadata;
} citius_key_agreement_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_KEY_DERIVATION_H */
