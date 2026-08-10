/**
 * @file citius_operation_params.h
 * @brief Per-call operation parameter structs.
 *
 * Mirrors api/proto/types/operation_params.proto (~527 lines).
 *
 * These are the run-time parameters passed alongside the scope spec on each
 * individual call — e.g. AAD for AEAD, KDF salts, domain-separation context.
 * They are distinct from the algorithm configuration structs in
 * citius_algorithm_params.h, which describe static algorithm properties.
 */

#ifndef CITIUS_OPERATION_PARAMS_H
#define CITIUS_OPERATION_PARAMS_H

#include "citius_types.h"
#include "citius_algorithm_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * No-params sentinel  (proto: NoParams)
 *
 * Used for operations that require no caller-supplied parameters (e.g.
 * pure Ed25519, AES-KW without padding).
 * ========================================================================= */

typedef struct {
    uint8_t _reserved; /**< Intentionally empty; use CITIUS_NO_PARAMS initialiser */
} citius_no_params_t;

/** Convenience zero-initialiser for citius_no_params_t. */
#define CITIUS_NO_PARAMS ((citius_no_params_t){0})

/* =========================================================================
 * Encryption operation parameters
 * ========================================================================= */

/**
 * AEAD encryption operation parameters  (proto: AeadEncryptParams)
 *
 * Provides the additional authenticated data (AAD) and, for CCM, the
 * expected plaintext length needed before the header can be finalised.
 */
typedef struct {
    citius_byte_buffer_t aad;               /**< Additional authenticated data; may be empty */
    size_t               plaintext_length;  /**< CCM only: total plaintext byte count         */
} citius_aead_encrypt_params_t;

/**
 * XTS / disk encryption operation parameters  (proto: XtsEncryptParams)
 *
 * The tweak encodes the sector number or data-unit address.
 */
typedef struct {
    uint8_t tweak[16]; /**< 128-bit tweak (sector/block address, little-endian) */
} citius_xts_encrypt_params_t;

/**
 * Asymmetric (OAEP / RSA) encryption operation parameters
 * (proto: AsymmetricEncryptParams)
 */
typedef struct {
    citius_byte_buffer_t label; /**< OAEP label; typically empty */
} citius_asym_encrypt_params_t;

/* =========================================================================
 * Signature operation parameters
 * ========================================================================= */

/**
 * Signature domain-separation context  (proto: SignatureDomainContext)
 *
 * Used by Ed25519ctx, ML-DSA, and SLH-DSA.
 * The context must be 0–255 bytes.
 */
typedef struct {
    citius_byte_buffer_t context; /**< Domain-separation context (0–255 bytes) */
} citius_signature_domain_context_t;

/* =========================================================================
 * KDF operation parameters
 * ========================================================================= */

/** HKDF salt type  (proto: HkdfSaltType) */
typedef enum {
    CITIUS_HKDF_SALT_TYPE_UNSPECIFIED = 0,
    CITIUS_HKDF_SALT_TYPE_DATA        = 1, /**< Raw salt bytes provided in salt field        */
    CITIUS_HKDF_SALT_TYPE_NULL        = 2, /**< RFC 5869 §2.2 zero-string salt               */
    CITIUS_HKDF_SALT_TYPE_KEY         = 3  /**< Salt is a stored key (salt_key_name)         */
} citius_hkdf_salt_type_t;

/**
 * HKDF operation parameters  (proto: HkdfOperationParams)
 *
 * PKCS#11 Reference: CK_HKDF_PARAMS.pSalt, CK_HKDF_PARAMS.pInfo
 */
typedef struct {
    citius_byte_buffer_t     salt;          /**< Extract-phase salt; absence = server generates */
    citius_byte_buffer_t     info;          /**< Expand-phase context (RFC 5869 "info")         */
    citius_hkdf_salt_type_t  salt_type;     /**< How the salt field is interpreted              */
    const char              *salt_key_name; /**< Used when salt_type == SALT_TYPE_KEY           */
} citius_hkdf_operation_params_t;

/**
 * PBKDF2 operation parameters  (proto: Pbkdf2OperationParams)
 *
 * PKCS#11 Reference: CK_PKCS5_PBKD2_PARAMS2.pPassword, .pSaltSourceData
 */
typedef struct {
    citius_byte_buffer_t password; /**< User password — REQUIRED                             */
    citius_byte_buffer_t salt;     /**< Salt; absence = server generates a random salt       */
} citius_pbkdf2_operation_params_t;

/**
 * Argon2 operation parameters  (proto: Argon2OperationParams)
 */
typedef struct {
    citius_byte_buffer_t password;        /**< User password — REQUIRED                      */
    citius_byte_buffer_t salt;            /**< Salt; absence = server generates a random salt */
    citius_byte_buffer_t associated_data; /**< Optional Argon2 "additional data" parameter   */
    citius_byte_buffer_t secret;          /**< Optional pepper; stored separately             */
} citius_argon2_operation_params_t;

/**
 * ECDH / X25519 / X448 key agreement operation parameters
 * (proto: EcdhOperationParams)
 *
 * PKCS#11 Reference: CK_ECDH1_DERIVE_PARAMS.pSharedData
 */
typedef struct {
    citius_byte_buffer_t shared_info; /**< Optional KDF context (SP 800-56A OtherInfo) */
} citius_ecdh_operation_params_t;

/**
 * X9.42 DH key agreement operation parameters  (proto: X942DhOperationParams)
 *
 * Use for: DH key agreement with X9.42 KDF
 * PKCS#11 Reference: CK_X9_42_DH_KDF_PARAMS.pOtherInfo
 */
typedef struct {
    citius_byte_buffer_t other_info; /**< OtherInfo for KDF per ANSI X9.42 */
} citius_x942_dh_operation_params_t;

/**
 * X3DH (Signal Protocol) operation parameters  (proto: X3dhOperationParams)
 *
 * Use for: Extended Triple Diffie-Hellman key agreement.
 * Not in PKCS#11 v3.0; included for modern messaging protocols.
 *
 * Applications SHOULD encode the X3DH role (initiator/responder) and key
 * bundle version in the context field for reproducible agreement.
 */
typedef struct {
    citius_byte_buffer_t context; /**< Protocol-specific context; may include app ID,
                                       version info, peer key bundle refs, or role */
} citius_x3dh_operation_params_t;

/**
 * TLS 1.0/1.1 PRF operation parameters  (proto: TlsPrfOperationParams)
 *
 * PKCS#11 Reference: CK_TLS_PRF_PARAMS.pLabel, CK_TLS_PRF_PARAMS.pSeed
 */
typedef struct {
    citius_byte_buffer_t label; /**< PRF label (e.g. "master secret", "key expansion") */
    citius_byte_buffer_t seed;  /**< PRF seed (ClientHello.random + ServerHello.random) */
} citius_tls_prf_operation_params_t;

/**
 * TLS 1.2 KDF operation parameters  (proto: Tls12KdfOperationParams)
 *
 * PKCS#11 Reference: CK_TLS_KDF_PARAMS, CK_TLS12_KEY_MAT_PARAMS.RandomInfo
 */
typedef struct {
    citius_byte_buffer_t label;         /**< Label string for PRF                          */
    citius_byte_buffer_t client_random; /**< Client random (exactly 32 bytes, RFC 5246)    */
    citius_byte_buffer_t server_random; /**< Server random (exactly 32 bytes, RFC 5246)    */
    citius_byte_buffer_t context_data;  /**< Additional context (extended master secret)   */
} citius_tls12_kdf_operation_params_t;

/* =========================================================================
 * SP 800-108 KDF operation parameters
 * ========================================================================= */

/**
 * Data parameter types for SP 800-108 KDF  (proto: Sp800108DataType)
 *
 * PKCS#11 Reference: CK_SP800_108_PRF_DATA_PARAM_TYPE
 */
typedef enum {
    CITIUS_SP800_108_DATA_TYPE_UNSPECIFIED        = 0,
    CITIUS_SP800_108_DATA_TYPE_ITERATION_VARIABLE = 1, /**< Counter position; value = byte width      */
    CITIUS_SP800_108_DATA_TYPE_COUNTER            = 2, /**< Explicit counter value (rarely used)      */
    CITIUS_SP800_108_DATA_TYPE_DKM_LENGTH         = 3, /**< DKM length in bits (big-endian in value)  */
    CITIUS_SP800_108_DATA_TYPE_BYTE_ARRAY         = 4  /**< Literal bytes (label, context, separator) */
} citius_sp800_108_data_type_t;

/**
 * One data element in an SP 800-108 PRF input  (proto: Sp800108DataParam)
 *
 * PKCS#11 Reference: CK_PRF_DATA_PARAM
 */
typedef struct {
    citius_sp800_108_data_type_t type;
    citius_byte_buffer_t         value; /**< Interpretation depends on type */
} citius_sp800_108_data_param_t;

/**
 * SP 800-108 KDF operation parameters  (proto: Sp800108OperationParams)
 *
 * PKCS#11 Reference: CK_SP800_108_KDF_PARAMS.pDataParams
 */
typedef struct {
    citius_sp800_108_data_param_t *data_params;    /**< Array of PRF input elements */
    size_t                         num_data_params;
} citius_sp800_108_operation_params_t;

/**
 * GOST KDF operation parameters  (proto: GostKdfOperationParams)
 *
 * PKCS#11 Reference: CK_GOSTR3410_DERIVE_PARAMS.pUKM
 */
typedef struct {
    citius_byte_buffer_t ukm; /**< User Keying Material (1–64 bytes depending on algorithm) */
} citius_gost_kdf_operation_params_t;

/* =========================================================================
 * Key wrapping operation parameters
 * ========================================================================= */

/**
 * Key-agreement-based wrap parameters  (proto: KeyAgreementWrapParams)
 *
 * Scope: ECDH-ES+AES-KW, ECMQV key agreement with wrapping.
 * Compatible with JWE ECDH-ES (RFC 7518 §4.6).
 */
typedef struct {
    citius_byte_buffer_t shared_info; /**< KDF context per NIST SP 800-56A                   */
    citius_byte_buffer_t apu;         /**< Agreement PartyUInfo (JWE "apu", RFC 7518 §4.6.2) */
    citius_byte_buffer_t apv;         /**< Agreement PartyVInfo (JWE "apv", RFC 7518 §4.6.2) */
} citius_key_agreement_wrap_operation_params_t;

/**
 * GOST key wrap operation parameters  (proto: GostWrapOperationParams)
 *
 * PKCS#11 Reference: CK_GOSTR3410_KEY_WRAP_PARAMS.pUKM
 */
typedef struct {
    citius_byte_buffer_t ukm; /**< User Keying Material for GOST key wrapping */
} citius_gost_wrap_operation_params_t;

/* =========================================================================
 * MAC operation parameters
 * ========================================================================= */

/**
 * Customizable MAC (KMAC) parameters  (proto: CustomizableMacParams)
 *
 * Scope: KMAC128, KMAC256, KMACXOF128, KMACXOF256 (NIST SP 800-185).
 */
typedef struct {
    citius_byte_buffer_t customization; /**< Domain-separation string; empty = default KMAC */
} citius_customizable_mac_params_t;

/* =========================================================================
 * Custom / vendor operation parameters  (proto: CustomOperationParams)
 *
 * Escape hatch for vendor-specific or custom algorithm operation parameters.
 * Implementations SHOULD validate custom parameters against an allow-list.
 * ========================================================================= */

/**
 * Custom / vendor operation parameters  (proto: CustomOperationParams)
 *
 * proto's `oneof params` (google.protobuf.Struct generic_params /
 * google.protobuf.Any typed_params) has no native C equivalent; both arms
 * are represented here as a single opaque byte blob (raw_params). This is
 * an intentional simplification, not a 1:1 field mirror — callers that need
 * structured parameters should encode/decode them into raw_params
 * themselves (e.g. as JSON or a provider-specific binary format).
 */
typedef struct {
    const char           *vendor;         /**< Vendor ID (e.g. "thales", "ibm"); empty = non-vendor */
    const char           *algorithm_name; /**< Must match CustomAlgorithm.name in the key's template */
    citius_byte_buffer_t  raw_params;     /**< Opaque binary params forwarded to the provider.
                                               Providers that don't support it MUST ignore silently. */
} citius_custom_operation_params_t;

/**
 * Vendor params wrapper for the encryption scope  (proto: VendorEncryptionParams)
 */
typedef struct {
    citius_custom_operation_params_t params;
} citius_vendor_encryption_params_t;

/**
 * Vendor params wrapper for the signature scope  (proto: VendorSignatureContext)
 */
typedef struct {
    citius_custom_operation_params_t params;
} citius_vendor_signature_context_t;

/**
 * Vendor params wrapper for the KDF scope  (proto: VendorKdfParams)
 */
typedef struct {
    citius_custom_operation_params_t params;
} citius_vendor_kdf_params_t;

/**
 * Vendor params wrapper for the key wrap scope  (proto: VendorWrapParams)
 */
typedef struct {
    citius_custom_operation_params_t params;
} citius_vendor_wrap_params_t;

/**
 * Vendor params wrapper for the MAC scope  (proto: VendorMacParams)
 */
typedef struct {
    citius_custom_operation_params_t params;
} citius_vendor_mac_params_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_OPERATION_PARAMS_H */
