/**
 * @file citius_common.h
 * @brief Per-primitive scope enums, scope specifications, key lifecycle, security
 *        properties, and error codes.
 *
 * Mirrors api/proto/types/common.proto.
 */

#ifndef CITIUS_COMMON_H
#define CITIUS_COMMON_H

#include "citius_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Per-primitive scope enums
 * ========================================================================= */

/** SignatureScope  (proto: SignatureScope) */
typedef enum {
    SIGNATURE_SCOPE_UNSPECIFIED           = 0,
    SIGNATURE_SCOPE_STANDARD              = 1, /**< Sign message directly              */
    SIGNATURE_SCOPE_WITH_CONTEXT          = 2, /**< Sign with domain-separation context */
    SIGNATURE_SCOPE_PREHASHED             = 3, /**< Sign pre-computed digest            */
    SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT = 4 /**< Sign digest with context            */
} citius_signature_scope_t;

/** AeadScope  (proto: AeadScope) */
typedef enum {
    AEAD_SCOPE_UNSPECIFIED    = 0,
    AEAD_SCOPE_STANDARD       = 1, /**< Standard AEAD (nonce, optional AAD)              */
    AEAD_SCOPE_DETERMINISTIC  = 2, /**< Deterministic (no nonce, AAD strongly recommended)*/
    AEAD_SCOPE_STREAMING      = 3  /**< Streaming (segment size param)                   */
} citius_aead_scope_t;

/** MacScope  (proto: MacScope) */
typedef enum {
    MAC_SCOPE_UNSPECIFIED = 0,
    MAC_SCOPE_STANDARD    = 1, /**< Standard MAC            */
    MAC_SCOPE_STREAMING   = 2  /**< Streaming MAC (incremental update) */
} citius_mac_scope_t;

/** KemScope  (proto: KemScope) */
typedef enum {
    KEM_SCOPE_UNSPECIFIED = 0,
    KEM_SCOPE_STANDARD    = 1, /**< Standard KEM        */
    KEM_SCOPE_HYBRID      = 2  /**< Hybrid classical+PQ */
} citius_kem_scope_t;

/** KeyAgreementScope  (proto: KeyAgreementScope) */
typedef enum {
    KEY_AGREEMENT_SCOPE_UNSPECIFIED = 0,
    KEY_AGREEMENT_SCOPE_STANDARD    = 1, /**< Standard ECDH/X25519 */
    KEY_AGREEMENT_SCOPE_HYBRID      = 2  /**< Hybrid classical+PQ  */
} citius_key_agreement_scope_t;

/** KdfScope  (proto: KdfScope) */
typedef enum {
    KDF_SCOPE_UNSPECIFIED    = 0,
    KDF_SCOPE_EXTRACT_EXPAND = 1, /**< IKM + salt + info → key (HKDF)                */
    KDF_SCOPE_PASSWORD       = 2, /**< password + salt + cost → key (PBKDF2, Argon2)  */
    KDF_SCOPE_AGREEMENT      = 3, /**< peer_public_key → shared secret (ECDH, X3DH…)  */
    KDF_SCOPE_COUNTER        = 4, /**< label + context + counter_format → key (SP800-108) */
    KDF_SCOPE_TLS            = 5, /**< cipher_suite + seed → key material (TLS PRF, 1.2) */
    KDF_SCOPE_GOST           = 6, /**< ukm → key (GOST R 34.11)                      */
    KDF_SCOPE_VENDOR         = 7  /**< custom parameters → key (vendor-specific)      */
} citius_kdf_scope_t;

/** HashScope  (proto: HashScope) */
typedef enum {
    HASH_SCOPE_UNSPECIFIED = 0,
    HASH_SCOPE_STANDARD    = 1, /**< Standard hash             */
    HASH_SCOPE_XOF         = 2  /**< Extendable output function */
} citius_hash_scope_t;

/** KeyWrappingScope  (proto: KeyWrappingScope) */
typedef enum {
    KEY_WRAPPING_SCOPE_UNSPECIFIED   = 0,
    KEY_WRAPPING_SCOPE_STANDARD      = 1, /**< Standard key wrap              */
    KEY_WRAPPING_SCOPE_WITH_PADDING  = 2  /**< Key wrap with padding (AES-KWP) */
} citius_key_wrapping_scope_t;

/** SymmetricCipherScope  (proto: SymmetricCipherScope) */
typedef enum {
    SYMMETRIC_CIPHER_SCOPE_UNSPECIFIED = 0,
    SYMMETRIC_CIPHER_SCOPE_BLOCK       = 1, /**< Block cipher (CBC) — NoParams */
    SYMMETRIC_CIPHER_SCOPE_STREAM      = 2  /**< Streaming modes (CTR, OFB) and stream ciphers */
} citius_symmetric_cipher_scope_t;

/** DiskEncryptionScope  (proto: DiskEncryptionScope) */
typedef enum {
    DISK_ENCRYPTION_SCOPE_UNSPECIFIED = 0,
    DISK_ENCRYPTION_SCOPE_STANDARD    = 1  /**< AES-XTS (IEEE 1619) — XtsEncryptParams */
} citius_disk_encryption_scope_t;

/** GenericSecretScope  (proto: GenericSecretScope) */
typedef enum {
    GENERIC_SECRET_SCOPE_UNSPECIFIED = 0,
    GENERIC_SECRET_SCOPE_STANDARD    = 1  /**< Standard generic secret management */
} citius_generic_secret_scope_t;

/** AsymmetricEncryptionScope  (proto: AsymmetricEncryptionScope) */
typedef enum {
    ASYMMETRIC_ENCRYPTION_SCOPE_UNSPECIFIED = 0,
    ASYMMETRIC_ENCRYPTION_SCOPE_STANDARD    = 1, /**< OAEP-padded (IND-CCA2): RSA-OAEP */
    ASYMMETRIC_ENCRYPTION_SCOPE_RAW         = 2  /**< Legacy PKCS#1 v1.5 (NOT recommended) */
} citius_asymmetric_encryption_scope_t;

/* =========================================================================
 * Universal security properties  (proto: UniversalSecurityProperties)
 * ========================================================================= */

/** NistSecurityLevel  (proto: NistSecurityLevel) */
typedef enum {
    NIST_SECURITY_LEVEL_UNSPECIFIED = 0,
    NIST_SECURITY_LEVEL_1           = 1, /**< AES-128 equivalent         */
    NIST_SECURITY_LEVEL_2           = 2, /**< SHA-256 collision resistance */
    NIST_SECURITY_LEVEL_3           = 3, /**< AES-192 equivalent         */
    NIST_SECURITY_LEVEL_4           = 4, /**< SHA-384 collision resistance */
    NIST_SECURITY_LEVEL_5           = 5  /**< AES-256 equivalent         */
} citius_nist_security_level_t;

/** NistStatus  (proto: NistStatus) */
typedef enum {
    NIST_STATUS_UNSPECIFIED = 0,
    NIST_STATUS_APPROVED    = 1, /**< NIST approved/standardized */
    NIST_STATUS_RECOMMENDED = 2, /**< NIST recommended           */
    NIST_STATUS_ACCEPTABLE  = 3, /**< Acceptable for legacy use  */
    NIST_STATUS_DEPRECATED  = 4, /**< Deprecated, avoid new use  */
    NIST_STATUS_FORBIDDEN   = 5  /**< Not allowed                */
} citius_nist_status_t;

typedef struct {
    uint32_t                     security_strength_bits; /**< Minimum security strength in bits */
    citius_nist_security_level_t nist_security_level;
    int8_t                       quantum_safe;   /**< -1 = unset, 0 = false, 1 = true */
    citius_nist_status_t         nist_status;
    int8_t                       fips_approved;  /**< -1 = unset, 0 = false, 1 = true */
} citius_universal_security_properties_t;

/* =========================================================================
 * Per-primitive scope specification structs  (proto: *ScopeSpec messages)
 *
 * Each struct wraps a scope enum + UniversalSecurityProperties + any
 * scope-specific boolean properties, mirroring the proto messages exactly.
 * The additional_properties map<string,string> is represented as a nullable
 * citius_map_t pointer (same convention used throughout this header).
 * ========================================================================= */

/** SignatureScopeSpec  (proto: SignatureScopeSpec) */
typedef struct {
    citius_signature_scope_t                scope;    /**< REQUIRED — must not be UNSPECIFIED */
    citius_universal_security_properties_t  security;
    int8_t                                  non_malleable; /**< -1 = unset, 0 = false, 1 = true */
    int8_t                                  deterministic; /**< -1 = unset, 0 = false, 1 = true */
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_signature_scope_spec_t;

/** AeadScopeSpec  (proto: AeadScopeSpec) */
typedef struct {
    citius_aead_scope_t                     scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    int8_t                                  nonce_misuse_resistant; /**< -1 = unset, 0 = false, 1 = true */
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_aead_scope_spec_t;

/** MacScopeSpec  (proto: MacScopeSpec) */
typedef struct {
    citius_mac_scope_t                      scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_mac_scope_spec_t;

/** KemScopeSpec  (proto: KemScopeSpec) */
typedef struct {
    citius_kem_scope_t                      scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_kem_scope_spec_t;

/** KeyAgreementScopeSpec  (proto: KeyAgreementScopeSpec) */
typedef struct {
    citius_key_agreement_scope_t            scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    int8_t                                  forward_secrecy; /**< -1 = unset, 0 = false, 1 = true */
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_key_agreement_scope_spec_t;

/** KdfScopeSpec  (proto: KdfScopeSpec) */
typedef struct {
    citius_kdf_scope_t                      scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    int8_t                                  memory_hard; /**< -1 = unset, 0 = false, 1 = true */
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_kdf_scope_spec_t;

/** HashScopeSpec  (proto: HashScopeSpec) */
typedef struct {
    citius_hash_scope_t                     scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_hash_scope_spec_t;

/** KeyWrappingScopeSpec  (proto: KeyWrappingScopeSpec) */
typedef struct {
    citius_key_wrapping_scope_t             scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_key_wrapping_scope_spec_t;

/** SymmetricCipherScopeSpec  (proto: SymmetricCipherScopeSpec) */
typedef struct {
    citius_symmetric_cipher_scope_t         scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_symmetric_cipher_scope_spec_t;

/** DiskEncryptionScopeSpec  (proto: DiskEncryptionScopeSpec) */
typedef struct {
    citius_disk_encryption_scope_t          scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_disk_encryption_scope_spec_t;

/** GenericSecretScopeSpec  (proto: GenericSecretScopeSpec) */
typedef struct {
    citius_generic_secret_scope_t           scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_generic_secret_scope_spec_t;

/** AsymmetricEncryptionScopeSpec  (proto: AsymmetricEncryptionScopeSpec) */
typedef struct {
    citius_asymmetric_encryption_scope_t    scope;    /**< REQUIRED */
    citius_universal_security_properties_t  security;
    const citius_map_t                     *additional_properties; /**< nullable */
} citius_asymmetric_encryption_scope_spec_t;

/* =========================================================================
 * ScopeSpecification  (proto: ScopeSpecification)
 *
 * Unified oneof wrapper — set exactly one arm; the type field is the
 * discriminator. Used in both CreateKeyRequest (requirements) and
 * TemplateInfo (capabilities).
 * ========================================================================= */

typedef enum {
    CITIUS_SCOPE_SPEC_UNSPECIFIED           = 0,
    CITIUS_SCOPE_SPEC_SIGNATURE             = 1,
    CITIUS_SCOPE_SPEC_AEAD                  = 2,
    CITIUS_SCOPE_SPEC_MAC                   = 3,
    CITIUS_SCOPE_SPEC_KEM                   = 4,
    CITIUS_SCOPE_SPEC_KEY_AGREEMENT         = 5,
    CITIUS_SCOPE_SPEC_KDF                   = 6,
    CITIUS_SCOPE_SPEC_HASH                  = 7,
    CITIUS_SCOPE_SPEC_KEY_WRAPPING          = 8,
    CITIUS_SCOPE_SPEC_SYMMETRIC_CIPHER      = 9,
    CITIUS_SCOPE_SPEC_GENERIC_SECRET        = 10,
    CITIUS_SCOPE_SPEC_DISK_ENCRYPTION       = 11,
    CITIUS_SCOPE_SPEC_ASYMMETRIC_ENCRYPTION = 12
} citius_scope_spec_type_t;

typedef struct {
    citius_scope_spec_type_t type; /**< Discriminator — which union arm is valid */
    union {
        citius_signature_scope_spec_t              signature;             /**< CITIUS_SCOPE_SPEC_SIGNATURE             */
        citius_aead_scope_spec_t                   aead;                  /**< CITIUS_SCOPE_SPEC_AEAD                  */
        citius_mac_scope_spec_t                    mac;                   /**< CITIUS_SCOPE_SPEC_MAC                   */
        citius_kem_scope_spec_t                    kem;                   /**< CITIUS_SCOPE_SPEC_KEM                   */
        citius_key_agreement_scope_spec_t          key_agreement;         /**< CITIUS_SCOPE_SPEC_KEY_AGREEMENT         */
        citius_kdf_scope_spec_t                    kdf;                   /**< CITIUS_SCOPE_SPEC_KDF                   */
        citius_hash_scope_spec_t                   hash;                  /**< CITIUS_SCOPE_SPEC_HASH                  */
        citius_key_wrapping_scope_spec_t           key_wrapping;          /**< CITIUS_SCOPE_SPEC_KEY_WRAPPING          */
        citius_symmetric_cipher_scope_spec_t       symmetric_cipher;      /**< CITIUS_SCOPE_SPEC_SYMMETRIC_CIPHER      */
        citius_generic_secret_scope_spec_t         generic_secret;        /**< CITIUS_SCOPE_SPEC_GENERIC_SECRET        */
        citius_disk_encryption_scope_spec_t        disk_encryption;       /**< CITIUS_SCOPE_SPEC_DISK_ENCRYPTION       */
        citius_asymmetric_encryption_scope_spec_t  asymmetric_encryption; /**< CITIUS_SCOPE_SPEC_ASYMMETRIC_ENCRYPTION */
    } spec;
} citius_scope_spec_t;

/* =========================================================================
 * Security guarantees  (proto: FormalSecurityNotions,
 *                               PracticalSecurityOutcomes,
 *                               OperationalBounds, SecurityGuarantees)
 *
 * Informational only — NOT used for template filtering or policy enforcement.
 * ========================================================================= */

/** FormalSecurityNotions  (proto: FormalSecurityNotions) */
typedef struct {
    /* Encryption notions */
    int8_t ind_cpa;  /**< -1 = unset */
    int8_t ind_cca1; /**< -1 = unset */
    int8_t ind_cca2; /**< -1 = unset */
    int8_t nm_cpa;   /**< -1 = unset */
    int8_t int_ctxt; /**< -1 = unset */
    int8_t int_ptxt; /**< -1 = unset */
    /* Signature / MAC notions */
    int8_t euf_cma;  /**< -1 = unset */
    int8_t suf_cma;  /**< -1 = unset */
    int8_t prf;      /**< -1 = unset */
    /* Hash notions */
    int8_t preimage_resistant;        /**< -1 = unset */
    int8_t second_preimage_resistant; /**< -1 = unset */
    int8_t collision_resistant;       /**< -1 = unset */
    /* KEM / key agreement notions */
    int8_t ow_cca;      /**< -1 = unset */
    int8_t ind_cca_kem; /**< -1 = unset */
} citius_formal_security_notions_t;

/** PracticalSecurityOutcomes  (proto: PracticalSecurityOutcomes) */
typedef struct {
    uint8_t confidentiality; /**< 1 if provided */
    uint8_t integrity;       /**< 1 if provided */
    uint8_t authenticity;    /**< 1 if provided */
    uint8_t non_repudiation; /**< 1 if provided */
} citius_practical_security_outcomes_t;

/** OperationalBounds  (proto: OperationalBounds) */
typedef struct {
    uint32_t    authentication_strength_bits;
    uint64_t    max_messages_per_key;
    uint64_t    max_plaintext_bytes_per_key;
    const char *attack_success_probability; /**< nullable; "2^N" or "XeY" notation */
} citius_operational_bounds_t;

/** SecurityGuarantees  (proto: SecurityGuarantees) */
typedef struct {
    citius_formal_security_notions_t     formal;
    citius_practical_security_outcomes_t practical;
    citius_operational_bounds_t          bounds;
    const citius_map_t                  *additional_properties; /**< nullable */
} citius_security_guarantees_t;

/* =========================================================================
 * Key lifecycle  (proto: KeyLifecycleState)
 * ========================================================================= */

typedef enum {
    KEY_LIFECYCLE_STATE_UNSPECIFIED           = 0,
    KEY_LIFECYCLE_STATE_PRE_ACTIVE            = 1, /**< Generated but not yet usable */
    KEY_LIFECYCLE_STATE_ACTIVE                = 2, /**< Normal use                   */
    KEY_LIFECYCLE_STATE_SUSPENDED             = 3, /**< Temporarily disabled         */
    KEY_LIFECYCLE_STATE_DEACTIVATED           = 4, /**< No new operations            */
    KEY_LIFECYCLE_STATE_COMPROMISED           = 5, /**< Key material may be exposed  */
    KEY_LIFECYCLE_STATE_DESTROYED             = 6, /**< Soft-deleted; metadata retained */
    KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED = 7  /**< Compromised key destroyed    */
} citius_key_lifecycle_state_t;

/* =========================================================================
 * Key/wrap formats  (proto: KeyFormat, WrapFormat)
 * ========================================================================= */

typedef enum {
    KEY_FORMAT_UNSPECIFIED = 0,
    KEY_FORMAT_RAW         = 1, /**< Raw key bytes                  */
    KEY_FORMAT_WRAPPED     = 2, /**< Key wrapped with a KEK         */
    KEY_FORMAT_PKCS8       = 3, /**< PKCS#8 DER (asymmetric private) */
    KEY_FORMAT_SPKI        = 4, /**< SubjectPublicKeyInfo DER (public) */
    KEY_FORMAT_JWK         = 5, /**< JSON Web Key (RFC 7517)        */
    KEY_FORMAT_PEM         = 6, /**< PEM encoding                   */
    KEY_FORMAT_SEC1        = 7  /**< SEC 1 DER (EC private, RFC 5915) */
} citius_key_format_t;

typedef enum {
    WRAP_FORMAT_UNSPECIFIED = 0,
    WRAP_FORMAT_PKCS8       = 1,
    WRAP_FORMAT_PKCS1       = 2,
    WRAP_FORMAT_RAW         = 3,
    WRAP_FORMAT_SPKI        = 4,
    WRAP_FORMAT_SEC1        = 5
} citius_wrap_format_t;

/* =========================================================================
 * CryptoOperation  (proto: CryptoOperation)
 * ========================================================================= */

typedef enum {
    CRYPTO_OPERATION_UNSPECIFIED       = 0,
    /* Key lifecycle */
    CRYPTO_OPERATION_CREATE_KEY        = 1,
    CRYPTO_OPERATION_READ_KEY          = 2,
    CRYPTO_OPERATION_DELETE_KEY        = 3,
    CRYPTO_OPERATION_ROTATE_KEY        = 4,
    CRYPTO_OPERATION_TRANSFORM_KEY     = 5,
    CRYPTO_OPERATION_IMPORT_KEY        = 6,
    CRYPTO_OPERATION_EXPORT_KEY        = 7,
    CRYPTO_OPERATION_UPDATE_KEY_POLICY = 8,
    CRYPTO_OPERATION_MIGRATE_KEY       = 9,
    /* Encryption */
    CRYPTO_OPERATION_ENCRYPT           = 10,
    CRYPTO_OPERATION_DECRYPT           = 11,
    /* Signing */
    CRYPTO_OPERATION_SIGN              = 20,
    CRYPTO_OPERATION_VERIFY            = 21,
    CRYPTO_OPERATION_DIGEST_SIGN       = 22,
    CRYPTO_OPERATION_DIGEST_VERIFY     = 23,
    /* Key wrapping */
    CRYPTO_OPERATION_WRAP_KEY          = 30,
    CRYPTO_OPERATION_UNWRAP_KEY        = 31,
    /* Key derivation */
    CRYPTO_OPERATION_DERIVE_KEY        = 40,
    /* MAC */
    CRYPTO_OPERATION_GENERATE_MAC      = 50,
    CRYPTO_OPERATION_VERIFY_MAC        = 51,
    /* Digest */
    CRYPTO_OPERATION_DIGEST            = 60,
    /* Key encapsulation */
    CRYPTO_OPERATION_ENCAPSULATE       = 70,
    CRYPTO_OPERATION_DECAPSULATE       = 71,
    /* Key agreement */
    CRYPTO_OPERATION_KEY_AGREEMENT     = 80,
    /* Random */
    CRYPTO_OPERATION_GENERATE_RANDOM   = 90,
    CRYPTO_OPERATION_SEED_RANDOM       = 91,
    /* Dual-function */
    CRYPTO_OPERATION_DIGEST_ENCRYPT    = 100,
    CRYPTO_OPERATION_DECRYPT_DIGEST    = 101,
    CRYPTO_OPERATION_SIGN_ENCRYPT      = 102,
    CRYPTO_OPERATION_DECRYPT_VERIFY    = 103
} citius_crypto_operation_t;

/* =========================================================================
 * CryptoErrorCode  (proto: CryptoErrorCode)
 * ========================================================================= */

typedef enum {
    CRYPTO_ERROR_UNSPECIFIED                  = 0,
    CRYPTO_ERROR_KEY_NOT_FOUND                = 1,
    CRYPTO_ERROR_KEY_EXPIRED                  = 2,
    CRYPTO_ERROR_KEY_VERSION_MISMATCH         = 3,
    CRYPTO_ERROR_KEY_NOT_EXPORTABLE           = 4,
    CRYPTO_ERROR_KEY_OPERATION_NOT_ALLOWED    = 5,
    CRYPTO_ERROR_TEMPLATE_NOT_FOUND           = 10,
    CRYPTO_ERROR_TEMPLATE_DEPRECATED          = 11,
    CRYPTO_ERROR_TEMPLATE_FORBIDDEN           = 12,
    CRYPTO_ERROR_NO_MATCHING_TEMPLATE         = 13,
    CRYPTO_ERROR_PROVIDER_NOT_FOUND           = 20,
    CRYPTO_ERROR_PROVIDER_UNAVAILABLE         = 21,
    CRYPTO_ERROR_PROVIDER_INCOMPATIBLE        = 22,
    CRYPTO_ERROR_NO_MATCHING_PROVIDER         = 23,
    CRYPTO_ERROR_POLICY_NOT_FOUND             = 30,
    CRYPTO_ERROR_POLICY_VIOLATION             = 31,
    CRYPTO_ERROR_INVALID_OPERATION_STATE      = 40,
    CRYPTO_ERROR_OPERATION_EXPIRED            = 41,
    CRYPTO_ERROR_AUTHENTICATION_FAILED        = 42,
    CRYPTO_ERROR_SIGNATURE_INVALID            = 43,
    CRYPTO_ERROR_INCOMPATIBLE_PARAMETERS      = 44,
    CRYPTO_ERROR_MIGRATION_NOT_FEASIBLE       = 50,
    CRYPTO_ERROR_KEY_NOT_EXTRACTABLE          = 51,
    CRYPTO_ERROR_INVALID_KEY_MATERIAL         = 60,
    CRYPTO_ERROR_KEY_SIZE_MISMATCH            = 61,
    CRYPTO_ERROR_INSUFFICIENT_ENTROPY         = 62,
    CRYPTO_ERROR_RATE_LIMITED                 = 70,
    CRYPTO_ERROR_CONCURRENT_ACCESS            = 71
} citius_crypto_error_code_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_COMMON_H */
