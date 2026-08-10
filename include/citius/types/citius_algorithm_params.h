/**
 * @file citius_algorithm_params.h
 * @brief Algorithm enumeration types and parameter structs.
 *
 * Mirrors api/proto/types/algorithm_params.proto (and, for the
 * AlgorithmDetails oneof / HybridAlgorithmParams / HybridComponent
 * messages, the algorithm-parameter portions of api/proto/types/templates.proto).
 *
 * Every proto message maps to a C struct; every proto enum maps to a C enum
 * with CITIUS_-prefixed constants. The top-level tagged union
 * citius_algorithm_params_t corresponds to the AlgorithmDetails oneof; its
 * discriminator is citius_algorithm_case_t (one value per oneof arm) — NOT
 * citius_crypto_primitive_t, which is a coarser CycloneDX classification
 * shared by several distinct oneof arms and cannot disambiguate them.
 */

#ifndef CITIUS_ALGORITHM_PARAMS_H
#define CITIUS_ALGORITHM_PARAMS_H

#include "citius_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Forward declaration only — the full definition lives in citius_templates.h.
 * Referenced here strictly by pointer (in citius_hybrid_component_t) to
 * break the mutual recursion in the proto: AlgorithmDetails.algorithm oneof
 * has a `hybrid` arm (HybridAlgorithmParams) whose components
 * (HybridComponent) each carry their own nested AlgorithmDetails.
 */
typedef struct citius_algorithm_details_s citius_algorithm_details_t;

/* =========================================================================
 * Hash algorithms  (proto: HashAlgorithm enum)
 *
 * Semantic mirror only — covers the same set of algorithms as proto's
 * HashAlgorithm, but the numeric values below are assigned independently
 * and do NOT match the proto enum's wire values member-for-member.
 * ========================================================================= */

typedef enum {
    CITIUS_HASH_UNSPECIFIED       = 0,

    /* SHA-2 family */
    CITIUS_HASH_SHA2_224          = 1,
    CITIUS_HASH_SHA2_256          = 2,
    CITIUS_HASH_SHA2_384          = 3,
    CITIUS_HASH_SHA2_512          = 4,
    CITIUS_HASH_SHA2_512_224      = 5,
    CITIUS_HASH_SHA2_512_256      = 6,

    /* SHA-3 family */
    CITIUS_HASH_SHA3_224          = 10,
    CITIUS_HASH_SHA3_256          = 11,
    CITIUS_HASH_SHA3_384          = 12,
    CITIUS_HASH_SHA3_512          = 13,

    /* SHAKE (XOF) */
    CITIUS_HASH_SHAKE128          = 20,
    CITIUS_HASH_SHAKE256          = 21,

    /* BLAKE2 family */
    CITIUS_HASH_BLAKE2B_256       = 30,
    CITIUS_HASH_BLAKE2B_384       = 31,
    CITIUS_HASH_BLAKE2B_512       = 32,
    CITIUS_HASH_BLAKE2S_160       = 33,
    CITIUS_HASH_BLAKE2S_224       = 34,
    CITIUS_HASH_BLAKE2S_256       = 35,

    /* BLAKE3 */
    CITIUS_HASH_BLAKE3            = 40,

    /* GOST */
    CITIUS_HASH_GOST_R34_11_94    = 50,
    CITIUS_HASH_GOST_R34_11_2012_256 = 51, /* Streebog-256 */
    CITIUS_HASH_GOST_R34_11_2012_512 = 52, /* Streebog-512 */

    /* Legacy — NOT RECOMMENDED for new applications */
    CITIUS_HASH_SHA1               = 100, /**< Required by HOTP/TOTP (RFC 4226/6238) */
    CITIUS_HASH_MD5                = 101,

    /* Extensible */
    CITIUS_HASH_OTHER              = 200  /**< Set alongside an OID for unlisted algorithms */
} citius_hash_algorithm_t;

/* =========================================================================
 * Elliptic curves  (proto: EllipticCurve enum)
 *
 * Semantic mirror only — the numeric values below are assigned
 * independently and do NOT match proto's EllipticCurve wire values.
 *
 * The four Edwards/Montgomery values below (ED25519/ED448/X25519/X448) have
 * NO counterpart in proto's EllipticCurve enum at all: proto instead
 * represents those curves generically (CURVE25519/CURVE448) only inside
 * Ed25519Params/Ed448Params/X25519Params/X448Params, none of which carry an
 * EllipticCurve-typed field. Nothing in this header currently assigns these
 * four C values either — EcdsaParams.curve and EcdhParams.curve (the only
 * two fields of this type) never take Ed/X values. Kept for possible future
 * use; treat as reserved/unused rather than a live proto mapping.
 * ========================================================================= */

typedef enum {
    CITIUS_CURVE_UNSPECIFIED      = 0,

    /* NIST prime curves */
    CITIUS_CURVE_P256             = 1,
    CITIUS_CURVE_P384             = 2,
    CITIUS_CURVE_P521             = 3,

    /* Koblitz / Certicom */
    CITIUS_CURVE_SECP256K1        = 10,

    /* Brainpool */
    CITIUS_CURVE_BRAINPOOL_P256R1 = 20,
    CITIUS_CURVE_BRAINPOOL_P384R1 = 21,
    CITIUS_CURVE_BRAINPOOL_P512R1 = 22,
    CITIUS_CURVE_BRAINPOOL_P256T1 = 23,
    CITIUS_CURVE_BRAINPOOL_P384T1 = 24, /* proto: ELLIPTIC_CURVE_BRAINPOOL_P384T1 */
    CITIUS_CURVE_BRAINPOOL_P512T1 = 25, /* proto: ELLIPTIC_CURVE_BRAINPOOL_P512T1 */

    /* Edwards / Montgomery — reserved/unused; see file note above */
    CITIUS_CURVE_ED25519          = 30,
    CITIUS_CURVE_ED448            = 31,
    CITIUS_CURVE_X25519           = 32,
    CITIUS_CURVE_X448             = 33,

    /* Binary curves (NIST) */
    CITIUS_CURVE_B163             = 40,
    CITIUS_CURVE_B233             = 41,
    CITIUS_CURVE_B283             = 42,
    CITIUS_CURVE_B409             = 43,
    CITIUS_CURVE_B571             = 44,
    CITIUS_CURVE_K163             = 45,
    CITIUS_CURVE_K233             = 46,
    CITIUS_CURVE_K283             = 47,
    CITIUS_CURVE_K409             = 48,
    CITIUS_CURVE_K571             = 49
} citius_elliptic_curve_t;

/* =========================================================================
 * Key types  (proto: KeyType enum)
 *
 * Not a member-for-member or numeric mirror. Proto's single generic
 * KEY_TYPE_SYMMETRIC bucket is deliberately expanded here into distinct
 * per-cipher values (AES/CHACHA20/3DES/CAMELLIA/ARIA/SEED/GOST28147, plus a
 * SYMMETRIC catch-all matching proto's generic value) for finer-grained
 * key management; the classical/PQ/hybrid values are also renumbered.
 * ========================================================================= */

typedef enum {
    CITIUS_KEY_TYPE_UNSPECIFIED   = 0,

    /* Symmetric */
    CITIUS_KEY_TYPE_AES           = 1,
    CITIUS_KEY_TYPE_CHACHA20      = 2,
    CITIUS_KEY_TYPE_3DES          = 3,
    CITIUS_KEY_TYPE_CAMELLIA      = 4,
    CITIUS_KEY_TYPE_ARIA          = 5,
    CITIUS_KEY_TYPE_SEED          = 6,
    CITIUS_KEY_TYPE_GOST28147     = 7,
    CITIUS_KEY_TYPE_SYMMETRIC     = 8, /**< Generic symmetric key (proto: KEY_TYPE_SYMMETRIC); prefer the specific values above when the cipher is known */

    /* Asymmetric classical */
    CITIUS_KEY_TYPE_RSA           = 20,
    CITIUS_KEY_TYPE_EC            = 21,
    CITIUS_KEY_TYPE_DSA           = 22,
    CITIUS_KEY_TYPE_DH            = 23, /**< Diffie-Hellman keys (finite field) */

    /* Asymmetric modern */
    CITIUS_KEY_TYPE_ED25519       = 30,
    CITIUS_KEY_TYPE_ED448         = 31,
    CITIUS_KEY_TYPE_X25519        = 32,
    CITIUS_KEY_TYPE_X448          = 33,

    /* Post-quantum */
    CITIUS_KEY_TYPE_ML_DSA        = 40,
    CITIUS_KEY_TYPE_SLH_DSA       = 41,
    CITIUS_KEY_TYPE_ML_KEM        = 42,

    /* Hybrid */
    CITIUS_KEY_TYPE_HYBRID        = 50,

    /* Special purpose */
    CITIUS_KEY_TYPE_HMAC          = 60,
    CITIUS_KEY_TYPE_GENERIC_SECRET= 61,
    CITIUS_KEY_TYPE_OTP           = 62,
    CITIUS_KEY_TYPE_GOST_R34_10   = 63,
    CITIUS_KEY_TYPE_PQ_EXPERIMENTAL = 64, /**< Pre-standard PQ algorithms (BIKE, HQC, McEliece, …) */
    CITIUS_KEY_TYPE_CUSTOM        = 65,   /**< Any other custom algorithm */
    CITIUS_KEY_TYPE_VENDOR        = 255
} citius_key_type_t;

/* =========================================================================
 * Cryptographic primitives  (proto: CryptographicPrimitive enum, CycloneDX)
 *
 * Coarse CBOM classification. NOT a discriminator — see
 * citius_algorithm_case_t below for the AlgorithmDetails.algorithm oneof
 * discriminator.
 * ========================================================================= */

typedef enum {
    CITIUS_PRIMITIVE_UNSPECIFIED      = 0,
    CITIUS_PRIMITIVE_AE               = 1,  /* Authenticated Encryption (proto: CRYPTO_PRIMITIVE_AE) */
    CITIUS_PRIMITIVE_BLOCK_CIPHER     = 2,
    CITIUS_PRIMITIVE_STREAM_CIPHER    = 3,
    CITIUS_PRIMITIVE_PKE              = 4,  /* Public Key Encryption */
    CITIUS_PRIMITIVE_SIGNATURE        = 10,
    CITIUS_PRIMITIVE_KEM              = 20,
    CITIUS_PRIMITIVE_KEY_AGREE        = 21, /* proto: CRYPTO_PRIMITIVE_KEY_AGREE */
    CITIUS_PRIMITIVE_HASH             = 30,
    CITIUS_PRIMITIVE_MAC              = 31,
    CITIUS_PRIMITIVE_XOF              = 32, /* Extendable Output Function */
    CITIUS_PRIMITIVE_KDF              = 40,
    CITIUS_PRIMITIVE_KEY_WRAP         = 41,
    CITIUS_PRIMITIVE_OTP              = 45,
    CITIUS_PRIMITIVE_DRBG             = 50,
    CITIUS_PRIMITIVE_COMBINER         = 51,
    CITIUS_PRIMITIVE_OTHER            = 99
} citius_crypto_primitive_t;

/* =========================================================================
 * AlgorithmDetails.algorithm oneof discriminator
 * (proto: templates.proto AlgorithmDetails, `oneof algorithm`)
 *
 * One value per oneof arm, valued after the arm's proto field number.
 * This is the discriminator for citius_algorithm_params_t.params below.
 * ========================================================================= */

typedef enum {
    CITIUS_ALGORITHM_UNSPECIFIED        = 0,

    CITIUS_ALGORITHM_AES_GCM            = 20,
    CITIUS_ALGORITHM_AES_CBC            = 21,
    CITIUS_ALGORITHM_AES_CTR            = 22,
    CITIUS_ALGORITHM_CHACHA20_POLY1305  = 23,
    CITIUS_ALGORITHM_AES_CCM            = 24,
    CITIUS_ALGORITHM_AES_XTS            = 25,

    CITIUS_ALGORITHM_TRIPLE_DES         = 27,
    CITIUS_ALGORITHM_BLOWFISH           = 28,
    CITIUS_ALGORITHM_TWOFISH            = 29,

    CITIUS_ALGORITHM_ECDSA              = 30,
    CITIUS_ALGORITHM_ED25519            = 31,
    CITIUS_ALGORITHM_ED448              = 32,
    CITIUS_ALGORITHM_RSA_PSS            = 33,
    CITIUS_ALGORITHM_RSA_PKCS1V15       = 34,
    CITIUS_ALGORITHM_DSA                = 35,

    CITIUS_ALGORITHM_ML_DSA             = 40,
    CITIUS_ALGORITHM_SLH_DSA            = 41,
    CITIUS_ALGORITHM_GOST3410           = 42,

    CITIUS_ALGORITHM_ML_KEM             = 50,
    CITIUS_ALGORITHM_RSA_OAEP           = 51,

    CITIUS_ALGORITHM_HKDF               = 60,
    CITIUS_ALGORITHM_PBKDF2             = 61,
    CITIUS_ALGORITHM_ARGON2             = 62,
    CITIUS_ALGORITHM_SP800_108_KDF      = 63,
    CITIUS_ALGORITHM_TLS12              = 64,

    CITIUS_ALGORITHM_HMAC               = 70,
    CITIUS_ALGORITHM_KMAC                = 71,
    CITIUS_ALGORITHM_CMAC               = 72,
    CITIUS_ALGORITHM_GOST3411           = 73,
    CITIUS_ALGORITHM_POLY1305           = 74,

    CITIUS_ALGORITHM_AES_KEY_WRAP       = 80,

    CITIUS_ALGORITHM_ECDH               = 90,
    CITIUS_ALGORITHM_X25519             = 91,
    CITIUS_ALGORITHM_X448               = 92,
    CITIUS_ALGORITHM_DIFFIE_HELLMAN     = 93,
    CITIUS_ALGORITHM_X3DH               = 94,

    CITIUS_ALGORITHM_CUSTOM             = 100,

    CITIUS_ALGORITHM_CAMELLIA           = 110,
    CITIUS_ALGORITHM_ARIA               = 111,
    CITIUS_ALGORITHM_SEED               = 112,
    CITIUS_ALGORITHM_GOST28147          = 113,

    CITIUS_ALGORITHM_HOTP               = 120,
    CITIUS_ALGORITHM_TOTP               = 121,

    CITIUS_ALGORITHM_HYBRID             = 130
} citius_algorithm_case_t;

/* =========================================================================
 * Post-quantum parameter sets
 * ========================================================================= */

/** ML-DSA (FIPS 204) parameter sets  (proto: MlDsaParameterSet) */
typedef enum {
    CITIUS_ML_DSA_PARAMETER_SET_UNSPECIFIED = 0,
    CITIUS_ML_DSA_44                        = 1, /**< NIST Level 2, 128-bit classical */
    CITIUS_ML_DSA_65                        = 2, /**< NIST Level 3, 192-bit classical */
    CITIUS_ML_DSA_87                        = 3  /**< NIST Level 5, 256-bit classical */
} citius_ml_dsa_parameter_set_t;

/** ML-KEM (FIPS 203) parameter sets  (proto: MlKemParameterSet) */
typedef enum {
    CITIUS_ML_KEM_PARAMETER_SET_UNSPECIFIED = 0,
    CITIUS_ML_KEM_512                       = 1, /**< NIST Level 1 */
    CITIUS_ML_KEM_768                       = 2, /**< NIST Level 3 */
    CITIUS_ML_KEM_1024                      = 3  /**< NIST Level 5 */
} citius_ml_kem_parameter_set_t;

/**
 * SLH-DSA (FIPS 205) parameter sets  (proto: SlhDsaParameterSet)
 *
 * proto splits this into two orthogonal required fields on SlhDsaParams:
 * hash_type (SlhDsaHashType: SHA2 or SHAKE) and parameter_set
 * (SlhDsaParameterSet: 128S..256F, 6 values). This enum instead encodes
 * the full cross product (2 hash types × 6 parameter sets = 12 values
 * below) — lossless, but citius_slh_dsa_params_t has no separate
 * hash_type field as a result; it's baked into which of these 12 values
 * you pick.
 */
typedef enum {
    CITIUS_SLH_DSA_PARAMETER_SET_UNSPECIFIED = 0,
    CITIUS_SLH_DSA_SHA2_128S                 = 1,
    CITIUS_SLH_DSA_SHA2_128F                 = 2,
    CITIUS_SLH_DSA_SHA2_192S                 = 3,
    CITIUS_SLH_DSA_SHA2_192F                 = 4,
    CITIUS_SLH_DSA_SHA2_256S                 = 5,
    CITIUS_SLH_DSA_SHA2_256F                 = 6,
    CITIUS_SLH_DSA_SHAKE_128S                = 7,
    CITIUS_SLH_DSA_SHAKE_128F                = 8,
    CITIUS_SLH_DSA_SHAKE_192S                = 9,
    CITIUS_SLH_DSA_SHAKE_192F                = 10,
    CITIUS_SLH_DSA_SHAKE_256S                = 11,
    CITIUS_SLH_DSA_SHAKE_256F                = 12
} citius_slh_dsa_parameter_set_t;

/* =========================================================================
 * RSA salt length (proto: RsaSaltLength)
 * ========================================================================= */

typedef enum {
    CITIUS_RSA_SALT_LENGTH_HASH        = 0, /**< Salt length == hash output length */
    CITIUS_RSA_SALT_LENGTH_MAX         = 1, /**< Maximum possible salt length      */
    CITIUS_RSA_SALT_LENGTH_EXPLICIT    = 2  /**< Caller-specified in explicit_bytes */
} citius_rsa_salt_length_t;

/* =========================================================================
 * Ed25519 variant  (proto: Ed25519Variant)
 * ========================================================================= */

typedef enum {
    CITIUS_ED25519_VARIANT_UNSPECIFIED = 0,
    CITIUS_ED25519_VARIANT_PURE        = 1, /**< Standard Ed25519 (RFC 8032)   */
    CITIUS_ED25519_VARIANT_CTX         = 2, /**< Ed25519ctx — with context      */
    CITIUS_ED25519_VARIANT_PH          = 3  /**< Ed25519ph — prehashed          */
} citius_ed25519_variant_t;

/* =========================================================================
 * Argon2 variant  (proto: Argon2Variant)
 * ========================================================================= */

typedef enum {
    CITIUS_ARGON2_VARIANT_UNSPECIFIED = 0,
    CITIUS_ARGON2_VARIANT_D           = 1, /**< Argon2d — data-dependent         */
    CITIUS_ARGON2_VARIANT_I           = 2, /**< Argon2i — data-independent       */
    CITIUS_ARGON2_VARIANT_ID          = 3  /**< Argon2id — hybrid (recommended)  */
} citius_argon2_variant_t;

/* =========================================================================
 * AES / block-cipher mode
 *
 * Proto has no single "AesMode" enum — instead, TripleDesParams.Mode,
 * CamelliaParams.Mode, AriaParams.Mode, SeedParams.Mode, and
 * Gost28147Params.Mode are five independent, message-local enums, each
 * with its own numbering (e.g. Gost28147Params.Mode{ECB=1,CBC=2,CFB=3} vs.
 * CamelliaParams.Mode{ECB=1,CBC=2,CTR=3}). This C enum deliberately
 * consolidates all of them (plus AES-GCM/CCM/XTS/SIV) into one shared type
 * for convenience; its values do not numerically match any single proto
 * Mode enum — treat it as a semantic union of ECB/CBC/CTR/CFB/... across
 * all five, not a mirror of one proto type.
 * ========================================================================= */

typedef enum {
    CITIUS_AES_MODE_UNSPECIFIED     = 0,
    CITIUS_AES_MODE_GCM             = 1,
    CITIUS_AES_MODE_CBC             = 2,
    CITIUS_AES_MODE_CTR             = 3,
    CITIUS_AES_MODE_CCM             = 4,
    CITIUS_AES_MODE_XTS             = 5,
    CITIUS_AES_MODE_SIV             = 6,
    CITIUS_AES_MODE_GCM_SIV         = 7,
    CITIUS_AES_MODE_ECB             = 8,
    CITIUS_AES_MODE_CFB             = 9
} citius_aes_mode_t;

/* =========================================================================
 * Padding scheme  (proto: PaddingScheme)
 * ========================================================================= */

typedef enum {
    CITIUS_PADDING_UNSPECIFIED = 0,
    CITIUS_PADDING_NONE        = 1, /**< No padding — input must be block-aligned */
    CITIUS_PADDING_PKCS7       = 2, /**< PKCS#7 (RFC 5652) — recommended */
    CITIUS_PADDING_ISO7816     = 3, /**< ISO/IEC 7816-4 (0x80 followed by zeros) */
    CITIUS_PADDING_X923        = 4, /**< ANSI X9.23 (zeros followed by length) */
    CITIUS_PADDING_ZERO        = 5  /**< Zero padding — not recommended (ambiguous) */
} citius_padding_scheme_t;

/* =========================================================================
 * Signature format  (proto: SignatureFormat)
 * ========================================================================= */

typedef enum {
    CITIUS_SIGNATURE_FORMAT_UNSPECIFIED = 0,
    CITIUS_SIGNATURE_FORMAT_DER         = 1, /**< ASN.1 DER (default for ECDSA, RSA) */
    CITIUS_SIGNATURE_FORMAT_IEEE_P1363  = 2, /**< Fixed-size r||s (WebCrypto, JWS)   */
    CITIUS_SIGNATURE_FORMAT_RAW         = 3  /**< Raw bytes (Ed25519/Ed448 native)   */
} citius_signature_format_t;

/* =========================================================================
 * Mask generation function  (proto: MaskGenerationFunction)
 * ========================================================================= */

typedef enum {
    CITIUS_MGF_UNSPECIFIED = 0,
    CITIUS_MGF_MGF1        = 1 /**< MGF1 (PKCS#1 v2.1) — only standardized option */
} citius_mgf_t;

/* =========================================================================
 * ECDH KDF type  (proto: EcdhKdfType) — used by EcdhParams, X25519Params,
 * X448Params
 * ========================================================================= */

typedef enum {
    CITIUS_ECDH_KDF_UNSPECIFIED  = 0, /**< Return raw shared secret (x-coordinate) */
    CITIUS_ECDH_KDF_HKDF_SHA256  = 1,
    CITIUS_ECDH_KDF_HKDF_SHA384  = 2,
    CITIUS_ECDH_KDF_HKDF_SHA512  = 3,
    CITIUS_ECDH_KDF_X963_SHA256  = 4,
    CITIUS_ECDH_KDF_X963_SHA384  = 5,
    CITIUS_ECDH_KDF_X963_SHA512  = 6
} citius_ecdh_kdf_type_t;

/* =========================================================================
 * Algorithm-specific parameter structs
 * ========================================================================= */

/* ----- Symmetric AEAD --------------------------------------------------- */

/** AES-GCM parameters  (proto: AesGcmParams) */
typedef struct {
    uint32_t key_size_bits;  /**< 128, 192, or 256             */
    uint32_t iv_length_bits; /**< Typically 96                 */
    uint32_t tag_length_bits;/**< 96, 104, 112, 120, or 128   */
} citius_aes_gcm_params_t;

/** AES-CCM parameters  (proto: AesCcmParams) */
typedef struct {
    uint32_t key_size_bits;
    uint32_t nonce_length_bits; /**< 56–104 (7–13 bytes, even values) */
    uint32_t tag_length_bits;   /**< 32, 48, 64, 80, 96, 112, or 128 */
} citius_aes_ccm_params_t;

/** AES-XTS parameters  (proto: AesXtsParams — disk encryption) */
typedef struct {
    uint32_t key_size_bits;  /**< 128 or 256 (per key; total key = 2×) */
    uint32_t sector_size;    /**< Sector / data-unit size in bytes       */
} citius_aes_xts_params_t;

/** ChaCha20-Poly1305 parameters  (proto: ChaCha20Poly1305Params) */
typedef struct {
    uint32_t nonce_length_bits; /**< 96 (IETF) or 192 (XChaCha20)       */
    uint32_t counter_bits;      /**< 32 (IETF) or 64 (original)         */
    uint8_t  extended_nonce;    /**< 1 = XChaCha20 (192-bit nonce) variant */
} citius_chacha20_poly1305_params_t;

/* ----- Symmetric non-AEAD ----------------------------------------------- */

/** AES-CBC parameters  (proto: AesCbcParams) */
typedef struct {
    uint32_t                key_size_bits;  /**< 128, 192, or 256 */
    citius_padding_scheme_t padding;
} citius_aes_cbc_params_t;

/** AES-CTR parameters  (proto: AesCtrParams) */
typedef struct {
    uint32_t key_size_bits;    /**< 128, 192, or 256 */
    uint32_t nonce_size_bits;  /**< 64 or 96 */
    uint32_t counter_bits;     /**< Bits used for counter (typically 32 or 128) */
} citius_aes_ctr_params_t;

/* ----- Classical asymmetric signatures ---------------------------------- */

/** ECDSA parameters  (proto: EcdsaParams) */
typedef struct {
    citius_elliptic_curve_t    curve;
    citius_hash_algorithm_t    hash;
    citius_signature_format_t  signature_format;
    uint8_t                    deterministic; /**< 1 = RFC 6979 deterministic nonce */
} citius_ecdsa_params_t;

/** Ed25519 parameters  (proto: Ed25519Params) */
typedef struct {
    citius_ed25519_variant_t variant;
} citius_ed25519_params_t;

/** Ed448 parameters  (proto: Ed448Params) */
typedef struct {
    uint8_t               prehash; /**< 0 = pure Ed448, 1 = Ed448ph */
    citius_byte_buffer_t  context; /**< 0-255 bytes; empty = pure mode */
} citius_ed448_params_t;

/** RSA-PSS parameters  (proto: RsaPssParams) */
typedef struct {
    uint32_t                 modulus_bits;    /**< 2048, 3072, 4096, 8192, 16384 */
    citius_hash_algorithm_t  hash;
    citius_mgf_t              mgf;
    citius_hash_algorithm_t  mgf_hash;        /**< 0 = same as hash */
    citius_rsa_salt_length_t salt_length;
    uint32_t                 explicit_salt_bytes; /**< Used if salt_length == EXPLICIT */
} citius_rsa_pss_params_t;

/** RSA-PKCS1v15 parameters  (proto: RsaPkcs1v15Params) */
typedef struct {
    uint32_t                modulus_bits;
    citius_hash_algorithm_t hash;
} citius_rsa_pkcs1v15_params_t;

/** DSA parameters  (proto: DsaParams — legacy) */
typedef struct {
    uint32_t                key_size_bits; /**< 2048 or 3072 (modulus L); proto excludes 1024 per NIST SP 800-131A Rev 2 */
    uint32_t                subprime_bits; /**< N: 224 or 256 */
    citius_hash_algorithm_t hash;
} citius_dsa_params_t;

/* ----- Post-quantum signatures ------------------------------------------ */

/** ML-DSA parameters  (proto: MlDsaParams) */
typedef struct {
    citius_ml_dsa_parameter_set_t parameter_set;
    uint8_t                       deterministic; /**< 0 = hedged, 1 = deterministic */
} citius_ml_dsa_params_t;

/** SLH-DSA parameters  (proto: SlhDsaParams) */
typedef struct {
    citius_slh_dsa_parameter_set_t parameter_set;
    uint8_t                        deterministic;
} citius_slh_dsa_params_t;

/** GOST R 34.10-2001/2012 signature version  (proto: Gost3410Params.Version) */
typedef enum {
    CITIUS_GOST3410_VERSION_UNSPECIFIED = 0,
    CITIUS_GOST3410_VERSION_2001        = 1, /**< 256-bit keys only */
    CITIUS_GOST3410_VERSION_2012        = 2  /**< 256 or 512-bit keys */
} citius_gost3410_version_t;

/** GOST R 34.10-2001/2012 signature parameters  (proto: Gost3410Params) */
typedef struct {
    citius_gost3410_version_t version;
    uint32_t                  key_size_bits;        /**< 256 or 512 */
    const char                *parameter_set_oid;   /**< PKCS#11: CKA_GOSTR3410_PARAMS */
    const char                *digest_param_set_oid; /**< nullable; PKCS#11: CKA_GOSTR3411_PARAMS */
} citius_gost3410_params_t;

/* ----- Key encapsulation (KEM) ------------------------------------------ */

/** ML-KEM parameters  (proto: MlKemParams) */
typedef struct {
    citius_ml_kem_parameter_set_t parameter_set;
} citius_ml_kem_params_t;

/** RSA-OAEP (used as KEM) parameters  (proto: RsaOaepParams) */
typedef struct {
    uint32_t                modulus_bits;
    citius_hash_algorithm_t hash;
    citius_mgf_t             mgf;
    citius_hash_algorithm_t mgf1_hash; /**< MGF hash; 0 = same as hash */
} citius_rsa_oaep_params_t;

/* ----- Key agreement ---------------------------------------------------- */

/** ECDH parameters  (proto: EcdhParams) */
typedef struct {
    citius_elliptic_curve_t  curve;
    uint8_t                  cofactor_mode; /**< 1 = cofactor ECDH (ECCDH) */
    citius_ecdh_kdf_type_t   kdf;           /**< UNSPECIFIED = raw shared secret */
} citius_ecdh_params_t;

/** X25519 key agreement parameters  (proto: X25519Params) */
typedef struct {
    citius_ecdh_kdf_type_t kdf; /**< UNSPECIFIED = raw shared secret */
} citius_x25519_params_t;

/** X448 key agreement parameters  (proto: X448Params) */
typedef struct {
    citius_ecdh_kdf_type_t kdf; /**< UNSPECIFIED = raw shared secret */
} citius_x448_params_t;

/** Diffie-Hellman variant  (proto: DiffieHellmanParams.Variant) */
typedef enum {
    CITIUS_DH_VARIANT_UNSPECIFIED = 0,
    CITIUS_DH_VARIANT_PKCS3       = 1, /**< PKCS#3 basic DH */
    CITIUS_DH_VARIANT_X942        = 2, /**< ANSI X9.42 DH with subprime */
    CITIUS_DH_VARIANT_X942_MQV    = 3  /**< X9.42 MQV 2-key-pair variant */
} citius_dh_variant_t;

/** Diffie-Hellman KDF type  (proto: DiffieHellmanParams.KdfType) */
typedef enum {
    CITIUS_DH_KDF_UNSPECIFIED      = 0,
    CITIUS_DH_KDF_NULL             = 1, /**< Raw shared secret (z) */
    CITIUS_DH_KDF_SHA1_CONCATENATE = 2, /**< X9.42 KDF (legacy) */
    CITIUS_DH_KDF_SHA256_SP800     = 3, /**< NIST SP 800-56A */
    CITIUS_DH_KDF_SHA384_SP800     = 4,
    CITIUS_DH_KDF_SHA512_SP800     = 5
} citius_dh_kdf_type_t;

/** Classic DH parameters  (proto: DiffieHellmanParams) */
typedef struct {
    citius_dh_variant_t  variant;
    uint32_t              prime_bits; /**< 2048, 3072, 4096, 6144, 8192 */
    citius_dh_kdf_type_t kdf;
    uint32_t              private_value_length_bits; /**< 0 = no limiter */
} citius_dh_params_t;

/* ----- KDF --------------------------------------------------------------- */

/** HKDF parameters  (proto: HkdfParams) */
typedef struct {
    citius_hash_algorithm_t hash;
    uint8_t                 extract;         /**< Perform HKDF-Extract step */
    uint8_t                 expand;          /**< Perform HKDF-Expand step */
    uint32_t                salt_size_bytes; /**< 0 = use hash output size */
    uint32_t                output_key_bits; /**< Requested derived key size */
} citius_hkdf_params_t;

/** PBKDF2 parameters  (proto: Pbkdf2Params) */
typedef struct {
    citius_hash_algorithm_t hash;
    uint32_t                iterations;      /**< Minimum: 10 000 */
    uint32_t                salt_size_bytes; /**< Minimum: 16 */
    uint32_t                output_key_bits;
} citius_pbkdf2_params_t;

/** Argon2 parameters  (proto: Argon2Params) */
typedef struct {
    citius_argon2_variant_t variant;
    uint32_t                memory_kib;      /**< Memory cost in KiB   */
    uint32_t                iterations;
    uint32_t                parallelism;     /**< Number of threads    */
    uint32_t                salt_size_bytes; /**< Minimum: 16 */
    uint32_t                output_key_bits;
} citius_argon2_params_t;

/** SP800-108 KDF mode  (proto: Sp800108KdfParams.Mode) */
typedef enum {
    CITIUS_SP800108_MODE_UNSPECIFIED = 0,
    CITIUS_SP800108_COUNTER          = 1,
    CITIUS_SP800108_FEEDBACK         = 2,
    CITIUS_SP800108_DOUBLE_PIPELINE  = 3
} citius_sp800108_mode_t;

/** SP800-108 pseudorandom function  (proto: Sp800108KdfParams.PrfType) */
typedef enum {
    CITIUS_SP800108_PRF_UNSPECIFIED   = 0,
    CITIUS_SP800108_PRF_HMAC_SHA1     = 1,
    CITIUS_SP800108_PRF_HMAC_SHA224   = 2,
    CITIUS_SP800108_PRF_HMAC_SHA256   = 3,
    CITIUS_SP800108_PRF_HMAC_SHA384   = 4,
    CITIUS_SP800108_PRF_HMAC_SHA512   = 5,
    CITIUS_SP800108_PRF_HMAC_SHA3_224 = 6,
    CITIUS_SP800108_PRF_HMAC_SHA3_256 = 7,
    CITIUS_SP800108_PRF_HMAC_SHA3_384 = 8,
    CITIUS_SP800108_PRF_HMAC_SHA3_512 = 9,
    CITIUS_SP800108_PRF_AES_CMAC      = 10,
    CITIUS_SP800108_PRF_DES3_CMAC     = 11
} citius_sp800108_prf_type_t;

/** SP800-108 counter format (COUNTER mode only)  (proto: Sp800108KdfParams.CounterFormat) */
typedef struct {
    uint8_t  little_endian; /**< 0 = big endian (default) */
    uint32_t width_bits;    /**< 8, 16, 24, or 32 */
} citius_sp800108_counter_format_t;

/** SP800-108 KDF parameters  (proto: Sp800108KdfParams) */
typedef struct {
    citius_sp800108_mode_t           mode;
    citius_sp800108_prf_type_t       prf;
    uint32_t                         output_key_bits;
    citius_sp800108_counter_format_t counter_format; /**< COUNTER mode only */
    uint32_t                         iv_length_bytes; /**< Required for FEEDBACK mode */
} citius_sp800108_params_t;

/** TLS 1.2 operation type  (proto: Tls12Params.Operation) */
typedef enum {
    CITIUS_TLS12_OP_UNSPECIFIED       = 0,
    CITIUS_TLS12_OP_MASTER_KEY_DERIVE = 1,
    CITIUS_TLS12_OP_KEY_AND_MAC_DERIVE = 2,
    CITIUS_TLS12_OP_KDF               = 3, /**< RFC 5705 exporter */
    CITIUS_TLS12_OP_MAC               = 4  /**< Finished message */
} citius_tls12_operation_t;

/** TLS 1.2 handshake random lengths  (proto: Tls12Params.RandomInfo) */
typedef struct {
    uint32_t client_random_length; /**< Fixed: 32 */
    uint32_t server_random_length; /**< Fixed: 32 */
} citius_tls12_random_info_t;

/** TLS 1.2 KEY_AND_MAC_DERIVE cipher-suite parameters  (proto: Tls12Params.KeyMaterialParams) */
typedef struct {
    uint32_t mac_size_bits;
    uint32_t key_size_bits;
    uint32_t iv_size_bits;
} citius_tls12_key_material_params_t;

/** TLS 1.2 KDF parameters  (proto: Tls12Params) */
typedef struct {
    citius_tls12_operation_t           operation;
    citius_hash_algorithm_t            prf_hash; /**< SHA-256 (default) or SHA-384 */
    citius_tls12_random_info_t         random_info;
    citius_tls12_key_material_params_t key_material; /**< KEY_AND_MAC_DERIVE only */
} citius_tls12_kdf_params_t;

/* ----- MAC --------------------------------------------------------------- */

/** HMAC parameters  (proto: HmacParams) */
typedef struct {
    citius_hash_algorithm_t hash;
    uint32_t                output_length_bits; /**< 0 = full hash output */
} citius_hmac_params_t;

/**
 * KMAC parameters  (proto: KmacParams)
 *
 * proto's KmacParams.variant is a plain uint32 constrained to the literal
 * values {128, 256}; here it's enum-ified with C-side ordinals (0/1) that
 * do NOT correspond to those literal values — do not cast this enum
 * directly to a bit-strength number.
 */
typedef enum {
    CITIUS_KMAC_128 = 0,
    CITIUS_KMAC_256 = 1
} citius_kmac_variant_t;

typedef struct {
    citius_kmac_variant_t variant;
    uint32_t              output_length_bits;
    citius_byte_buffer_t  customization; /**< S parameter — domain separation; nullable */
} citius_kmac_params_t;

/** CMAC block cipher  (proto: CmacParams.BlockCipher) */
typedef enum {
    CITIUS_CMAC_CIPHER_UNSPECIFIED = 0,
    CITIUS_CMAC_CIPHER_AES         = 1, /**< 128-bit block, recommended */
    CITIUS_CMAC_CIPHER_3DES        = 2  /**< 64-bit block, legacy */
} citius_cmac_cipher_t;

/** CMAC parameters  (proto: CmacParams) */
typedef struct {
    citius_cmac_cipher_t cipher;
    uint32_t              key_size_bits;      /**< 128, 192, or 256 */
    uint32_t              output_length_bits; /**< 0 = full block size */
} citius_cmac_params_t;

/** Poly1305 parameters  (proto: Poly1305Params) */
typedef struct {
    uint8_t one_time_key; /**< 1 = OTP semantics; key must never be reused */
} citius_poly1305_params_t;

/** GOST R 34.11-94 hash parameters  (proto: Gost3411Params) */
typedef struct {
    citius_byte_buffer_t initial_value; /**< Optional IHV customization; max 32 bytes */
} citius_gost3411_params_t;

/* ----- Key wrapping ------------------------------------------------------ */

/** AES Key Wrap parameters  (proto: AesKeyWrapParams) */
typedef struct {
    uint32_t kek_size_bits;  /**< 128, 192, or 256 */
    uint8_t  with_padding;   /**< 0 = AES-KW (RFC 3394), 1 = AES-KWP (RFC 5649) */
} citius_aes_key_wrap_params_t;

/* ----- Legacy / regional ------------------------------------------------- */

/** Triple-DES keying option  (proto: TripleDesParams.KeyingOption) */
typedef enum {
    CITIUS_3DES_KEYING_UNSPECIFIED = 0,
    CITIUS_3DES_KEYING_TWO_KEY     = 1, /**< K1||K2||K1 — 112-bit effective */
    CITIUS_3DES_KEYING_THREE_KEY   = 2  /**< K1||K2||K3 — 168-bit effective */
} citius_3des_keying_option_t;

/** Triple-DES parameters  (proto: TripleDesParams — deprecated) */
typedef struct {
    citius_3des_keying_option_t keying_option;
    citius_aes_mode_t            mode;    /**< ECB or CBC */
    uint32_t                     iv_size_bits; /**< 0 or 64 */
    citius_padding_scheme_t      padding;
} citius_3des_params_t;

/** Blowfish parameters  (proto: BlowfishParams — deprecated) */
typedef struct {
    uint32_t                 key_size_bits; /**< 128–448 */
    uint32_t                 iv_size_bits;  /**< Fixed: 64 */
    citius_padding_scheme_t  padding;
} citius_blowfish_params_t;

/** Twofish parameters  (proto: TwofishParams) */
typedef struct {
    uint32_t                 key_size_bits; /**< 128, 192, or 256 */
    uint32_t                 iv_size_bits;  /**< Fixed: 128 */
    citius_padding_scheme_t  padding;
} citius_twofish_params_t;

/** Camellia parameters  (proto: CamelliaParams) */
typedef struct {
    uint32_t                 key_size_bits; /**< 128, 192, or 256 */
    citius_aes_mode_t        mode;          /**< ECB, CBC, or CTR */
    uint32_t                 iv_size_bits;  /**< 0 (ECB) or 128 */
    uint32_t                 counter_bits;  /**< CTR mode only */
    citius_padding_scheme_t  padding;       /**< CBC mode only */
} citius_camellia_params_t;

/** ARIA parameters  (proto: AriaParams) */
typedef struct {
    uint32_t                 key_size_bits;
    citius_aes_mode_t        mode;          /**< ECB or CBC */
    uint32_t                 iv_size_bits;  /**< 0 (ECB) or 128 */
    citius_padding_scheme_t  padding;       /**< CBC mode only */
} citius_aria_params_t;

/** SEED parameters  (proto: SeedParams) */
typedef struct {
    uint32_t                 key_size_bits; /**< Fixed: 128 */
    citius_aes_mode_t        mode;          /**< ECB or CBC */
    uint32_t                 iv_size_bits;  /**< 0 (ECB) or 128 */
    citius_padding_scheme_t  padding;       /**< CBC mode only */
} citius_seed_params_t;

/** GOST 28147-89 parameters  (proto: Gost28147Params) */
typedef struct {
    citius_aes_mode_t mode;         /**< ECB, CBC, or CFB */
    uint32_t           iv_size_bits; /**< 0 (ECB) or 64 */
    uint8_t            s_box_id;     /**< S-box selector (0 = CryptoPro, 1 = id-Gost28147-89-TestParamSet) */
} citius_gost28147_params_t;

/* ----- OTP --------------------------------------------------------------- */

/** HOTP parameters  (proto: HotpParams) */
typedef struct {
    citius_hash_algorithm_t hash;     /**< Typically SHA-1 or SHA-256 */
    uint32_t                digits;   /**< 6 or 8                     */
    uint64_t                counter_start;
} citius_hotp_params_t;

/** TOTP parameters  (proto: TotpParams) */
typedef struct {
    citius_hash_algorithm_t hash;
    uint32_t                digits;
    uint32_t                period_seconds; /**< Typically 30            */
    uint64_t                t0;             /**< Unix epoch start time; default 0 */
    uint32_t                skew_steps;     /**< Acceptable clock skew (C-side convenience; no proto counterpart) */
} citius_totp_params_t;

/* ----- Signal Protocol ---------------------------------------------------- */

/** X3DH handshake role  (proto: X3dhParams.Role) */
typedef enum {
    CITIUS_X3DH_ROLE_UNSPECIFIED = 0,
    CITIUS_X3DH_ROLE_INITIATOR   = 1, /**< Alice */
    CITIUS_X3DH_ROLE_RESPONDER   = 2  /**< Bob */
} citius_x3dh_role_t;

/** X3DH final shared-secret KDF  (proto: X3dhParams.X3dhKdfType) */
typedef enum {
    CITIUS_X3DH_KDF_UNSPECIFIED   = 0,
    CITIUS_X3DH_KDF_SHA256        = 1,
    CITIUS_X3DH_KDF_SHA512        = 2,
    CITIUS_X3DH_KDF_BLAKE2B_256   = 3,
    CITIUS_X3DH_KDF_BLAKE2B_512   = 4
} citius_x3dh_kdf_type_t;

/** X3DH (Signal Protocol) template-level parameters  (proto: X3dhParams) */
typedef struct {
    citius_x3dh_role_t     role;
    citius_x3dh_kdf_type_t kdf;
} citius_x3dh_params_t;

/* ----- Hybrid / composite ------------------------------------------------ */

/** Combiner strategy for hybrid algorithms  (proto: HybridAlgorithmParams.CombinerStrategy) */
typedef enum {
    CITIUS_COMBINER_UNSPECIFIED     = 0,
    CITIUS_COMBINER_CONCATENATION   = 1, /**< Independent operations; outputs concatenated */
    CITIUS_COMBINER_NESTING         = 2, /**< Output of first fed into second */
    CITIUS_COMBINER_KDF_COMBINATION = 3  /**< Component outputs combined via a KDF (e.g. X-Wing) */
} citius_combiner_strategy_t;

/**
 * A single component within a hybrid algorithm.
 * (proto: HybridComponent)
 */
typedef struct {
    const char                  *label;    /**< e.g. "classical", "pq"; nullable */
    uint32_t                     order;    /**< 1-based position in the combination */
    citius_crypto_primitive_t    primitive; /**< C-only convenience — no proto HybridComponent field.
                                                 Lets callers classify this component (AE/signature/KEM/...)
                                                 without inspecting algorithm->algorithm first; should agree
                                                 with algorithm->primitive when both are set. */
    citius_algorithm_details_t  *algorithm; /**< REQUIRED — this component's own algorithm config */
} citius_hybrid_component_t;

/** Hybrid / composite algorithm parameters  (proto: HybridAlgorithmParams) */
typedef struct {
    citius_combiner_strategy_t combiner;
    citius_hybrid_component_t *components;   /**< Array of component descriptors; min 2 */
    size_t                     num_components;
    uint32_t                   total_key_size_bits;
} citius_hybrid_params_t;

/* ----- Custom / vendor --------------------------------------------------- */

/**
 * Vendor-defined or custom algorithm  (proto: CustomAlgorithm)
 *
 * proto's `oneof params` (google.protobuf.Struct generic_params /
 * google.protobuf.Any typed_params) has no native C equivalent and is
 * represented here as an opaque byte blob (raw_params) — an intentional
 * simplification, not a 1:1 field mirror.
 */
typedef struct {
    const char              *vendor;         /**< Vendor identifier; empty for non-vendor algorithms */
    const char              *algorithm_name; /**< Vendor-specific name           */
    citius_key_type_t        key_type;
    uint32_t                 key_size_bits;  /**< 0 = not applicable / variable */
    citius_byte_buffer_t     raw_params;     /**< Opaque parameter blob          */
} citius_custom_algorithm_params_t;

/* =========================================================================
 * Top-level tagged union: citius_algorithm_params_t
 *
 * Corresponds to the AlgorithmDetails.algorithm oneof in
 * api/proto/types/templates.proto. `algorithm_case` is the discriminator;
 * read the union member with the matching name.
 * ========================================================================= */

typedef struct {
    citius_algorithm_case_t algorithm_case; /**< Discriminator — which union arm is valid */
    union {
        /* AEAD */
        citius_aes_gcm_params_t          aes_gcm;
        citius_aes_ccm_params_t          aes_ccm;
        citius_aes_xts_params_t          aes_xts;
        citius_chacha20_poly1305_params_t chacha20_poly1305;

        /* Block / stream cipher */
        citius_aes_cbc_params_t          aes_cbc;
        citius_aes_ctr_params_t          aes_ctr;
        citius_camellia_params_t         camellia;
        citius_aria_params_t             aria;
        citius_seed_params_t             seed;
        citius_gost28147_params_t        gost28147;
        citius_3des_params_t             triple_des;
        citius_blowfish_params_t         blowfish;
        citius_twofish_params_t          twofish;

        /* Signature — classical */
        citius_ecdsa_params_t            ecdsa;
        citius_ed25519_params_t          ed25519;
        citius_ed448_params_t            ed448;
        citius_rsa_pss_params_t          rsa_pss;
        citius_rsa_pkcs1v15_params_t     rsa_pkcs1v15;
        citius_dsa_params_t              dsa;
        citius_gost3410_params_t         gost3410;

        /* Signature — post-quantum */
        citius_ml_dsa_params_t           ml_dsa;
        citius_slh_dsa_params_t          slh_dsa;

        /* KEM */
        citius_ml_kem_params_t           ml_kem;
        citius_rsa_oaep_params_t         rsa_oaep;

        /* Key agreement */
        citius_ecdh_params_t             ecdh;
        citius_x25519_params_t           x25519;
        citius_x448_params_t             x448;
        citius_dh_params_t               dh;
        citius_x3dh_params_t             x3dh;

        /* KDF */
        citius_hkdf_params_t             hkdf;
        citius_pbkdf2_params_t           pbkdf2;
        citius_argon2_params_t           argon2;
        citius_sp800108_params_t         sp800108;
        citius_tls12_kdf_params_t        tls12_kdf;

        /* MAC */
        citius_hmac_params_t             hmac;
        citius_kmac_params_t             kmac;
        citius_cmac_params_t             cmac;
        citius_gost3411_params_t         gost3411;
        citius_poly1305_params_t         poly1305;

        /* Key wrap */
        citius_aes_key_wrap_params_t     aes_key_wrap;

        /* OTP */
        citius_hotp_params_t             hotp;
        citius_totp_params_t             totp;

        /* Hybrid */
        citius_hybrid_params_t           hybrid;

        /* Custom / vendor */
        citius_custom_algorithm_params_t custom;
    } params;
} citius_algorithm_params_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_ALGORITHM_PARAMS_H */
