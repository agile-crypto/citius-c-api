/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_algorithm_params.h — algorithm identity and configuration
 * (api/types/algorithm_params.proto and the AlgorithmDetails / hybrid
 * messages of api/types/templates.proto).
 *
 * HAND-WRITTEN. The C projection of the 44-arm AlgorithmDetails.algorithm
 * oneof: one struct per algorithm, a tagged union over all of them
 * (agc_algorithm_params), and the identity wrapper agc_algorithm_details.
 *
 * Distinct from agc_params.h, which projects operation_params.proto -- the
 * parameters supplied AT CALL TIME (an AEAD's AAD, a KDF's salt). The
 * parameters here are the TEMPLATE's fixed configuration: which key size,
 * which curve, which padding. One is per-operation, the other per-template.
 *
 * TAGGING. agc_algorithm_kind's values ARE the proto field numbers of the
 * oneof arms, the same convention as agc_scope_kind and
 * agc_algorithm_output_kind. Nested enums keep their proto values too.
 *
 * STORAGE. Every struct here is embedded by value in an enclosing record
 * (agc_template_info). Fields that cannot be bounded -- strings, byte
 * strings, arrays -- point into that record's `storage` region: proto
 * `bytes` becomes agc_slice, proto `string` becomes a NUL-terminated
 * const char *, repeated fields become a const pointer plus a _count.
 * Nothing here is allocated by the library.
 */

#ifndef AGC_ALGORITHM_PARAMS_H
#define AGC_ALGORITHM_PARAMS_H

#include "agc_abi.h"
#include "agc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration: HybridComponent refers back to AlgorithmDetails. */
struct agc_algorithm_details;

/* ==========================================================================
 * Symmetric encryption (AEAD and non-AEAD)
 * ========================================================================== */

typedef struct agc_aes_gcm_params {
    uint32_t key_size_bits;   /* 128, 192, 256 */
    uint32_t iv_size_bits;    /* 64, 96, 128 */
    uint32_t tag_size_bits;   /* 96, 104, 112, 120, 128 */
} agc_aes_gcm_params;

typedef struct agc_aes_cbc_params {
    uint32_t           key_size_bits;  /* 128, 192, 256 */
    uint32_t           iv_size_bits;   /* 128 */
    agc_padding_scheme padding;
} agc_aes_cbc_params;

typedef struct agc_aes_ctr_params {
    uint32_t key_size_bits;    /* 128, 192, 256 */
    uint32_t nonce_size_bits;  /* 64, 96 */
    uint32_t counter_bits;     /* 1..128 */
} agc_aes_ctr_params;

typedef struct agc_chacha20_poly1305_params {
    uint32_t nonce_size_bits;     /* 64, 96, 192 */
    uint32_t block_counter_bits;  /* 32, 64 */
    int      extended_nonce;      /* XChaCha20 when non-zero; requires nonce_size_bits 192 */
} agc_chacha20_poly1305_params;

typedef struct agc_aes_ccm_params {
    uint32_t key_size_bits;    /* 128, 192, 256 */
    uint32_t nonce_size_bits;  /* 56..104 in steps of 8 */
    uint32_t tag_size_bits;    /* 32..128 in steps of 16 */
} agc_aes_ccm_params;

typedef struct agc_aes_xts_params {
    uint32_t key_size_bits;        /* 256, 512 */
    uint32_t tweak_size_bytes;     /* 16 */
    uint32_t data_unit_size_bytes;
} agc_aes_xts_params;

/* ==========================================================================
 * Symmetric encryption (legacy)
 * ========================================================================== */

typedef enum agc_triple_des_keying_option {
    AGC_TRIPLE_DES_KEYING_OPTION_UNSPECIFIED = 0,
    AGC_TRIPLE_DES_TWO_KEY                   = 1,
    AGC_TRIPLE_DES_THREE_KEY                 = 2
    AGC_ENUM32(agc_triple_des_keying_option)
} agc_triple_des_keying_option;

typedef enum agc_triple_des_mode {
    AGC_TRIPLE_DES_MODE_UNSPECIFIED = 0,
    AGC_TRIPLE_DES_MODE_ECB         = 1,
    AGC_TRIPLE_DES_MODE_CBC         = 2
    AGC_ENUM32(agc_triple_des_mode)
} agc_triple_des_mode;

/* Deprecated in the proto; projected for catalog fidelity. */
typedef struct agc_triple_des_params {
    agc_triple_des_keying_option keying_option;
    agc_triple_des_mode          mode;
    uint32_t                     iv_size_bits;  /* 0 or 64 */
    agc_padding_scheme           padding;
} agc_triple_des_params;

/* Deprecated in the proto. */
typedef struct agc_blowfish_params {
    uint32_t           key_size_bits;  /* 128..448 */
    uint32_t           iv_size_bits;   /* 64 */
    agc_padding_scheme padding;
} agc_blowfish_params;

/* Deprecated in the proto. */
typedef struct agc_twofish_params {
    uint32_t           key_size_bits;  /* 128, 192, 256 */
    uint32_t           iv_size_bits;   /* 128 */
    agc_padding_scheme padding;
} agc_twofish_params;

/* ==========================================================================
 * Digital signatures (classical)
 * ========================================================================== */

typedef struct agc_ecdsa_params {
    agc_elliptic_curve   curve;
    agc_hash_algorithm   hash;
    agc_signature_format signature_format;
    int                  deterministic;  /* RFC 6979 when non-zero */
} agc_ecdsa_params;

typedef struct agc_ed25519_params {
    agc_ed25519_variant variant;
} agc_ed25519_params;

/* The Ed448ctx/Ed448ph context is an operation parameter
 * (agc_sign_params.u.domain_context), not part of the algorithm. */
typedef struct agc_ed448_params {
    agc_ed448_variant variant;
} agc_ed448_params;

typedef enum agc_rsa_pss_salt_length_mode {
    AGC_RSA_PSS_SALT_LENGTH_MODE_HASH_LENGTH = 0,
    AGC_RSA_PSS_SALT_LENGTH_MODE_MAX         = 1,
    AGC_RSA_PSS_SALT_LENGTH_MODE_EXPLICIT    = 2
    AGC_ENUM32(agc_rsa_pss_salt_length_mode)
} agc_rsa_pss_salt_length_mode;

typedef struct agc_rsa_pss_params {
    uint32_t                     key_size_bits;  /* 2048..16384 */
    agc_hash_algorithm           hash;
    agc_mask_generation_function mgf;
    agc_hash_algorithm           mgf_hash;
    agc_rsa_pss_salt_length_mode salt_length_mode;
    uint32_t                     salt_length_bytes;  /* <= 512; > 0 when mode is EXPLICIT */
} agc_rsa_pss_params;

typedef struct agc_rsa_pkcs1v15_params {
    uint32_t           key_size_bits;  /* 2048..16384 */
    agc_hash_algorithm hash;
} agc_rsa_pkcs1v15_params;

/* Deprecated in the proto. */
typedef struct agc_dsa_params {
    uint32_t           modulus_bits;   /* 2048, 3072 */
    uint32_t           subprime_bits;  /* 224, 256 */
    agc_hash_algorithm hash;
} agc_dsa_params;

/* ==========================================================================
 * Digital signatures (post-quantum)
 * ========================================================================== */

typedef struct agc_ml_dsa_params {
    agc_ml_dsa_parameter_set parameter_set;
    int                      deterministic;
} agc_ml_dsa_params;

typedef struct agc_slh_dsa_params {
    agc_slh_dsa_hash_type     hash_type;
    agc_slh_dsa_parameter_set parameter_set;
    int                       deterministic;
} agc_slh_dsa_params;

/* TODO: Change category (classical digital signatures). GOST R 34.10-2012 is
 * an elliptic-curve signature scheme, not post-quantum; it sits in this
 * section only because the proto's own oneof groups it here. */
typedef enum agc_gost3410_version {
    AGC_GOST3410_VERSION_UNSPECIFIED = 0,
    AGC_GOST3410_VERSION_2001        = 1,
    AGC_GOST3410_VERSION_2012        = 2
    AGC_ENUM32(agc_gost3410_version)
} agc_gost3410_version;

typedef struct agc_gost3410_params {
    agc_gost3410_version version;
    uint32_t             key_size_bits;          /* 256, 512 */
    const char          *parameter_set_oid;      /* NUL-terminated, in storage; REQUIRED */
    const char          *digest_param_set_oid;   /* NUL-terminated, in storage; "" if unset */
} agc_gost3410_params;

/* ==========================================================================
 * Key encapsulation
 * ========================================================================== */

typedef struct agc_ml_kem_params {
    agc_ml_kem_parameter_set parameter_set;
} agc_ml_kem_params;

typedef struct agc_rsa_oaep_params {
    uint32_t                     key_size_bits;  /* 2048..16384 */
    agc_hash_algorithm           hash;
    agc_mask_generation_function mgf;
    agc_hash_algorithm           mgf_hash;
} agc_rsa_oaep_params;

/* ==========================================================================
 * Key derivation
 * ========================================================================== */

typedef struct agc_hkdf_params {
    agc_hash_algorithm hash;
    int                extract;
    int                expand;
    uint32_t           salt_size_bytes;
    uint32_t           output_length;  /* 1..16320, and <= 255 * hash output size */
} agc_hkdf_params;

typedef struct agc_pbkdf2_params {
    agc_hash_algorithm hash;
    uint32_t           iterations;       /* >= 10000 */
    uint32_t           salt_size_bytes;  /* >= 16 */
    uint32_t           output_length;    /* 16..512 */
} agc_pbkdf2_params;

typedef struct agc_argon2_params {
    agc_argon2_variant variant;
    uint32_t           version;          /* 19 */
    uint32_t           memory_kib;       /* >= 19456 */
    uint32_t           iterations;       /* >= 1 */
    uint32_t           parallelism;      /* 1..255 */
    uint32_t           salt_size_bytes;  /* >= 16 */
    uint32_t           output_length;    /* >= 16 */
} agc_argon2_params;

typedef enum agc_sp800_108_mode {
    AGC_SP800_108_MODE_UNSPECIFIED     = 0,
    AGC_SP800_108_MODE_COUNTER         = 1,
    AGC_SP800_108_MODE_FEEDBACK        = 2,
    AGC_SP800_108_MODE_DOUBLE_PIPELINE = 3
    AGC_ENUM32(agc_sp800_108_mode)
} agc_sp800_108_mode;

typedef enum agc_sp800_108_prf_type {
    AGC_SP800_108_PRF_UNSPECIFIED   = 0,
    AGC_SP800_108_PRF_HMAC_SHA1     = 1,
    AGC_SP800_108_PRF_HMAC_SHA224   = 2,
    AGC_SP800_108_PRF_HMAC_SHA256   = 3,
    AGC_SP800_108_PRF_HMAC_SHA384   = 4,
    AGC_SP800_108_PRF_HMAC_SHA512   = 5,
    AGC_SP800_108_PRF_HMAC_SHA3_224 = 6,
    AGC_SP800_108_PRF_HMAC_SHA3_256 = 7,
    AGC_SP800_108_PRF_HMAC_SHA3_384 = 8,
    AGC_SP800_108_PRF_HMAC_SHA3_512 = 9,
    AGC_SP800_108_PRF_AES_CMAC      = 10,
    AGC_SP800_108_PRF_DES3_CMAC     = 11
    AGC_ENUM32(agc_sp800_108_prf_type)
} agc_sp800_108_prf_type;

/* Sp800108KdfParams.CounterFormat. */
typedef struct agc_sp800_108_counter_format {
    int      little_endian;
    uint32_t width_bits;   /* 8, 16, 24, 32 */
} agc_sp800_108_counter_format;

typedef struct agc_sp800_108_kdf_params {
    agc_sp800_108_mode           mode;
    agc_sp800_108_prf_type       prf;
    uint32_t                     derived_key_length_bytes;  /* 16..512 */
    int                          has_counter_format;        /* proto message presence */
    agc_sp800_108_counter_format counter_format;
    uint32_t                     iv_length_bytes;
} agc_sp800_108_kdf_params;

typedef enum agc_tls12_operation {
    AGC_TLS12_OPERATION_UNSPECIFIED        = 0,
    AGC_TLS12_OPERATION_MASTER_KEY_DERIVE  = 1,
    AGC_TLS12_OPERATION_KEY_AND_MAC_DERIVE = 2,
    AGC_TLS12_OPERATION_KDF                = 3,
    AGC_TLS12_OPERATION_MAC                = 4
    AGC_ENUM32(agc_tls12_operation)
} agc_tls12_operation;

/* Tls12Params.RandomInfo. */
typedef struct agc_tls12_random_info {
    uint32_t client_random_length;  /* 32 */
    uint32_t server_random_length;  /* 32 */
} agc_tls12_random_info;

/* Tls12Params.KeyMaterialParams. */
typedef struct agc_tls12_key_material_params {
    uint32_t mac_size_bits;
    uint32_t key_size_bits;
    uint32_t iv_size_bits;
} agc_tls12_key_material_params;

typedef struct agc_tls12_params {
    agc_tls12_operation           operation;
    agc_hash_algorithm            prf_hash;
    int                           has_random_info;   /* proto message presence */
    agc_tls12_random_info         random_info;
    int                           has_key_material;  /* proto message presence */
    agc_tls12_key_material_params key_material;
} agc_tls12_params;

/* ==========================================================================
 * Message authentication
 * ========================================================================== */

typedef struct agc_hmac_params {
    agc_hash_algorithm hash;
    uint32_t           truncation_bits;  /* 0 = full length */
} agc_hmac_params;

typedef struct agc_kmac_params {
    uint32_t       variant;          /* 128, 256 */
    uint32_t       output_bits;      /* 128..4096 */
    agc_slice      customization;    /* data in the enclosing record's storage; at most 1024 bytes */
} agc_kmac_params;

typedef enum agc_cmac_block_cipher {
    AGC_CMAC_BLOCK_CIPHER_UNSPECIFIED = 0,
    AGC_CMAC_BLOCK_CIPHER_AES         = 1,
    AGC_CMAC_BLOCK_CIPHER_DES3        = 2
    AGC_ENUM32(agc_cmac_block_cipher)
} agc_cmac_block_cipher;

typedef struct agc_cmac_params {
    agc_cmac_block_cipher cipher;
    uint32_t              key_size_bits;  /* 128, 192, 256 */
    uint32_t              output_bits;    /* 0 = full block */
} agc_cmac_params;

/* TODO: Change category (hash functions). GOST R 34.11-2012 (Streebog) is a
 * hash function, not a MAC; it sits in this section only because the proto's
 * own oneof groups it here. */
typedef struct agc_gost3411_params {
    agc_slice      initial_value;    /* data in the enclosing record's storage; at most 32 bytes */
} agc_gost3411_params;

/* Poly1305Params is an empty message: the arm is a tag with no fields.
 * Projected as a struct with one reserved member so it can appear in the
 * union without a zero-size type, which C forbids. */
typedef struct agc_poly1305_params {
    char reserved;
} agc_poly1305_params;

/* ==========================================================================
 * Key wrapping
 * ========================================================================== */

typedef struct agc_aes_key_wrap_params {
    uint32_t key_size_bits;  /* 128, 192, 256 */
    int      with_padding;   /* AES-KWP when non-zero */
} agc_aes_key_wrap_params;

/* ==========================================================================
 * Key agreement
 * ========================================================================== */

typedef struct agc_ecdh_params {
    agc_elliptic_curve curve;
    int                cofactor_mode;
    agc_ecdh_kdf_type  kdf;
} agc_ecdh_params;

typedef struct agc_x25519_params {
    agc_ecdh_kdf_type kdf;
} agc_x25519_params;

typedef struct agc_x448_params {
    agc_ecdh_kdf_type kdf;
} agc_x448_params;

typedef enum agc_diffie_hellman_variant {
    AGC_DIFFIE_HELLMAN_VARIANT_UNSPECIFIED = 0,
    AGC_DIFFIE_HELLMAN_VARIANT_PKCS3       = 1,
    AGC_DIFFIE_HELLMAN_VARIANT_X942        = 2,
    AGC_DIFFIE_HELLMAN_VARIANT_X942_MQV    = 3
    AGC_ENUM32(agc_diffie_hellman_variant)
} agc_diffie_hellman_variant;

typedef enum agc_diffie_hellman_kdf_type {
    AGC_DIFFIE_HELLMAN_KDF_UNSPECIFIED      = 0,
    AGC_DIFFIE_HELLMAN_KDF_NULL             = 1,
    AGC_DIFFIE_HELLMAN_KDF_SHA1_CONCATENATE = 2,
    AGC_DIFFIE_HELLMAN_KDF_SHA256_SP800     = 3,
    AGC_DIFFIE_HELLMAN_KDF_SHA384_SP800     = 4,
    AGC_DIFFIE_HELLMAN_KDF_SHA512_SP800     = 5
    AGC_ENUM32(agc_diffie_hellman_kdf_type)
} agc_diffie_hellman_kdf_type;

typedef struct agc_diffie_hellman_params {
    agc_diffie_hellman_variant  variant;
    uint32_t                    prime_bits;  /* 2048..8192 */
    agc_diffie_hellman_kdf_type kdf;
    uint32_t                    private_value_length_bits;
} agc_diffie_hellman_params;

typedef enum agc_x3dh_role {
    AGC_X3DH_ROLE_UNSPECIFIED = 0,
    AGC_X3DH_ROLE_INITIATOR   = 1,
    AGC_X3DH_ROLE_RESPONDER   = 2
    AGC_ENUM32(agc_x3dh_role)
} agc_x3dh_role;

typedef enum agc_x3dh_kdf_type {
    AGC_X3DH_KDF_UNSPECIFIED  = 0,
    AGC_X3DH_KDF_SHA256       = 1,
    AGC_X3DH_KDF_SHA512       = 2,
    AGC_X3DH_KDF_BLAKE2B_256  = 3,
    AGC_X3DH_KDF_BLAKE2B_512  = 4
    AGC_ENUM32(agc_x3dh_kdf_type)
} agc_x3dh_kdf_type;

typedef struct agc_x3dh_params {
    agc_x3dh_role     role;
    agc_x3dh_kdf_type kdf;
} agc_x3dh_params;

/* ==========================================================================
 * Regional / national standard ciphers
 * ========================================================================== */

typedef enum agc_camellia_mode {
    AGC_CAMELLIA_MODE_UNSPECIFIED = 0,
    AGC_CAMELLIA_MODE_ECB         = 1,
    AGC_CAMELLIA_MODE_CBC         = 2,
    AGC_CAMELLIA_MODE_CTR         = 3
    AGC_ENUM32(agc_camellia_mode)
} agc_camellia_mode;

typedef struct agc_camellia_params {
    uint32_t           key_size_bits;  /* 128, 192, 256 */
    agc_camellia_mode  mode;
    uint32_t           iv_size_bits;   /* 0 for ECB, 128 otherwise */
    uint32_t           counter_bits;   /* 1..128 */
    agc_padding_scheme padding;
} agc_camellia_params;

typedef enum agc_aria_mode {
    AGC_ARIA_MODE_UNSPECIFIED = 0,
    AGC_ARIA_MODE_ECB         = 1,
    AGC_ARIA_MODE_CBC         = 2
    AGC_ENUM32(agc_aria_mode)
} agc_aria_mode;

typedef struct agc_aria_params {
    uint32_t           key_size_bits;  /* 128, 192, 256 */
    agc_aria_mode      mode;
    uint32_t           iv_size_bits;   /* 0 for ECB, 128 otherwise */
    agc_padding_scheme padding;
} agc_aria_params;

typedef enum agc_seed_mode {
    AGC_SEED_MODE_UNSPECIFIED = 0,
    AGC_SEED_MODE_ECB         = 1,
    AGC_SEED_MODE_CBC         = 2
    AGC_ENUM32(agc_seed_mode)
} agc_seed_mode;

typedef struct agc_seed_params {
    uint32_t           key_size_bits;  /* 128 */
    agc_seed_mode      mode;
    uint32_t           iv_size_bits;   /* 0 or 128 */
    agc_padding_scheme padding;
} agc_seed_params;

typedef enum agc_gost28147_mode {
    AGC_GOST28147_MODE_UNSPECIFIED = 0,
    AGC_GOST28147_MODE_ECB         = 1,
    AGC_GOST28147_MODE_CBC         = 2,
    AGC_GOST28147_MODE_CFB         = 3
    AGC_ENUM32(agc_gost28147_mode)
} agc_gost28147_mode;

typedef struct agc_gost28147_params {
    agc_gost28147_mode mode;
    uint32_t           iv_size_bits;  /* 0 or 64 */
    const char        *sbox_oid;      /* NUL-terminated, in the enclosing record's storage */
} agc_gost28147_params;

/* ==========================================================================
 * One-time passwords
 * ========================================================================== */

typedef struct agc_hotp_params {
    agc_hash_algorithm hash;
    uint32_t           digits;         /* 6, 8 */
    uint64_t           counter_start;
} agc_hotp_params;

typedef struct agc_totp_params {
    agc_hash_algorithm hash;
    uint32_t           digits;             /* 6, 8 */
    uint32_t           time_step_seconds;  /* 1..300 */
    uint64_t           t0;
} agc_totp_params;

/* ==========================================================================
 * Extensibility
 * ========================================================================== */

/* Discriminant for CustomAlgorithm.params. Values are the proto field
 * numbers, matching agc_custom_params_kind in agc_params.h. */
typedef enum agc_custom_algorithm_params_kind {
    AGC_CUSTOM_ALGORITHM_PARAMS_NONE    = 0,
    AGC_CUSTOM_ALGORITHM_PARAMS_GENERIC = 10,  /* google.protobuf.Struct, as canonical JSON */
    AGC_CUSTOM_ALGORITHM_PARAMS_TYPED   = 11   /* google.protobuf.Any, as type_url + value */
    AGC_ENUM32(agc_custom_algorithm_params_kind)
} agc_custom_algorithm_params_kind;

typedef struct agc_custom_algorithm {
    const char                      *vendor;         /* NUL-terminated, in storage */
    const char                      *name;           /* NUL-terminated, in storage; REQUIRED */
    agc_key_type                     key_type;
    uint32_t                         key_size_bits;
    agc_custom_algorithm_params_kind params_kind;
    const char                      *generic_params_json;    /* params_kind == GENERIC; in storage */
    const char                      *typed_params_type_url;  /* params_kind == TYPED; in storage */
    agc_slice                        typed_params_value;     /* params_kind == TYPED; data in storage */
} agc_custom_algorithm;

/* One entry of VendorAlgorithmRegistry.algorithms (map<string,
 * CustomAlgorithm>). The map key is the algorithm name, e.g.
 * "VENDOR_AES_GCM_SIV". */
typedef struct agc_vendor_algorithm_entry {
    const char          *name;       /* map key; NUL-terminated, in the registry's storage */
    agc_custom_algorithm algorithm;  /* map value */
} agc_vendor_algorithm_entry;

/* VendorAlgorithmRegistry: a vendor's algorithm definitions, loaded from a
 * vendor-supplied JSON or YAML file at startup. Templates then reference
 * these through CustomAlgorithm.
 *
 * DESCRIPTIVE ONLY: no storage of its own. No function in the current C
 * surface produces or consumes one; it is declared for completeness against
 * the proto. Whichever call eventually returns one must supply the storage
 * its pointers reference, as every other response does. */
typedef struct agc_vendor_algorithm_registry {
    size_t                            struct_size;
    const char                       *vendor_id;    /* NUL-terminated, in storage; REQUIRED, 1..64;
                                                       must match agc_custom_algorithm.vendor */
    const char                       *vendor_name;  /* NUL-terminated, in storage; at most 256 */
    const agc_vendor_algorithm_entry *algorithms;   /* array in storage */
    size_t                            algorithms_count;
    const char                       *version;      /* NUL-terminated, in storage; semver recommended */
    const char                       *description;  /* NUL-terminated, in storage; at most 2048 */
    const char                       *support_url;  /* NUL-terminated, in storage; at most 512 */
} agc_vendor_algorithm_registry;

/* ==========================================================================
 * Hybrid / composite
 * ========================================================================== */

/* One component of a hybrid construction. p_algorithm points at a nested
 * agc_algorithm_details in the enclosing record's storage, which is how the
 * proto's recursion (HybridComponent.algorithm is an AlgorithmDetails) is
 * expressed without an infinitely sized C type. */
typedef struct agc_hybrid_component {
    const struct agc_algorithm_details *algorithm;     /* REQUIRED; in the enclosing record's storage */
    const char                         *label;        /* NUL-terminated, in storage; "classical", "pqc", "kdf" */
    uint32_t                            order;        /* 1-based position */
} agc_hybrid_component;

typedef struct agc_hybrid_algorithm_params {
    agc_combiner_strategy       combiner_strategy;
    const agc_hybrid_component *components;         /* array in the enclosing record's storage; at least 2 */
    size_t                      components_count;
    uint32_t                    total_key_size_bits;
} agc_hybrid_algorithm_params;

/* ==========================================================================
 * The tagged union
 * ========================================================================== */

/* Discriminant for the AlgorithmDetails.algorithm oneof. VALUES ARE THE
 * PROTO FIELD NUMBERS of the oneof arms. AGC_ALGORITHM_NONE (0) means the
 * oneof is unset, which a valid TemplateInfo never has: `algorithm` is a
 * required field. Field 26 is reserved in the proto (poly1305 moved to 74). */
typedef enum agc_algorithm_kind {
    AGC_ALGORITHM_NONE              = 0,

    /* Symmetric encryption, AEAD and non-AEAD. */
    AGC_ALGORITHM_AES_GCM           = 20,
    AGC_ALGORITHM_AES_CBC           = 21,
    AGC_ALGORITHM_AES_CTR           = 22,
    AGC_ALGORITHM_CHACHA20_POLY1305 = 23,
    AGC_ALGORITHM_AES_CCM           = 24,
    AGC_ALGORITHM_AES_XTS           = 25,

    /* Symmetric encryption, legacy. */
    AGC_ALGORITHM_TRIPLE_DES        = 27,   /* deprecated */
    AGC_ALGORITHM_BLOWFISH          = 28,   /* deprecated */
    AGC_ALGORITHM_TWOFISH           = 29,   /* deprecated */

    /* Signatures, classical. */
    AGC_ALGORITHM_ECDSA             = 30,
    AGC_ALGORITHM_ED25519           = 31,
    AGC_ALGORITHM_ED448             = 32,
    AGC_ALGORITHM_RSA_PSS           = 33,
    AGC_ALGORITHM_RSA_PKCS1V15      = 34,
    AGC_ALGORITHM_DSA               = 35,   /* deprecated */

    /* Signatures, post-quantum. */
    AGC_ALGORITHM_ML_DSA            = 40,
    AGC_ALGORITHM_SLH_DSA           = 41,
    AGC_ALGORITHM_GOST3410          = 42,   /* TODO: Change category (classical digital signatures) */

    /* Key encapsulation. */
    AGC_ALGORITHM_ML_KEM            = 50,
    AGC_ALGORITHM_RSA_OAEP          = 51,

    /* Key derivation. */
    AGC_ALGORITHM_HKDF              = 60,
    AGC_ALGORITHM_PBKDF2            = 61,
    AGC_ALGORITHM_ARGON2            = 62,
    AGC_ALGORITHM_SP800_108_KDF     = 63,
    AGC_ALGORITHM_TLS12             = 64,

    /* Message authentication. */
    AGC_ALGORITHM_HMAC              = 70,
    AGC_ALGORITHM_KMAC              = 71,
    AGC_ALGORITHM_CMAC              = 72,
    AGC_ALGORITHM_GOST3411          = 73,   /* TODO: Change category (hash functions) */
    AGC_ALGORITHM_POLY1305          = 74,

    /* Key wrapping. */
    AGC_ALGORITHM_AES_KEY_WRAP      = 80,

    /* Key agreement. */
    AGC_ALGORITHM_ECDH              = 90,
    AGC_ALGORITHM_X25519            = 91,
    AGC_ALGORITHM_X448              = 92,
    AGC_ALGORITHM_DIFFIE_HELLMAN    = 93,
    AGC_ALGORITHM_X3DH              = 94,

    /* Extensibility. */
    AGC_ALGORITHM_CUSTOM            = 100,

    /* Regional / national standards. */
    AGC_ALGORITHM_CAMELLIA          = 110,
    AGC_ALGORITHM_ARIA              = 111,
    AGC_ALGORITHM_SEED              = 112,
    AGC_ALGORITHM_GOST28147         = 113,

    /* One-time passwords. */
    AGC_ALGORITHM_HOTP              = 120,
    AGC_ALGORITHM_TOTP              = 121,

    /* Hybrid / composite. */
    AGC_ALGORITHM_HYBRID            = 130
    AGC_ENUM32(agc_algorithm_kind)
} agc_algorithm_kind;

/* The AlgorithmDetails.algorithm oneof: exactly one arm is live, selected by
 * `kind`. AGC_INIT() on the enclosing record leaves the others zero. */
typedef struct agc_algorithm_params {
    agc_algorithm_kind kind;
    union {
        agc_aes_gcm_params            aes_gcm;
        agc_aes_cbc_params            aes_cbc;
        agc_aes_ctr_params            aes_ctr;
        agc_chacha20_poly1305_params  chacha20_poly1305;
        agc_aes_ccm_params            aes_ccm;
        agc_aes_xts_params            aes_xts;
        agc_triple_des_params         triple_des;
        agc_blowfish_params           blowfish;
        agc_twofish_params            twofish;
        agc_ecdsa_params              ecdsa;
        agc_ed25519_params            ed25519;
        agc_ed448_params              ed448;
        agc_rsa_pss_params            rsa_pss;
        agc_rsa_pkcs1v15_params       rsa_pkcs1v15;
        agc_dsa_params                dsa;
        agc_ml_dsa_params             ml_dsa;
        agc_slh_dsa_params            slh_dsa;
        agc_gost3410_params           gost3410;
        agc_ml_kem_params             ml_kem;
        agc_rsa_oaep_params           rsa_oaep;
        agc_hkdf_params               hkdf;
        agc_pbkdf2_params             pbkdf2;
        agc_argon2_params             argon2;
        agc_sp800_108_kdf_params      sp800_108_kdf;
        agc_tls12_params              tls12;
        agc_hmac_params               hmac;
        agc_kmac_params               kmac;
        agc_cmac_params               cmac;
        agc_gost3411_params           gost3411;
        agc_poly1305_params           poly1305;
        agc_aes_key_wrap_params       aes_key_wrap;
        agc_ecdh_params               ecdh;
        agc_x25519_params             x25519;
        agc_x448_params               x448;
        agc_diffie_hellman_params     diffie_hellman;
        agc_x3dh_params               x3dh;
        agc_custom_algorithm          custom;
        agc_camellia_params           camellia;
        agc_aria_params               aria;
        agc_seed_params               seed;
        agc_gost28147_params          gost28147;
        agc_hotp_params               hotp;
        agc_totp_params               totp;
        agc_hybrid_algorithm_params   hybrid;
    } u;
} agc_algorithm_params;

/* ==========================================================================
 * AlgorithmDetails (api/types/templates.proto)
 * ========================================================================== */

/* Algorithm identity and configuration. Embedded by value in
 * agc_template_info; its strings live in that record's storage.
 *
 * Template = Algorithm + Configuration. This is template-level because
 * scopes define HOW the algorithm is called (the API), not WHAT algorithm
 * it is. */
typedef struct agc_algorithm_details {
    const char          *oid;        /* NUL-terminated, in the enclosing record's storage;
                                        e.g. "2.16.840.1.101.3.4.1.46"; "" if unstated */
    agc_crypto_primitive primitive;  /* optional in the proto: derivable from params.kind
                                        when AGC_CRYPTO_PRIMITIVE_UNSPECIFIED, and takes
                                        precedence over the derived value when set */
    agc_algorithm_params params;     /* REQUIRED: the oneof arm and its configuration */
} agc_algorithm_details;

#ifdef __cplusplus
}
#endif
#endif /* AGC_ALGORITHM_PARAMS_H */
