/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_types.h — Abstract Cryptographic API, C binding: generated vocabulary.
 *
 * ============================================================================
 * THIS FILE IS GENERATED FROM THE PROTOBUF SPECIFICATION. DO NOT EDIT.
 * Source of truth: proto/types/ *.proto (package caas.crypto.v1)
 * Generator:       tools/protoc-gen-agc-c-enums
 * ============================================================================
 *
 * Every enumerator below carries the SAME NUMERIC VALUE as the corresponding
 * protobuf enum value. This is a hard invariant, enforced in CI by comparing
 * this header against the FileDescriptorSet. It allows a value read from a C
 * caller to be placed on the wire without a translation table, and it means a
 * gRPC front-end layered over this library is a pure marshalling shim.
 *
 * Enum storage: all enums are declared with an explicit `= 0x7fffffff` sentinel
 * so that every enum has int32 width on every conforming compiler, matching the
 * protobuf wire type and making the ABI independent of -fshort-enums.
 */

#ifndef AGC_TYPES_H
#define AGC_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ABI / API version
 * -------------------------------------------------------------------------- */

#define AGC_API_VERSION_MAJOR 1
#define AGC_API_VERSION_MINOR 0
#define AGC_API_VERSION_PATCH 0

/* Matches OperationMetadata.api_version ("major.minor"). */
#define AGC_API_VERSION_STRING "1.0"

/* Every versioned parameter struct begins with `size_t struct_size`. Callers
 * MUST set it to sizeof(the struct they compiled against); the library uses it
 * to decide which trailing fields are present. See AGC_INIT(). */
#define AGC_INIT(p) \
    do { memset((p), 0, sizeof(*(p))); (p)->struct_size = sizeof(*(p)); } while (0)

#if defined(_WIN32)
#  if defined(AGC_BUILDING_DLL)
#    define AGC_API __declspec(dllexport)
#  elif !defined(AGC_STATIC)
#    define AGC_API __declspec(dllimport)
#  else
#    define AGC_API
#  endif
#else
#  define AGC_API __attribute__((visibility("default")))
#endif

/* Forces int32 storage for every enum regardless of -fshort-enums, so the
 * C enum width matches the protobuf wire type. */
#define AGC_ENUM32(n) , n##_FORCE32 = 0x7fffffff

/* --------------------------------------------------------------------------
 * Presence: three-valued booleans
 *
 * proto3 `optional bool` is a THREE-valued type: absent / false / true.
 * Absence is semantically load-bearing throughout this API — in a request an
 * absent filter means "don't care", while `false` means "must NOT have this
 * property". Collapsing it to C `bool` would silently turn every "don't care"
 * into a hard "must be false" and make FIPS/quantum-safe filters unusable.
 * -------------------------------------------------------------------------- */

typedef enum agc_tribool {
    AGC_UNSET = 0,   /* proto field absent */
    AGC_FALSE = 1,   /* proto field present, value false */
    AGC_TRUE  = 2    /* proto field present, value true  */
    AGC_ENUM32(agc_tribool)
} agc_tribool;

/* --------------------------------------------------------------------------
 * Scalar value types
 * -------------------------------------------------------------------------- */

/* Borrowed, immutable byte range. Maps proto `bytes` in the INPUT direction.
 * Never owns memory; never freed. A zero-length slice with data == NULL is the
 * canonical "empty bytes" and is distinct from absence (see agc_optional_slice). */
typedef struct agc_slice {
    const uint8_t *data;
    size_t         len;
} agc_slice;

/* Explicit-presence bytes. Required wherever the proto uses `optional bytes`
 * and distinguishes absent from empty — notably HkdfOperationParams.salt,
 * Pbkdf2OperationParams.salt and Argon2OperationParams.salt, where absent means
 * "server generates a random salt" and empty means "use an all-zero salt". */
typedef struct agc_optional_slice {
    agc_slice slice;
    int       present;   /* 0 = absent, non-zero = present (possibly empty) */
} agc_optional_slice;

/* Mutable, caller-owned output region. Maps proto `bytes` in the OUTPUT
 * direction under the two-call size-query convention: pass data = NULL to learn
 * the required length in *out_len, then call again with a buffer of that size. */
typedef struct agc_buf {
    uint8_t *data;      /* NULL => size query */
    size_t   cap;       /* capacity of data in bytes */
} agc_buf;

/* Borrowed, immutable NUL-terminated UTF-8 string. Maps proto `string`. */
typedef const char *agc_str;

/* One entry of a proto map<string, string>. */
typedef struct agc_kv {
    agc_str key;
    agc_str value;
} agc_kv;

/* A proto map<string, string> as a flat array. Order is not significant and is
 * not preserved across a round-trip through the wire format. Duplicate keys are
 * rejected with AGC_ERR_INVALID_ARGUMENT. */
typedef struct agc_kv_list {
    const agc_kv *items;
    size_t        count;
} agc_kv_list;

/* One entry of a proto map<string, bytes> (VendorOutput.parameters). */
typedef struct agc_kb {
    agc_str   key;
    agc_slice value;
} agc_kb;

typedef struct agc_kb_list {
    const agc_kb *items;
    size_t        count;
} agc_kb_list;

/* Borrowed array of NUL-terminated strings. Maps proto `repeated string`. */
typedef struct agc_str_list {
    const agc_str *items;
    size_t         count;
} agc_str_list;

/* google.protobuf.Timestamp with explicit presence. */
typedef struct agc_timestamp {
    int64_t seconds;    /* seconds since 1970-01-01T00:00:00Z */
    int32_t nanos;      /* [0, 999999999] */
    int     present;    /* 0 = field absent */
} agc_timestamp;

/* --------------------------------------------------------------------------
 * Result codes
 *
 * Layout:
 *   AGC_OK                = 0
 *   AGC_ERR_* (transport, argument, resource)  = -1 .. -99
 *   AGC_ERR_CRYPTO_*      = -(1000 + CryptoErrorCode)
 *
 * The second range is a mechanical transform of the CryptoErrorCode enum in
 * types/common.proto: agc_rc = -(1000 + wire_value). The offset keeps the
 * generated range disjoint from the hand-written range, and the transform is
 * reversible, so a gRPC front-end recovers the wire value arithmetically:
 *   wire = -rc - 1000
 * -------------------------------------------------------------------------- */

typedef int32_t agc_rc;

#define AGC_OK                                  ((agc_rc)0)

/* --- Hand-written codes: conditions that exist only in a local library --- */
#define AGC_ERR_UNSPECIFIED                     ((agc_rc)-1)
#define AGC_ERR_INVALID_ARGUMENT                ((agc_rc)-2)  /* NULL where required, bad length, bad enum */
#define AGC_ERR_BUFFER_TOO_SMALL                ((agc_rc)-3)  /* out_len holds the required size */
#define AGC_ERR_OUT_OF_MEMORY                   ((agc_rc)-4)
#define AGC_ERR_NOT_IMPLEMENTED                 ((agc_rc)-5)  /* optional RPC not offered by this build */
#define AGC_ERR_INVALID_HANDLE                  ((agc_rc)-6)  /* stale/foreign/freed handle */
#define AGC_ERR_ABI_MISMATCH                    ((agc_rc)-7)  /* struct_size not recognised */
#define AGC_ERR_UNAVAILABLE                     ((agc_rc)-8)  /* remote deployment mode: transport failure */
#define AGC_ERR_PERMISSION_DENIED               ((agc_rc)-9)  /* caller identity lacks the IAM scope */
#define AGC_ERR_ALREADY_EXISTS                  ((agc_rc)-10)
#define AGC_ERR_CANCELLED                       ((agc_rc)-11)
#define AGC_ERR_DEADLINE_EXCEEDED               ((agc_rc)-12)
#define AGC_ERR_INTERNAL                        ((agc_rc)-13)
#define AGC_ERR_PROVIDER_CONTRACT_VIOLATION     ((agc_rc)-14) /* e.g. unset ProviderOutput.algorithm_output */
#define AGC_ERR_ITERATOR_EXHAUSTED              ((agc_rc)-15) /* normal end of a list iteration */

/* --- Generated from CryptoErrorCode (types/common.proto) --- */
#define AGC_ERR_CRYPTO_KEY_NOT_FOUND                ((agc_rc)-1001)
#define AGC_ERR_CRYPTO_KEY_EXPIRED                  ((agc_rc)-1002)
#define AGC_ERR_CRYPTO_KEY_VERSION_MISMATCH         ((agc_rc)-1003)
#define AGC_ERR_CRYPTO_KEY_NOT_EXPORTABLE           ((agc_rc)-1004)
#define AGC_ERR_CRYPTO_KEY_OPERATION_NOT_ALLOWED    ((agc_rc)-1005)
#define AGC_ERR_CRYPTO_INVALID_KEY_STATE_TRANSITION ((agc_rc)-1006)
#define AGC_ERR_CRYPTO_TEMPLATE_NOT_FOUND           ((agc_rc)-1010)
#define AGC_ERR_CRYPTO_TEMPLATE_DEPRECATED          ((agc_rc)-1011)
#define AGC_ERR_CRYPTO_TEMPLATE_FORBIDDEN           ((agc_rc)-1012)
#define AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE         ((agc_rc)-1013)
#define AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND           ((agc_rc)-1020)
#define AGC_ERR_CRYPTO_PROVIDER_UNAVAILABLE         ((agc_rc)-1021)
#define AGC_ERR_CRYPTO_PROVIDER_INCOMPATIBLE        ((agc_rc)-1022)
#define AGC_ERR_CRYPTO_NO_MATCHING_PROVIDER         ((agc_rc)-1023)
#define AGC_ERR_CRYPTO_POLICY_NOT_FOUND             ((agc_rc)-1030)
#define AGC_ERR_CRYPTO_POLICY_VIOLATION             ((agc_rc)-1031)
#define AGC_ERR_CRYPTO_POLICY_VERSION_CONFLICT      ((agc_rc)-1032)
#define AGC_ERR_CRYPTO_INVALID_OPERATION_STATE      ((agc_rc)-1040)
#define AGC_ERR_CRYPTO_OPERATION_EXPIRED            ((agc_rc)-1041)
#define AGC_ERR_CRYPTO_AUTHENTICATION_FAILED        ((agc_rc)-1042)
#define AGC_ERR_CRYPTO_SIGNATURE_INVALID            ((agc_rc)-1043)
#define AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS      ((agc_rc)-1044)
#define AGC_ERR_CRYPTO_MIGRATION_NOT_FEASIBLE       ((agc_rc)-1050)
#define AGC_ERR_CRYPTO_KEY_NOT_EXTRACTABLE          ((agc_rc)-1051)
#define AGC_ERR_CRYPTO_INVALID_KEY_MATERIAL         ((agc_rc)-1060)
#define AGC_ERR_CRYPTO_KEY_SIZE_MISMATCH            ((agc_rc)-1061)
#define AGC_ERR_CRYPTO_INSUFFICIENT_ENTROPY         ((agc_rc)-1062)
#define AGC_ERR_CRYPTO_RATE_LIMITED                 ((agc_rc)-1070)
#define AGC_ERR_CRYPTO_CONCURRENT_ACCESS            ((agc_rc)-1071)

/* ==========================================================================
 * SCOPE ENUMS — per-primitive operational variants (types/common.proto)
 * ========================================================================== */

typedef enum agc_signature_scope {
    AGC_SIGNATURE_SCOPE_UNSPECIFIED             = 0,
    AGC_SIGNATURE_SCOPE_STANDARD                = 1,
    AGC_SIGNATURE_SCOPE_WITH_CONTEXT            = 2,
    AGC_SIGNATURE_SCOPE_PREHASHED               = 3,
    AGC_SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT  = 4
    AGC_ENUM32(agc_signature_scope)
} agc_signature_scope;

typedef enum agc_aead_scope {
    AGC_AEAD_SCOPE_UNSPECIFIED    = 0,
    AGC_AEAD_SCOPE_STANDARD       = 1,
    AGC_AEAD_SCOPE_DETERMINISTIC  = 2,
    AGC_AEAD_SCOPE_STREAMING      = 3
    AGC_ENUM32(agc_aead_scope)
} agc_aead_scope;

typedef enum agc_mac_scope {
    AGC_MAC_SCOPE_UNSPECIFIED = 0,
    AGC_MAC_SCOPE_STANDARD    = 1,
    AGC_MAC_SCOPE_STREAMING   = 2
    AGC_ENUM32(agc_mac_scope)
} agc_mac_scope;

typedef enum agc_kem_scope {
    AGC_KEM_SCOPE_UNSPECIFIED = 0,
    AGC_KEM_SCOPE_STANDARD    = 1,
    AGC_KEM_SCOPE_HYBRID      = 2
    AGC_ENUM32(agc_kem_scope)
} agc_kem_scope;

typedef enum agc_key_agreement_scope {
    AGC_KEY_AGREEMENT_SCOPE_UNSPECIFIED = 0,
    AGC_KEY_AGREEMENT_SCOPE_STANDARD    = 1,
    AGC_KEY_AGREEMENT_SCOPE_HYBRID      = 2
    AGC_ENUM32(agc_key_agreement_scope)
} agc_key_agreement_scope;

typedef enum agc_kdf_scope {
    AGC_KDF_SCOPE_UNSPECIFIED    = 0,
    AGC_KDF_SCOPE_EXTRACT_EXPAND = 1,
    AGC_KDF_SCOPE_PASSWORD       = 2,
    AGC_KDF_SCOPE_AGREEMENT      = 3,
    AGC_KDF_SCOPE_COUNTER        = 4,
    AGC_KDF_SCOPE_TLS            = 5,
    AGC_KDF_SCOPE_GOST           = 6,
    AGC_KDF_SCOPE_VENDOR         = 7
    AGC_ENUM32(agc_kdf_scope)
} agc_kdf_scope;

typedef enum agc_hash_scope {
    AGC_HASH_SCOPE_UNSPECIFIED = 0,
    AGC_HASH_SCOPE_STANDARD    = 1,
    AGC_HASH_SCOPE_XOF         = 2
    AGC_ENUM32(agc_hash_scope)
} agc_hash_scope;

typedef enum agc_key_wrapping_scope {
    AGC_KEY_WRAPPING_SCOPE_UNSPECIFIED  = 0,
    AGC_KEY_WRAPPING_SCOPE_STANDARD     = 1,
    AGC_KEY_WRAPPING_SCOPE_WITH_PADDING = 2
    AGC_ENUM32(agc_key_wrapping_scope)
} agc_key_wrapping_scope;

typedef enum agc_symmetric_cipher_scope {
    AGC_SYMMETRIC_CIPHER_SCOPE_UNSPECIFIED = 0,
    AGC_SYMMETRIC_CIPHER_SCOPE_BLOCK       = 1,
    AGC_SYMMETRIC_CIPHER_SCOPE_STREAM      = 2
    AGC_ENUM32(agc_symmetric_cipher_scope)
} agc_symmetric_cipher_scope;

typedef enum agc_disk_encryption_scope {
    AGC_DISK_ENCRYPTION_SCOPE_UNSPECIFIED = 0,
    AGC_DISK_ENCRYPTION_SCOPE_STANDARD    = 1
    AGC_ENUM32(agc_disk_encryption_scope)
} agc_disk_encryption_scope;

typedef enum agc_generic_secret_scope {
    AGC_GENERIC_SECRET_SCOPE_UNSPECIFIED = 0,
    AGC_GENERIC_SECRET_SCOPE_STANDARD    = 1
    AGC_ENUM32(agc_generic_secret_scope)
} agc_generic_secret_scope;

typedef enum agc_asymmetric_encryption_scope {
    AGC_ASYMMETRIC_ENCRYPTION_SCOPE_UNSPECIFIED = 0,
    AGC_ASYMMETRIC_ENCRYPTION_SCOPE_STANDARD    = 1,
    AGC_ASYMMETRIC_ENCRYPTION_SCOPE_RAW         = 2
    AGC_ENUM32(agc_asymmetric_encryption_scope)
} agc_asymmetric_encryption_scope;

/* Discriminant for the ScopeSpecification oneof. Values are the proto FIELD
 * NUMBERS of the oneof arms, not an independent enum: this makes the tag
 * directly usable by a wire encoder and immune to reordering mistakes. */
typedef enum agc_scope_kind {
    AGC_SCOPE_KIND_NONE                  = 0,
    AGC_SCOPE_KIND_SIGNATURE             = 1,
    AGC_SCOPE_KIND_AEAD                  = 2,
    AGC_SCOPE_KIND_MAC                   = 3,
    AGC_SCOPE_KIND_KEM                   = 4,
    AGC_SCOPE_KIND_KEY_AGREEMENT         = 5,
    AGC_SCOPE_KIND_KDF                   = 6,
    AGC_SCOPE_KIND_HASH                  = 7,
    AGC_SCOPE_KIND_KEY_WRAPPING          = 8,
    AGC_SCOPE_KIND_SYMMETRIC_CIPHER      = 9,
    AGC_SCOPE_KIND_GENERIC_SECRET        = 10,
    AGC_SCOPE_KIND_DISK_ENCRYPTION       = 11,
    AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION = 12
    AGC_ENUM32(agc_scope_kind)
} agc_scope_kind;

/* ==========================================================================
 * KEY LIFECYCLE (types/common.proto)
 * ========================================================================== */

typedef enum agc_key_lifecycle_state {
    AGC_KEY_LIFECYCLE_STATE_UNSPECIFIED           = 0,
    AGC_KEY_LIFECYCLE_STATE_PRE_ACTIVE            = 1,
    AGC_KEY_LIFECYCLE_STATE_ACTIVE                = 2,
    AGC_KEY_LIFECYCLE_STATE_SUSPENDED             = 3,
    AGC_KEY_LIFECYCLE_STATE_DEACTIVATED           = 4,
    AGC_KEY_LIFECYCLE_STATE_COMPROMISED           = 5,
    AGC_KEY_LIFECYCLE_STATE_DESTROYED             = 6,
    AGC_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED = 7
    AGC_ENUM32(agc_key_lifecycle_state)
} agc_key_lifecycle_state;

typedef enum agc_key_origin {
    AGC_KEY_ORIGIN_UNSPECIFIED = 0,
    AGC_KEY_ORIGIN_GENERATED   = 1,
    AGC_KEY_ORIGIN_IMPORTED    = 2,
    AGC_KEY_ORIGIN_DERIVED     = 3,
    AGC_KEY_ORIGIN_UNWRAPPED   = 4
    AGC_ENUM32(agc_key_origin)
} agc_key_origin;

typedef enum agc_key_format {
    AGC_KEY_FORMAT_UNSPECIFIED = 0,
    AGC_KEY_FORMAT_RAW         = 1,
    AGC_KEY_FORMAT_WRAPPED     = 2,
    AGC_KEY_FORMAT_PKCS8       = 3,
    AGC_KEY_FORMAT_SPKI        = 4,
    AGC_KEY_FORMAT_JWK         = 5,
    AGC_KEY_FORMAT_PEM         = 6,
    AGC_KEY_FORMAT_SEC1        = 7
    AGC_ENUM32(agc_key_format)
} agc_key_format;

typedef enum agc_wrap_format {
    AGC_WRAP_FORMAT_UNSPECIFIED = 0,
    AGC_WRAP_FORMAT_PKCS8       = 1,
    AGC_WRAP_FORMAT_PKCS1       = 2,
    AGC_WRAP_FORMAT_RAW         = 3,
    AGC_WRAP_FORMAT_SPKI        = 4,
    AGC_WRAP_FORMAT_SEC1        = 5
    AGC_ENUM32(agc_wrap_format)
} agc_wrap_format;

typedef enum agc_migration_strategy {
    AGC_MIGRATION_STRATEGY_UNSPECIFIED        = 0,
    AGC_MIGRATION_STRATEGY_PROVIDER_SWITCH    = 1,
    AGC_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT = 2,
    AGC_MIGRATION_STRATEGY_WRAPPED_TRANSFER   = 3,
    AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE  = 4,
    AGC_MIGRATION_STRATEGY_REKEY_AND_DESTROY  = 5
    AGC_ENUM32(agc_migration_strategy)
} agc_migration_strategy;

/* ==========================================================================
 * SECURITY PROPERTIES (types/common.proto)
 * ========================================================================== */

typedef enum agc_nist_security_level {
    AGC_NIST_SECURITY_LEVEL_UNSPECIFIED = 0,
    AGC_NIST_SECURITY_LEVEL_1           = 1,
    AGC_NIST_SECURITY_LEVEL_2           = 2,
    AGC_NIST_SECURITY_LEVEL_3           = 3,
    AGC_NIST_SECURITY_LEVEL_4           = 4,
    AGC_NIST_SECURITY_LEVEL_5           = 5
    AGC_ENUM32(agc_nist_security_level)
} agc_nist_security_level;

typedef enum agc_nist_status {
    AGC_NIST_STATUS_UNSPECIFIED = 0,
    AGC_NIST_STATUS_APPROVED    = 1,
    AGC_NIST_STATUS_RECOMMENDED = 2,
    AGC_NIST_STATUS_ACCEPTABLE  = 3,
    AGC_NIST_STATUS_DEPRECATED  = 4,
    AGC_NIST_STATUS_FORBIDDEN   = 5
    AGC_ENUM32(agc_nist_status)
} agc_nist_status;

/* UniversalSecurityProperties. Dual-interpretation (requirement vs capability)
 * is preserved exactly as in the proto: the same struct is used in requests
 * (minimums / filters) and in template descriptions (provided characteristics). */
typedef struct agc_security_properties {
    size_t                  struct_size;
    uint32_t                security_strength_bits;  /* 0 = unspecified */
    agc_nist_security_level nist_security_level;
    agc_tribool             quantum_safe;
    agc_nist_status         nist_status;
    agc_tribool             fips_approved;
} agc_security_properties;

/* ==========================================================================
 * OPERATIONS (types/common.proto: CryptoOperation)
 * ========================================================================== */

typedef enum agc_operation {
    AGC_OP_UNSPECIFIED        = 0,
    AGC_OP_CREATE_KEY         = 1,
    AGC_OP_READ_KEY           = 2,
    AGC_OP_DELETE_KEY         = 3,
    AGC_OP_ROTATE_KEY         = 4,
    AGC_OP_TRANSFORM_KEY      = 5,
    AGC_OP_IMPORT_KEY         = 6,
    AGC_OP_EXPORT_KEY         = 7,
    AGC_OP_UPDATE_KEY_POLICY  = 8,
    AGC_OP_MIGRATE_KEY        = 9,
    AGC_OP_ENCRYPT            = 10,
    AGC_OP_DECRYPT            = 11,
    AGC_OP_UPDATE_KEY_STATE   = 12,
    AGC_OP_SIGN               = 20,
    AGC_OP_VERIFY             = 21,
    AGC_OP_DIGEST_SIGN        = 22,
    AGC_OP_DIGEST_VERIFY      = 23,
    AGC_OP_WRAP_KEY           = 30,
    AGC_OP_UNWRAP_KEY         = 31,
    AGC_OP_DERIVE_KEY         = 40,
    AGC_OP_GENERATE_MAC       = 50,
    AGC_OP_VERIFY_MAC         = 51,
    AGC_OP_DIGEST             = 60,
    AGC_OP_ENCAPSULATE        = 70,
    AGC_OP_DECAPSULATE        = 71,
    AGC_OP_KEY_AGREEMENT      = 80,
    AGC_OP_GENERATE_RANDOM    = 90,
    AGC_OP_SEED_RANDOM        = 91,
    AGC_OP_DIGEST_ENCRYPT     = 100,
    AGC_OP_DECRYPT_DIGEST     = 101,
    AGC_OP_SIGN_ENCRYPT       = 102,
    AGC_OP_DECRYPT_VERIFY     = 103
    AGC_ENUM32(agc_operation)
} agc_operation;

/* ==========================================================================
 * TEMPLATES (types/templates.proto)
 * ========================================================================== */

typedef enum agc_template_status {
    AGC_TEMPLATE_STATUS_UNSPECIFIED  = 0,
    AGC_TEMPLATE_STATUS_ACTIVE       = 1,
    AGC_TEMPLATE_STATUS_ACCEPTABLE   = 2,
    AGC_TEMPLATE_STATUS_DEPRECATED   = 3,
    AGC_TEMPLATE_STATUS_FORBIDDEN    = 4,
    AGC_TEMPLATE_STATUS_EXPERIMENTAL = 5
    AGC_ENUM32(agc_template_status)
} agc_template_status;

typedef enum agc_combiner_strategy {
    AGC_COMBINER_UNSPECIFIED     = 0,
    AGC_COMBINER_CONCATENATION   = 1,
    AGC_COMBINER_NESTING         = 2,
    AGC_COMBINER_KDF_COMBINATION = 3
    AGC_ENUM32(agc_combiner_strategy)
} agc_combiner_strategy;

/* ==========================================================================
 * ALGORITHM VOCABULARY (types/algorithm_params.proto)
 * ========================================================================== */

typedef enum agc_hash_algorithm {
    AGC_HASH_ALGORITHM_UNSPECIFIED        = 0,
    AGC_HASH_ALGORITHM_SHA256             = 1,
    AGC_HASH_ALGORITHM_SHA384             = 2,
    AGC_HASH_ALGORITHM_SHA512             = 3,
    AGC_HASH_ALGORITHM_SHA512_256         = 4,
    AGC_HASH_ALGORITHM_SHA224             = 5,
    AGC_HASH_ALGORITHM_SHA512_224         = 6,
    AGC_HASH_ALGORITHM_SHA3_256           = 10,
    AGC_HASH_ALGORITHM_SHA3_384           = 11,
    AGC_HASH_ALGORITHM_SHA3_512           = 12,
    AGC_HASH_ALGORITHM_SHA3_224           = 13,
    AGC_HASH_ALGORITHM_SHAKE128           = 20,
    AGC_HASH_ALGORITHM_SHAKE256           = 21,
    AGC_HASH_ALGORITHM_BLAKE2B_256        = 30,
    AGC_HASH_ALGORITHM_BLAKE2B_384        = 31,
    AGC_HASH_ALGORITHM_BLAKE2B_512        = 32,
    AGC_HASH_ALGORITHM_BLAKE2S_256        = 33,
    AGC_HASH_ALGORITHM_BLAKE2S_160        = 34,
    AGC_HASH_ALGORITHM_BLAKE2S_224        = 35,
    AGC_HASH_ALGORITHM_BLAKE3             = 40,
    AGC_HASH_ALGORITHM_GOST_R3411_94      = 50,
    AGC_HASH_ALGORITHM_GOST_R3411_2012_256= 51,
    AGC_HASH_ALGORITHM_GOST_R3411_2012_512= 52,
    AGC_HASH_ALGORITHM_SHA1               = 100,  /* deprecated */
    AGC_HASH_ALGORITHM_MD5                = 101,  /* deprecated */
    AGC_HASH_ALGORITHM_OTHER              = 200
    AGC_ENUM32(agc_hash_algorithm)
} agc_hash_algorithm;

typedef enum agc_elliptic_curve {
    AGC_ELLIPTIC_CURVE_UNSPECIFIED      = 0,
    AGC_ELLIPTIC_CURVE_P256             = 1,
    AGC_ELLIPTIC_CURVE_P384             = 2,
    AGC_ELLIPTIC_CURVE_P521             = 3,
    AGC_ELLIPTIC_CURVE_CURVE25519       = 10,
    AGC_ELLIPTIC_CURVE_CURVE448         = 11,
    AGC_ELLIPTIC_CURVE_SECP256K1        = 20,
    AGC_ELLIPTIC_CURVE_BRAINPOOL_P256R1 = 30,
    AGC_ELLIPTIC_CURVE_BRAINPOOL_P384R1 = 31,
    AGC_ELLIPTIC_CURVE_BRAINPOOL_P512R1 = 32,
    AGC_ELLIPTIC_CURVE_BRAINPOOL_P256T1 = 33,
    AGC_ELLIPTIC_CURVE_BRAINPOOL_P384T1 = 34,
    AGC_ELLIPTIC_CURVE_BRAINPOOL_P512T1 = 35,
    AGC_ELLIPTIC_CURVE_K163             = 40,
    AGC_ELLIPTIC_CURVE_B163             = 41,
    AGC_ELLIPTIC_CURVE_K233             = 42,
    AGC_ELLIPTIC_CURVE_B233             = 43,
    AGC_ELLIPTIC_CURVE_K283             = 44,
    AGC_ELLIPTIC_CURVE_B283             = 45,
    AGC_ELLIPTIC_CURVE_K409             = 46,
    AGC_ELLIPTIC_CURVE_B409             = 47,
    AGC_ELLIPTIC_CURVE_K571             = 48,
    AGC_ELLIPTIC_CURVE_B571             = 49
    AGC_ENUM32(agc_elliptic_curve)
} agc_elliptic_curve;

typedef enum agc_padding_scheme {
    AGC_PADDING_SCHEME_UNSPECIFIED = 0,
    AGC_PADDING_SCHEME_NONE        = 1,
    AGC_PADDING_SCHEME_PKCS7       = 2,
    AGC_PADDING_SCHEME_ISO7816     = 3,
    AGC_PADDING_SCHEME_X923        = 4,
    AGC_PADDING_SCHEME_ZERO        = 5
    AGC_ENUM32(agc_padding_scheme)
} agc_padding_scheme;

typedef enum agc_signature_format {
    AGC_SIGNATURE_FORMAT_UNSPECIFIED = 0,
    AGC_SIGNATURE_FORMAT_DER         = 1,
    AGC_SIGNATURE_FORMAT_IEEE_P1363  = 2,
    AGC_SIGNATURE_FORMAT_RAW         = 3
    AGC_ENUM32(agc_signature_format)
} agc_signature_format;

typedef enum agc_mgf {
    AGC_MGF_UNSPECIFIED = 0,
    AGC_MGF_MGF1        = 1
    AGC_ENUM32(agc_mgf)
} agc_mgf;

typedef enum agc_argon2_variant {
    AGC_ARGON2_VARIANT_UNSPECIFIED = 0,
    AGC_ARGON2_VARIANT_D           = 1,
    AGC_ARGON2_VARIANT_I           = 2,
    AGC_ARGON2_VARIANT_ID          = 3
    AGC_ENUM32(agc_argon2_variant)
} agc_argon2_variant;

typedef enum agc_ed25519_variant {
    AGC_ED25519_VARIANT_UNSPECIFIED = 0,
    AGC_ED25519_VARIANT_PURE        = 1,
    AGC_ED25519_VARIANT_CTX         = 2,
    AGC_ED25519_VARIANT_PH          = 3
    AGC_ENUM32(agc_ed25519_variant)
} agc_ed25519_variant;

typedef enum agc_ed448_variant {
    AGC_ED448_VARIANT_UNSPECIFIED = 0,
    AGC_ED448_VARIANT_PURE        = 1,
    AGC_ED448_VARIANT_PH          = 2
    AGC_ENUM32(agc_ed448_variant)
} agc_ed448_variant;

typedef enum agc_key_type {
    AGC_KEY_TYPE_UNSPECIFIED      = 0,
    AGC_KEY_TYPE_SYMMETRIC        = 1,
    AGC_KEY_TYPE_RSA              = 10,
    AGC_KEY_TYPE_EC               = 11,
    AGC_KEY_TYPE_ED25519          = 12,
    AGC_KEY_TYPE_ED448            = 13,
    AGC_KEY_TYPE_X25519           = 14,
    AGC_KEY_TYPE_X448             = 15,
    AGC_KEY_TYPE_DSA              = 16,
    AGC_KEY_TYPE_DH               = 17,
    AGC_KEY_TYPE_ML_KEM           = 20,
    AGC_KEY_TYPE_ML_DSA           = 21,
    AGC_KEY_TYPE_SLH_DSA          = 22,
    AGC_KEY_TYPE_HYBRID           = 30,
    AGC_KEY_TYPE_GOST             = 40,
    AGC_KEY_TYPE_OTP              = 50,
    AGC_KEY_TYPE_VENDOR           = 100,
    AGC_KEY_TYPE_PQ_EXPERIMENTAL  = 101,
    AGC_KEY_TYPE_CUSTOM           = 199
    AGC_ENUM32(agc_key_type)
} agc_key_type;

typedef enum agc_crypto_primitive {
    AGC_CRYPTO_PRIMITIVE_UNSPECIFIED   = 0,
    AGC_CRYPTO_PRIMITIVE_AE            = 1,
    AGC_CRYPTO_PRIMITIVE_BLOCK_CIPHER  = 2,
    AGC_CRYPTO_PRIMITIVE_STREAM_CIPHER = 3,
    AGC_CRYPTO_PRIMITIVE_PKE           = 4,
    AGC_CRYPTO_PRIMITIVE_SIGNATURE     = 10,
    AGC_CRYPTO_PRIMITIVE_KEM           = 20,
    AGC_CRYPTO_PRIMITIVE_KEY_AGREE     = 21,
    AGC_CRYPTO_PRIMITIVE_HASH          = 30,
    AGC_CRYPTO_PRIMITIVE_MAC           = 31,
    AGC_CRYPTO_PRIMITIVE_XOF           = 32,
    AGC_CRYPTO_PRIMITIVE_KDF           = 40,
    AGC_CRYPTO_PRIMITIVE_KEY_WRAP      = 41,
    AGC_CRYPTO_PRIMITIVE_OTP           = 45,
    AGC_CRYPTO_PRIMITIVE_DRBG          = 50,
    AGC_CRYPTO_PRIMITIVE_COMBINER      = 51,
    AGC_CRYPTO_PRIMITIVE_OTHER         = 99
    AGC_ENUM32(agc_crypto_primitive)
} agc_crypto_primitive;

typedef enum agc_ml_dsa_parameter_set {
    AGC_ML_DSA_PARAMETER_SET_UNSPECIFIED = 0,
    AGC_ML_DSA_44                        = 1,
    AGC_ML_DSA_65                        = 2,
    AGC_ML_DSA_87                        = 3
    AGC_ENUM32(agc_ml_dsa_parameter_set)
} agc_ml_dsa_parameter_set;

typedef enum agc_ml_kem_parameter_set {
    AGC_ML_KEM_PARAMETER_SET_UNSPECIFIED = 0,
    AGC_ML_KEM_512                       = 1,
    AGC_ML_KEM_768                       = 2,
    AGC_ML_KEM_1024                      = 3
    AGC_ENUM32(agc_ml_kem_parameter_set)
} agc_ml_kem_parameter_set;

typedef enum agc_slh_dsa_hash_type {
    AGC_SLH_DSA_HASH_TYPE_UNSPECIFIED = 0,
    AGC_SLH_DSA_SHA2                  = 1,
    AGC_SLH_DSA_SHAKE                 = 2
    AGC_ENUM32(agc_slh_dsa_hash_type)
} agc_slh_dsa_hash_type;

typedef enum agc_slh_dsa_parameter_set {
    AGC_SLH_DSA_PARAMETER_SET_UNSPECIFIED = 0,
    AGC_SLH_DSA_128S = 1, AGC_SLH_DSA_128F = 2,
    AGC_SLH_DSA_192S = 3, AGC_SLH_DSA_192F = 4,
    AGC_SLH_DSA_256S = 5, AGC_SLH_DSA_256F = 6
    AGC_ENUM32(agc_slh_dsa_parameter_set)
} agc_slh_dsa_parameter_set;

typedef enum agc_ecdh_kdf_type {
    AGC_ECDH_KDF_UNSPECIFIED = 0,
    AGC_ECDH_KDF_HKDF_SHA256 = 1,
    AGC_ECDH_KDF_HKDF_SHA384 = 2,
    AGC_ECDH_KDF_HKDF_SHA512 = 3,
    AGC_ECDH_KDF_X963_SHA256 = 4,
    AGC_ECDH_KDF_X963_SHA384 = 5,
    AGC_ECDH_KDF_X963_SHA512 = 6
    AGC_ENUM32(agc_ecdh_kdf_type)
} agc_ecdh_kdf_type;

typedef enum agc_hkdf_salt_type {
    AGC_HKDF_SALT_TYPE_UNSPECIFIED = 0,
    AGC_HKDF_SALT_TYPE_DATA        = 1,
    AGC_HKDF_SALT_TYPE_NULL        = 2,
    AGC_HKDF_SALT_TYPE_KEY         = 3
    AGC_ENUM32(agc_hkdf_salt_type)
} agc_hkdf_salt_type;

typedef enum agc_sp800108_data_type {
    AGC_SP800_108_DATA_TYPE_UNSPECIFIED        = 0,
    AGC_SP800_108_DATA_TYPE_ITERATION_VARIABLE = 1,
    AGC_SP800_108_DATA_TYPE_COUNTER            = 2,
    AGC_SP800_108_DATA_TYPE_DKM_LENGTH         = 3,
    AGC_SP800_108_DATA_TYPE_BYTE_ARRAY         = 4
    AGC_ENUM32(agc_sp800108_data_type)
} agc_sp800108_data_type;

/* ==========================================================================
 * PROVIDERS AND IMPLEMENTATION (types/providers.proto, types/implementation.proto)
 * ========================================================================== */

typedef enum agc_provider_type {
    AGC_PROVIDER_TYPE_UNSPECIFIED = 0,
    AGC_PROVIDER_TYPE_SOFTWARE    = 1,
    AGC_PROVIDER_TYPE_HSM         = 2,
    AGC_PROVIDER_TYPE_CLOUD_KMS   = 3,
    AGC_PROVIDER_TYPE_REMOTE      = 4
    AGC_ENUM32(agc_provider_type)
} agc_provider_type;

typedef enum agc_fips140_level {
    AGC_FIPS_140_LEVEL_UNSPECIFIED = 0,
    AGC_FIPS_140_LEVEL_1           = 1,
    AGC_FIPS_140_LEVEL_2           = 2,
    AGC_FIPS_140_LEVEL_3           = 3,
    AGC_FIPS_140_LEVEL_4           = 4
    AGC_ENUM32(agc_fips140_level)
} agc_fips140_level;

/* ==========================================================================
 * POLICY (messages/policy.proto)
 * ========================================================================== */

typedef enum agc_policy_denial_reason {
    AGC_POLICY_DENIAL_REASON_UNSPECIFIED                  = 0,
    AGC_POLICY_DENIAL_REASON_POLICY_NOT_FOUND             = 1,
    AGC_POLICY_DENIAL_REASON_OPERATION_NOT_ALLOWED        = 2,
    AGC_POLICY_DENIAL_REASON_TEMPLATE_NOT_ALLOWED         = 3,
    AGC_POLICY_DENIAL_REASON_SCOPE_NOT_ALLOWED            = 4,
    AGC_POLICY_DENIAL_REASON_PROVIDER_NOT_ALLOWED         = 5,
    AGC_POLICY_DENIAL_REASON_KEY_NOT_FOUND                = 6,
    AGC_POLICY_DENIAL_REASON_PROPERTY_MISMATCH            = 7,
    AGC_POLICY_DENIAL_REASON_SECURITY_LEVEL_INSUFFICIENT  = 8,
    AGC_POLICY_DENIAL_REASON_ALGORITHM_DEPRECATED         = 9,
    AGC_POLICY_DENIAL_REASON_PQC_REQUIRED                 = 10
    AGC_ENUM32(agc_policy_denial_reason)
} agc_policy_denial_reason;

/* ==========================================================================
 * ALGORITHM OUTPUT (messages/metadata.proto: ProviderOutput.algorithm_output)
 * Tag values are the proto field numbers of the oneof arms.
 * ========================================================================== */

typedef enum agc_algorithm_output_kind {
    AGC_ALGORITHM_OUTPUT_NONE          = 0,   /* provider bug: oneof unset */
    AGC_ALGORITHM_OUTPUT_NO_OUTPUT     = 10,  /* explicit "no system-generated params" */
    AGC_ALGORITHM_OUTPUT_AEAD          = 11,
    AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER  = 12,
    AGC_ALGORITHM_OUTPUT_COUNTER_MODE  = 13,
    AGC_ALGORITHM_OUTPUT_STREAM_CIPHER = 14,
    AGC_ALGORITHM_OUTPUT_KDF           = 15,
    AGC_ALGORITHM_OUTPUT_VENDOR        = 16
    AGC_ENUM32(agc_algorithm_output_kind)
} agc_algorithm_output_kind;

/* ==========================================================================
 * SCOPE SPECIFICATION — tagged union for ScopeSpecification
 * ========================================================================== */

typedef struct agc_signature_scope_spec {
    agc_signature_scope     scope;
    agc_security_properties security;
    agc_tribool             non_malleable;
    agc_tribool             deterministic;
    agc_kv_list             additional_properties;
} agc_signature_scope_spec;

typedef struct agc_aead_scope_spec {
    agc_aead_scope          scope;
    agc_security_properties security;
    agc_tribool             nonce_misuse_resistant;
    agc_kv_list             additional_properties;
} agc_aead_scope_spec;

typedef struct agc_mac_scope_spec {
    agc_mac_scope           scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_mac_scope_spec;

typedef struct agc_kem_scope_spec {
    agc_kem_scope           scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_kem_scope_spec;

typedef struct agc_key_agreement_scope_spec {
    agc_key_agreement_scope scope;
    agc_security_properties security;
    agc_tribool             forward_secrecy;
    agc_kv_list             additional_properties;
} agc_key_agreement_scope_spec;

typedef struct agc_kdf_scope_spec {
    agc_kdf_scope           scope;
    agc_security_properties security;
    agc_tribool             memory_hard;
    agc_kv_list             additional_properties;
} agc_kdf_scope_spec;

typedef struct agc_hash_scope_spec {
    agc_hash_scope          scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_hash_scope_spec;

typedef struct agc_key_wrapping_scope_spec {
    agc_key_wrapping_scope  scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_key_wrapping_scope_spec;

typedef struct agc_symmetric_cipher_scope_spec {
    agc_symmetric_cipher_scope scope;
    agc_security_properties    security;
    agc_kv_list                additional_properties;
} agc_symmetric_cipher_scope_spec;

typedef struct agc_generic_secret_scope_spec {
    agc_generic_secret_scope scope;
    agc_security_properties  security;
    agc_kv_list              additional_properties;
} agc_generic_secret_scope_spec;

typedef struct agc_disk_encryption_scope_spec {
    agc_disk_encryption_scope scope;
    agc_security_properties   security;
    agc_kv_list               additional_properties;
} agc_disk_encryption_scope_spec;

typedef struct agc_asymmetric_encryption_scope_spec {
    agc_asymmetric_encryption_scope scope;
    agc_security_properties         security;
    agc_kv_list                     additional_properties;
} agc_asymmetric_encryption_scope_spec;

/* ScopeSpecification. `kind` selects the active union member. The library
 * rejects AGC_SCOPE_KIND_NONE wherever the proto marks the oneof required
 * (buf.validate.oneof.required = true). */
typedef struct agc_scope_spec {
    size_t         struct_size;
    agc_scope_kind kind;
    union {
        agc_signature_scope_spec             signature;
        agc_aead_scope_spec                  aead;
        agc_mac_scope_spec                   mac;
        agc_kem_scope_spec                   kem;
        agc_key_agreement_scope_spec         key_agreement;
        agc_kdf_scope_spec                   kdf;
        agc_hash_scope_spec                  hash;
        agc_key_wrapping_scope_spec          key_wrapping;
        agc_symmetric_cipher_scope_spec      symmetric_cipher;
        agc_generic_secret_scope_spec        generic_secret;
        agc_disk_encryption_scope_spec       disk_encryption;
        agc_asymmetric_encryption_scope_spec asymmetric_encryption;
    } u;
} agc_scope_spec;

/* ==========================================================================
 * OPERATION-TIME PARAMETERS (types/operation_params.proto)
 *
 * Each proto `oneof scope_params` becomes one tagged union type. Tag values are
 * NOT proto field numbers here, because the same conceptual arm carries a
 * different field number in each enclosing message (e.g. aead_params is field 4
 * in EncryptRequest and field 3 in EncryptInitRequest). A stable, independent
 * discriminant is used instead; the marshalling layer maps it per message.
 * ========================================================================== */

/* ---- Vendor escape hatch (CustomOperationParams) ---- */

typedef enum agc_custom_params_kind {
    AGC_CUSTOM_PARAMS_NONE    = 0,
    AGC_CUSTOM_PARAMS_GENERIC = 10,  /* google.protobuf.Struct, as canonical JSON */
    AGC_CUSTOM_PARAMS_TYPED   = 11   /* google.protobuf.Any, as type_url + value */
    AGC_ENUM32(agc_custom_params_kind)
} agc_custom_params_kind;

/* CustomOperationParams. google.protobuf.Struct and Any have no natural C
 * representation, so they are carried in their canonical serialised forms:
 *   generic_params_json : UTF-8 JSON object (the canonical JSON encoding of Struct)
 *   typed_params_type_url + typed_params_value : the two fields of Any
 * A gRPC front-end re-parses these into real messages; a local provider that
 * understands the vendor format consumes them directly. */
typedef struct agc_custom_params {
    size_t                 struct_size;
    agc_str                vendor;
    agc_str                algorithm_name;
    agc_custom_params_kind kind;
    agc_str                generic_params_json;    /* kind == GENERIC */
    agc_str                typed_params_type_url;  /* kind == TYPED   */
    agc_slice              typed_params_value;     /* kind == TYPED   */
    agc_slice              raw_params;             /* additive, always forwarded */
} agc_custom_params;

/* ---- Encryption scope params (EncryptRequest.scope_params et al.) ---- */

typedef enum agc_encrypt_params_kind {
    AGC_ENCRYPT_PARAMS_NONE       = 0,  /* invalid: the oneof is required */
    AGC_ENCRYPT_PARAMS_NO_PARAMS  = 1,  /* NoParams — AES-CBC/CTR, ChaCha20, 3DES */
    AGC_ENCRYPT_PARAMS_AEAD       = 2,  /* AeadEncryptParams */
    AGC_ENCRYPT_PARAMS_XTS        = 3,  /* XtsEncryptParams */
    AGC_ENCRYPT_PARAMS_ASYMMETRIC = 4,  /* AsymmetricEncryptParams */
    AGC_ENCRYPT_PARAMS_VENDOR     = 5   /* VendorEncryptionParams */
    AGC_ENUM32(agc_encrypt_params_kind)
} agc_encrypt_params_kind;

typedef struct agc_aead_encrypt_params {
    agc_slice aad;
    uint64_t  plaintext_length;      /* CCM: total plaintext length */
    int       has_plaintext_length;  /* proto `optional uint64` presence */
} agc_aead_encrypt_params;

typedef struct agc_xts_encrypt_params {
    uint8_t tweak[16];  /* buf.validate: bytes.len == 16 — fixed array, not a slice */
} agc_xts_encrypt_params;

typedef struct agc_asymmetric_encrypt_params {
    agc_slice label;    /* OAEP label / PKCS#11 pSourceData */
} agc_asymmetric_encrypt_params;

typedef struct agc_encrypt_params {
    size_t                  struct_size;
    agc_encrypt_params_kind kind;
    union {
        agc_aead_encrypt_params       aead;
        agc_xts_encrypt_params        xts;
        agc_asymmetric_encrypt_params asymmetric;
        agc_custom_params             vendor;
    } u;
} agc_encrypt_params;

/* ---- Signature scope params (SignRequest.scope_params et al.) ---- */

typedef enum agc_sign_params_kind {
    AGC_SIGN_PARAMS_NONE           = 0,  /* invalid: the oneof is required */
    AGC_SIGN_PARAMS_NO_CONTEXT     = 1,  /* NoParams — ECDSA, RSA-PSS, DSA */
    AGC_SIGN_PARAMS_DOMAIN_CONTEXT = 2,  /* SignatureDomainContext — EdDSA, ML-DSA, SLH-DSA */
    AGC_SIGN_PARAMS_VENDOR         = 3   /* VendorSignatureContext */
    AGC_ENUM32(agc_sign_params_kind)
} agc_sign_params_kind;

/* SignatureDomainContext. buf.validate caps context at 255 bytes; the fixed
 * array removes an allocation from the hot path and makes the bound structural. */
typedef struct agc_signature_domain_context {
    uint8_t context[255];
    uint8_t context_len;   /* 0..255 */
} agc_signature_domain_context;

typedef struct agc_sign_params {
    size_t               struct_size;
    agc_sign_params_kind kind;
    union {
        agc_signature_domain_context domain_context;
        agc_custom_params            vendor;
    } u;
} agc_sign_params;

/* ---- MAC scope params (GenerateMACRequest.scope_params et al.) ---- */

typedef enum agc_mac_params_kind {
    AGC_MAC_PARAMS_NONE         = 0,  /* invalid: the oneof is required */
    AGC_MAC_PARAMS_NO_PARAMS    = 1,  /* NoParams — HMAC, CMAC, GMAC, Poly1305 */
    AGC_MAC_PARAMS_CUSTOMIZABLE = 2,  /* CustomizableMacParams — KMAC */
    AGC_MAC_PARAMS_VENDOR       = 3   /* VendorMacParams */
    AGC_ENUM32(agc_mac_params_kind)
} agc_mac_params_kind;

typedef struct agc_customizable_mac_params {
    agc_slice customization;   /* NIST SP 800-185 customization string S */
} agc_customizable_mac_params;

typedef struct agc_mac_params {
    size_t              struct_size;
    agc_mac_params_kind kind;
    union {
        agc_customizable_mac_params customizable;
        agc_custom_params           vendor;
    } u;
} agc_mac_params;

/* ---- Key-wrapping scope params (WrapKeyRequest.scope_params) ---- */

typedef enum agc_wrap_params_kind {
    AGC_WRAP_PARAMS_NONE      = 0,  /* invalid: the oneof is required */
    AGC_WRAP_PARAMS_NO_PARAMS = 1,  /* NoParams — AES-KW, AES-KWP, RSA wrap */
    AGC_WRAP_PARAMS_KA_WRAP   = 2,  /* KeyAgreementWrapParams — ECDH-ES+AES-KW */
    AGC_WRAP_PARAMS_GOST      = 3,  /* GostWrapOperationParams */
    AGC_WRAP_PARAMS_VENDOR    = 4   /* VendorWrapParams */
    AGC_ENUM32(agc_wrap_params_kind)
} agc_wrap_params_kind;

typedef struct agc_key_agreement_wrap_params {
    agc_slice shared_info;
    agc_slice apu;   /* JWE "apu" header, base64url-decoded (RFC 7518 §4.6.2) */
    agc_slice apv;   /* JWE "apv" header, base64url-decoded */
} agc_key_agreement_wrap_params;

typedef struct agc_gost_wrap_params {
    agc_slice ukm;
} agc_gost_wrap_params;

typedef struct agc_wrap_params {
    size_t               struct_size;
    agc_wrap_params_kind kind;
    union {
        agc_key_agreement_wrap_params ka_wrap;
        agc_gost_wrap_params          gost;
        agc_custom_params             vendor;
    } u;
} agc_wrap_params;

/* ---- KDF / key-agreement operation params (DeriveKeyRequest.kdf_params,
 *      KeyAgreementRequest.agreement_params) ---- */

typedef enum agc_kdf_params_kind {
    AGC_KDF_PARAMS_NONE      = 0,   /* invalid: the oneof is required */
    AGC_KDF_PARAMS_HKDF      = 1,
    AGC_KDF_PARAMS_PBKDF2    = 2,
    AGC_KDF_PARAMS_ARGON2    = 3,
    AGC_KDF_PARAMS_ECDH      = 4,
    AGC_KDF_PARAMS_X942_DH   = 5,
    AGC_KDF_PARAMS_TLS_PRF   = 6,
    AGC_KDF_PARAMS_TLS12     = 7,
    AGC_KDF_PARAMS_SP800_108 = 8,
    AGC_KDF_PARAMS_GOST      = 9,
    AGC_KDF_PARAMS_X3DH      = 10,
    AGC_KDF_PARAMS_VENDOR    = 11
    AGC_ENUM32(agc_kdf_params_kind)
} agc_kdf_params_kind;

typedef struct agc_hkdf_operation_params {
    agc_optional_slice salt;          /* absent => server generates random salt */
    agc_slice          info;
    agc_hkdf_salt_type salt_type;
    agc_str            salt_key_name; /* salt_type == KEY */
} agc_hkdf_operation_params;

typedef struct agc_pbkdf2_operation_params {
    agc_slice          password;
    agc_optional_slice salt;
} agc_pbkdf2_operation_params;

typedef struct agc_argon2_operation_params {
    agc_slice          password;
    agc_optional_slice salt;
    agc_slice          associated_data;
    agc_slice          secret;        /* pepper */
} agc_argon2_operation_params;

typedef struct agc_ecdh_operation_params {
    agc_slice shared_info;
} agc_ecdh_operation_params;

typedef struct agc_x942_dh_operation_params {
    agc_slice other_info;
} agc_x942_dh_operation_params;

typedef struct agc_tls_prf_operation_params {
    agc_slice label;
    agc_slice seed;
} agc_tls_prf_operation_params;

typedef struct agc_tls12_kdf_operation_params {
    agc_slice label;
    uint8_t   client_random[32];   /* buf.validate: bytes.len == 32 */
    uint8_t   server_random[32];   /* buf.validate: bytes.len == 32 */
    agc_slice context_data;
} agc_tls12_kdf_operation_params;

typedef struct agc_sp800108_data_param {
    agc_sp800108_data_type type;
    agc_slice              value;
} agc_sp800108_data_param;

typedef struct agc_sp800108_operation_params {
    const agc_sp800108_data_param *data_params;
    size_t                         data_params_count;
} agc_sp800108_operation_params;

typedef struct agc_gost_kdf_operation_params {
    agc_slice ukm;
} agc_gost_kdf_operation_params;

typedef struct agc_x3dh_operation_params {
    agc_slice context;
} agc_x3dh_operation_params;

typedef struct agc_kdf_params {
    size_t              struct_size;
    agc_kdf_params_kind kind;
    union {
        agc_hkdf_operation_params      hkdf;
        agc_pbkdf2_operation_params    pbkdf2;
        agc_argon2_operation_params    argon2;
        agc_ecdh_operation_params      ecdh;
        agc_x942_dh_operation_params   x942_dh;
        agc_tls_prf_operation_params   tls_prf;
        agc_tls12_kdf_operation_params tls12;
        agc_sp800108_operation_params  sp800_108;
        agc_gost_kdf_operation_params  gost;
        agc_x3dh_operation_params      x3dh;
        agc_custom_params              vendor;
    } u;
} agc_kdf_params;

/* ==========================================================================
 * PROVIDER SELECTION (types/implementation.proto: ProviderRequirements)
 * ========================================================================== */

typedef struct agc_provider_requirements {
    size_t            struct_size;
    agc_tribool       fips_140_certified;
    agc_fips140_level min_fips_level;
    agc_tribool       common_criteria_certified;
    agc_tribool       formally_verified;
    agc_tribool       memory_safe;
    agc_tribool       constant_time;
    agc_tribool       side_channel_hardened;
    agc_tribool       no_known_cve;
    agc_tribool       prefer_hardware_accelerated;  /* soft preference, not a filter */
    agc_kv_list       additional;
} agc_provider_requirements;

/* ==========================================================================
 * Enum <-> string helpers.
 *
 * Generated alongside the enums so that tooling, logs and CBOM exporters do not
 * hand-maintain parallel tables. The returned pointers are static storage with
 * program lifetime; never free them.
 * ========================================================================== */

AGC_API const char *agc_rc_name(agc_rc rc);
AGC_API const char *agc_rc_message(agc_rc rc);   /* short English description */
AGC_API const char *agc_operation_name(agc_operation op);
AGC_API const char *agc_key_lifecycle_state_name(agc_key_lifecycle_state s);
AGC_API const char *agc_template_status_name(agc_template_status s);
AGC_API const char *agc_hash_algorithm_name(agc_hash_algorithm h);
AGC_API const char *agc_elliptic_curve_name(agc_elliptic_curve c);
AGC_API const char *agc_scope_kind_name(agc_scope_kind k);
AGC_API const char *agc_provider_type_name(agc_provider_type t);
AGC_API const char *agc_migration_strategy_name(agc_migration_strategy s);
AGC_API const char *agc_policy_denial_reason_name(agc_policy_denial_reason r);

/* Reverse lookups return AGC_OK, or AGC_ERR_INVALID_ARGUMENT if unrecognised. */
AGC_API agc_rc agc_operation_from_name(const char *name, agc_operation *out);
AGC_API agc_rc agc_hash_algorithm_from_name(const char *name, agc_hash_algorithm *out);
AGC_API agc_rc agc_hash_algorithm_from_oid(const char *oid, agc_hash_algorithm *out);

/* Digest length in bytes for a fixed-output hash. Returns 0 for XOFs and for
 * AGC_HASH_ALGORITHM_OTHER/UNSPECIFIED. Used to implement the digest-length
 * validation that DigestSign/DigestVerify require. */
AGC_API size_t agc_hash_algorithm_output_len(agc_hash_algorithm h);

#ifdef __cplusplus
}
#endif
#endif /* AGC_TYPES_H */
