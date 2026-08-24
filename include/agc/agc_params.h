/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_params.h — Abstract Cryptographic API, C binding: operation-time
 * parameters (api/types/operation_params.proto).
 *
 * HAND-WRITTEN. Each proto `oneof scope_params`/`kdf_params` becomes one
 * tagged union type here. Two different tagging conventions are in play, and
 * mixing them up is a real correctness bug, not a style choice:
 *
 *   - agc_custom_params_kind: tags ARE the proto field numbers (10, 11) of
 *     CustomOperationParams.params, verified by
 *     conformance/tier1c_oneof_tags.py.
 *
 *   - The five request-level unions below (encrypt/sign/mac/wrap/kdf params):
 *     tags are an INDEPENDENT enum, NOT proto field numbers, because the same
 *     conceptual arm carries a DIFFERENT field number in each enclosing
 *     message. Concretely: aead_params is field 4 in EncryptRequest, field 5
 *     in DecryptRequest, and field 4 again in EncryptInitRequest; no_context
 *     is field 3 in SignRequest but field 5 in VerifyRequest. A field number
 *     therefore cannot serve as a stable discriminant for these five, so the
 *     marshalling layer (commits 7-10) maps the independent tag to the
 *     correct per-message field number itself. Stated here so nobody later
 *     "fixes" these to look like agc_scope_kind.
 *
 * NoParams (`message NoParams {}`) becomes a TAG VALUE, never an empty
 * struct: AGC_ENCRYPT_PARAMS_NO_PARAMS etc. This preserves the proto's key
 * property that "intentionally no parameters" (a valid oneof selection) is
 * distinguishable from "forgot to set the required oneof" — tag 0 is NONE
 * and is always rejected.
 */

#ifndef AGC_PARAMS_H
#define AGC_PARAMS_H

#include "agc_abi.h"
#include "agc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Vendor escape hatch: CustomOperationParams
 * -------------------------------------------------------------------------- */

/* Tags ARE the proto field numbers: generic_params = 10, typed_params = 11.
 * NONE = 0 is the "oneof unset" sentinel, not a wire value. */
typedef enum agc_custom_params_kind {
    AGC_CUSTOM_PARAMS_NONE    = 0,
    AGC_CUSTOM_PARAMS_GENERIC = 10,  /* google.protobuf.Struct, as canonical JSON */
    AGC_CUSTOM_PARAMS_TYPED   = 11   /* google.protobuf.Any, as type_url + value */
    AGC_ENUM32(agc_custom_params_kind)
} agc_custom_params_kind;

/* google.protobuf.Struct and Any have no natural C representation, so they
 * are carried in their canonical serialised forms: generic_params_json is
 * the canonical JSON encoding of Struct (round-trips losslessly per the
 * protobuf JSON mapping); typed_params_type_url/_value are Any's two wire
 * fields verbatim. raw_params is additive in both directions and always
 * forwarded, per the proto's stated precedence rule. */
typedef struct agc_custom_params {
    size_t                 struct_size;
    agc_str                vendor;
    agc_str                algorithm_name;
    agc_custom_params_kind kind;
    agc_str                generic_params_json;    /* kind == GENERIC */
    agc_str                typed_params_type_url;   /* kind == TYPED   */
    agc_slice              typed_params_value;      /* kind == TYPED   */
    agc_slice              raw_params;              /* additive, always forwarded */
} agc_custom_params;

/* --------------------------------------------------------------------------
 * Encryption scope params (EncryptRequest.scope_params et al.)
 * -------------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------------
 * Signature scope params (SignRequest.scope_params et al.)
 * -------------------------------------------------------------------------- */

typedef enum agc_sign_params_kind {
    AGC_SIGN_PARAMS_NONE           = 0,  /* invalid: the oneof is required */
    AGC_SIGN_PARAMS_NO_CONTEXT     = 1,  /* NoParams — ECDSA, RSA-PSS, DSA */
    AGC_SIGN_PARAMS_DOMAIN_CONTEXT = 2,  /* SignatureDomainContext — EdDSA, ML-DSA, SLH-DSA */
    AGC_SIGN_PARAMS_VENDOR         = 3   /* VendorSignatureContext */
    AGC_ENUM32(agc_sign_params_kind)
} agc_sign_params_kind;

/* buf.validate caps context at 255 bytes; the fixed array removes an
 * allocation from the hot path and makes the bound structural. */
typedef struct agc_signature_domain_context {
    uint8_t context[255];
    uint8_t context_len;   /* 0..255 */
} agc_signature_domain_context;

typedef struct agc_sign_params {
    size_t               struct_size;
    agc_sign_params_kind kind;
    union {
        agc_signature_domain_context domain_context;
        agc_custom_params             vendor;
    } u;
} agc_sign_params;

/* --------------------------------------------------------------------------
 * MAC scope params (GenerateMACRequest.scope_params et al.)
 * -------------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------------
 * Key-wrapping scope params (WrapKeyRequest.scope_params)
 * -------------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------------
 * KDF / key-agreement operation params
 * (DeriveKeyRequest.kdf_params, KeyAgreementRequest.agreement_params)
 *
 * agc_key_agreement_params (commit 10) reuses this union rather than
 * defining a near-identical narrower one, because agreement_params
 * {Ecdh, X942Dh, X3dh, Vendor} is a strict subset of kdf_params. Out-of-
 * subset tags are rejected at runtime with AGC_ERR_CRYPTO_INCOMPATIBLE_
 * PARAMETERS — one source of truth traded for compile-time enforcement.
 * -------------------------------------------------------------------------- */

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

#ifdef __cplusplus
}
#endif
#endif /* AGC_PARAMS_H */
