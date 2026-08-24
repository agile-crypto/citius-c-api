/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_establish.h — KeyEstablishmentService (6 RPCs).
 *
 * Keys acting on keys. Every function here produces a NEW NAMED KEY in the key
 * store; none of them return key material. That is the invariant that makes the
 * whole surface safe to expose from C: there is no buffer for a caller to leak,
 * forget to zeroize, or accidentally log.
 *
 * The four NIST key-establishment categories:
 *   Key transport    (SP 800-56B)  agc_wrap_key / agc_unwrap_key
 *   Key agreement    (SP 800-56A)  agc_key_agreement
 *   Key encapsulation(SP 800-56C)  agc_encapsulate_key / agc_decapsulate_key
 *   Key derivation   (SP 800-108)  agc_derive_key
 */

#ifndef AGC_ESTABLISH_H
#define AGC_ESTABLISH_H

#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * WrapKey / UnwrapKey  (key transport)
 * -------------------------------------------------------------------------- */

typedef struct agc_wrap_key_params {
    size_t                 struct_size;
    const char            *key_to_wrap_name;   /* REQUIRED */
    const char            *wrapping_key_name;  /* REQUIRED — the KEK */
    /* Encoding of the inner key material BEFORE wrapping. Distinct from
     * agc_key_format, which describes import/export transport encoding.
     * AGC_WRAP_FORMAT_UNSPECIFIED lets the server pick the natural format
     * (RAW for symmetric, PKCS8 for private keys); the format actually used is
     * reported in *out_actual_format. */
    agc_wrap_format        format;
    const agc_wrap_params *params;             /* REQUIRED — the oneof is required */
    agc_kv_list            user_context;
} agc_wrap_key_params;

/* The wrapped blob is the one output in this header that IS bytes, because it
 * is ciphertext and must be transportable. Two-call convention. */
AGC_API agc_rc agc_wrap_key(agc_ctx *ctx, const agc_wrap_key_params *p,
                            agc_buf out_wrapped, size_t *out_len,
                            agc_wrap_format *out_actual_format,
                            agc_metadata **out_md);

typedef struct agc_unwrap_key_params {
    size_t                 struct_size;
    agc_slice              wrapped_key;               /* REQUIRED */
    const char            *wrapping_key_name;         /* REQUIRED — the KEK */
    const char            *unwrapped_key_name;        /* REQUIRED — name for the result */
    const char            *unwrapped_key_template_id; /* template for the result */
    agc_wrap_format        format;                    /* must match wrapping */
    const agc_metadata    *metadata;                  /* from the wrap call */
    const agc_wrap_params *params;                    /* REQUIRED — must match wrapping */
    agc_kv_list            user_context;
} agc_unwrap_key_params;

/* The unwrapped key is recorded with origin = AGC_KEY_ORIGIN_UNWRAPPED. */
AGC_API agc_rc agc_unwrap_key(agc_ctx *ctx, const agc_unwrap_key_params *p,
                              agc_key_info **out_key,
                              agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * DeriveKey  (key derivation)
 *
 * The base key's template fixes BOTH the KDF algorithm and the output key type,
 * so no scope_spec or template_id appears here — a deliberate omission carried
 * over from the proto, which avoids the "KDF says 256 bits, template says 128"
 * conflict entirely.
 *
 * The derived key is ALWAYS created in the base key's provider. This is not
 * configurable, in C or on the wire: it is what keeps material inside one
 * security domain. Cross-provider movement goes through wrap/unwrap.
 * -------------------------------------------------------------------------- */

typedef struct agc_derive_key_params {
    size_t                struct_size;
    const char           *base_key_name;     /* REQUIRED; must allow DERIVE_KEY */
    const char           *derived_key_name;  /* REQUIRED; unique */
    /* NULL => inherit the base key's policy (the common case). If set, it must
     * appear in the base policy's allowed_derived_policies. */
    const char           *policy;
    const agc_kdf_params *params;            /* REQUIRED — must match the base key's KDF */
    agc_kv_list           user_context;
} agc_derive_key_params;

AGC_API agc_rc agc_derive_key(agc_ctx *ctx, const agc_derive_key_params *p,
                              agc_key_info **out_key,
                              agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * KeyAgreement  (two-party Diffie-Hellman family)
 * -------------------------------------------------------------------------- */

typedef struct agc_key_agreement_params {
    size_t                struct_size;
    const char           *private_key_name;   /* REQUIRED — our side */
    agc_slice             peer_public_key;    /* REQUIRED — their side */
    /* AGC_KEY_FORMAT_UNSPECIFIED means algorithm-native raw encoding:
     * uncompressed/compressed point for ECDH, raw little-endian scalar for
     * X25519/X448, DER SubjectPublicKeyInfo for X9.42 DH. Set explicitly to
     * SPKI or PEM when the peer key arrives in those forms. */
    agc_key_format        peer_public_key_format;
    const char           *shared_secret_name;        /* REQUIRED — name for the result */
    const char           *shared_secret_template_id; /* NULL => policy selects */
    const agc_kdf_params *params;             /* REQUIRED: ECDH / X942_DH / X3DH / VENDOR */
    agc_kv_list           user_context;
} agc_key_agreement_params;

/* Shares agc_kdf_params with agc_derive_key because the proto's
 * agreement_params oneof is a strict subset of the kdf_params oneof. The
 * library rejects a params.kind outside {ECDH, X942_DH, X3DH, VENDOR} with
 * AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS, so the narrowing is enforced at
 * runtime rather than duplicated as a near-identical union type. */
AGC_API agc_rc agc_key_agreement(agc_ctx *ctx, const agc_key_agreement_params *p,
                                 agc_key_info **out_key,
                                 agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * EncapsulateKey / DecapsulateKey  (post-quantum KEMs)
 * -------------------------------------------------------------------------- */

typedef struct agc_encapsulate_params {
    size_t      struct_size;
    const char *recipient_public_key_name;   /* REQUIRED; must allow ENCAPSULATE */
    const char *shared_secret_name;          /* REQUIRED — name for the result */
    const char *shared_secret_template_id;   /* NULL => policy selects */
    agc_kv_list user_context;
} agc_encapsulate_params;

/* out_ciphertext is the KEM encapsulation, to be sent to the peer along with
 * the encoded metadata. The KEM algorithm is deliberately NOT carried in either;
 * the decapsulating side resolves it from its own private key's template, since
 * metadata is unauthenticated. */
AGC_API agc_rc agc_encapsulate_key(agc_ctx *ctx, const agc_encapsulate_params *p,
                                   agc_buf out_ciphertext, size_t *out_len,
                                   agc_key_info **out_key,
                                   agc_metadata **out_md);

typedef struct agc_decapsulate_params {
    size_t              struct_size;
    const char         *private_key_name;          /* REQUIRED; must allow DECAPSULATE */
    agc_slice           ciphertext;                /* REQUIRED */
    const char         *shared_secret_name;        /* REQUIRED */
    const char         *shared_secret_template_id; /* should match the encapsulating side */
    const agc_metadata *metadata;                  /* relayed from encapsulation */
    agc_kv_list         user_context;
} agc_decapsulate_params;

AGC_API agc_rc agc_decapsulate_key(agc_ctx *ctx, const agc_decapsulate_params *p,
                                   agc_key_info **out_key,
                                   agc_metadata **out_md);

/* Upper bound on KEM ciphertext length for the named public key, so callers can
 * size a buffer without a probe call. */
AGC_API agc_rc agc_encapsulate_max_len(agc_ctx *ctx, const char *public_key_name,
                                       size_t *out_max);

#ifdef __cplusplus
}
#endif
#endif /* AGC_ESTABLISH_H */
