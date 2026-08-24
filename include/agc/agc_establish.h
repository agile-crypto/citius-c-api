/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_establish.h — KeyEstablishmentService (6 RPCs;
 * api/services/key_establishment_service.proto). Fields verified directly
 * against messages/key_wrapping.proto, key_derivation.proto,
 * key_encapsulation.proto -- notably, KeyAgreementRequest has no
 * peer_public_key_format field (an earlier draft of this reconciliation
 * invented one).
 *
 * Keys acting on keys. Every function here produces a NEW NAMED KEY in the
 * key store; none return key material. That is the invariant that makes the
 * whole surface safe to expose from C: there is no buffer for a caller to
 * leak, forget to zeroize, or accidentally log.
 */

#ifndef AGC_ESTABLISH_H
#define AGC_ESTABLISH_H

#include "agc_core.h"
#include "agc_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * WrapKey / UnwrapKey (key transport)
 * -------------------------------------------------------------------------- */

typedef struct agc_wrap_key_params {
    size_t                 struct_size;
    const char            *key_to_wrap_name;   /* REQUIRED */
    const char            *wrapping_key_name;  /* REQUIRED -- the KEK */
    agc_wrap_format        format;             /* REQUIRED */
    const agc_wrap_params *params;             /* REQUIRED -- the oneof is required */
    agc_kv_list            user_context;
} agc_wrap_key_params;

/* The wrapped blob is the one output in this header that IS bytes -- it is
 * ciphertext and must be transportable. Two-call convention. */
AGC_API agc_rc agc_wrap_key(agc_ctx *ctx, const agc_wrap_key_params *p,
                             agc_buf out_wrapped, size_t *out_len, agc_metadata **out_md);

typedef struct agc_unwrap_key_params {
    size_t                 struct_size;
    agc_slice               wrapped_key;               /* REQUIRED */
    const char             *wrapping_key_name;         /* REQUIRED -- the KEK */
    const char             *unwrapped_key_name;        /* REQUIRED -- name for the result */
    const char             *unwrapped_key_template_id;
    agc_wrap_format         format;                    /* REQUIRED -- must match wrapping */
    const agc_metadata     *metadata;                  /* REQUIRED -- from the wrap call */
    const agc_wrap_params  *params;                    /* REQUIRED -- must match wrapping */
    agc_kv_list             user_context;
} agc_unwrap_key_params;

/* The unwrapped key is recorded with origin = AGC_KEY_ORIGIN_UNWRAPPED
 * (commit 11, once agc_key_info exposes origin). */
AGC_API agc_rc agc_unwrap_key(agc_ctx *ctx, const agc_unwrap_key_params *p,
                               agc_key_info **out_key, agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * DeriveKey (key derivation)
 *
 * No scope_spec or template_id here: the base key's template fixes both the
 * KDF algorithm and the output key type, which avoids a "KDF says 256 bits,
 * template wants 128" conflict. The derived key is ALWAYS created in the
 * base key's provider -- not configurable in C any more than on the wire,
 * because that is what keeps material inside one security domain.
 * -------------------------------------------------------------------------- */

typedef struct agc_derive_key_params {
    size_t                struct_size;
    const char           *base_key_name;     /* REQUIRED; must allow DERIVE_KEY */
    const char           *derived_key_name;  /* REQUIRED; unique */
    const char           *policy;            /* NULL => inherit the base key's policy */
    const agc_kdf_params *params;            /* REQUIRED -- must match the base key's KDF */
    agc_kv_list           user_context;
} agc_derive_key_params;

AGC_API agc_rc agc_derive_key(agc_ctx *ctx, const agc_derive_key_params *p,
                               agc_key_info **out_key, agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * KeyAgreement (two-party Diffie-Hellman family)
 * -------------------------------------------------------------------------- */

typedef struct agc_key_agreement_params {
    size_t                struct_size;
    const char           *private_key_name;          /* REQUIRED -- our side */
    agc_slice             peer_public_key;            /* REQUIRED -- their side, algorithm-native raw encoding */
    const char           *shared_secret_name;         /* REQUIRED -- name for the result */
    const char           *shared_secret_template_id;  /* NULL => policy selects */
    const agc_kdf_params *params;                     /* REQUIRED: ECDH / X942_DH / X3DH / VENDOR only */
    agc_kv_list           user_context;
} agc_key_agreement_params;

/* Shares agc_kdf_params with agc_derive_key because the proto's
 * agreement_params oneof (Ecdh/X942Dh/X3dh/Vendor) is a strict subset of the
 * kdf_params oneof (11 arms). The library rejects a params->kind outside
 * that subset with AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS rather than
 * duplicating a near-identical union type -- one source of truth, checked
 * at runtime instead of compile time. */
AGC_API agc_rc agc_key_agreement(agc_ctx *ctx, const agc_key_agreement_params *p,
                                  agc_key_info **out_key, agc_metadata **out_md);

/* --------------------------------------------------------------------------
 * EncapsulateKey / DecapsulateKey (post-quantum KEMs)
 * -------------------------------------------------------------------------- */

typedef struct agc_encapsulate_params {
    size_t      struct_size;
    const char *recipient_public_key_name;  /* REQUIRED; must allow ENCAPSULATE */
    const char *shared_secret_name;         /* REQUIRED -- name for the result */
    const char *shared_secret_template_id;  /* NULL => policy selects */
    agc_kv_list user_context;
} agc_encapsulate_params;

/* out_ciphertext is the KEM encapsulation, to be sent to the peer alongside
 * the encoded metadata. The KEM algorithm is deliberately NOT carried in
 * either: metadata is unauthenticated, so the decapsulating side resolves
 * the algorithm from its own private key's template. */
AGC_API agc_rc agc_encapsulate_key(agc_ctx *ctx, const agc_encapsulate_params *p,
                                    agc_buf out_ciphertext, size_t *out_len,
                                    agc_key_info **out_key, agc_metadata **out_md);

typedef struct agc_decapsulate_params {
    size_t               struct_size;
    const char          *private_key_name;          /* REQUIRED; must allow DECAPSULATE */
    agc_slice            ciphertext;                 /* REQUIRED */
    const char          *shared_secret_name;         /* REQUIRED */
    const char          *shared_secret_template_id;
    const agc_metadata  *metadata;                   /* relayed from encapsulation */
    agc_kv_list          user_context;
} agc_decapsulate_params;

AGC_API agc_rc agc_decapsulate_key(agc_ctx *ctx, const agc_decapsulate_params *p,
                                    agc_key_info **out_key, agc_metadata **out_md);

#ifdef __cplusplus
}
#endif
#endif /* AGC_ESTABLISH_H */
