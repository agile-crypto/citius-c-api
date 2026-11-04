/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_establish_types.h — KeyEstablishmentService: types.
 *
 * The request and response structs of agc_establish.h, separated from the
 * function declarations. Fields verified directly against
 * messages/key_wrapping.proto, key_derivation.proto and
 * key_encapsulation.proto -- notably, KeyAgreementRequest has no
 * peer_public_key_format field (an earlier draft of this reconciliation
 * invented one).
 *
 * Every struct here is CALLER-ALLOCATED and begins with struct_size
 * (AGC_INIT): the library writes only into regions the caller placed in the
 * response, allocates nothing the caller sees, and there is nothing to free.
 * Rules: docs/agc_crypto.md.
 *
 * SIZE QUERIES
 * ------------
 * Every output region in a response is an agc_buf plus a length. If ANY
 * output region has data == NULL, or is present but too small, the call
 * returns AGC_ERR_BUFFER_TOO_SMALL with EVERY *_len field of the response
 * set to its requirement, having performed no provider work and created no
 * key. One retry therefore always suffices, and no key is ever created that
 * the caller cannot read back. Because these operations mutate the key
 * store, the requirement reported for an embedded agc_key_info.storage is an
 * upper bound computed before the operation runs, exactly as in
 * agc_key_types.h's STORAGE CONTRACT; the real call may consume less.
 *
 * METADATA
 * --------
 * Every operation returns its OperationMetadata ENCODED in
 * req->metadata_encoding, encoding byte first, into resp->metadata, plus
 * resp->key_version as a scalar copy of the value inside -- the same
 * contract as agc_crypto_types.h. Metadata is never projected here. A
 * request that CONSUMES metadata takes it as an agc_slice of those same
 * bytes; the encoding is read from byte 0.
 *
 * VARIABLE-LENGTH OUTPUTS
 * -----------------------
 * The key record each response carries is an agc_key_info, which is
 * descriptive and has no storage of its own: its strings, public key and
 * provider-metadata map live in the RESPONSE's `storage` region, under the
 * STORAGE CONTRACT of agc_key_types.h.
 */

#ifndef AGC_ESTABLISH_TYPES_H
#define AGC_ESTABLISH_TYPES_H

#include "agc_core.h"
#include "agc_params.h"
#include "agc_metadata.h"
#include "agc_key_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Shared response: a new named key plus the operation's metadata
 *
 * Used by UnwrapKey, DeriveKey, KeyAgreement and DecapsulateKey, whose
 * outputs are identical in shape once the proto's success/message fields
 * collapse into agc_rc (D4). WrapKey and EncapsulateKey have their own
 * response types because they also emit bytes.
 * -------------------------------------------------------------------------- */

typedef struct agc_establish_key_response {
    size_t       struct_size;
     /* docs/divergence_c_vs_proto.md for the pending rename. */
    agc_key_info key_info; /* pointers' values live in `storage` below */

    agc_buf      metadata;      /* IN: caller region. OUT: encoded OperationMetadata, encoding byte first */
    size_t       metadata_len;
    uint32_t     key_version;   /* copy of the key_version inside `metadata` */

    agc_buf      storage;       /* IN: caller region for key_info's strings, key bytes and map */
    size_t       storage_used;  /* OUT: bytes consumed, or required */
} agc_establish_key_response;

/* --------------------------------------------------------------------------
 * WrapKey / UnwrapKey (key transport)
 * -------------------------------------------------------------------------- */

typedef struct agc_wrap_key_request {
    size_t                 struct_size;
    const char            *key_to_wrap_name;   /* REQUIRED */
    const char            *wrapping_key_name;  /* REQUIRED -- the KEK */
    agc_wrap_format        format;             /* REQUIRED */
    const agc_wrap_params *params;             /* REQUIRED -- the oneof is required */
    agc_kv_list            user_context;       /* borrowed for the call; echoed into the metadata */
    agc_encoding           metadata_encoding;  /* REQUIRED; UNSPECIFIED is rejected */
} agc_wrap_key_request;

/* WrapKey creates no key, so this response carries no agc_key_info: it
 * carries the wrapped blob, which is ciphertext and must be transportable. */
typedef struct agc_wrap_key_response {
    size_t   struct_size;
    agc_buf  wrapped_key;       /* IN: caller region. OUT: the wrapped blob */
    size_t   wrapped_key_len;
    agc_buf  metadata;          /* IN: caller region. OUT: encoded metadata, encoding byte first */
    size_t   metadata_len;
    uint32_t key_version;       /* the KEK version used; copy of the value inside `metadata` */
} agc_wrap_key_response;

typedef struct agc_unwrap_key_request {
    size_t                 struct_size;
    agc_slice              wrapped_key;               /* REQUIRED -- borrowed for the call */
    const char            *wrapping_key_name;         /* REQUIRED -- the KEK */
    const char            *unwrapped_key_name;        /* REQUIRED -- name for the result */
    const char            *unwrapped_key_template_id; /* NULL => policy selects */
    agc_wrap_format        format;                    /* REQUIRED -- must match wrapping */
    agc_slice              metadata;                  /* REQUIRED -- encoded, encoding byte first,
                                                         from the wrap call */
    const agc_wrap_params *params;                    /* REQUIRED -- must match wrapping */
    agc_kv_list            user_context;
    agc_encoding           metadata_encoding;         /* REQUIRED -- encoding of resp->metadata */
} agc_unwrap_key_request;

/* --------------------------------------------------------------------------
 * DeriveKey (key derivation)
 *
 * No scope_spec or template_id here: the base key's template fixes both the
 * KDF algorithm and the output key type, which avoids a "KDF says 256 bits,
 * template wants 128" conflict. The derived key is ALWAYS created in the
 * base key's provider -- not configurable in C any more than on the wire,
 * because that is what keeps material inside one security domain.
 * -------------------------------------------------------------------------- */

typedef struct agc_derive_key_request {
    size_t                struct_size;
    const char           *base_key_name;      /* REQUIRED; must allow DERIVE_KEY */
    const char           *derived_key_name;   /* REQUIRED; unique */
    const char           *policy_name;        /* NULL or "" => inherit the base key's policy */
    const agc_kdf_params *params;             /* REQUIRED -- must match the base key's KDF */
    agc_kv_list           user_context;
    agc_encoding          metadata_encoding;  /* REQUIRED */
} agc_derive_key_request;

/* --------------------------------------------------------------------------
 * KeyAgreement (two-party Diffie-Hellman family)
 * -------------------------------------------------------------------------- */

typedef struct agc_key_agreement_request {
    size_t                struct_size;
    const char           *private_key_name;          /* REQUIRED -- our side */
    agc_slice             peer_public_key;           /* REQUIRED -- their side, algorithm-native raw
                                                        encoding; borrowed for the call */
    const char           *shared_secret_name;        /* REQUIRED -- name for the result */
    const char           *shared_secret_template_id; /* NULL => policy selects */
    const agc_agreement_params *params;              /* REQUIRED -- the oneof is required */
    agc_kv_list           user_context;
    agc_encoding          metadata_encoding;         /* REQUIRED */
} agc_key_agreement_request;

/* --------------------------------------------------------------------------
 * EncapsulateKey / DecapsulateKey (post-quantum KEMs)
 * -------------------------------------------------------------------------- */

typedef struct agc_encapsulate_key_request {
    size_t       struct_size;
    const char  *recipient_public_key_name;  /* REQUIRED; must allow ENCAPSULATE */
    const char  *shared_secret_name;         /* REQUIRED -- name for the result */
    const char  *shared_secret_template_id;  /* NULL => policy selects */
    agc_kv_list  user_context;
    agc_encoding metadata_encoding;          /* REQUIRED */
} agc_encapsulate_key_request;

/* EncapsulateKey both creates a key and emits bytes, so it has its own
 * response type: the shared-secret record plus the KEM encapsulation.
 *
 * `ciphertext` is sent to the peer alongside the encoded metadata. The KEM
 * algorithm is deliberately NOT carried in either: metadata is
 * unauthenticated, so the decapsulating side resolves the algorithm from its
 * own private key's template. */
typedef struct agc_encapsulate_key_response {
    size_t       struct_size;
    agc_buf      ciphertext;    /* IN: caller region. OUT: the KEM encapsulation */
    size_t       ciphertext_len;

    /* The shared-secret key this operation created */
    agc_key_info key_info;

    agc_buf      metadata;      /* IN: caller region. OUT: encoded metadata, encoding byte first */
    size_t       metadata_len;
    uint32_t     key_version;   /* copy of the key_version inside `metadata` */

    agc_buf      storage;       /* IN: caller region for key_info's strings, key bytes and map */
    size_t       storage_used;  /* OUT: bytes consumed, or required */
} agc_encapsulate_key_response;

typedef struct agc_decapsulate_key_request {
    size_t       struct_size;
    const char  *private_key_name;          /* REQUIRED; must allow DECAPSULATE */
    agc_slice    ciphertext;                /* REQUIRED -- the peer's encapsulation, borrowed */
    const char  *shared_secret_name;        /* REQUIRED -- name for the result */
    const char  *shared_secret_template_id; /* NULL => policy selects */
    agc_slice    metadata;                  /* encoded, encoding byte first; relayed from
                                               encapsulation. {NULL,0} if the peer sent none */
    agc_kv_list  user_context;
    agc_encoding metadata_encoding;         /* REQUIRED -- encoding of resp->metadata */
} agc_decapsulate_key_request;

#ifdef __cplusplus
}
#endif
#endif /* AGC_ESTABLISH_TYPES_H */
