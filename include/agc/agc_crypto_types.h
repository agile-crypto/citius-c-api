/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_crypto_types.h — CryptoService: types.
 *
 * The request and response structs of agc_crypto.h, separated from the
 * function declarations. Every struct here is CALLER-ALLOCATED and begins
 * with struct_size (AGC_INIT): the library writes only into regions the
 * caller placed in the response, allocates nothing the caller sees, and
 * there is nothing to free. Rules: docs/agc_crypto.md.
 *
 * SIZE QUERIES
 * ------------
 * Every output region in a response is an agc_buf plus a length. If ANY
 * output region has data == NULL, or is present but too small, the call
 * returns AGC_ERR_BUFFER_TOO_SMALL with EVERY *_len field of the response
 * set to its requirement, having performed no provider work and drawn no
 * randomness. One retry therefore always suffices. A response
 * materialisation can never fail after the provider has done its work.
 * The same rule governs the `storage` region of the keyless responses,
 * whose requirement is reported in `storage_used`.
 *
 * METADATA
 * --------
 * Every keyed operation that produces an artifact returns its
 * OperationMetadata ENCODED in req->metadata_encoding, encoding byte first,
 * into resp->metadata, plus resp->key_version as a scalar copy of the value
 * inside. The metadata is handed back as agc_slice to the consuming
 * operation. It can be decoded with agc_metadata_decode() when fields are
 * needed. Keyless operations (digest, xof, random) have no key and no
 * metadata: they report the provider, template and policy version that
 * served them instead.
 */

#ifndef AGC_CRYPTO_TYPES_H
#define AGC_CRYPTO_TYPES_H

#include "agc_core.h"
#include "agc_scope.h"
#include "agc_params.h"
#include "agc_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NUL-terminated provider identifier capacity in responses that name the
 * provider that served a request. */
#define AGC_PROVIDER_ID_MAX   64
/* NUL-terminated human-readable message capacity (agc_seed_random_response). */
#define AGC_SEED_MESSAGE_MAX 128
#define AGC_TEMPLATE_ID_MAX   64

/* --------------------------------------------------------------------------
 * Encrypt / Decrypt
 * -------------------------------------------------------------------------- */

typedef struct agc_encrypt_request {
    size_t                    struct_size;
    const char               *key_name;           /* REQUIRED */
    agc_slice                 plaintext;          /* borrowed for the call */
    const agc_encrypt_params *params;             /* REQUIRED -- the oneof is required */
    agc_kv_list               user_context;       /* borrowed for the call; echoed into the metadata */
    agc_encoding              metadata_encoding;  /* REQUIRED; UNSPECIFIED is rejected */
} agc_encrypt_request;

typedef struct agc_encrypt_response {
    size_t   struct_size;
    agc_buf  ciphertext;      /* IN: caller region. OUT: written; length below */
    size_t   ciphertext_len;
    agc_buf  metadata;        /* IN: caller region. OUT: encoded OperationMetadata, encoding byte first */
    size_t   metadata_len;
    uint32_t key_version;     /* copy of the key_version inside `metadata` */
} agc_encrypt_response;

typedef struct agc_decrypt_request {
    size_t                    struct_size;
    const char               *key_name;      /* REQUIRED */
    agc_slice                 ciphertext;    /* borrowed for the call */
    agc_slice                 metadata;      /* REQUIRED -- encoded, encoding byte first, from the encrypt call */
    const agc_encrypt_params *params;        /* REQUIRED -- must match encryption */
    agc_kv_list               user_context;  /* borrowed for the call */
} agc_decrypt_request;

typedef struct agc_decrypt_response {
    size_t   struct_size;
    agc_buf  plaintext;       /* IN: caller region. OUT: written on success only */
    size_t   plaintext_len;
    agc_buf  metadata;        /* IN: caller region. OUT: encoded metadata of this decrypt, in the
                                 encoding of req->metadata; may be {NULL,0} if the caller does not want it */
    size_t   metadata_len;
    uint32_t key_version;
} agc_decrypt_response;

/* --------------------------------------------------------------------------
 * Sign / Verify
 * -------------------------------------------------------------------------- */

typedef struct agc_sign_request {
    size_t                 struct_size;
    const char            *key_name;           /* REQUIRED */
    agc_slice              input;              /* message; the service hashes/signs it */
    const agc_sign_params *params;             /* REQUIRED -- the oneof is required */
    agc_kv_list            user_context;
    agc_encoding           metadata_encoding;  /* REQUIRED */
} agc_sign_request;

/* Shared by sign and digest_sign. */
typedef struct agc_sign_response {
    size_t   struct_size;
    agc_buf  signature;       /* IN: caller region. OUT: written */
    size_t   signature_len;
    agc_buf  metadata;        /* IN: caller region. OUT: encoded metadata, encoding byte first */
    size_t   metadata_len;
    uint32_t key_version;
} agc_sign_response;

typedef struct agc_verify_request {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    agc_slice              input;
    agc_slice              signature;
    agc_slice              metadata;      /* encoded, encoding byte first; carries key_version, REQUIRED after rotation.
                                             {NULL,0} => the key's latest version */
    const agc_sign_params *params;        /* REQUIRED -- must match signing */
    agc_kv_list            user_context;
} agc_verify_request;

/* Shared by every verify-shaped operation (verify, digest_verify, verify_mac).
 * THE VERIFICATION CONTRACT (D9): `valid` is set to 0 BEFORE any work, and a
 * cryptographically invalid signature/MAC returns
 * AGC_ERR_CRYPTO_SIGNATURE_INVALID / AGC_ERR_CRYPTO_AUTHENTICATION_FAILED
 * AND leaves `valid` 0. Either `rc != AGC_OK` or `!resp->valid` alone is
 * sufficient (DV-01). */
typedef struct agc_verify_response {
    size_t   struct_size;
    int      valid;           /* OUT: 0 until proven otherwise (D9) */
    agc_buf  metadata;        /* IN: caller region, or {NULL,0} to opt out. OUT: encoded metadata of
                                 this verification, in the encoding of req->metadata (or WIRE_V1 if
                                 the request carried none) */
    size_t   metadata_len;
    uint32_t key_version;     /* the version actually used */
} agc_verify_response;

/* --------------------------------------------------------------------------
 * DigestSign / DigestVerify -- caller supplies a pre-computed digest
 * -------------------------------------------------------------------------- */

typedef struct agc_digest_sign_request {
    size_t                 struct_size;
    const char            *key_name;            /* REQUIRED */
    agc_slice              digest;              /* pre-computed */
    const agc_sign_params *params;              /* REQUIRED */

    /* REQUIRED. Declares which hash produced `digest`. It must be one of
     * the key version's accepted_digest_hashes (agc_read_key) and the digest
     * must have its length (agc_hash_algorithm_output_len), which is what
     * stops a SHA-1 digest being presented as SHA-256. UNSPECIFIED and OTHER
     * are rejected. The library records it in the metadata's digest_hash. */
    agc_hash_algorithm     hash_algorithm;

    agc_kv_list            user_context;
    /* REQUIRED. AGC_ENCODING_PROTOBUF: WIRE_V1 cannot carry the digest_hash
     * this operation records (DV-16). */
    agc_encoding           metadata_encoding;
} agc_digest_sign_request;

typedef struct agc_digest_verify_request {
    size_t                 struct_size;
    const char            *key_name;
    agc_slice              digest;
    agc_slice              signature;
    /* REQUIRED: the metadata agc_digest_sign returned, encoded, encoding
     * byte first. It names the key version and, in digest_hash, the hash
     * that produced the digest. */
    agc_slice              metadata;
    const agc_sign_params *params;
    agc_kv_list            user_context;
} agc_digest_verify_request;

/* --------------------------------------------------------------------------
 * GenerateMAC / VerifyMAC
 * -------------------------------------------------------------------------- */

typedef struct agc_mac_request {
    size_t                struct_size;
    const char           *key_name;           /* REQUIRED */
    agc_slice             message;
    const agc_mac_params *params;             /* REQUIRED -- the oneof is required */
    agc_kv_list           user_context;
    agc_encoding          metadata_encoding;  /* REQUIRED */
} agc_mac_request;

typedef struct agc_mac_response {
    size_t   struct_size;
    agc_buf  mac;             /* IN: caller region. OUT: written */
    size_t   mac_len;
    agc_buf  metadata;        /* IN: caller region. OUT: encoded metadata, encoding byte first */
    size_t   metadata_len;
    uint32_t key_version;
} agc_mac_response;

typedef struct agc_verify_mac_request {
    size_t                struct_size;
    const char           *key_name;
    agc_slice             message;
    agc_slice             mac;
    agc_slice             metadata;      /* encoded, encoding byte first; {NULL,0} => latest version */
    const agc_mac_params *params;        /* REQUIRED -- must match generation */
    agc_kv_list           user_context;
} agc_verify_mac_request;

/* --------------------------------------------------------------------------
 * Digest / Xof -- keyless, provider and template selected by policy
 * -------------------------------------------------------------------------- */

typedef struct agc_digest_request {
    size_t                          struct_size;
    agc_hash_scope_spec             scope_spec;             /* REQUIRED */
    const char                      *template_id;           /* optional; NULL => policy selects */
    const char                      *provider_id;           /* optional; NULL => policy selects */
    agc_kv_list                     provider_configuration; /* may be empty */
    const agc_provider_requirements *provider_requirements; /* NULL => no filter */
    agc_slice                       data;
    const char                      *policy_name;           /* policy governing the operation; NULL => the context's default_policy */
    agc_kv_list                     user_context;
} agc_digest_request;

/* Shared by digest and xof.
   Size query for storage: if storage is NULL or too small, returns AGC_ERR_BUFFER_TOO_SMALL and sets storage_used to the required size.
*/
typedef struct agc_digest_response {
    size_t      struct_size;
    agc_buf     output;                               /* IN: caller region. OUT: digest or XOF output */
    size_t      output_len;
    char        api_version[AGC_API_VERSION_MAX_LEN];  /* OUT: NUL-terminated version of the library that produced it */
    char        *provider_id;                         /* OUT: NUL-terminated id of the provider that served it;
                                                         matters for FIPS evidence;
                                                         If provided by the request, points to the request's provider_id;
                                                         otherwise, lives in the response's storage */
    char        *template_id;                         /* OUT: NUL-terminated id of the template that served it;
                                                         matters for FIPS evidence and reproducibility;
                                                         If provided by the request, points to the request's template_id;
                                                         otherwise, lives in the response's storage */
    uint32_t    policy_version;                       /* OUT: version of the policy that selected the provider/template */
    agc_buf     storage;                              /* IN: caller region */
    size_t      storage_used;
} agc_digest_response;

typedef struct agc_xof_request {
    size_t                          struct_size;
    agc_hash_scope_spec             scope_spec;             /* REQUIRED */
    const char                      *template_id;           /* optional; NULL => policy selects */
    const char                      *provider_id;           /* optional; NULL => policy selects */
    agc_kv_list                     provider_configuration; /* may be empty */
    const agc_provider_requirements *provider_requirements; /* NULL => no filter */
    agc_slice                       data;
    uint32_t                        output_length_bytes;    /* REQUIRED; resp->output must hold this many */
    const char                      *policy_name;           /* policy governing the operation; NULL => the context's default_policy */
    agc_kv_list                     user_context;
} agc_xof_request;

/* --------------------------------------------------------------------------
 * Random
 * -------------------------------------------------------------------------- */

typedef struct agc_random_request {
    size_t                          struct_size;
    uint32_t                        num_bytes;              /* REQUIRED */
    const char                      *provider_id;           /* optional; NULL => policy selects */
    agc_kv_list                     provider_configuration; /* may be empty */
    const agc_provider_requirements *provider_requirements; /* NULL => no filter */
    const char                      *policy_name;           /* optional: governs which RNGs are permitted */
    agc_kv_list                     user_context;
} agc_random_request;

/* Size query for storage: if storage is NULL or too small, returns AGC_ERR_BUFFER_TOO_SMALL and sets storage_used to the required size. */
typedef struct agc_random_response {
    size_t   struct_size;
    agc_buf  output;                               /* IN: caller region, cap >= num_bytes. OUT: exactly num_bytes */
    size_t   output_len;                           /* == req->num_bytes on success */
    char     api_version[AGC_API_VERSION_MAX_LEN]; /* OUT: NUL-terminated version of the library that produced it */
    char     *provider_id;                         /* OUT: NUL-terminated id of the provider that served it;
                                                      matters for FIPS evidence;
                                                      If provided by the request, points to the request's provider_id;
                                                      otherwise, lives in the response's storage */
    uint32_t policy_version;                       /* OUT: version of the policy that selected the provider/template */
    agc_buf  storage;                              /* IN: caller region */
    size_t   storage_used;
} agc_random_response;

typedef struct agc_seed_random_request {
    size_t       struct_size;
    agc_slice    seed;           /* borrowed for the call; mixed into a DRBG, never its sole source */
    const char  *provider_id;
    const char  *policy_name;
    agc_kv_list  user_context;
} agc_seed_random_request;

typedef struct agc_seed_random_response {
    size_t struct_size;
    int    success;                          /* OUT: 0 = declined, non-zero = mixed in */
    char   message[AGC_SEED_MESSAGE_MAX];     /* OUT: NUL-terminated explanation if not accepted, may be "" */
} agc_seed_random_response;

#ifdef __cplusplus
}
#endif
#endif /* AGC_CRYPTO_TYPES_H */
