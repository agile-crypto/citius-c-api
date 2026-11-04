/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_stream_types.h — StreamingCryptoService: types.
 *
 * The request and response structs of agc_stream.h, separated from the
 * function declarations.
 *
 * Every struct here is CALLER-ALLOCATED and begins with struct_size
 * (AGC_INIT): the library writes only into regions the caller placed in the
 * response, allocates nothing the caller sees, and there is nothing to free.
 * The one exception is agc_session, which stays a library-owned opaque
 * handle because it holds live operation state that must be zeroized on a
 * schedule the library controls. Rules: docs/agc_crypto.md.
 *
 * SIZE QUERIES
 * ------------
 * Every output region in a response is an agc_buf plus a length. If ANY
 * output region has data == NULL, or is present but too small, the call
 * returns AGC_ERR_BUFFER_TOO_SMALL with EVERY *_len field of the response
 * set to its requirement, having consumed no input and advanced no session
 * state. One retry therefore always suffices, and a failed size query never
 * corrupts a stream: the same chunk may be submitted again.
 *
 * METADATA
 * --------
 * The same contract as agc_crypto_types.h. A session that will produce
 * metadata takes the encoding at Init, in its request's metadata_encoding;
 * the closing call writes the encoded OperationMetadata, encoding byte
 * first, into the response's `metadata` region and copies key_version out
 * as a scalar. Metadata is never projected here. A request that CONSUMES
 * metadata takes it as an agc_slice of those same bytes; the encoding is
 * read from byte 0.
 *
 * The keyless families (digest, xof) have no key and therefore no metadata:
 * like agc_digest in agc_crypto_types.h they report the api_version, the
 * provider and template that served them, and the policy version that
 * selected those, and they share agc_digest_response with it.
 *
 * SHARED RESPONSES
 * ----------------
 * Several families produce identically shaped output, so they share a type
 * rather than repeating it:
 *   agc_stream_chunk_response     every Update and Next, and all four
 *                                 dual-function calls: one emitted chunk.
 *   agc_stream_final_response     the four AEAD closing calls: remaining
 *                                 bytes (the tag, for AEAD) plus metadata.
 *   agc_stream_metadata_response  EncryptMessageBegin: metadata alone.
 *   agc_sign_response             every call that emits a signature.
 *   agc_verify_response           every call that reports validity.
 *   agc_encrypt_response /
 *   agc_decrypt_response          the single-shot message calls, whose
 *                                 output really is ciphertext / plaintext.
 *   agc_digest_response           DigestFinal and XofFinal.
 */

#ifndef AGC_STREAM_TYPES_H
#define AGC_STREAM_TYPES_H

#include "agc_core.h"
#include "agc_crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * Shared responses
 * ========================================================================== */

/* One emitted chunk. Filled by every Update and Next call and by the four
 * dual-function calls. A caller may reuse one of these across a whole
 * streaming loop. */
typedef struct agc_stream_chunk_response {
    size_t  struct_size;
    agc_buf output;      /* IN: caller region. OUT: the chunk this call emitted */
    size_t  output_len;
} agc_stream_chunk_response;

/* The closing call of an AEAD stream: whatever bytes remain, plus the
 * operation's metadata. For the AEAD family the remaining bytes are the
 * authentication tag; for other families the region may come back empty.
 * `output` is deliberately neutral rather than named ciphertext or
 * plaintext, because the same type serves both directions. */
typedef struct agc_stream_final_response {
    size_t   struct_size;
    agc_buf  output;        /* IN: caller region. OUT: remaining bytes, the tag for AEAD */
    size_t   output_len;
    agc_buf  metadata;      /* IN: caller region. OUT: encoded OperationMetadata, encoding byte first */
    size_t   metadata_len;
    uint32_t key_version;   /* copy of the key_version inside `metadata` */
} agc_stream_final_response;

/* Metadata alone, with no byte output: EncryptMessageBegin, whose only
 * result is the nonce the decrypting side needs before it can start. */
typedef struct agc_stream_metadata_response {
    size_t   struct_size;
    agc_buf  metadata;      /* IN: caller region. OUT: encoded metadata, encoding byte first */
    size_t   metadata_len;
} agc_stream_metadata_response;

/* ==========================================================================
 * 1. MULTI-PART ENCRYPTION (EncryptInit/Update/Final, DecryptInit/Update/Final)
 * ========================================================================== */

typedef struct agc_encrypt_init_request {
    size_t                    struct_size;
    const char               *key_name;           /* REQUIRED */
    const char               *operation_id;       /* optional caller-chosen id */
    const agc_encrypt_params *params;             /* REQUIRED */
    agc_kv_list               user_context;
    agc_encoding              metadata_encoding;  /* REQUIRED; encoding the closing call emits */
} agc_encrypt_init_request;

typedef struct agc_decrypt_init_request {
    size_t                    struct_size;
    const char               *key_name;           /* REQUIRED */
    const char               *operation_id;
    const agc_encrypt_params *params;             /* REQUIRED -- must match encryption */
    agc_slice                 metadata;           /* REQUIRED -- encoded, encoding byte first;
                                                     carries the nonce/IV */
    agc_kv_list               user_context;
    agc_encoding              metadata_encoding;  /* REQUIRED; encoding the closing call emits */
} agc_decrypt_init_request;

/* ==========================================================================
 * 2. MESSAGE-BASED AEAD
 *    (Encrypt/DecryptMessageInit, Message, MessageBegin, MessageNext, MessageFinal)
 *
 * One session, many independent messages, each with its own nonce.
 * ========================================================================== */

typedef struct agc_encrypt_message_request {
    size_t       struct_size;
    const char  *key_name;           /* REQUIRED -- matches EncryptMessageRequest, which
                                      * (unusually for this family) carries its own
                                      * key_name rather than relying on the session */
    agc_slice    associated_data;
    agc_slice    plaintext;
    agc_kv_list  user_context;
    agc_encoding metadata_encoding;  /* REQUIRED */
} agc_encrypt_message_request;

/* DecryptMessageInitRequest is {key_name, operation_id, scope_params,
 * user_context} -- NOT the same shape as DecryptInitRequest: it carries no
 * metadata field, because there is no session-wide nonce to recover here
 * (each message gets its own, supplied fresh at agc_decrypt_message_begin()
 * or agc_decrypt_message()). Reusing agc_decrypt_init_request for this
 * function would silently add a field the wire message does not have. */
typedef struct agc_decrypt_message_init_request {
    size_t                    struct_size;
    const char               *key_name;           /* REQUIRED */
    const char               *operation_id;
    const agc_encrypt_params *params;             /* REQUIRED -- must match encryption */
    agc_kv_list               user_context;
    agc_encoding              metadata_encoding;  /* REQUIRED; encoding the closing call emits */
} agc_decrypt_message_init_request;

typedef struct agc_decrypt_message_request {
    size_t       struct_size;
    const char  *key_name;           /* REQUIRED */
    agc_slice    associated_data;
    agc_slice    ciphertext;

    /* The per-message metadata from the corresponding agc_encrypt_message()
     * call -- not the session's. DecryptMessageRequest carries NO metadata
     * field on the wire: this is declared divergence DV-04
     * (RECONCILIATION_PLAN.md §4), because the function is structurally
     * unusable without the per-message nonce, and a gRPC front-end recovers
     * it from the same channel EncryptMessage's response used. Encoded,
     * encoding byte first. */
    agc_slice    metadata;

    agc_kv_list  user_context;
    agc_encoding metadata_encoding;  /* REQUIRED; encoding of the response's metadata */
} agc_decrypt_message_request;

/* ==========================================================================
 * 3. MULTI-PART SIGNING (SignInit/Update/Final, VerifyInit/Update/Final)
 * ========================================================================== */

typedef struct agc_sign_init_request {
    size_t                 struct_size;
    const char            *key_name;           /* REQUIRED */
    const char            *operation_id;
    const agc_sign_params *params;             /* REQUIRED */
    agc_kv_list            user_context;
    agc_encoding           metadata_encoding;  /* REQUIRED */
} agc_sign_init_request;

/* Neither VerifyInitRequest nor VerifyFinalRequest carries a metadata field
 * on the wire (unlike single-shot VerifyRequest, which does) -- verified
 * directly against messages/signing.proto. Multi-part verification here
 * always uses the key's latest version; there is currently no wire-level
 * way to verify a multi-part signature made under a since-rotated key
 * version. Not a simplification introduced by this header. */
typedef struct agc_verify_init_request {
    size_t                 struct_size;
    const char            *key_name;           /* REQUIRED */
    const char            *operation_id;
    const agc_sign_params *params;             /* REQUIRED -- must match signing */
    agc_kv_list            user_context;
    agc_encoding           metadata_encoding;  /* REQUIRED; encoding the closing call emits */
} agc_verify_init_request;

/* ==========================================================================
 * 4. MESSAGE-BASED SIGNING
 * ========================================================================== */

typedef struct agc_sign_message_request {
    size_t       struct_size;
    const char  *key_name;           /* REQUIRED */
    agc_slice    message;
    agc_kv_list  user_context;
    agc_encoding metadata_encoding;  /* REQUIRED */
} agc_sign_message_request;

/* VerifyMessageRequest carries no metadata field on the wire (unlike the
 * single-shot VerifyRequest, which does) -- verification here always uses
 * the key's latest version. This is a genuine asymmetry in the proto as
 * written, not a simplification introduced by this header: there is
 * currently no wire-level way to verify a message-based signature made
 * under a since-rotated key version. */
typedef struct agc_verify_message_request {
    size_t       struct_size;
    const char  *key_name;
    agc_slice    message;
    agc_slice    signature;
    agc_kv_list  user_context;
    agc_encoding metadata_encoding;  /* REQUIRED; encoding of the response's metadata */
} agc_verify_message_request;

/* ==========================================================================
 * 5. MULTI-PART DIGEST / XOF -- keyless
 *
 * No key, so no key_version and no metadata: DigestFinal and XofFinal fill
 * an agc_digest_response, reporting the provider, template and policy
 * version that served the stream, exactly as agc_digest does in
 * agc_crypto_types.h. The selection inputs live on the Init request, so that
 * a streaming digest is governed by policy the same way the single-shot one
 * is.
 * ========================================================================== */

typedef struct agc_digest_init_request {
    size_t                           struct_size;
    agc_hash_scope_spec              scope_spec;             /* REQUIRED */
    const char                      *operation_id;
    const char                      *template_id;            /* optional; NULL => policy selects */
    const char                      *provider_id;            /* optional; NULL => policy selects */
    agc_kv_list                      provider_configuration; /* may be empty */
    const agc_provider_requirements *provider_requirements;  /* NULL => no filter */
    const char                      *policy_name;            /* REQUIRED */
    agc_kv_list                      user_context;
} agc_digest_init_request;

typedef struct agc_xof_init_request {
    size_t                           struct_size;
    agc_hash_scope_spec              scope_spec;             /* REQUIRED */
    const char                      *operation_id;
    const char                      *template_id;            /* optional; NULL => policy selects */
    const char                      *provider_id;            /* optional; NULL => policy selects */
    agc_kv_list                      provider_configuration; /* may be empty */
    const agc_provider_requirements *provider_requirements;  /* NULL => no filter */
    uint32_t                         output_length_bytes;    /* REQUIRED */
    const char                      *policy_name;            /* REQUIRED */
    agc_kv_list                      user_context;
} agc_xof_init_request;

#ifdef __cplusplus
}
#endif
#endif /* AGC_STREAM_TYPES_H */
