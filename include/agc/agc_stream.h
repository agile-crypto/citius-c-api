/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_stream.h — StreamingCryptoService (43 RPCs;
 * api/services/streaming_crypto_service.proto).
 *
 * Three families of stateful operation, all keyed on an opaque agc_session
 * (commit 5) rather than the proto's request-supplied operation_id string:
 *
 *   1. Multi-part      Init -> Update* -> Final              (PKCS#11 classic)
 *   2. Message-based   MessageInit -> ( Message
 *                                     | Begin -> Next* ) * -> MessageFinal
 *   3. Dual-function    two live sessions advanced together
 *
 * THE UNAUTHENTICATED-PLAINTEXT RULE
 * -----------------------------------
 * For every decrypt-shaped stream, plaintext released by Update/Next before
 * the final call is NOT authenticated. This is stated in the proto and is
 * also the natural consequence of how the stub backend computes ciphertext
 * incrementally per chunk (a pure function of key/nonce/offset) while the
 * authentication tag can only be computed once the complete message is
 * known, at Final. Callers MUST buffer and MUST NOT act on early plaintext
 * until the closing call returns AGC_OK. Authentication failure returns
 * AGC_ERR_CRYPTO_AUTHENTICATION_FAILED and releases nothing further.
 *
 * SESSIONS, NOT STRINGS
 * ----------------------
 * See agc_core.h's Sessions section (commit 5) and
 * RECONCILIATION_PLAN.md D10: operation_id is a real, client-suppliable
 * request field on the wire (EncryptInitRequest.operation_id etc.), not
 * server-generated as an earlier draft of this reconciliation assumed. Every
 * every Init/MessageInit function below accepts an optional caller-chosen id
 * through its params struct; agc_session_id() recovers it either way.
 */

#ifndef AGC_STREAM_H
#define AGC_STREAM_H

#include "agc_core.h"
#include "agc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * 1. MULTI-PART ENCRYPTION (EncryptInit/Update/Final, DecryptInit/Update/Final)
 * ========================================================================== */

typedef struct agc_encrypt_init_params {
    size_t                    struct_size;
    const char               *key_name;        /* REQUIRED */
    const char               *operation_id;    /* optional caller-chosen id */
    const agc_encrypt_params *params;          /* REQUIRED */
    agc_kv_list               user_context;
} agc_encrypt_init_params;

AGC_API agc_rc agc_encrypt_init(agc_ctx *ctx, const agc_encrypt_init_params *p,
                                 agc_session **out_session);

/* Emits the ciphertext for this chunk. Two-call convention; for the AEAD
 * family the emitted length equals the input length (the tag is withheld
 * until Final). */
AGC_API agc_rc agc_encrypt_update(agc_session *s, agc_slice plaintext_chunk,
                                   agc_buf out, size_t *out_len);

/* Emits the AEAD tag (for the AEAD family; empty for others) and the
 * metadata. The session is closed on return, success or failure. */
AGC_API agc_rc agc_encrypt_final(agc_session *s, agc_buf out, size_t *out_len,
                                  agc_metadata **out_md);

typedef struct agc_decrypt_init_params {
    size_t                    struct_size;
    const char               *key_name;        /* REQUIRED */
    const char               *operation_id;
    const agc_encrypt_params *params;          /* REQUIRED -- must match encryption */
    const agc_metadata       *metadata;        /* REQUIRED: carries the nonce/IV */
    agc_kv_list               user_context;
} agc_decrypt_init_params;

AGC_API agc_rc agc_decrypt_init(agc_ctx *ctx, const agc_decrypt_init_params *p,
                                 agc_session **out_session);

/* UNAUTHENTICATED OUTPUT -- see the header comment. */
AGC_API agc_rc agc_decrypt_update(agc_session *s, agc_slice ciphertext_chunk,
                                   agc_buf out, size_t *out_len);

/* Verifies the tag. On failure returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED
 * and writes nothing further; the caller must discard everything Update
 * produced. */
AGC_API agc_rc agc_decrypt_final(agc_session *s, agc_buf out, size_t *out_len,
                                  agc_metadata **out_md);

/* ==========================================================================
 * 2. MESSAGE-BASED AEAD
 *    (Encrypt/DecryptMessageInit, Message, MessageBegin, MessageNext, MessageFinal)
 *
 * One session, many independent messages, each with its own nonce.
 * ========================================================================== */

AGC_API agc_rc agc_encrypt_message_init(agc_ctx *ctx, const agc_encrypt_init_params *p,
                                         agc_session **out_session);

typedef struct agc_encrypt_message_request {
    size_t      struct_size;
    const char *key_name;      /* REQUIRED -- matches EncryptMessageRequest, which
                                 * (unusually for this family) carries its own
                                 * key_name rather than relying on the session */
    agc_slice   associated_data;
    agc_slice   plaintext;
    agc_kv_list user_context;
} agc_encrypt_message_request;

/* Single-shot message within the session: does not require Init first
 * (mirrors EncryptMessageRequest carrying key_name directly). Each call
 * produces its own nonce, returned in *out_md. */
AGC_API agc_rc agc_encrypt_message(agc_ctx *ctx, const agc_encrypt_message_request *req,
                                    agc_buf out, size_t *out_len, agc_metadata **out_md);

/* Begins a multi-part message inside a session opened by
 * agc_encrypt_message_init(). *out_partial_md carries the nonce generated
 * for THIS message; the decrypting side needs it before it can begin. */
AGC_API agc_rc agc_encrypt_message_begin(agc_session *s, agc_slice associated_data,
                                          agc_metadata **out_partial_md);

/* Emits ciphertext for this chunk (EncryptMessageNextResponse carries only
 * ciphertext_chunk -- no end-of-message marker exists on the wire here, so
 * neither does one in this signature: see the header comment on
 * agc_encrypt_message_final() below for what that structurally means). */
AGC_API agc_rc agc_encrypt_message_next(agc_session *s, agc_slice plaintext_chunk,
                                         agc_buf out, size_t *out_len);

/* Completes the CURRENT (and, as specified, only) message and tears the
 * session down: emits ciphertext_final (the tag, per "Ciphertext || Tag")
 * plus metadata, exactly matching EncryptMessageFinalResponse. Because
 * EncryptMessageNext carries no per-message terminator, a session begun
 * with agc_encrypt_message_begin() can carry exactly one message before
 * this ends it -- a real limitation of the wire specification as written,
 * not a simplification introduced here (see docs/PROTO_RFCS.md RFC-03,
 * commit 13, for the proposed fix). Multiple independent messages within
 * one session ARE supported via repeated agc_encrypt_message() single-shot
 * calls, which need no Begin/Next/Final at all. */
AGC_API agc_rc agc_encrypt_message_final(agc_session *s, agc_buf out, size_t *out_len,
                                          agc_metadata **out_md);

/* DecryptMessageInitRequest is {key_name, operation_id, scope_params,
 * user_context} -- NOT the same shape as DecryptInitRequest: it carries no
 * metadata field, because there is no session-wide nonce to recover here
 * (each message gets its own, supplied fresh at agc_decrypt_message_begin()
 * or agc_decrypt_message()). Reusing agc_decrypt_init_params for this
 * function would silently add a field the wire message does not have. */
typedef struct agc_decrypt_message_init_params {
    size_t                    struct_size;
    const char               *key_name;      /* REQUIRED */
    const char               *operation_id;
    const agc_encrypt_params *params;        /* REQUIRED -- must match encryption */
    agc_kv_list               user_context;
} agc_decrypt_message_init_params;

AGC_API agc_rc agc_decrypt_message_init(agc_ctx *ctx, const agc_decrypt_message_init_params *p,
                                         agc_session **out_session);

typedef struct agc_decrypt_message_request {
    size_t      struct_size;
    const char *key_name;      /* REQUIRED */
    agc_slice   associated_data;
    agc_slice   ciphertext;
    agc_kv_list user_context;
} agc_decrypt_message_request;

/* metadata is the per-message metadata from the corresponding
 * agc_encrypt_message() call -- not the session's. DecryptMessageRequest
 * carries no metadata field on the wire (same DV-04 gap as
 * agc_decrypt_message_begin() above); passed as a separate parameter here
 * rather than folded into agc_decrypt_message_request so the divergence
 * stays visible at every call site instead of looking like a real field. */
AGC_API agc_rc agc_decrypt_message(agc_ctx *ctx, const agc_decrypt_message_request *req,
                                    const agc_metadata *metadata,
                                    agc_buf out, size_t *out_len, agc_metadata **out_md);

/* partial_md is the per-message metadata from agc_encrypt_message_begin().
 * DecryptMessageBeginRequest carries no metadata field on the wire; this
 * parameter is a declared divergence (DV-04, RECONCILIATION_PLAN.md §4) --
 * the function is structurally unusable without the per-message nonce, and
 * a gRPC front-end recovers it from the same channel EncryptMessageBegin's
 * response used. */
AGC_API agc_rc agc_decrypt_message_begin(agc_session *s, agc_slice associated_data,
                                          const agc_metadata *partial_md);

/* UNAUTHENTICATED OUTPUT until agc_decrypt_message_final() succeeds. */
AGC_API agc_rc agc_decrypt_message_next(agc_session *s, agc_slice ciphertext_chunk,
                                         agc_buf out, size_t *out_len);

/* Verifies the tag and completes the session's one message (see the
 * agc_encrypt_message_final() comment on why "one message per session" is
 * the wire specification's own current limit, not a simplification here).
 * On failure returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED and writes
 * nothing; the caller must discard everything Next produced. */
AGC_API agc_rc agc_decrypt_message_final(agc_session *s, agc_buf out, size_t *out_len,
                                          agc_metadata **out_md);

/* ==========================================================================
 * 3. MULTI-PART SIGNING (SignInit/Update/Final, VerifyInit/Update/Final)
 * ========================================================================== */

typedef struct agc_sign_init_params {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    const char            *operation_id;
    const agc_sign_params *params;        /* REQUIRED */
    agc_kv_list            user_context;
} agc_sign_init_params;

AGC_API agc_rc agc_sign_init(agc_ctx *ctx, const agc_sign_init_params *p, agc_session **out_session);

/* Produces no output -- SignUpdateResponse{bool success} collapses into the
 * return code (D4). */
AGC_API agc_rc agc_sign_update(agc_session *s, agc_slice data_chunk);

AGC_API agc_rc agc_sign_final(agc_session *s, agc_buf out_signature, size_t *out_len,
                               agc_metadata **out_md);

/* Neither VerifyInitRequest nor VerifyFinalRequest carries a metadata field
 * on the wire (unlike single-shot VerifyRequest, which does) -- verified
 * directly against messages/signing.proto. Multi-part verification here
 * always uses the key's latest version; there is currently no wire-level
 * way to verify a multi-part signature made under a since-rotated key
 * version. Not a simplification introduced by this header. */
typedef struct agc_verify_init_params {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    const char            *operation_id;
    const agc_sign_params *params;        /* REQUIRED -- must match signing */
    agc_kv_list            user_context;
} agc_verify_init_params;

AGC_API agc_rc agc_verify_init(agc_ctx *ctx, const agc_verify_init_params *p, agc_session **out_session);

AGC_API agc_rc agc_verify_update(agc_session *s, agc_slice data_chunk);

/* Fail-closed as agc_verify() (D9): *out_valid is cleared first, and an
 * invalid signature returns AGC_ERR_CRYPTO_SIGNATURE_INVALID. */
AGC_API agc_rc agc_verify_final(agc_session *s, agc_slice signature, int *out_valid, agc_metadata **out_md);

/* ==========================================================================
 * 4. MESSAGE-BASED SIGNING
 * ========================================================================== */

AGC_API agc_rc agc_sign_message_init(agc_ctx *ctx, const agc_sign_init_params *p, agc_session **out_session);

typedef struct agc_sign_message_request {
    size_t      struct_size;
    const char *key_name;    /* REQUIRED */
    agc_slice   message;
    agc_kv_list user_context;
} agc_sign_message_request;

AGC_API agc_rc agc_sign_message(agc_ctx *ctx, const agc_sign_message_request *req,
                                 agc_buf out_signature, size_t *out_len, agc_metadata **out_md);

AGC_API agc_rc agc_sign_message_begin(agc_session *s);

/* SignMessageNextResponse is {bool success} -- no output, matching the
 * multi-part family's Update. */
AGC_API agc_rc agc_sign_message_next(agc_session *s, agc_slice message_chunk);

/* Completes the session's one message: returns the signature over
 * everything absorbed since Begin, plus metadata, matching
 * SignMessageFinalResponse{signature, metadata} exactly (unlike the AEAD
 * families, SignMessageNext genuinely has no output to withhold, so this
 * "one message per session" shape is simply how message-based signing
 * always worked here, not a limitation this reconciliation ran into). */
AGC_API agc_rc agc_sign_message_final(agc_session *s, agc_buf out_signature, size_t *out_len,
                                       agc_metadata **out_md);

AGC_API agc_rc agc_verify_message_init(agc_ctx *ctx, const agc_verify_init_params *p, agc_session **out_session);

typedef struct agc_verify_message_request {
    size_t      struct_size;
    const char *key_name;
    agc_slice   message;
    agc_slice   signature;
    agc_kv_list user_context;
} agc_verify_message_request;

/* VerifyMessageRequest carries no metadata field on the wire (unlike the
 * single-shot VerifyRequest, which does) -- verification here always uses
 * the key's latest version. This is a genuine asymmetry in the proto as
 * written, not a simplification introduced by this header: there is
 * currently no wire-level way to verify a message-based signature made
 * under a since-rotated key version. */
AGC_API agc_rc agc_verify_message(agc_ctx *ctx, const agc_verify_message_request *req,
                                   int *out_valid, agc_metadata **out_md);

AGC_API agc_rc agc_verify_message_begin(agc_session *s);
AGC_API agc_rc agc_verify_message_next(agc_session *s, agc_slice message_chunk);

/* signature arrives here, matching VerifyMessageFinalRequest{operation_id,
 * signature} -- verification only makes sense once the whole message and
 * its signature are both known. Fail-closed contract applies to
 * *out_valid (D9). */
AGC_API agc_rc agc_verify_message_final(agc_session *s, agc_slice signature,
                                         int *out_valid, agc_metadata **out_md);

/* Note: there is no "5. Multi-part MAC" family here. MacScope has a
 * MAC_SCOPE_STREAMING = 2 value in the vocabulary, but the proto defines no
 * GenerateMACInit/Update/Final or VerifyMACInit/Update/Final RPCs to use it
 * -- verified directly against streaming_crypto_service.proto's RPC list
 * (43 RPCs total, none of them MAC-shaped). An earlier draft of this
 * reconciliation invented a 6-function MAC streaming family here; seeing a
 * vocabulary value with nothing to back it is exactly the kind of gap
 * worth raising with the specification rather than papering over locally
 * -- see docs/PROTO_RFCS.md RFC-13 (commit 13) and agc_ext.h for an
 * opt-in, clearly-labelled proposed family callers may enable. */

/* ==========================================================================
 * 5. MULTI-PART DIGEST (DigestInit/Update/Key/Final)
 * ========================================================================== */

typedef struct agc_digest_init_params {
    size_t                struct_size;
    const agc_scope_spec *scope_spec;    /* hash scope */
    const char           *operation_id;
    const char           *template_id;   /* explicit; NULL => policy selects */
    const char           *policy_name;
    agc_kv_list           user_context;
} agc_digest_init_params;

/* The template the service selected is available from
 * agc_session_selected_template_id(*out_session). */
AGC_API agc_rc agc_digest_init(agc_ctx *ctx, const agc_digest_init_params *p, agc_session **out_session);
AGC_API agc_rc agc_digest_update(agc_session *s, agc_slice data_chunk);

/* Folds a stored key's value into the digest without the caller ever seeing
 * it (PKCS#11 C_DigestKey) -- takes a name, not bytes. */
AGC_API agc_rc agc_digest_key(agc_session *s, const char *key_name);

AGC_API agc_rc agc_digest_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md);

/* ==========================================================================
 * 6. MULTI-PART XOF (XofInit/Update/Final)
 * ========================================================================== */

typedef struct agc_xof_init_params {
    size_t                struct_size;
    const agc_scope_spec *scope_spec;
    const char           *operation_id;
    const char           *template_id;
    uint32_t              output_length_bytes;  /* REQUIRED */
    const char           *policy_name;
    agc_kv_list           user_context;
} agc_xof_init_params;

AGC_API agc_rc agc_xof_init(agc_ctx *ctx, const agc_xof_init_params *p, agc_session **out_session);
AGC_API agc_rc agc_xof_update(agc_session *s, agc_slice data_chunk);
AGC_API agc_rc agc_xof_final(agc_session *s, agc_buf out, size_t *out_len, agc_metadata **out_md);

/* ==========================================================================
 * 7. DUAL-FUNCTION OPERATIONS
 *
 * Each advances two live sessions in lockstep. Two typed handles (rather
 * than the proto's two operation_id strings) let the library validate both
 * handles and both agc_session_operation() values before touching either,
 * turning "session doesn't exist / wrong kind / belongs elsewhere" into an
 * immediate AGC_ERR_INVALID_HANDLE instead of a confusing downstream error.
 * ========================================================================== */

/* Digest and encrypt one chunk: digest_session absorbs the PLAINTEXT while
 * encrypt_session produces ciphertext from it. */
AGC_API agc_rc agc_digest_encrypt_update(agc_session *digest_session, agc_session *encrypt_session,
                                          agc_slice plaintext_chunk, agc_buf out_ciphertext, size_t *out_len);

/* Decrypt then digest: the digest absorbs the recovered PLAINTEXT.
 * UNAUTHENTICATED OUTPUT until the decrypt session's Final succeeds. */
AGC_API agc_rc agc_decrypt_digest_update(agc_session *decrypt_session, agc_session *digest_session,
                                          agc_slice ciphertext_chunk, agc_buf out_plaintext, size_t *out_len);

/* Sign and encrypt one chunk: sign_session absorbs the plaintext. */
AGC_API agc_rc agc_sign_encrypt_update(agc_session *sign_session, agc_session *encrypt_session,
                                        agc_slice plaintext_chunk, agc_buf out_ciphertext, size_t *out_len);

/* Decrypt then verify: verify_session absorbs the recovered plaintext.
 * UNAUTHENTICATED OUTPUT until the decrypt session's Final succeeds. */
AGC_API agc_rc agc_decrypt_verify_update(agc_session *decrypt_session, agc_session *verify_session,
                                          agc_slice ciphertext_chunk, agc_buf out_plaintext, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* AGC_STREAM_H */
