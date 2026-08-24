/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_stream.h — StreamingCryptoService (50 RPCs).
 *
 * Three families of stateful operation, all keyed on an opaque agc_session
 * rather than the proto's server-generated operation_id string:
 *
 *   1. Multi-part            Init -> Update* -> Final          (PKCS#11 classic)
 *   2. Message-based         MessageInit -> ( Message
 *                                           | Begin -> Next* ) * -> MessageFinal
 *   3. Dual-function         two live sessions advanced together
 *
 * WHY SESSIONS INSTEAD OF STRINGS
 * -------------------------------
 * The proto must name sessions with a string because gRPC is stateless between
 * calls. A local library has no such constraint. A handle is:
 *   - cheaper: no string hashing on every Update in a hot loop
 *   - safer:   a freed handle is a use-after-free the sanitizer catches, where
 *              a stale string is a silent lookup miss at best
 *   - RAII-able: agc_session_free cancels an open session, so an early return
 *                cannot leak provider state or leave key material resident
 * agc_session_id() recovers the string when one is genuinely needed (audit
 * correlation, relaying to a remote front-end), and agc_session_attach() goes
 * the other way, so the two representations stay interconvertible.
 *
 * THE UNAUTHENTICATED-PLAINTEXT RULE
 * ----------------------------------
 * For every decrypt-shaped stream, plaintext released by Update / Next before
 * the final call is NOT authenticated. The proto says so in a comment; here it
 * is also enforced structurally where possible and stated on every relevant
 * function. Callers MUST buffer and MUST NOT act on early plaintext until the
 * closing call returns AGC_OK. Authentication failure returns
 * AGC_ERR_CRYPTO_AUTHENTICATION_FAILED — never plaintext plus a flag.
 *
 * SESSION EXPIRY
 * --------------
 * Sessions hold provider state and are subject to a mandatory idle TTL
 * (agc_ctx_config.session_idle_ttl_seconds). Operating on an expired session
 * returns AGC_ERR_CRYPTO_OPERATION_EXPIRED and the handle is dead; free it.
 */

#ifndef AGC_STREAM_H
#define AGC_STREAM_H

#include "agc_core.h"
#include "agc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * 1. MULTI-PART ENCRYPTION  (EncryptInit/Update/Final, DecryptInit/Update/Final)
 * ========================================================================== */

typedef struct agc_encrypt_init_params {
    size_t                    struct_size;
    const char               *key_name;      /* REQUIRED */
    const agc_encrypt_params *params;        /* REQUIRED */
    agc_kv_list               user_context;
} agc_encrypt_init_params;

AGC_API agc_rc agc_encrypt_init(agc_ctx *ctx, const agc_encrypt_init_params *p,
                                agc_session **out_session);

/* Emits the ciphertext for this chunk. Two-call convention; note that for
 * block modes the emitted length is not equal to the input length. */
AGC_API agc_rc agc_encrypt_update(agc_session *s, agc_slice plaintext_chunk,
                                  agc_buf out, size_t *out_len);

/* Emits any residual ciphertext plus, for AEAD, the authentication tag.
 * The session is closed on return, success or failure; free the handle. */
AGC_API agc_rc agc_encrypt_final(agc_session *s, agc_buf out, size_t *out_len,
                                 agc_metadata **out_md);

typedef struct agc_decrypt_init_params {
    size_t                    struct_size;
    const char               *key_name;      /* REQUIRED */
    const agc_encrypt_params *params;        /* REQUIRED — must match encryption */
    /* REQUIRED. Without the metadata from the encrypting side the provider
     * cannot recover the IV/nonce and initialisation is impossible. */
    const agc_metadata       *metadata;
    agc_kv_list               user_context;
} agc_decrypt_init_params;

AGC_API agc_rc agc_decrypt_init(agc_ctx *ctx, const agc_decrypt_init_params *p,
                                agc_session **out_session);

/* UNAUTHENTICATED OUTPUT. See the header comment. */
AGC_API agc_rc agc_decrypt_update(agc_session *s, agc_slice ciphertext_chunk,
                                  agc_buf out, size_t *out_len);

/* Verifies the tag. On failure returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED and
 * writes nothing; the caller must discard everything Update produced. */
AGC_API agc_rc agc_decrypt_final(agc_session *s, agc_buf out, size_t *out_len,
                                 agc_metadata **out_md);

/* ==========================================================================
 * 2. MESSAGE-BASED AEAD
 *    (Encrypt/DecryptMessageInit, Message, MessageBegin, MessageNext, MessageFinal)
 *
 * One session, many independent messages, each with its own nonce. Amortises
 * key setup across TLS records, database rows, queue items.
 * ========================================================================== */

AGC_API agc_rc agc_encrypt_message_init(agc_ctx *ctx, const agc_encrypt_init_params *p,
                                        agc_session **out_session);

/* Single-shot message within the session. Each call produces its own nonce,
 * returned in *out_md, which MUST be stored with this message's ciphertext. */
AGC_API agc_rc agc_encrypt_message(agc_session *s,
                                   agc_slice associated_data,
                                   agc_slice plaintext,
                                   agc_buf out, size_t *out_len,
                                   agc_metadata **out_md);

/* Begins a multi-part message inside the session. *out_partial_md carries the
 * nonce generated for THIS message; the decrypting side needs it before it can
 * begin. The session-level metadata is not a substitute. */
AGC_API agc_rc agc_encrypt_message_begin(agc_session *s, agc_slice associated_data,
                                         agc_metadata **out_partial_md);

/* Feeds a chunk of the current message. Set end_of_message on the last chunk
 * (PKCS#11 CKF_END_OF_MESSAGE); the output then includes the remaining
 * ciphertext and the tag, per the Ciphertext || Tag convention. The session
 * stays open for further messages. */
AGC_API agc_rc agc_encrypt_message_next(agc_session *s, agc_slice plaintext_chunk,
                                        int end_of_message,
                                        agc_buf out, size_t *out_len);

/* Tears the SESSION down. Carries no ciphertext — per-message output was
 * completed by the end_of_message Next (or by agc_encrypt_message). */
AGC_API agc_rc agc_encrypt_message_final(agc_session *s);

AGC_API agc_rc agc_decrypt_message_init(agc_ctx *ctx, const agc_decrypt_init_params *p,
                                        agc_session **out_session);

/* metadata is the per-message metadata from the corresponding
 * agc_encrypt_message call, not the session's. */
AGC_API agc_rc agc_decrypt_message(agc_session *s,
                                   agc_slice associated_data,
                                   agc_slice ciphertext,
                                   const agc_metadata *metadata,
                                   agc_buf out, size_t *out_len,
                                   agc_metadata **out_md);

/* partial_md is the per-message metadata from agc_encrypt_message_begin. */
AGC_API agc_rc agc_decrypt_message_begin(agc_session *s, agc_slice associated_data,
                                         const agc_metadata *partial_md);

/* UNAUTHENTICATED OUTPUT until the end_of_message call returns AGC_OK. */
AGC_API agc_rc agc_decrypt_message_next(agc_session *s, agc_slice ciphertext_chunk,
                                        int end_of_message,
                                        agc_buf out, size_t *out_len);

AGC_API agc_rc agc_decrypt_message_final(agc_session *s);

/* ==========================================================================
 * 3. MULTI-PART SIGNING  (SignInit/Update/Final, VerifyInit/Update/Final)
 * ========================================================================== */

typedef struct agc_sign_init_params {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    const agc_sign_params *params;        /* REQUIRED */
    agc_kv_list            user_context;
} agc_sign_init_params;

AGC_API agc_rc agc_sign_init(agc_ctx *ctx, const agc_sign_init_params *p,
                             agc_session **out_session);

/* SignUpdate produces no output — the proto's SignUpdateResponse{bool success}
 * collapses into the return code, since a separate success flag alongside a
 * result code is two ways to say the same thing. */
AGC_API agc_rc agc_sign_update(agc_session *s, agc_slice data_chunk);

AGC_API agc_rc agc_sign_final(agc_session *s, agc_buf out_signature, size_t *out_len,
                              agc_metadata **out_md);

typedef struct agc_verify_init_params {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    const agc_sign_params *params;        /* REQUIRED — must match signing */
    const agc_metadata    *metadata;      /* carries key_version; critical post-rotation */
    agc_kv_list            user_context;
} agc_verify_init_params;

AGC_API agc_rc agc_verify_init(agc_ctx *ctx, const agc_verify_init_params *p,
                               agc_session **out_session);

AGC_API agc_rc agc_verify_update(agc_session *s, agc_slice data_chunk);

/* Fail-closed contract as in agc_verify: *out_valid is cleared first, and an
 * invalid signature returns AGC_ERR_CRYPTO_SIGNATURE_INVALID. */
AGC_API agc_rc agc_verify_final(agc_session *s, agc_slice signature,
                                int *out_valid, agc_metadata **out_md);

/* ==========================================================================
 * 4. MESSAGE-BASED SIGNING
 * ========================================================================== */

AGC_API agc_rc agc_sign_message_init(agc_ctx *ctx, const agc_sign_init_params *p,
                                     agc_session **out_session);

AGC_API agc_rc agc_sign_message(agc_session *s, agc_slice message,
                                agc_buf out_signature, size_t *out_len,
                                agc_metadata **out_md);

AGC_API agc_rc agc_sign_message_begin(agc_session *s);

/* On the end_of_message call the signature over the whole message is written to
 * out_signature and *out_md is populated; on other calls out_signature is left
 * untouched, *out_len is set to 0 and *out_md to NULL. Passing NULL for
 * out_signature/out_md on non-final chunks is legal and idiomatic. */
AGC_API agc_rc agc_sign_message_next(agc_session *s, agc_slice message_chunk,
                                     int end_of_message,
                                     agc_buf out_signature, size_t *out_len,
                                     agc_metadata **out_md);

AGC_API agc_rc agc_sign_message_final(agc_session *s);

AGC_API agc_rc agc_verify_message_init(agc_ctx *ctx, const agc_verify_init_params *p,
                                       agc_session **out_session);

AGC_API agc_rc agc_verify_message(agc_session *s, agc_slice message,
                                  agc_slice signature,
                                  const agc_metadata *metadata,
                                  int *out_valid, agc_metadata **out_md);

AGC_API agc_rc agc_verify_message_begin(agc_session *s);

/* signature is supplied only on the end_of_message call (pass an empty slice
 * otherwise), matching PKCS#11 C_VerifyMessageNext. Fail-closed contract
 * applies to *out_valid. */
AGC_API agc_rc agc_verify_message_next(agc_session *s, agc_slice message_chunk,
                                       int end_of_message, agc_slice signature,
                                       int *out_valid, agc_metadata **out_md);

AGC_API agc_rc agc_verify_message_final(agc_session *s);

/* ==========================================================================
 * 5. MULTI-PART MAC
 * ========================================================================== */

typedef struct agc_mac_init_params {
    size_t                struct_size;
    const char           *key_name;      /* REQUIRED */
    const agc_mac_params *params;        /* REQUIRED */
    const agc_metadata   *metadata;      /* verify only: carries key_version */
    agc_kv_list           user_context;
} agc_mac_init_params;

AGC_API agc_rc agc_generate_mac_init(agc_ctx *ctx, const agc_mac_init_params *p,
                                     agc_session **out_session);
AGC_API agc_rc agc_generate_mac_update(agc_session *s, agc_slice data_chunk);
AGC_API agc_rc agc_generate_mac_final(agc_session *s, agc_buf out_mac, size_t *out_len,
                                      agc_metadata **out_md);

AGC_API agc_rc agc_verify_mac_init(agc_ctx *ctx, const agc_mac_init_params *p,
                                   agc_session **out_session);
AGC_API agc_rc agc_verify_mac_update(agc_session *s, agc_slice data_chunk);
/* Constant-time comparison; fail-closed contract on *out_valid. */
AGC_API agc_rc agc_verify_mac_final(agc_session *s, agc_slice mac,
                                    int *out_valid, agc_metadata **out_md);

/* ==========================================================================
 * 6. MULTI-PART DIGEST  (DigestInit/Update/Key/Final)
 * ========================================================================== */

typedef struct agc_digest_init_params {
    size_t                struct_size;
    const agc_scope_spec *scope_spec;    /* hash scope */
    const char           *template_id;   /* explicit; NULL => policy selects */
    const char           *policy_name;
    agc_kv_list           user_context;
} agc_digest_init_params;

/* The template the service selected is available from
 * agc_session_selected_template(*out_session). */
AGC_API agc_rc agc_digest_init(agc_ctx *ctx, const agc_digest_init_params *p,
                               agc_session **out_session);

AGC_API agc_rc agc_digest_update(agc_session *s, agc_slice data_chunk);

/* DigestKey: folds a stored key's value into the digest without the caller ever
 * seeing that value (PKCS#11 C_DigestKey). This is the reason the operation
 * exists and the reason it takes a name rather than bytes. */
AGC_API agc_rc agc_digest_key(agc_session *s, const char *key_name);

AGC_API agc_rc agc_digest_final(agc_session *s, agc_buf out, size_t *out_len,
                                agc_metadata **out_md);

/* ==========================================================================
 * 7. MULTI-PART XOF  (XofInit/Update/Final)
 * ========================================================================== */

typedef struct agc_xof_init_params {
    size_t                struct_size;
    const agc_scope_spec *scope_spec;
    const char           *template_id;
    uint32_t              output_length_bytes;  /* REQUIRED, 1..1048576 */
    const char           *policy_name;
    agc_kv_list           user_context;
} agc_xof_init_params;

AGC_API agc_rc agc_xof_init(agc_ctx *ctx, const agc_xof_init_params *p,
                            agc_session **out_session);
AGC_API agc_rc agc_xof_update(agc_session *s, agc_slice data_chunk);
AGC_API agc_rc agc_xof_final(agc_session *s, agc_buf out, size_t *out_len,
                             agc_metadata **out_md);

/* ==========================================================================
 * 8. DUAL-FUNCTION OPERATIONS
 *
 * Each advances two live sessions in lockstep. Taking two handles makes the
 * requirement structural: the proto's two operation_id strings could name
 * sessions that do not exist, are the wrong kind, or belong to different
 * contexts. Here the library validates both handles and their operations before
 * touching either.
 * ========================================================================== */

/* Digest and encrypt one chunk: digest_session absorbs the PLAINTEXT while
 * encrypt_session produces ciphertext from it. */
AGC_API agc_rc agc_digest_encrypt_update(agc_session *digest_session,
                                         agc_session *encrypt_session,
                                         agc_slice plaintext_chunk,
                                         agc_buf out_ciphertext, size_t *out_len);

/* Decrypt then digest: the digest absorbs the recovered PLAINTEXT.
 * UNAUTHENTICATED OUTPUT until the decrypt session's Final succeeds. */
AGC_API agc_rc agc_decrypt_digest_update(agc_session *decrypt_session,
                                         agc_session *digest_session,
                                         agc_slice ciphertext_chunk,
                                         agc_buf out_plaintext, size_t *out_len);

/* Sign and encrypt one chunk: sign_session absorbs the plaintext. */
AGC_API agc_rc agc_sign_encrypt_update(agc_session *sign_session,
                                       agc_session *encrypt_session,
                                       agc_slice plaintext_chunk,
                                       agc_buf out_ciphertext, size_t *out_len);

/* Decrypt then verify: verify_session absorbs the recovered plaintext.
 * UNAUTHENTICATED OUTPUT until the decrypt session's Final succeeds. */
AGC_API agc_rc agc_decrypt_verify_update(agc_session *decrypt_session,
                                         agc_session *verify_session,
                                         agc_slice ciphertext_chunk,
                                         agc_buf out_plaintext, size_t *out_len);

/* ==========================================================================
 * 9. SESSION MANAGEMENT
 *
 * CancelOperation is agc_session_cancel() in agc_core.h; it is declared there
 * because it belongs to the session's lifecycle rather than to any one
 * cryptographic family.
 * ========================================================================== */

#ifdef __cplusplus
}
#endif
#endif /* AGC_STREAM_H */
