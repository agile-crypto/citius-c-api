/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_stream.h — StreamingCryptoService (43 RPCs;
 * api/services/streaming_crypto_service.proto).
 *
 * Functions only. Every request and response type they name is defined in
 * agc_stream_types.h, which also states the SIZE QUERY and METADATA rules
 * that govern them.
 *
 * Three families of stateful operation, all keyed on an opaque agc_session
 * rather than the proto's operation_id string:
 *
 *   1. Multi-part      Init -> Update* -> Final              (PKCS#11 classic)
 *   2. Message-based   MessageInit -> ( Message
 *                                     | Begin -> Next* ) * -> MessageFinal
 *   3. Dual-function    two live sessions advanced together
 *
 * SHAPE OF EVERY CALL
 * -------------------
 * Init takes a context and a request and hands back a session. Every later
 * call takes that session, the chunk or value it consumes, and a
 * CALLER-ALLOCATED response. The library writes only into regions the caller
 * placed in the response; it allocates nothing the caller sees and there is
 * nothing to free except the session itself. Rules: docs/agc_crypto.md.
 *
 * THE SESSION IS THE ONE LIBRARY-OWNED THING HERE
 * ------------------------------------------------
 * agc_session stays an opaque handle: it holds live operation state -- a
 * partial hash, a cipher position, a key schedule -- that must be zeroized
 * when the session ends or its idle TTL expires, on a schedule the library
 * controls. That is the same rule that keeps agc_ctx and the key store
 * behind handles. Everything the caller reads is caller-allocated.
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
 * See agc_core.h's Sessions section and RECONCILIATION_PLAN.md D10: the
 * service issues the operation_id (EncryptInitResponse.operation_id etc.,
 * since api v0.3.0); the caller cannot choose it. Every Init function
 * returns a session, and agc_session_id() gives its operation_id, which
 * the single-shot message functions (agc_encrypt_message, ...) name their
 * session by, as the proto's requests do.
 *
 * STATUS: declarations only. Implementation follows; see
 * docs/implementation_progress.md.
 */

#ifndef AGC_STREAM_H
#define AGC_STREAM_H

#include "agc_core.h"
#include "agc_stream_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * 1. MULTI-PART ENCRYPTION (EncryptInit/Update/Final, DecryptInit/Update/Final)
 * ========================================================================== */

AGC_API agc_rc agc_encrypt_init(agc_ctx *ctx, const agc_encrypt_init_request *req,
                                 agc_session **out_session);

/* Emits the ciphertext for this chunk; for the AEAD family the emitted
 * length equals the input length, the tag being withheld until Final. */
AGC_API agc_rc agc_encrypt_update(agc_session *s, agc_slice plaintext_chunk,
                                   agc_stream_chunk_response *resp);

/* Emits the AEAD tag (empty for non-AEAD families) and the metadata. The
 * session is closed on return, success or failure. */
AGC_API agc_rc agc_encrypt_final(agc_session *s, agc_stream_final_response *resp);

AGC_API agc_rc agc_decrypt_init(agc_ctx *ctx, const agc_decrypt_init_request *req,
                                 agc_session **out_session);

/* UNAUTHENTICATED OUTPUT -- see the header comment. */
AGC_API agc_rc agc_decrypt_update(agc_session *s, agc_slice ciphertext_chunk,
                                   agc_stream_chunk_response *resp);

/* Verifies the tag. On failure returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED
 * and writes nothing further; the caller must discard everything Update
 * produced. */
AGC_API agc_rc agc_decrypt_final(agc_session *s, agc_stream_final_response *resp);

/* ==========================================================================
 * 2. MESSAGE-BASED AEAD
 *    (Encrypt/DecryptMessageInit, Message, MessageBegin, MessageNext, MessageFinal)
 *
 * One session, many independent messages, each with its own nonce (PKCS#11
 * C_MessageEncryptInit). A message is either one agc_*_message() call, or
 * Begin, then Next calls, the last with end_of_message set. Final ends the
 * session, not a message.
 * ========================================================================== */

AGC_API agc_rc agc_encrypt_message_init(agc_ctx *ctx, const agc_encrypt_init_request *req,
                                         agc_session **out_session);

/* One whole message within the session req->operation_id. Each call produces
 * its own nonce, reported in resp->metadata. Its output really is
 * ciphertext, so it shares agc_encrypt_response with agc_encrypt. */
AGC_API agc_rc agc_encrypt_message(agc_ctx *ctx, const agc_encrypt_message_request *req,
                                    agc_encrypt_response *resp);

/* Begins a multi-part message inside a session opened by
 * agc_encrypt_message_init(). resp->metadata carries the nonce generated for
 * THIS message; the decrypting side needs it before it can begin. */
AGC_API agc_rc agc_encrypt_message_begin(agc_session *s, agc_slice associated_data,
                                          agc_stream_metadata_response *resp);

/* Emits ciphertext for this chunk. With end_of_message set it ends the
 * message: the output includes the authentication tag (Ciphertext || Tag),
 * and the session is ready for the next message's Begin. */
AGC_API agc_rc agc_encrypt_message_next(agc_session *s, agc_slice plaintext_chunk,
                                         int end_of_message, agc_stream_chunk_response *resp);

/* Ends the session; EncryptMessageFinalResponse{success} collapses (D4). A
 * message begun but not ended with end_of_message is discarded. */
AGC_API agc_rc agc_encrypt_message_final(agc_session *s);

AGC_API agc_rc agc_decrypt_message_init(agc_ctx *ctx, const agc_decrypt_message_init_request *req,
                                         agc_session **out_session);

/* One whole message within the session req->operation_id; req->metadata is
 * that message's metadata from agc_encrypt_message(). Its output really is
 * plaintext, so it shares agc_decrypt_response with agc_decrypt. */
AGC_API agc_rc agc_decrypt_message(agc_ctx *ctx, const agc_decrypt_message_request *req,
                                    agc_decrypt_response *resp);

/* partial_metadata is the per-message metadata from
 * agc_encrypt_message_begin(), encoded, encoding byte first. */
AGC_API agc_rc agc_decrypt_message_begin(agc_session *s, agc_slice associated_data,
                                          agc_slice partial_metadata);

/* UNAUTHENTICATED OUTPUT until this message's end_of_message call succeeds.
 * That call's chunk includes the tag, which is verified before the last
 * plaintext is returned; on failure it returns
 * AGC_ERR_CRYPTO_AUTHENTICATION_FAILED and writes nothing, and the caller
 * must discard everything this message's Next calls produced. */
AGC_API agc_rc agc_decrypt_message_next(agc_session *s, agc_slice ciphertext_chunk,
                                         int end_of_message, agc_stream_chunk_response *resp);

/* Ends the session; DecryptMessageFinalResponse{success} collapses (D4). */
AGC_API agc_rc agc_decrypt_message_final(agc_session *s);

/* ==========================================================================
 * 3. MULTI-PART SIGNING (SignInit/Update/Final, VerifyInit/Update/Final)
 * ========================================================================== */

AGC_API agc_rc agc_sign_init(agc_ctx *ctx, const agc_sign_init_request *req,
                              agc_session **out_session);

/* Produces no output -- SignUpdateResponse{bool success} collapses into the
 * return code (D4). */
AGC_API agc_rc agc_sign_update(agc_session *s, agc_slice data_chunk);

/* Shares agc_sign_response with agc_sign. */
AGC_API agc_rc agc_sign_final(agc_session *s, agc_sign_response *resp);

AGC_API agc_rc agc_verify_init(agc_ctx *ctx, const agc_verify_init_request *req,
                                agc_session **out_session);

AGC_API agc_rc agc_verify_update(agc_session *s, agc_slice data_chunk);

/* Fail-closed as agc_verify() (D9): resp->valid is cleared first, and an
 * invalid signature returns AGC_ERR_CRYPTO_SIGNATURE_INVALID. Shares
 * agc_verify_response with agc_verify. */
AGC_API agc_rc agc_verify_final(agc_session *s, agc_slice signature,
                                 agc_verify_response *resp);

/* ==========================================================================
 * 4. MESSAGE-BASED SIGNING
 * ========================================================================== */

AGC_API agc_rc agc_sign_message_init(agc_ctx *ctx, const agc_sign_init_request *req,
                                      agc_session **out_session);

AGC_API agc_rc agc_sign_message(agc_ctx *ctx, const agc_sign_message_request *req,
                                 agc_sign_response *resp);

AGC_API agc_rc agc_sign_message_begin(agc_session *s);

/* With end_of_message set, ends the message and fills *resp with the
 * signature over everything absorbed since Begin, plus metadata
 * (SignMessageNextResponse). Otherwise resp may be NULL and nothing is
 * written. */
AGC_API agc_rc agc_sign_message_next(agc_session *s, agc_slice message_chunk,
                                      int end_of_message, agc_sign_response *resp);

/* Ends the session; SignMessageFinalResponse{success} collapses (D4). */
AGC_API agc_rc agc_sign_message_final(agc_session *s);

AGC_API agc_rc agc_verify_message_init(agc_ctx *ctx, const agc_verify_init_request *req,
                                        agc_session **out_session);

AGC_API agc_rc agc_verify_message(agc_ctx *ctx, const agc_verify_message_request *req,
                                   agc_verify_response *resp);

AGC_API agc_rc agc_verify_message_begin(agc_session *s);
/* With end_of_message set, `signature` is REQUIRED and *resp receives this
 * message's result (VerifyMessageNextResponse) under the fail-closed
 * contract (D9): resp->valid is cleared first, and an invalid signature
 * returns AGC_ERR_CRYPTO_SIGNATURE_INVALID. Otherwise signature is
 * {NULL,0}, resp may be NULL, and nothing is written. */
AGC_API agc_rc agc_verify_message_next(agc_session *s, agc_slice message_chunk,
                                        int end_of_message, agc_slice signature,
                                        agc_verify_response *resp);

/* Ends the session; VerifyMessageFinalResponse{success} collapses (D4). */
AGC_API agc_rc agc_verify_message_final(agc_session *s);

/* ==========================================================================
 * 5. MULTI-PART DIGEST (DigestInit/Update/Key/Final)
 * ========================================================================== */

/* The template the service selected is available from
 * agc_session_selected_template_id(*out_session), and again in the closing
 * call's response. */
AGC_API agc_rc agc_digest_init(agc_ctx *ctx, const agc_digest_init_request *req,
                                agc_session **out_session);

AGC_API agc_rc agc_digest_update(agc_session *s, agc_slice data_chunk);

/* Folds a stored key's value into the digest without the caller ever seeing
 * it (PKCS#11 C_DigestKey) -- takes a name, not bytes. */
AGC_API agc_rc agc_digest_key(agc_session *s, const char *key_name);

/* Keyless, so no metadata: shares agc_digest_response with agc_digest and
 * reports the provider, template and policy version that served the stream. */
AGC_API agc_rc agc_digest_final(agc_session *s, agc_digest_response *resp);

/* ==========================================================================
 * 6. MULTI-PART XOF (XofInit/Update/Final)
 * ========================================================================== */

AGC_API agc_rc agc_xof_init(agc_ctx *ctx, const agc_xof_init_request *req,
                             agc_session **out_session);

AGC_API agc_rc agc_xof_update(agc_session *s, agc_slice data_chunk);

/* Shares agc_digest_response with agc_digest_final. */
AGC_API agc_rc agc_xof_final(agc_session *s, agc_digest_response *resp);

/* ==========================================================================
 * 7. DUAL-FUNCTION OPERATIONS
 *
 * Each advances two live sessions in lockstep. Two typed handles (rather
 * than the proto's two operation_id strings) let the library validate both
 * handles and both agc_session_operation() values before touching either,
 * turning "session doesn't exist / wrong kind / belongs elsewhere" into an
 * immediate AGC_ERR_INVALID_HANDLE instead of a confusing downstream error.
 * All four share agc_stream_chunk_response: each emits exactly one chunk.
 * ========================================================================== */

/* Digest and encrypt one chunk: digest_session absorbs the PLAINTEXT while
 * encrypt_session produces ciphertext from it. */
AGC_API agc_rc agc_digest_encrypt_update(agc_session *digest_session, agc_session *encrypt_session,
                                          agc_slice plaintext_chunk,
                                          agc_stream_chunk_response *resp);

/* Decrypt then digest: the digest absorbs the recovered PLAINTEXT.
 * UNAUTHENTICATED OUTPUT until the decrypt session's Final succeeds. */
AGC_API agc_rc agc_decrypt_digest_update(agc_session *decrypt_session, agc_session *digest_session,
                                          agc_slice ciphertext_chunk,
                                          agc_stream_chunk_response *resp);

/* Sign and encrypt one chunk: sign_session absorbs the plaintext. */
AGC_API agc_rc agc_sign_encrypt_update(agc_session *sign_session, agc_session *encrypt_session,
                                        agc_slice plaintext_chunk,
                                        agc_stream_chunk_response *resp);

/* Decrypt then verify: verify_session absorbs the recovered plaintext.
 * UNAUTHENTICATED OUTPUT until the decrypt session's Final succeeds. */
AGC_API agc_rc agc_decrypt_verify_update(agc_session *decrypt_session, agc_session *verify_session,
                                          agc_slice ciphertext_chunk,
                                          agc_stream_chunk_response *resp);

/* ==========================================================================
 * 8. MULTI-PART MAC (GenerateMACInit/Update/Final, VerifyMACInit/...)
 * ========================================================================== */

AGC_API agc_rc agc_generate_mac_init(agc_ctx *ctx, const agc_generate_mac_init_request *req,
                                      agc_session **out_session);

/* GenerateMACUpdateResponse{bool success} collapses (D4). */
AGC_API agc_rc agc_generate_mac_update(agc_session *s, agc_slice data_chunk);

/* Shares agc_mac_response with agc_generate_mac. */
AGC_API agc_rc agc_generate_mac_final(agc_session *s, agc_mac_response *resp);

AGC_API agc_rc agc_verify_mac_init(agc_ctx *ctx, const agc_verify_mac_init_request *req,
                                    agc_session **out_session);

AGC_API agc_rc agc_verify_mac_update(agc_session *s, agc_slice data_chunk);

/* Fail-closed as agc_verify_mac() (D9): resp->valid is cleared first, a
 * mismatch returns AGC_ERR_CRYPTO_AUTHENTICATION_FAILED, and the
 * comparison is constant-time. Shares agc_verify_response. */
AGC_API agc_rc agc_verify_mac_final(agc_session *s, agc_slice mac, agc_verify_response *resp);

/* ==========================================================================
 * 9. CancelOperation
 * ========================================================================== */

/* Ends the streaming operation `operation_id` (agc_session_id()) and releases
 * its state before its idle TTL. `reason` goes to the audit trail; NULL for
 * none. CancelOperationResponse's success and message collapse (D4). An
 * unknown or already-finished operation_id fails with
 * AGC_ERR_CRYPTO_OPERATION_EXPIRED. The handle, if this process holds one,
 * stays owned by its creator, who must still agc_session_free() it. For a
 * session this process holds, agc_session_cancel() does the same. */
AGC_API agc_rc agc_cancel_operation(agc_ctx *ctx, const char *operation_id, const char *reason);

#ifdef __cplusplus
}
#endif
#endif /* AGC_STREAM_H */
