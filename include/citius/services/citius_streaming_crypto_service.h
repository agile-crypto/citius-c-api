/**
 * @file citius_streaming_crypto_service.h
 * @brief Multi-part and message-based stateful operations (StreamingCryptoService).
 *
 * C mirror of api/proto/services/streaming_crypto_service.proto —
 * StreamingCryptoService.
 *
 * When to use this vs CryptoService
 * -----------------------------------
 *   CryptoService:          Stateless, single request/response.  Use for
 *                           individual operations (document encryption, etc.)
 *   StreamingCryptoService: Stateful, multi-step sessions.  Use when:
 *                           - Data doesn't fit in memory (multi-part streaming)
 *                           - Many messages share one key setup (message AEAD)
 *                           - PKCS#11 interop requires Init/Update/Final pattern
 *
 * Operation context lifecycle
 * ---------------------------
 *   1. citius_<op>_init(key_name, scope_params, &ctx)
 *   2. citius_<op>_update(ctx, chunk, output)  [0 or more]
 *   3. citius_<op>_final(ctx, output)
 *   4. citius_op_ctx_free(ctx)              [always, even after error]
 *
 * Proto → C mapping (Init/Update/Final families)
 * -----------------------------------------------
 *   EncryptInit / EncryptUpdate / EncryptFinal
 *       citius_encrypt_init() / citius_encrypt_update() / citius_encrypt_final()
 *
 *   DecryptInit / DecryptUpdate / DecryptFinal
 *       citius_decrypt_init() / citius_decrypt_update() / citius_decrypt_final()
 *
 *   SignInit / SignUpdate / SignFinal
 *       citius_sign_init() / citius_sign_update() / citius_sign_final()
 *
 *   VerifyInit / VerifyUpdate / VerifyFinal
 *       citius_verify_init() / citius_verify_update() / citius_verify_final()
 *
 *   DigestInit / DigestUpdate / DigestKey / DigestFinal
 *       citius_digest_init() / citius_digest_update() /
 *       citius_digest_key()  / citius_digest_final()
 *
 *   XofInit / XofUpdate / XofFinal
 *       citius_xof_init() / citius_xof_update() / citius_xof_final()
 *
 * Proto → C mapping (message-based AEAD)
 * ----------------------------------------
 *   EncryptMessageInit / EncryptMessage / EncryptMessageBegin /
 *   EncryptMessageNext / EncryptMessageFinal
 *       citius_message_encrypt_init() / citius_message_encrypt() /
 *       citius_message_encrypt_begin() / citius_message_encrypt_next() /
 *       citius_message_encrypt_final()
 *
 *   DecryptMessageInit / DecryptMessage / DecryptMessageBegin /
 *   DecryptMessageNext / DecryptMessageFinal
 *       citius_message_decrypt_init() / citius_message_decrypt() /
 *       citius_message_decrypt_begin() / citius_message_decrypt_next() /
 *       citius_message_decrypt_final()
 *
 * Proto → C mapping (message-based signing)
 * -------------------------------------------
 *   SignMessageInit / SignMessage / SignMessageBegin /
 *   SignMessageNext / SignMessageFinal
 *       citius_sign_message_init() / citius_sign_message() /
 *       citius_sign_message_begin() / citius_sign_message_next() /
 *       citius_sign_message_final()
 *
 *   VerifyMessageInit / VerifyMessage / VerifyMessageBegin /
 *   VerifyMessageNext / VerifyMessageFinal
 *       citius_verify_message_init() / citius_verify_message() /
 *       citius_verify_message_begin() / citius_verify_message_next() /
 *       citius_verify_message_final()
 *
 * Proto → C mapping (dual-function Update operations)
 * -----------------------------------------------------
 *   DigestEncryptUpdate  → citius_digest_encrypt_update()
 *   DecryptDigestUpdate  → citius_decrypt_digest_update()
 *   SignEncryptUpdate    → citius_sign_encrypt_update()
 *   DecryptVerifyUpdate  → citius_decrypt_verify_update()
 *
 * HTTP REST paths (selected):
 *   POST /v1/encrypt/init/{key_name}           citius_encrypt_init()
 *   POST /v1/encrypt/update/{operation_id}     citius_encrypt_update()
 *   POST /v1/encrypt/final/{operation_id}      citius_encrypt_final()
 *   POST /v1/encrypt/message/init/{key_name}   citius_message_encrypt_init()
 *   POST /v1/encrypt/message/{key_name}        citius_message_encrypt()
 *   POST /v1/sign/message/init/{key_name}      citius_sign_message_init()
 *   POST /v1/digest/init                       citius_digest_init()
 *   POST /v1/digest/key/{operation_id}         citius_digest_key()
 *   (see proto file for the full set of 43 RPC paths)
 */

#ifndef CITIUS_SERVICES_STREAMING_CRYPTO_SERVICE_H
#define CITIUS_SERVICES_STREAMING_CRYPTO_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_operation_params.h"
#include "citius/messages/citius_encryption.h"
#include "citius/messages/citius_signing.h"
#include "citius/messages/citius_digest.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Opaque operation context
 * ========================================================================= */

/** Opaque pointer to an in-progress multi-part operation context.
 *  Allocated by an Init function; freed by citius_op_ctx_free(). */
typedef struct citius_op_ctx_s *citius_op_ctx_t;

/**
 * @brief Free an operation context and release all associated resources.
 *
 * Must be called after Final (or on error after Init).
 * Passing NULL is a no-op.
 */
CITIUS_RV citius_op_ctx_free(citius_op_ctx_t ctx);

/* =========================================================================
 * Multi-part encryption  (EncryptInit / EncryptUpdate / EncryptFinal)
 * ========================================================================= */

CITIUS_RV citius_encrypt_init(
    const citius_encrypt_init_request_t      *request,
    citius_encrypt_init_response_t           *response,
    citius_op_ctx_t                          *ctx_out
);

CITIUS_RV citius_encrypt_update(
    citius_op_ctx_t                           ctx,
    const citius_encrypt_update_request_t    *request,
    citius_encrypt_update_response_t         *response
);

CITIUS_RV citius_encrypt_final(
    citius_op_ctx_t                           ctx,
    const citius_encrypt_final_request_t     *request,
    citius_encrypt_final_response_t          *response
);

/* =========================================================================
 * Multi-part decryption  (DecryptInit / DecryptUpdate / DecryptFinal)
 * ========================================================================= */

CITIUS_RV citius_decrypt_init(
    const citius_decrypt_init_request_t      *request,
    citius_decrypt_init_response_t           *response,
    citius_op_ctx_t                          *ctx_out
);

CITIUS_RV citius_decrypt_update(
    citius_op_ctx_t                           ctx,
    const citius_decrypt_update_request_t    *request,
    citius_decrypt_update_response_t         *response
);

CITIUS_RV citius_decrypt_final(
    citius_op_ctx_t                           ctx,
    const citius_decrypt_final_request_t     *request,
    citius_decrypt_final_response_t          *response
);

/* =========================================================================
 * Multi-part signing  (SignInit / SignUpdate / SignFinal)
 * ========================================================================= */

CITIUS_RV citius_sign_init(
    const citius_sign_init_request_t         *request,
    citius_sign_init_response_t              *response,
    citius_op_ctx_t                          *ctx_out
);

CITIUS_RV citius_sign_update(
    citius_op_ctx_t                           ctx,
    const citius_sign_update_request_t       *request,
    citius_sign_update_response_t            *response
);

CITIUS_RV citius_sign_final(
    citius_op_ctx_t                           ctx,
    const citius_sign_final_request_t        *request,
    citius_sign_final_response_t             *response
);

/* =========================================================================
 * Multi-part verification  (VerifyInit / VerifyUpdate / VerifyFinal)
 * ========================================================================= */

CITIUS_RV citius_verify_init(
    const citius_verify_init_request_t       *request,
    citius_verify_init_response_t            *response,
    citius_op_ctx_t                          *ctx_out
);

CITIUS_RV citius_verify_update(
    citius_op_ctx_t                           ctx,
    const citius_verify_update_request_t     *request,
    citius_verify_update_response_t          *response
);

CITIUS_RV citius_verify_final(
    citius_op_ctx_t                           ctx,
    const citius_verify_final_request_t      *request,
    citius_verify_final_response_t           *response
);

/* =========================================================================
 * Streaming digest  (DigestInit / DigestUpdate / DigestKey / DigestFinal)
 * ========================================================================= */

CITIUS_RV citius_digest_init(
    const citius_digest_init_request_t       *request,
    citius_digest_init_response_t            *response,
    citius_op_ctx_t                          *ctx_out
);

CITIUS_RV citius_digest_update(
    citius_op_ctx_t                           ctx,
    const citius_digest_update_request_t     *request,
    citius_digest_update_response_t          *response
);

/**
 * @brief Incorporate a named key's value into the running digest.
 *
 * Mirrors StreamingCryptoService.DigestKey (PKCS#11 C_DigestKey).
 */
CITIUS_RV citius_digest_key(
    citius_op_ctx_t                           ctx,
    const citius_digest_key_request_t        *request,
    citius_digest_key_response_t             *response
);

CITIUS_RV citius_digest_final(
    citius_op_ctx_t                           ctx,
    const citius_digest_final_request_t      *request,
    citius_digest_final_response_t           *response
);

/* =========================================================================
 * Streaming XOF  (XofInit / XofUpdate / XofFinal)
 * ========================================================================= */

CITIUS_RV citius_xof_init(
    const citius_xof_init_request_t          *request,
    citius_xof_init_response_t               *response,
    citius_op_ctx_t                          *ctx_out
);

CITIUS_RV citius_xof_update(
    citius_op_ctx_t                           ctx,
    const citius_xof_update_request_t        *request,
    citius_xof_update_response_t             *response
);

CITIUS_RV citius_xof_final(
    citius_op_ctx_t                           ctx,
    const citius_xof_final_request_t         *request,
    citius_xof_final_response_t              *response
);

/* =========================================================================
 * Message-based AEAD encrypt
 * (EncryptMessageInit / EncryptMessage / EncryptMessageBegin /
 *  EncryptMessageNext / EncryptMessageFinal)
 * ========================================================================= */

CITIUS_RV citius_message_encrypt_init(
    const citius_encrypt_message_init_request_t   *request,
    citius_encrypt_message_init_response_t        *response,
    citius_op_ctx_t                               *ctx_out
);

CITIUS_RV citius_message_encrypt(
    citius_op_ctx_t                                ctx,
    const citius_encrypt_message_request_t        *request,
    citius_encrypt_message_response_t             *response
);

CITIUS_RV citius_message_encrypt_begin(
    citius_op_ctx_t                                ctx,
    const citius_encrypt_message_begin_request_t  *request,
    citius_encrypt_message_begin_response_t       *response
);

CITIUS_RV citius_message_encrypt_next(
    citius_op_ctx_t                                ctx,
    const citius_encrypt_message_next_request_t   *request,
    citius_encrypt_message_next_response_t        *response
);

CITIUS_RV citius_message_encrypt_final(
    citius_op_ctx_t                                ctx,
    const citius_encrypt_message_final_request_t  *request,
    citius_encrypt_message_final_response_t       *response
);

/* =========================================================================
 * Message-based AEAD decrypt
 * (DecryptMessageInit / DecryptMessage / DecryptMessageBegin /
 *  DecryptMessageNext / DecryptMessageFinal)
 * ========================================================================= */

CITIUS_RV citius_message_decrypt_init(
    const citius_decrypt_message_init_request_t   *request,
    citius_decrypt_message_init_response_t        *response,
    citius_op_ctx_t                               *ctx_out
);

CITIUS_RV citius_message_decrypt(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_message_request_t        *request,
    citius_decrypt_message_response_t             *response
);

CITIUS_RV citius_message_decrypt_begin(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_message_begin_request_t  *request,
    citius_decrypt_message_begin_response_t       *response
);

CITIUS_RV citius_message_decrypt_next(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_message_next_request_t   *request,
    citius_decrypt_message_next_response_t        *response
);

/**
 * IND-CCA2: if this returns CITIUS_OK, authentication has already succeeded.
 * Authentication failure is returned as an error code, never alongside plaintext.
 */
CITIUS_RV citius_message_decrypt_final(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_message_final_request_t  *request,
    citius_decrypt_message_final_response_t       *response
);

/* =========================================================================
 * Message-based signing
 * (SignMessageInit / SignMessage / SignMessageBegin /
 *  SignMessageNext / SignMessageFinal)
 * ========================================================================= */

CITIUS_RV citius_sign_message_init(
    const citius_sign_message_init_request_t     *request,
    citius_sign_message_init_response_t          *response,
    citius_op_ctx_t                              *ctx_out
);

CITIUS_RV citius_sign_message(
    citius_op_ctx_t                               ctx,
    const citius_sign_message_request_t          *request,
    citius_sign_message_response_t               *response
);

CITIUS_RV citius_sign_message_begin(
    citius_op_ctx_t                               ctx,
    const citius_sign_message_begin_request_t    *request,
    citius_sign_message_begin_response_t         *response
);

CITIUS_RV citius_sign_message_next(
    citius_op_ctx_t                               ctx,
    const citius_sign_message_next_request_t     *request,
    citius_sign_message_next_response_t          *response
);

CITIUS_RV citius_sign_message_final(
    citius_op_ctx_t                               ctx,
    const citius_sign_message_final_request_t    *request,
    citius_sign_message_final_response_t         *response
);

/* =========================================================================
 * Message-based verification
 * (VerifyMessageInit / VerifyMessage / VerifyMessageBegin /
 *  VerifyMessageNext / VerifyMessageFinal)
 * ========================================================================= */

CITIUS_RV citius_verify_message_init(
    const citius_verify_message_init_request_t    *request,
    citius_verify_message_init_response_t         *response,
    citius_op_ctx_t                               *ctx_out
);

CITIUS_RV citius_verify_message(
    citius_op_ctx_t                                ctx,
    const citius_verify_message_request_t         *request,
    citius_verify_message_response_t              *response
);

CITIUS_RV citius_verify_message_begin(
    citius_op_ctx_t                                ctx,
    const citius_verify_message_begin_request_t   *request,
    citius_verify_message_begin_response_t        *response
);

CITIUS_RV citius_verify_message_next(
    citius_op_ctx_t                                ctx,
    const citius_verify_message_next_request_t    *request,
    citius_verify_message_next_response_t         *response
);

CITIUS_RV citius_verify_message_final(
    citius_op_ctx_t                                ctx,
    const citius_verify_message_final_request_t   *request,
    citius_verify_message_final_response_t        *response
);

/* =========================================================================
 * Dual-function Update operations
 * ========================================================================= */

/** Feed a chunk simultaneously through a running digest and encrypt context. */
CITIUS_RV citius_digest_encrypt_update(
    citius_op_ctx_t                                ctx,
    const citius_digest_encrypt_update_request_t  *request,
    citius_digest_encrypt_update_response_t       *response
);

/** Feed a chunk simultaneously through a running decrypt and digest context. */
CITIUS_RV citius_decrypt_digest_update(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_digest_update_request_t  *request,
    citius_decrypt_digest_update_response_t       *response
);

/** Feed a chunk simultaneously through a running sign and encrypt context. */
CITIUS_RV citius_sign_encrypt_update(
    citius_op_ctx_t                                ctx,
    const citius_sign_encrypt_update_request_t    *request,
    citius_sign_encrypt_update_response_t         *response
);

/** Feed a chunk simultaneously through a running decrypt and verify context. */
CITIUS_RV citius_decrypt_verify_update(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_verify_update_request_t  *request,
    citius_decrypt_verify_update_response_t       *response
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_STREAMING_CRYPTO_SERVICE_H */
