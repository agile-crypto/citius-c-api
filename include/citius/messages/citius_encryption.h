/**
 * @file citius_encryption.h
 * @brief Encrypt / Decrypt request and response structs.
 *
 * Mirrors api/proto/messages/encryption.proto in full:
 *   - Single-shot Encrypt/Decrypt
 *   - Multi-part EncryptInit/Update/Final, DecryptInit/Update/Final
 *   - Message-based EncryptMessageInit/Message/Begin/Next/Final and
 *     DecryptMessageInit/Message/Begin/Next/Final
 *   - Dual-function DigestEncryptUpdate, DecryptDigestUpdate,
 *     SignEncryptUpdate, DecryptVerifyUpdate
 *
 * Proto correspondence
 * --------------------
 *  EncryptRequest                → citius_encrypt_request_t
 *  EncryptResponse               → citius_encrypt_response_t
 *  DecryptRequest                → citius_decrypt_request_t
 *  DecryptResponse               → citius_decrypt_response_t
 *  EncryptInitRequest            → citius_encrypt_init_request_t
 *  EncryptInitResponse           → citius_encrypt_init_response_t
 *  EncryptUpdateRequest          → citius_encrypt_update_request_t
 *  EncryptUpdateResponse         → citius_encrypt_update_response_t
 *  EncryptFinalRequest           → citius_encrypt_final_request_t
 *  EncryptFinalResponse          → citius_encrypt_final_response_t
 *  DecryptInitRequest            → citius_decrypt_init_request_t
 *  DecryptInitResponse           → citius_decrypt_init_response_t
 *  DecryptUpdateRequest          → citius_decrypt_update_request_t
 *  DecryptUpdateResponse         → citius_decrypt_update_response_t
 *  DecryptFinalRequest           → citius_decrypt_final_request_t
 *  DecryptFinalResponse          → citius_decrypt_final_response_t
 *  EncryptMessageInitRequest     → citius_encrypt_message_init_request_t
 *  EncryptMessageInitResponse    → citius_encrypt_message_init_response_t
 *  EncryptMessageRequest         → citius_encrypt_message_request_t
 *  EncryptMessageResponse        → citius_encrypt_message_response_t
 *  EncryptMessageBeginRequest    → citius_encrypt_message_begin_request_t
 *  EncryptMessageBeginResponse   → citius_encrypt_message_begin_response_t
 *  EncryptMessageNextRequest     → citius_encrypt_message_next_request_t
 *  EncryptMessageNextResponse    → citius_encrypt_message_next_response_t
 *  EncryptMessageFinalRequest    → citius_encrypt_message_final_request_t
 *  EncryptMessageFinalResponse   → citius_encrypt_message_final_response_t
 *  DecryptMessageInitRequest     → citius_decrypt_message_init_request_t
 *  DecryptMessageInitResponse    → citius_decrypt_message_init_response_t
 *  DecryptMessageRequest         → citius_decrypt_message_request_t
 *  DecryptMessageResponse        → citius_decrypt_message_response_t
 *  DecryptMessageBeginRequest    → citius_decrypt_message_begin_request_t
 *  DecryptMessageBeginResponse   → citius_decrypt_message_begin_response_t
 *  DecryptMessageNextRequest     → citius_decrypt_message_next_request_t
 *  DecryptMessageNextResponse    → citius_decrypt_message_next_response_t
 *  DecryptMessageFinalRequest    → citius_decrypt_message_final_request_t
 *  DecryptMessageFinalResponse   → citius_decrypt_message_final_response_t
 *  DigestEncryptUpdateRequest    → citius_digest_encrypt_update_request_t
 *  DigestEncryptUpdateResponse   → citius_digest_encrypt_update_response_t
 *  DecryptDigestUpdateRequest    → citius_decrypt_digest_update_request_t
 *  DecryptDigestUpdateResponse   → citius_decrypt_digest_update_response_t
 *  SignEncryptUpdateRequest      → citius_sign_encrypt_update_request_t
 *  SignEncryptUpdateResponse     → citius_sign_encrypt_update_response_t
 *  DecryptVerifyUpdateRequest    → citius_decrypt_verify_update_request_t
 *  DecryptVerifyUpdateResponse   → citius_decrypt_verify_update_response_t
 */

#ifndef CITIUS_MESSAGES_ENCRYPTION_H
#define CITIUS_MESSAGES_ENCRYPTION_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_operation_params.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Encryption scope parameters tagged union
 * (proto: oneof scope_params in EncryptRequest / DecryptRequest / *InitRequest)
 * oneof: NoParams | AeadEncryptParams | XtsEncryptParams |
 *        AsymmetricEncryptParams | VendorEncryptionParams
 * ========================================================================= */

typedef enum {
    CITIUS_ENCRYPT_PARAMS_NONE              = 0, /**< AES-CBC, AES-CTR, ChaCha20, 3DES          */
    CITIUS_ENCRYPT_PARAMS_AEAD              = 1, /**< AES-GCM, AES-CCM, ChaCha20-Poly1305       */
    CITIUS_ENCRYPT_PARAMS_XTS               = 2, /**< AES-XTS (disk/sector encryption)          */
    CITIUS_ENCRYPT_PARAMS_ASYMMETRIC        = 3, /**< RSA-OAEP and other asymmetric encryption  */
    CITIUS_ENCRYPT_PARAMS_VENDOR            = 4  /**< Vendor/custom scope                       */
} citius_encrypt_params_type_t;

typedef struct {
    citius_encrypt_params_type_t type; /**< Discriminator — which union arm is valid.
                                            NONE means no per-call params required
                                            (proto: NoParams); the params union is not read. */
    union {
        citius_aead_encrypt_params_t      aead;    /**< CITIUS_ENCRYPT_PARAMS_AEAD       */
        citius_xts_encrypt_params_t       xts;     /**< CITIUS_ENCRYPT_PARAMS_XTS        */
        citius_asym_encrypt_params_t      asym;    /**< CITIUS_ENCRYPT_PARAMS_ASYMMETRIC */
        citius_vendor_encryption_params_t vendor;  /**< CITIUS_ENCRYPT_PARAMS_VENDOR     */
    } params;
} citius_encrypt_params_t;

/** Convenience: explicit no-params (simple symmetric). */
#define CITIUS_ENCRYPT_PARAMS_NONE_INIT \
    ((citius_encrypt_params_t){ .type = CITIUS_ENCRYPT_PARAMS_NONE })

/* =========================================================================
 * EncryptRequest / EncryptResponse  (single-shot)
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    citius_byte_buffer_t      plaintext;
    citius_encrypt_params_t   scope_params; /**< REQUIRED — one of: NONE (simple symmetric),
                                                 AEAD (AES-GCM/CCM/ChaCha20-Poly1305),
                                                 XTS (AES-XTS), ASYMMETRIC (RSA-OAEP),
                                                 VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_encrypt_request_t;

typedef struct {
    citius_mutable_buffer_t      ciphertext;
    citius_operation_metadata_t  metadata;
} citius_encrypt_response_t;

/* =========================================================================
 * DecryptRequest / DecryptResponse  (single-shot)
 * ========================================================================= */

typedef struct {
    const char                        *key_name;
    citius_byte_buffer_t               ciphertext;
    citius_operation_metadata_t        metadata;
    citius_encrypt_params_t            scope_params; /**< REQUIRED — must match scope used for encryption */
    const citius_map_t                *user_context; /**< nullable */
} citius_decrypt_request_t;

typedef struct {
    citius_mutable_buffer_t      plaintext;
    citius_operation_metadata_t  metadata;
} citius_decrypt_response_t;

/* =========================================================================
 * Multi-part encryption  (EncryptInit / EncryptUpdate / EncryptFinal)
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_encrypt_params_t   scope_params; /**< REQUIRED — one of: NONE, AEAD, XTS, ASYMMETRIC, VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_encrypt_init_request_t;

typedef struct {
    uint8_t success;
} citius_encrypt_init_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  plaintext_chunk;
} citius_encrypt_update_request_t;

typedef struct {
    citius_mutable_buffer_t ciphertext_chunk;
} citius_encrypt_update_response_t;

typedef struct {
    const char *operation_id;
} citius_encrypt_final_request_t;

typedef struct {
    citius_mutable_buffer_t      ciphertext_final;
    citius_operation_metadata_t  metadata;
} citius_encrypt_final_response_t;

/* =========================================================================
 * Multi-part decryption  (DecryptInit / DecryptUpdate / DecryptFinal)
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_encrypt_params_t   scope_params; /**< REQUIRED — must match scope used for EncryptInit */
    const citius_map_t       *user_context; /**< nullable */
} citius_decrypt_init_request_t;

typedef struct {
    uint8_t success;
} citius_decrypt_init_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  ciphertext_chunk;
} citius_decrypt_update_request_t;

typedef struct {
    citius_mutable_buffer_t plaintext_chunk;
} citius_decrypt_update_response_t;

typedef struct {
    const char *operation_id;
} citius_decrypt_final_request_t;

typedef struct {
    citius_mutable_buffer_t      plaintext_final;
    citius_operation_metadata_t  metadata;
} citius_decrypt_final_response_t;

/* =========================================================================
 * Message-based AEAD — Init
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_encrypt_params_t   scope_params; /**< REQUIRED — one of: NONE, AEAD, XTS, ASYMMETRIC, VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_encrypt_message_init_request_t;

typedef struct {
    uint8_t success;
} citius_encrypt_message_init_response_t;

/* =========================================================================
 * Message-based AEAD — single-message EncryptMessage / DecryptMessage
 * ========================================================================= */

typedef struct {
    const char           *key_name;
    citius_byte_buffer_t  associated_data;
    citius_byte_buffer_t  plaintext;
    const citius_map_t   *user_context; /**< nullable */
} citius_encrypt_message_request_t;

typedef struct {
    citius_mutable_buffer_t      ciphertext;
    citius_operation_metadata_t  metadata;
} citius_encrypt_message_response_t;

/* =========================================================================
 * Message-based AEAD — streaming Begin/Next/Final (encrypt side)
 * ========================================================================= */

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  associated_data;
} citius_encrypt_message_begin_request_t;

typedef struct {
    uint8_t                      success;
    /**< Partial metadata carrying the generated IV/nonce; full metadata in Final */
    citius_operation_metadata_t  partial_metadata;
} citius_encrypt_message_begin_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  plaintext_chunk;
} citius_encrypt_message_next_request_t;

typedef struct {
    citius_mutable_buffer_t ciphertext_chunk;
} citius_encrypt_message_next_response_t;

typedef struct {
    const char *operation_id;
} citius_encrypt_message_final_request_t;

typedef struct {
    citius_mutable_buffer_t      ciphertext_final;
    citius_operation_metadata_t  metadata;
} citius_encrypt_message_final_response_t;

/* =========================================================================
 * Message-based AEAD — DecryptMessage Init
 * ========================================================================= */

typedef struct {
    const char               *key_name;
    const char               *operation_id;
    citius_encrypt_params_t   scope_params; /**< REQUIRED — must match scope used for EncryptMessageInit */
    const citius_map_t       *user_context; /**< nullable */
} citius_decrypt_message_init_request_t;

typedef struct {
    uint8_t success;
} citius_decrypt_message_init_response_t;

/* =========================================================================
 * Message-based AEAD — single-message DecryptMessage
 * ========================================================================= */

typedef struct {
    const char           *key_name;
    citius_byte_buffer_t  associated_data;
    citius_byte_buffer_t  ciphertext;
    const citius_map_t   *user_context; /**< nullable */
} citius_decrypt_message_request_t;

typedef struct {
    citius_mutable_buffer_t      plaintext;
    citius_operation_metadata_t  metadata;
} citius_decrypt_message_response_t;

/* =========================================================================
 * Message-based AEAD — streaming Begin/Next/Final (decrypt side)
 * ========================================================================= */

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  associated_data;
} citius_decrypt_message_begin_request_t;

typedef struct {
    uint8_t success;
} citius_decrypt_message_begin_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  ciphertext_chunk;
} citius_decrypt_message_next_request_t;

typedef struct {
    citius_mutable_buffer_t plaintext_chunk;
} citius_decrypt_message_next_response_t;

typedef struct {
    const char *operation_id;
} citius_decrypt_message_final_request_t;

/**
 * citius_decrypt_message_final_response_t  (proto: DecryptMessageFinalResponse)
 *
 * IND-CCA2 note: if this struct is returned, authentication has already
 * succeeded.  Authentication failure is surfaced as CITIUS_AUTHENTICATION_FAILED,
 * never as a flag alongside plaintext.
 */
typedef struct {
    citius_mutable_buffer_t      plaintext_final;
    citius_operation_metadata_t  metadata;
} citius_decrypt_message_final_response_t;

/* =========================================================================
 * Dual-function operations
 * ========================================================================= */

/** DigestEncryptUpdateRequest — feed a chunk through both a running digest
 *  and a running encrypt operation simultaneously. */
typedef struct {
    const char           *digest_operation_id;
    const char           *encrypt_operation_id;
    citius_byte_buffer_t  plaintext_chunk;
} citius_digest_encrypt_update_request_t;

typedef struct {
    citius_mutable_buffer_t ciphertext_chunk;
} citius_digest_encrypt_update_response_t;

/** DecryptDigestUpdateRequest — feed a chunk through a running decrypt and
 *  a running digest simultaneously. */
typedef struct {
    const char           *decrypt_operation_id;
    const char           *digest_operation_id;
    citius_byte_buffer_t  ciphertext_chunk;
} citius_decrypt_digest_update_request_t;

typedef struct {
    citius_mutable_buffer_t plaintext_chunk;
} citius_decrypt_digest_update_response_t;

/** SignEncryptUpdateRequest — feed a chunk through a running sign and a
 *  running encrypt operation simultaneously. */
typedef struct {
    const char           *sign_operation_id;
    const char           *encrypt_operation_id;
    citius_byte_buffer_t  plaintext_chunk;
} citius_sign_encrypt_update_request_t;

typedef struct {
    citius_mutable_buffer_t ciphertext_chunk;
} citius_sign_encrypt_update_response_t;

/** DecryptVerifyUpdateRequest — feed a chunk through a running decrypt and
 *  a running verify operation simultaneously. */
typedef struct {
    const char           *decrypt_operation_id;
    const char           *verify_operation_id;
    citius_byte_buffer_t  ciphertext_chunk;
} citius_decrypt_verify_update_request_t;

typedef struct {
    citius_mutable_buffer_t plaintext_chunk;
} citius_decrypt_verify_update_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_ENCRYPTION_H */
