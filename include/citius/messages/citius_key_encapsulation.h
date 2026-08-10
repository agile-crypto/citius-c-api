/**
 * @file citius_key_encapsulation.h
 * @brief EncapsulateKey / DecapsulateKey request and response structs.
 *
 * Mirrors api/proto/messages/key_encapsulation.proto.
 *
 * Proto correspondence
 * --------------------
 *  EncapsulateKeyRequest   → citius_encapsulate_key_request_t
 *  EncapsulateKeyResponse  → citius_encapsulate_key_response_t
 *  DecapsulateKeyRequest   → citius_decapsulate_key_request_t
 *  DecapsulateKeyResponse  → citius_decapsulate_key_response_t
 *
 * Design note
 * -----------
 * KEM operations store the derived shared secret as a named key object inside
 * the provider rather than returning raw key bytes.  The key_metadata field in
 * the response mirrors the metadata returned by CreateKey / ImportKey for
 * consistency.
 *
 * The KEM algorithm is determined by the recipient's public key template —
 * no scope or template_id is specified at encapsulation time.
 */

#ifndef CITIUS_MESSAGES_KEY_ENCAPSULATION_H
#define CITIUS_MESSAGES_KEY_ENCAPSULATION_H

#include "citius/types/citius_types.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyMetadata is defined in messages/citius_key_management.h; forward-declare
 * the typedef here so this header can be included without that dependency. */
#ifndef CITIUS_KEY_METADATA_DEFINED
struct citius_key_metadata_s;
typedef struct citius_key_metadata_s citius_key_metadata_t;
#define CITIUS_KEY_METADATA_DEFINED 1
#endif

/* =========================================================================
 * EncapsulateKeyRequest / EncapsulateKeyResponse
 * ========================================================================= */

typedef struct {
    const char         *recipient_public_key_name;
    const char         *shared_secret_name;        /**< nullable */
    const char         *shared_secret_template_id; /**< nullable */
    const citius_map_t *user_context;               /**< nullable */
} citius_encapsulate_key_request_t;

typedef struct {
    citius_mutable_buffer_t      ciphertext;   /**< KEM ciphertext — transmit to decapsulator */
    citius_operation_metadata_t  metadata;
    citius_key_metadata_t        key_metadata;
} citius_encapsulate_key_response_t;

/* =========================================================================
 * DecapsulateKeyRequest / DecapsulateKeyResponse
 * ========================================================================= */

typedef struct {
    const char                        *private_key_name;
    citius_byte_buffer_t               ciphertext;
    const char                        *shared_secret_name;        /**< nullable */
    const char                        *shared_secret_template_id; /**< nullable */
    citius_operation_metadata_t        metadata;
    const citius_map_t                *user_context; /**< nullable */
} citius_decapsulate_key_request_t;

typedef struct {
    uint8_t                      success;
    citius_operation_metadata_t  metadata;
    citius_key_metadata_t        key_metadata;
} citius_decapsulate_key_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_KEY_ENCAPSULATION_H */
