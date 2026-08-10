/**
 * @file citius_digest.h
 * @brief Digest and XOF request and response structs.
 *
 * Mirrors api/proto/messages/digest.proto in full:
 *   - Single-shot DigestRequest / DigestResponse
 *   - Streaming DigestInit/Update/DigestKey/Final
 *   - Single-shot XofRequest / XofResponse
 *   - Streaming XofInit/Update/Final
 *
 * Algorithm selection follows the proto pattern: a ScopeSpecification
 * (citius_scope_specification_t from citius_common.h) plus an optional
 * explicit template_id string.
 *
 * Proto correspondence
 * --------------------
 *  DigestRequest         → citius_digest_request_t
 *  DigestResponse        → citius_digest_response_t
 *  DigestInitRequest     → citius_digest_init_request_t
 *  DigestInitResponse    → citius_digest_init_response_t
 *  DigestUpdateRequest   → citius_digest_update_request_t
 *  DigestUpdateResponse  → citius_digest_update_response_t
 *  DigestKeyRequest      → citius_digest_key_request_t
 *  DigestKeyResponse     → citius_digest_key_response_t
 *  DigestFinalRequest    → citius_digest_final_request_t
 *  DigestFinalResponse   → citius_digest_final_response_t
 *  XofRequest            → citius_xof_request_t
 *  XofResponse           → citius_xof_response_t
 *  XofInitRequest        → citius_xof_init_request_t
 *  XofInitResponse       → citius_xof_init_response_t
 *  XofUpdateRequest      → citius_xof_update_request_t
 *  XofUpdateResponse     → citius_xof_update_response_t
 *  XofFinalRequest       → citius_xof_final_request_t
 *  XofFinalResponse      → citius_xof_final_response_t
 */

#ifndef CITIUS_MESSAGES_DIGEST_H
#define CITIUS_MESSAGES_DIGEST_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_templates.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * DigestRequest / DigestResponse  (single-shot)
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope_spec;
    const char                   *template_id;   /**< optional explicit template; nullable */
    citius_byte_buffer_t          data;
    const char                   *policy_name;   /**< nullable */
    const citius_map_t            *user_context;  /**< nullable */
} citius_digest_request_t;

typedef struct {
    citius_mutable_buffer_t      digest;
    citius_operation_metadata_t  metadata;
} citius_digest_response_t;

/* =========================================================================
 * Streaming digest  (DigestInit / DigestUpdate / DigestKey / DigestFinal)
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope_spec;
    const char                   *template_id;   /**< nullable */
    const char                   *operation_id;
    const char                   *policy_name;   /**< nullable */
    const citius_map_t            *user_context;  /**< nullable */
} citius_digest_init_request_t;

typedef struct {
    uint8_t     success;
    const char *selected_template_id; /**< Template selected for this operation */
} citius_digest_init_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  data_chunk;
} citius_digest_update_request_t;

typedef struct {
    uint8_t success;
} citius_digest_update_response_t;

/** Feed a named key's value directly into the running digest (PKCS#11 C_DigestKey). */
typedef struct {
    const char *operation_id;
    const char *key_name;
} citius_digest_key_request_t;

typedef struct {
    uint8_t success;
} citius_digest_key_response_t;

typedef struct {
    const char *operation_id;
} citius_digest_final_request_t;

typedef struct {
    citius_mutable_buffer_t      digest;
    citius_operation_metadata_t  metadata;
} citius_digest_final_response_t;

/* =========================================================================
 * XofRequest / XofResponse  (single-shot)
 *
 * XOFs (SHAKE128, SHAKE256, BLAKE3, etc.) produce variable-length output.
 * They are a distinct primitive (CITIUS_PRIMITIVE_XOF) from fixed-output
 * digests.
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope_spec;
    const char                   *template_id;          /**< nullable */
    citius_byte_buffer_t          data;
    uint32_t                      output_length_bytes;  /**< Required: desired output length */
    const char                   *policy_name;          /**< nullable */
    const citius_map_t            *user_context;         /**< nullable */
} citius_xof_request_t;

typedef struct {
    citius_mutable_buffer_t      output;
    citius_operation_metadata_t  metadata;
} citius_xof_response_t;

/* =========================================================================
 * Streaming XOF  (XofInit / XofUpdate / XofFinal)
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope_spec;
    const char                   *template_id;         /**< nullable */
    const char                   *operation_id;
    uint32_t                      output_length_bytes; /**< Required */
    const char                   *policy_name;         /**< nullable */
    const citius_map_t            *user_context;        /**< nullable */
} citius_xof_init_request_t;

typedef struct {
    uint8_t     success;
    const char *selected_template_id;
} citius_xof_init_response_t;

typedef struct {
    const char           *operation_id;
    citius_byte_buffer_t  data_chunk;
} citius_xof_update_request_t;

typedef struct {
    uint8_t success;
} citius_xof_update_response_t;

typedef struct {
    const char *operation_id;
} citius_xof_final_request_t;

typedef struct {
    citius_mutable_buffer_t      output;
    citius_operation_metadata_t  metadata;
} citius_xof_final_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_DIGEST_H */
