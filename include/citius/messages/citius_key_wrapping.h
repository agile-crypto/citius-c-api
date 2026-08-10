/**
 * @file citius_key_wrapping.h
 * @brief WrapKey / UnwrapKey request and response structs.
 *
 * Mirrors api/proto/messages/key_wrapping.proto.
 *
 * Proto correspondence
 * --------------------
 *  WrapKeyRequest    → citius_wrap_key_request_t
 *  WrapKeyResponse   → citius_wrap_key_response_t
 *  UnwrapKeyRequest  → citius_unwrap_key_request_t
 *  UnwrapKeyResponse → citius_unwrap_key_response_t
 */

#ifndef CITIUS_MESSAGES_KEY_WRAPPING_H
#define CITIUS_MESSAGES_KEY_WRAPPING_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_operation_params.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyMetadata and citius_wrap_format_t are defined in
 * messages/citius_key_management.h and types/citius_common.h respectively.
 * Forward-declare only what is needed to avoid circular includes. */
#ifndef CITIUS_KEY_METADATA_DEFINED
struct citius_key_metadata_s;
typedef struct citius_key_metadata_s citius_key_metadata_t;
#define CITIUS_KEY_METADATA_DEFINED 1
#endif

/* citius_wrap_format_t is defined in citius/types/citius_common.h,
 * included above. */

/* =========================================================================
 * Key-wrapping scope parameters tagged union
 * (proto: oneof scope_params in WrapKeyRequest / UnwrapKeyRequest)
 * oneof: NoParams | KeyAgreementWrapParams | GostWrapOperationParams |
 *        VendorWrapParams
 * ========================================================================= */

typedef enum {
    CITIUS_WRAP_PARAMS_NONE             = 0, /**< AES-KW, AES-KWP, RSA key wrap */
    CITIUS_WRAP_PARAMS_KEY_AGREEMENT    = 1, /**< ECDH-ES+AES-KW, ECMQV         */
    CITIUS_WRAP_PARAMS_GOST             = 2, /**< GOST key wrapping              */
    CITIUS_WRAP_PARAMS_VENDOR           = 3  /**< Vendor/custom scope            */
} citius_wrap_params_type_t;

typedef struct {
    citius_wrap_params_type_t type; /**< Discriminator — which union arm is valid.
                                         NONE means no per-call params required
                                         (proto: NoParams); the params union is not read. */
    union {
        citius_key_agreement_wrap_operation_params_t  key_agreement; /**< CITIUS_WRAP_PARAMS_KEY_AGREEMENT */
        citius_gost_wrap_operation_params_t           gost;          /**< CITIUS_WRAP_PARAMS_GOST          */
        citius_vendor_wrap_params_t                   vendor;        /**< CITIUS_WRAP_PARAMS_VENDOR        */
    } params;
} citius_wrap_params_t;

/** Convenience: explicit no-params (standard wrapping). */
#define CITIUS_WRAP_PARAMS_NONE_INIT \
    ((citius_wrap_params_t){ .type = CITIUS_WRAP_PARAMS_NONE })

/* =========================================================================
 * WrapKeyRequest / WrapKeyResponse
 * ========================================================================= */

typedef struct {
    const char               *key_to_wrap_name;
    const char               *wrapping_key_name;
    citius_wrap_format_t      format;
    citius_wrap_params_t      scope_params; /**< REQUIRED — one of: NONE (AES-KW/AES-KWP/RSA),
                                                 KEY_AGREEMENT (ECDH-ES+AES-KW),
                                                 GOST, VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_wrap_key_request_t;

typedef struct {
    citius_mutable_buffer_t      wrapped_key;
    citius_operation_metadata_t  metadata;
} citius_wrap_key_response_t;

/* =========================================================================
 * UnwrapKeyRequest / UnwrapKeyResponse
 * ========================================================================= */

typedef struct {
    citius_byte_buffer_t       wrapped_key;
    const char                *wrapping_key_name;
    const char                *unwrapped_key_name;        /**< nullable */
    const char                *unwrapped_key_template_id; /**< nullable */
    citius_wrap_format_t       format;
    citius_operation_metadata_t metadata;
    citius_wrap_params_t       scope_params; /**< REQUIRED — must match scope used during wrapping */
    const citius_map_t        *user_context; /**< nullable */
} citius_unwrap_key_request_t;

typedef struct {
    uint8_t                      success;
    const char                  *message;      /**< nullable */
    citius_operation_metadata_t  metadata;
    citius_key_metadata_t        key_metadata;
} citius_unwrap_key_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_KEY_WRAPPING_H */
