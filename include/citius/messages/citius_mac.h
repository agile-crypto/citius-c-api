/**
 * @file citius_mac.h
 * @brief GenerateMAC / VerifyMAC request and response structs.
 *
 * Mirrors api/proto/messages/mac.proto.
 *
 * Proto correspondence
 * --------------------
 *  GenerateMACRequest  → citius_generate_mac_request_t
 *  GenerateMACResponse → citius_generate_mac_response_t
 *  VerifyMACRequest    → citius_verify_mac_request_t
 *  VerifyMACResponse   → citius_verify_mac_response_t
 */

#ifndef CITIUS_MESSAGES_MAC_H
#define CITIUS_MESSAGES_MAC_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_operation_params.h"
#include "citius/messages/citius_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * MAC scope parameters tagged union
 * (proto: oneof scope_params in GenerateMACRequest / VerifyMACRequest)
 * oneof: NoParams | CustomizableMacParams | VendorMacParams
 * ========================================================================= */

typedef enum {
    CITIUS_MAC_PARAMS_NONE          = 0, /**< HMAC, CMAC, Poly1305       */
    CITIUS_MAC_PARAMS_CUSTOMIZABLE  = 1, /**< KMAC128, KMAC256, KMACXOF* */
    CITIUS_MAC_PARAMS_VENDOR        = 2  /**< Vendor/custom scope        */
} citius_mac_params_type_t;

typedef struct {
    citius_mac_params_type_t type; /**< Discriminator — which union arm is valid.
                                        NONE means no per-call params required
                                        (proto: NoParams); the params union is not read. */
    union {
        citius_customizable_mac_params_t  customizable; /**< CITIUS_MAC_PARAMS_CUSTOMIZABLE */
        citius_vendor_mac_params_t        vendor;       /**< CITIUS_MAC_PARAMS_VENDOR       */
    } params;
} citius_mac_params_t;

/** Convenience: explicit no-params (standard MACs). */
#define CITIUS_MAC_PARAMS_NONE_INIT \
    ((citius_mac_params_t){ .type = CITIUS_MAC_PARAMS_NONE })

/* =========================================================================
 * GenerateMACRequest / GenerateMACResponse
 * ========================================================================= */

/**
 * citius_generate_mac_request_t  (proto: GenerateMACRequest)
 *
 * @field scope_params  Use one of:
 *                        CITIUS_MAC_PARAMS_NONE         – HMAC, CMAC, Poly1305
 *                        CITIUS_MAC_PARAMS_CUSTOMIZABLE – KMAC (with customisation string)
 *                        CITIUS_MAC_PARAMS_VENDOR       – vendor/custom
 */
typedef struct {
    const char               *key_name;
    citius_byte_buffer_t      message;
    citius_mac_params_t       scope_params; /**< REQUIRED — one of: NONE (HMAC/CMAC/Poly1305),
                                                 CUSTOMIZABLE (KMAC), VENDOR */
    const citius_map_t       *user_context; /**< nullable */
} citius_generate_mac_request_t;

/**
 * citius_generate_mac_response_t  (proto: GenerateMACResponse)
 *
 * @field mac       Caller-allocated output buffer (size-query supported).
 * @field metadata  Carry to the corresponding VerifyMACRequest so the
 *                  provider can use the correct key version.
 */
typedef struct {
    citius_mutable_buffer_t      mac;
    citius_operation_metadata_t  metadata;
} citius_generate_mac_response_t;

/* =========================================================================
 * VerifyMACRequest / VerifyMACResponse
 * ========================================================================= */

/**
 * citius_verify_mac_request_t  (proto: VerifyMACRequest)
 *
 * @field metadata  OperationMetadata from the GenerateMAC response.
 *                  Carries key_version to ensure the correct key is used.
 * @field scope_params  Must match scope_params used during generation.
 */
typedef struct {
    const char                        *key_name;
    citius_byte_buffer_t               message;
    citius_byte_buffer_t               mac;
    const citius_operation_metadata_t *metadata;
    citius_mac_params_t                scope_params; /**< REQUIRED — must match scope used during generation */
    const citius_map_t                *user_context; /**< nullable */
} citius_verify_mac_request_t;

/**
 * citius_verify_mac_response_t  (proto: VerifyMACResponse)
 *
 * @field valid  1 if the MAC is valid; 0 otherwise.
 *               The function also returns CITIUS_VERIFICATION_FAILED when
 *               valid == 0.
 */
typedef struct {
    uint8_t                      valid;
    citius_operation_metadata_t  metadata;
} citius_verify_mac_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_MAC_H */
