/**
 * @file citius_policy.h  (messages/)
 * @brief Crypto policy management and evaluation request/response structs.
 *
 * Mirrors api/proto/messages/policy.proto.
 *
 * Proto correspondence
 * --------------------
 *  CreateCryptoPolicyRequest    → citius_create_crypto_policy_request_t
 *  CreateCryptoPolicyResponse   → citius_create_crypto_policy_response_t
 *  ReadCryptoPolicyRequest      → citius_read_crypto_policy_request_t
 *  ReadCryptoPolicyResponse     → citius_read_crypto_policy_response_t
 *  UpdateCryptoPolicyRequest    → citius_update_crypto_policy_request_t
 *  UpdateCryptoPolicyResponse   → citius_update_crypto_policy_response_t
 *  DeleteCryptoPolicyRequest    → citius_delete_crypto_policy_request_t
 *  DeleteCryptoPolicyResponse   → citius_delete_crypto_policy_response_t
 *  ListCryptoPoliciesRequest    → citius_list_crypto_policies_request_t
 *  ListCryptoPoliciesResponse   → citius_list_crypto_policies_response_t
 *  PolicySummary                → citius_policy_summary_t
 *  PolicyDenialReason (enum)    → citius_policy_denial_reason_t
 *  PolicyDecisionDetails        → citius_policy_decision_details_t
 *  EvaluatePolicyRequest        → citius_evaluate_policy_request_t
 *  EvaluatePolicyResponse       → citius_evaluate_policy_response_t
 *  BatchEvaluatePolicyRequest   → citius_batch_evaluate_policy_request_t
 *  BatchEvaluatePolicyResponse  → citius_batch_evaluate_policy_response_t
 */

#ifndef CITIUS_MESSAGES_POLICY_H
#define CITIUS_MESSAGES_POLICY_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_templates.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * CreateCryptoPolicyRequest / CreateCryptoPolicyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
    const char *policy_document;
} citius_create_crypto_policy_request_t;

typedef struct {
    uint8_t     success;
    const char *message; /**< nullable */
} citius_create_crypto_policy_response_t;

/* =========================================================================
 * ReadCryptoPolicyRequest / ReadCryptoPolicyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
} citius_read_crypto_policy_request_t;

typedef struct {
    const char *name;
    const char *policy_document;
} citius_read_crypto_policy_response_t;

/* =========================================================================
 * UpdateCryptoPolicyRequest / UpdateCryptoPolicyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
    const char *policy_document; /**< Replaces existing document entirely */
} citius_update_crypto_policy_request_t;

typedef struct {
    uint8_t     success;
    const char *message; /**< nullable */
} citius_update_crypto_policy_response_t;

/* =========================================================================
 * DeleteCryptoPolicyRequest / DeleteCryptoPolicyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
} citius_delete_crypto_policy_request_t;

typedef struct {
    uint8_t success;
} citius_delete_crypto_policy_response_t;

/* =========================================================================
 * PolicySummary  (proto: PolicySummary)
 * ========================================================================= */

typedef struct {
    const char *name;
    const char *created_at; /**< ISO 8601 timestamp; nullable */
    const char *updated_at; /**< ISO 8601 timestamp; nullable */
} citius_policy_summary_t;

/* =========================================================================
 * ListCryptoPoliciesRequest / ListCryptoPoliciesResponse
 * ========================================================================= */

typedef struct {
    const char *name_prefix;  /**< nullable — empty string or NULL means all */
    int32_t     page_size;    /**< 0 = server default = return all */
    const char *page_token;   /**< nullable */
} citius_list_crypto_policies_request_t;

typedef struct {
    const citius_policy_summary_t *policies;        /**< array */
    size_t                         policy_count;
    const char                    *next_page_token; /**< nullable */
} citius_list_crypto_policies_response_t;

/* =========================================================================
 * PolicyDenialReason  (proto: PolicyDenialReason)
 * ========================================================================= */

typedef enum {
    CITIUS_POLICY_DENIAL_REASON_UNSPECIFIED              = 0,
    CITIUS_POLICY_DENIAL_REASON_POLICY_NOT_FOUND         = 1,
    CITIUS_POLICY_DENIAL_REASON_OPERATION_NOT_ALLOWED    = 2,
    CITIUS_POLICY_DENIAL_REASON_TEMPLATE_NOT_ALLOWED     = 3,
    CITIUS_POLICY_DENIAL_REASON_SCOPE_NOT_ALLOWED        = 4,
    CITIUS_POLICY_DENIAL_REASON_PROVIDER_NOT_ALLOWED     = 5,
    CITIUS_POLICY_DENIAL_REASON_KEY_NOT_FOUND            = 6,
    CITIUS_POLICY_DENIAL_REASON_PROPERTY_MISMATCH        = 7,
    CITIUS_POLICY_DENIAL_REASON_SECURITY_LEVEL_INSUFFICIENT = 8,
    CITIUS_POLICY_DENIAL_REASON_ALGORITHM_DEPRECATED     = 9,
    CITIUS_POLICY_DENIAL_REASON_PQC_REQUIRED             = 10
} citius_policy_denial_reason_t;

/* =========================================================================
 * PolicyDecisionDetails  (proto: PolicyDecisionDetails)
 * ========================================================================= */

typedef struct {
    const char                        *policy_name;
    const char                        *policy_version;          /**< nullable */
    const char                        *evaluation_timestamp;    /**< ISO 8601; nullable */
    const char * const                *checks_performed;        /**< NULL-terminated array; nullable */
    const char                        *failed_check;            /**< nullable */
    const char * const                *allowed_templates;       /**< NULL-terminated array; nullable */
    const citius_crypto_operation_t   *allowed_operations;      /**< array; nullable */
    size_t                             allowed_operations_count;
    const citius_scope_specification_t *allowed_scopes;         /**< array; nullable */
    size_t                             allowed_scopes_count;
} citius_policy_decision_details_t;

/* =========================================================================
 * EvaluatePolicyRequest / EvaluatePolicyResponse
 * ========================================================================= */

typedef struct {
    const char                   *policy_name;   /**< required */
    citius_crypto_operation_t     operation;     /**< required */
    /* Context: at least one should be provided for meaningful evaluation */
    const char                   *key_name;      /**< nullable */
    const char                   *template_id;   /**< nullable */
    citius_scope_specification_t  scope_spec;
    const char                   *provider_id;   /**< nullable */
    const citius_map_t            *properties;    /**< additional context; nullable */
} citius_evaluate_policy_request_t;

typedef struct {
    uint8_t                           allowed;
    citius_policy_denial_reason_t     denial_reason;
    const char                       *message;  /**< nullable */
    citius_policy_decision_details_t  details;
} citius_evaluate_policy_response_t;

/* =========================================================================
 * BatchEvaluatePolicyRequest / BatchEvaluatePolicyResponse
 * ========================================================================= */

typedef struct {
    const citius_evaluate_policy_request_t *evaluations; /**< array */
    size_t                                  evaluation_count;
} citius_batch_evaluate_policy_request_t;

typedef struct {
    const citius_evaluate_policy_response_t *results;       /**< array, same order as requests */
    size_t                                   result_count;
    int32_t                                  allowed_count;
    int32_t                                  denied_count;
} citius_batch_evaluate_policy_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_POLICY_H */
