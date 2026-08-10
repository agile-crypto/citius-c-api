/**
 * @file citius_crypto_policy_service.h
 * @brief Cryptographic policy lifecycle and evaluation (CryptoPolicyService).
 *
 * C mirror of api/proto/services/crypto_policy_service.proto —
 * CryptoPolicyService.
 *
 * This service manages cryptographic policies and provides policy evaluation:
 *   - CRUD operations on crypto policies (create, read, update, delete, list)
 *   - Single and batch policy evaluation (pre-flight checks)
 *
 * Crypto policies govern:
 *   - Which algorithm templates are allowed for a given scope
 *   - Minimum security level requirements (e.g. 256-bit minimum)
 *   - Compliance constraints (e.g. FIPS-approved only, quantum-safe only)
 *
 * Note: To change which policy is bound to a specific KEY, use
 * citius_key_update_policy() (KeyManagementService).  This service manages
 * the policy RESOURCE itself.
 *
 * Proto → C mapping
 * -----------------
 *   rpc CreateCryptoPolicy(CreateCryptoPolicyRequest) → CreateCryptoPolicyResponse
 *       citius_create_crypto_policy(request*, response*)
 *
 *   rpc ReadCryptoPolicy(ReadCryptoPolicyRequest) → ReadCryptoPolicyResponse
 *       citius_read_crypto_policy(request*, response*)
 *
 *   rpc DeleteCryptoPolicy(DeleteCryptoPolicyRequest) → DeleteCryptoPolicyResponse
 *       citius_delete_crypto_policy(request*, response*)
 *
 *   rpc UpdateCryptoPolicy(UpdateCryptoPolicyRequest) → UpdateCryptoPolicyResponse
 *       citius_update_crypto_policy(request*, response*)
 *
 *   rpc ListCryptoPolicies(ListCryptoPoliciesRequest) → ListCryptoPoliciesResponse
 *       citius_list_crypto_policies(request*, response*)
 *
 *   rpc EvaluatePolicy(EvaluatePolicyRequest) → EvaluatePolicyResponse
 *       citius_evaluate_policy(request*, response*)
 *
 *   rpc BatchEvaluatePolicy(BatchEvaluatePolicyRequest) → BatchEvaluatePolicyResponse
 *       citius_batch_evaluate_policy(request*, response*)
 *
 * HTTP REST paths (from proto annotations):
 *   POST   /v1/policies/{name}                  citius_create_crypto_policy()
 *   GET    /v1/policies/{name}                  citius_read_crypto_policy()
 *   DELETE /v1/policies/{name}                  citius_delete_crypto_policy()
 *   PUT    /v1/policies/{name}                  citius_update_crypto_policy()
 *   GET    /v1/policies                         citius_list_crypto_policies()
 *   POST   /v1/policies/{policy_name}/evaluate  citius_evaluate_policy()
 *   POST   /v1/policies/evaluate/batch          citius_batch_evaluate_policy()
 */

#ifndef CITIUS_SERVICES_CRYPTO_POLICY_SERVICE_H
#define CITIUS_SERVICES_CRYPTO_POLICY_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/messages/citius_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

CITIUS_RV citius_create_crypto_policy(
    const citius_create_crypto_policy_request_t   *request,
    citius_create_crypto_policy_response_t        *response
);

CITIUS_RV citius_read_crypto_policy(
    const citius_read_crypto_policy_request_t     *request,
    citius_read_crypto_policy_response_t          *response
);

CITIUS_RV citius_delete_crypto_policy(
    const citius_delete_crypto_policy_request_t   *request,
    citius_delete_crypto_policy_response_t        *response
);

CITIUS_RV citius_update_crypto_policy(
    const citius_update_crypto_policy_request_t   *request,
    citius_update_crypto_policy_response_t        *response
);

CITIUS_RV citius_list_crypto_policies(
    const citius_list_crypto_policies_request_t   *request,
    citius_list_crypto_policies_response_t        *response
);

CITIUS_RV citius_evaluate_policy(
    const citius_evaluate_policy_request_t        *request,
    citius_evaluate_policy_response_t             *response
);

CITIUS_RV citius_batch_evaluate_policy(
    const citius_batch_evaluate_policy_request_t  *request,
    citius_batch_evaluate_policy_response_t       *response
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_CRYPTO_POLICY_SERVICE_H */
