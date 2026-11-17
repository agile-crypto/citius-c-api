/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_policy.h — CryptoPolicyService (7 RPCs;
 * api/services/crypto_policy_service.proto and api/messages/policy.proto).
 *
 * Functions only. Every request and response type they name is defined in
 * agc_policy_types.h, which also states the STORAGE CONTRACT that governs
 * every caller-allocated record below.
 *
 * SHAPE OF EVERY CALL
 * -------------------
 *     agc_rc agc_<op>(agc_ctx *ctx, const agc_<op>_request *req, agc_<op>_response *resp);
 *
 * One request struct, one response struct, both CALLER-ALLOCATED, both
 * beginning with struct_size (AGC_INIT). The library writes only into
 * regions the caller placed in the response; it allocates nothing the caller
 * sees and there is nothing to free, except the one iterator handle.
 * Rules: docs/agc_crypto.md.
 *
 * Two shapes differ, for reasons recorded here:
 *   - Create, Update and Delete take no response parameter. Their proto
 *     responses carry only success/message, which collapse into agc_rc and
 *     agc_last_error (D4), leaving nothing to project.
 *   - Read and Delete take a bare `const char *name` rather than a
 *     one-field request struct, matching agc_read_key and agc_delete_key.
 */

#ifndef AGC_POLICY_H
#define AGC_POLICY_H

#include "agc_core.h"
#include "agc_policy_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Policy CRUD
 * -------------------------------------------------------------------------- */

/* CreateCryptoPolicyResponse is {success, message, version}: success and
 * message collapse into the return code and agc_last_error (D4); version
 * (1 for a new policy) goes to *out_version, which may be NULL. */
AGC_API agc_rc agc_create_policy(agc_ctx *ctx, const agc_create_policy_request *req,
                                  int64_t *out_version);

/* UpdateCryptoPolicyResponse is {success, message, version}; as for create,
 * the new version goes to *out_version, which may be NULL. */
AGC_API agc_rc agc_update_policy(agc_ctx *ctx, const agc_update_policy_request *req,
                                  int64_t *out_version);

/* ReadCryptoPolicyRequest is {name}, flattened to a bare string. */
AGC_API agc_rc agc_read_policy(agc_ctx *ctx, const char *name,
                                agc_read_policy_response *resp);

/* DeleteCryptoPolicyRequest is {name}, flattened; DeleteCryptoPolicyResponse
 * is {success, message}, which collapse (D4). Fails while keys are still bound to
 * the policy (referential integrity); the reason is available from
 * agc_last_error(). */
AGC_API agc_rc agc_delete_policy(agc_ctx *ctx, const char *name);

/* --------------------------------------------------------------------------
 * ListCryptoPolicies
 * -------------------------------------------------------------------------- */

/* The iterator is a library-owned handle (it has a lifecycle: paging
 * bookkeeping, D12); the records it yields are caller-allocated. */
AGC_API agc_rc agc_list_policies(agc_ctx *ctx, const agc_list_policies_request *req,
                                  agc_policy_iter **out_iter);

/* Fills *out with the next policy summary. On AGC_ERR_BUFFER_TOO_SMALL the
 * cursor does not advance, so the caller may resize out->storage and call
 * again for the same policy. AGC_ERR_ITERATOR_EXHAUSTED at the end. A caller
 * may reuse one record and one storage region across the whole loop. */
AGC_API agc_rc agc_policy_iter_next(agc_policy_iter *it, agc_policy_summary_response *out);
AGC_API void   agc_policy_iter_free(agc_policy_iter *it);

/* --------------------------------------------------------------------------
 * Policy evaluation
 * -------------------------------------------------------------------------- */

/* Read-only: performs no cryptographic work. A DENIED decision is still a
 * SUCCESSFUL call -- it returns AGC_OK with resp->decision.allowed == 0.
 * Mapping denial onto an error code would make it impossible to distinguish
 * "policy says no" from "policy engine is broken". */
AGC_API agc_rc agc_evaluate_policy(agc_ctx *ctx, const agc_evaluate_policy_request *req,
                                    agc_evaluate_policy_response *resp);

/* Evaluates several requests in one call, filling resp->results in request
 * order. Same read-only contract as agc_evaluate_policy: a denied decision
 * is a successful call. */
AGC_API agc_rc agc_batch_evaluate_policy(agc_ctx *ctx,
                                          const agc_batch_evaluate_policy_request *req,
                                          agc_batch_evaluate_policy_response *resp);

#ifdef __cplusplus
}
#endif
#endif /* AGC_POLICY_H */
