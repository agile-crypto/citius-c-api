/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_policy.h — CryptoPolicyService (7 RPCs).
 *
 * Policy CRUD plus pre-flight evaluation.
 *
 * The policy document stays an OPAQUE STRING here exactly as in the proto. The
 * API deliberately does not know whether a deployment writes JSON, Rego or
 * Cedar; `format` names the language so that tooling can parse it and the
 * server can validate it. Projecting a policy schema into C would freeze one
 * policy language into the ABI and defeat the point of the abstraction.
 */

#ifndef AGC_POLICY_H
#define AGC_POLICY_H

#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Policy CRUD
 * -------------------------------------------------------------------------- */

/* format may be NULL, in which case the server's default policy format applies.
 * *out_version receives the initial version (1). */
AGC_API agc_rc agc_create_policy(agc_ctx *ctx, const char *name,
                                 const char *policy_document, const char *format,
                                 int64_t *out_version);

typedef struct agc_policy_document {
    size_t        struct_size;
    const char   *name;
    const char   *policy_document;
    const char   *format;
    int64_t       version;
    agc_timestamp created_at;
    agc_timestamp updated_at;
} agc_policy_document;

/* The strings in *out are owned by the library and are invalidated by
 * agc_policy_document_release. */
AGC_API agc_rc agc_read_policy(agc_ctx *ctx, const char *name,
                               agc_policy_document *out);
AGC_API void   agc_policy_document_release(agc_policy_document *doc);

/* expected_version implements optimistic concurrency. Pass 0 for
 * last-writer-wins, which is NOT RECOMMENDED for shared governance artifacts;
 * a mismatch returns AGC_ERR_CRYPTO_POLICY_VERSION_CONFLICT. */
AGC_API agc_rc agc_update_policy(agc_ctx *ctx, const char *name,
                                 const char *policy_document, const char *format,
                                 int64_t expected_version,
                                 int64_t *out_new_version);

/* Fails while keys are still bound to the policy (referential integrity);
 * the reason is available from agc_last_error(). */
AGC_API agc_rc agc_delete_policy(agc_ctx *ctx, const char *name);

/* name_prefix may be NULL to list all. */
AGC_API agc_rc agc_list_policies(agc_ctx *ctx, const char *name_prefix,
                                 uint32_t page_size, agc_policy_iter **out_iter);

/* --------------------------------------------------------------------------
 * Policy evaluation
 * -------------------------------------------------------------------------- */

typedef struct agc_evaluate_policy_request {
    size_t                struct_size;
    const char           *policy_name;   /* REQUIRED */
    agc_operation         operation;     /* REQUIRED; UNSPECIFIED is rejected */

    /* Context. The proto requires at least one of these to be present (CEL
     * rule "evaluation_context_required"); the same check is applied here and
     * returns AGC_ERR_INVALID_ARGUMENT when all are empty. */
    const char           *key_name;
    const char           *template_id;
    const agc_scope_spec *scope_spec;
    const char           *provider_id;
    agc_kv_list           properties;
} agc_evaluate_policy_request;

/* Read-only: performs no cryptographic work. Note that a DENIED decision is
 * still a SUCCESSFUL call — it returns AGC_OK with *decision reporting
 * allowed == 0. Mapping denial onto an error code would make it impossible to
 * distinguish "policy says no" from "policy engine is broken", which is exactly
 * the distinction a UI enablement check needs. */
AGC_API agc_rc agc_evaluate_policy(agc_ctx *ctx,
                                   const agc_evaluate_policy_request *req,
                                   agc_policy_decision **out_decision);

/* Batch evaluation. requests is an array of `count` requests, bounded to 100 by
 * the proto; exceeding it returns AGC_ERR_INVALID_ARGUMENT. out_decisions must
 * point to an array of `count` pointers, filled in request order; each element
 * must be freed individually. */
AGC_API agc_rc agc_batch_evaluate_policy(agc_ctx *ctx,
                                         const agc_evaluate_policy_request *requests,
                                         size_t count,
                                         agc_policy_decision **out_decisions,
                                         int32_t *out_allowed_count,
                                         int32_t *out_denied_count);

AGC_API void agc_policy_decision_free(agc_policy_decision *d);

AGC_API int                      agc_policy_decision_allowed(const agc_policy_decision *d);
AGC_API agc_policy_denial_reason agc_policy_decision_denial_reason(const agc_policy_decision *d);
AGC_API const char              *agc_policy_decision_message(const agc_policy_decision *d);

/* PolicyDecisionDetails — audit trail for the decision. */
AGC_API const char   *agc_policy_decision_policy_name(const agc_policy_decision *d);
AGC_API const char   *agc_policy_decision_policy_version(const agc_policy_decision *d);
AGC_API agc_timestamp agc_policy_decision_timestamp(const agc_policy_decision *d);
AGC_API const char   *agc_policy_decision_failed_check(const agc_policy_decision *d);
AGC_API size_t        agc_policy_decision_check_count(const agc_policy_decision *d);
AGC_API const char   *agc_policy_decision_check_at(const agc_policy_decision *d, size_t i);

/* Helpful alternatives for a denied decision. */
AGC_API size_t      agc_policy_decision_allowed_template_count(const agc_policy_decision *d);
AGC_API const char *agc_policy_decision_allowed_template_at(const agc_policy_decision *d, size_t i);
AGC_API size_t      agc_policy_decision_allowed_operation_count(const agc_policy_decision *d);
AGC_API agc_rc      agc_policy_decision_allowed_operation_at(const agc_policy_decision *d,
                                                             size_t i, agc_operation *out);
AGC_API size_t      agc_policy_decision_allowed_scope_count(const agc_policy_decision *d);
AGC_API agc_rc      agc_policy_decision_allowed_scope_at(const agc_policy_decision *d,
                                                         size_t i, agc_scope_spec *out);

#ifdef __cplusplus
}
#endif
#endif /* AGC_POLICY_H */
