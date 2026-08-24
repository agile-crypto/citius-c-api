/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_policy.h — CryptoPolicyService (7 RPCs; api/services/crypto_policy_service.proto
 * and api/messages/policy.proto). Fields verified directly against the proto:
 * there is NO policy format and NO optimistic-concurrency version anywhere
 * on the wire (CreateCryptoPolicyRequest is {name, policy_document};
 * PolicySummary is {name, created_at, updated_at}) -- an earlier draft of
 * this reconciliation invented a format string, a version counter, and a
 * CRYPTO_ERROR_POLICY_VERSION_CONFLICT code to go with it. See
 * docs/PROTO_RFCS.md RFC-02 (commit 13) for that as a proposed extension.
 *
 * The policy document itself stays an OPAQUE STRING, exactly as in the
 * proto -- the API deliberately does not know whether a deployment writes
 * JSON, Rego or Cedar. Projecting any policy schema into C would freeze one
 * policy language into the ABI.
 */

#ifndef AGC_POLICY_H
#define AGC_POLICY_H

#include "agc_core.h"
#include "agc_scope.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Policy CRUD
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_create_policy(agc_ctx *ctx, const char *name, const char *policy_document);

typedef struct agc_policy_document {
    size_t      struct_size;
    const char *name;
    const char *policy_document;
} agc_policy_document;

/* The strings in *out are owned by the library and invalidated by
 * agc_policy_document_release(). */
AGC_API agc_rc agc_read_policy(agc_ctx *ctx, const char *name, agc_policy_document *out);
AGC_API void   agc_policy_document_release(agc_policy_document *doc);

AGC_API agc_rc agc_update_policy(agc_ctx *ctx, const char *name, const char *policy_document);

/* Fails while keys are still bound to the policy (referential integrity);
 * the reason is available from agc_last_error(). */
AGC_API agc_rc agc_delete_policy(agc_ctx *ctx, const char *name);

/* name_prefix may be NULL to list all. */
AGC_API agc_rc agc_list_policies(agc_ctx *ctx, const char *name_prefix, uint32_t page_size,
                                  agc_policy_iter **out_iter);

typedef struct agc_policy_summary {
    const char   *name;
    agc_timestamp created_at;
    agc_timestamp updated_at;
} agc_policy_summary;

/* The strings in *out are owned by the iterator and invalidated by the next
 * call to agc_policy_iter_next() on the same iterator. */
AGC_API agc_rc agc_policy_iter_next(agc_policy_iter *it, agc_policy_summary *out);
AGC_API void   agc_policy_iter_free(agc_policy_iter *it);

/* --------------------------------------------------------------------------
 * Policy evaluation
 * -------------------------------------------------------------------------- */

typedef struct agc_evaluate_policy_request {
    size_t                struct_size;
    const char           *policy_name;   /* REQUIRED */
    agc_crypto_operation   operation;     /* REQUIRED; UNSPECIFIED is rejected */

    /* Context. The proto requires at least one of these to be present (CEL
     * rule "evaluation_context_required"); the same check is applied here. */
    const char           *key_name;
    const char           *template_id;
    const agc_scope_spec *scope_spec;
    const char           *provider_id;
    agc_kv_list           properties;
} agc_evaluate_policy_request;

/* Read-only: performs no cryptographic work. A DENIED decision is still a
 * SUCCESSFUL call -- it returns AGC_OK with agc_policy_decision_allowed()
 * reporting 0. Mapping denial onto an error code would make it impossible
 * to distinguish "policy says no" from "policy engine is broken". */
AGC_API agc_rc agc_evaluate_policy(agc_ctx *ctx, const agc_evaluate_policy_request *req,
                                    agc_policy_decision **out_decision);

/* requests is an array of `count` requests; out_decisions must point to an
 * array of `count` pointers, filled in request order, each freed
 * individually. */
AGC_API agc_rc agc_batch_evaluate_policy(agc_ctx *ctx, const agc_evaluate_policy_request *requests,
                                          size_t count, agc_policy_decision **out_decisions,
                                          int32_t *out_allowed_count, int32_t *out_denied_count);

AGC_API void agc_policy_decision_free(agc_policy_decision *d);

AGC_API int                      agc_policy_decision_allowed(const agc_policy_decision *d);
AGC_API agc_policy_denial_reason agc_policy_decision_denial_reason(const agc_policy_decision *d);
AGC_API const char              *agc_policy_decision_message(const agc_policy_decision *d);

/* PolicyDecisionDetails -- audit trail for the decision.
 *
 * checks_performed lists every check the evaluator actually ran; since
 * this stub evaluator's real semantics are a single substring test against
 * the opaque policy document (see policy.c's module comment), that list
 * always has exactly one entry: the operation name checked.
 * PolicyDecisionDetails.allowed_operations is NOT projected here -- the
 * stub evaluator answers "is THIS operation allowed", never "list every
 * operation this policy allows", which is a different (and, for an opaque
 * text document, considerably harder) question this reconciliation does
 * not attempt. */
AGC_API const char   *agc_policy_decision_policy_name(const agc_policy_decision *d);
AGC_API const char   *agc_policy_decision_policy_version(const agc_policy_decision *d);
AGC_API agc_timestamp agc_policy_decision_timestamp(const agc_policy_decision *d);
AGC_API const char   *agc_policy_decision_failed_check(const agc_policy_decision *d);
AGC_API size_t        agc_policy_decision_checks_performed_count(const agc_policy_decision *d);
AGC_API const char   *agc_policy_decision_checks_performed_at(const agc_policy_decision *d, size_t i);

/* Helpful alternatives for a denied decision. Always 0 items in this
 * build: the minimal evaluator never computes an allow-list of OTHER
 * templates, only a yes/no on the one operation asked about. */
AGC_API size_t      agc_policy_decision_allowed_templates_count(const agc_policy_decision *d);
AGC_API const char *agc_policy_decision_allowed_template_at(const agc_policy_decision *d, size_t i);

#ifdef __cplusplus
}
#endif
#endif /* AGC_POLICY_H */
