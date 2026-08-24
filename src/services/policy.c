/* SPDX-License-Identifier: Apache-2.0
 *
 * policy.c — CryptoPolicyService entry points over policystore.c, plus the
 * EvaluatePolicy/BatchEvaluatePolicy decision logic.
 *
 * EVALUATION SEMANTICS: the policy document is opaque (no schema is
 * enforced or assumed -- D-plan §4.5), so this stub cannot run CEL/Rego/OPA
 * against it. What it implements instead is small and real, not faked: a
 * policy denies an operation if its document contains the literal substring
 * "deny:<OPERATION_NAME>" or "forbid:<OPERATION_NAME>" (matching the
 * generated agc_crypto_operation_name()), and allows everything else. This
 * is enough to exercise both the allow and deny paths meaningfully; a real
 * deployment plugs a real policy engine in at this one function.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

struct agc_policy_decision {
    int                      allowed;
    agc_policy_denial_reason denial_reason;
    char                    *message;
    char                    *policy_name;
    char                    *failed_check;
    char                   **allowed_templates;
    size_t                   allowed_template_count;
};

static void free_decision(struct agc_policy_decision *d)
{
    if (!d) return;
    free(d->message);
    free(d->policy_name);
    free(d->failed_check);
    for (size_t i = 0; i < d->allowed_template_count; i++) free(d->allowed_templates[i]);
    free(d->allowed_templates);
    free(d);
}

static int has_evaluation_context(const agc_evaluate_policy_request *req)
{
    return (req->key_name && *req->key_name) ||
           (req->template_id && *req->template_id) ||
           (req->scope_spec != NULL) ||
           (req->provider_id && *req->provider_id) ||
           (req->properties.count > 0);
}

static agc_rc evaluate_one(agc_ctx *ctx, const agc_evaluate_policy_request *req,
                            struct agc_policy_decision **out)
{
    *out = NULL;
    if (!req || req->struct_size == 0 || !req->policy_name || !*req->policy_name) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    if (req->operation == AGC_CRYPTO_OPERATION_UNSPECIFIED) return AGC_ERR_INVALID_ARGUMENT;
    if (!has_evaluation_context(req)) return AGC_ERR_INVALID_ARGUMENT;

    agc_policy_document doc;
    AGC_INIT(&doc);
    agc_rc rc = agc_read_policy(ctx, req->policy_name, &doc);
    if (rc != AGC_OK) return rc;

    struct agc_policy_decision *d = calloc(1, sizeof(*d));
    if (!d) { agc_policy_document_release(&doc); return AGC_ERR_OUT_OF_MEMORY; }
    d->policy_name = strdup(req->policy_name);

    const char *op_name = agc_crypto_operation_name(req->operation);
    char deny_needle[160], forbid_needle[160];
    snprintf(deny_needle, sizeof(deny_needle), "deny:%s", op_name);
    snprintf(forbid_needle, sizeof(forbid_needle), "forbid:%s", op_name);

    if (strstr(doc.policy_document, deny_needle) || strstr(doc.policy_document, forbid_needle)) {
        d->allowed = 0;
        d->denial_reason = AGC_POLICY_DENIAL_REASON_OPERATION_NOT_ALLOWED;
        d->message = strdup("operation denied by policy document");
        d->failed_check = strdup(op_name);
    } else {
        d->allowed = 1;
        d->denial_reason = AGC_POLICY_DENIAL_REASON_UNSPECIFIED;
        d->message = strdup("allowed");
    }

    agc_policy_document_release(&doc);
    *out = d;
    return AGC_OK;
}

agc_rc agc_evaluate_policy(agc_ctx *ctx, const agc_evaluate_policy_request *req,
                            agc_policy_decision **out_decision)
{
    if (out_decision) *out_decision = NULL;
    if (!ctx_usable(ctx) || !out_decision) return AGC_ERR_INVALID_ARGUMENT;
    return evaluate_one(ctx, req, out_decision);
}

agc_rc agc_batch_evaluate_policy(agc_ctx *ctx, const agc_evaluate_policy_request *requests, size_t count,
                                  agc_policy_decision **out_decisions, int32_t *out_allowed_count,
                                  int32_t *out_denied_count)
{
    if (!ctx_usable(ctx) || !requests || !out_decisions) return AGC_ERR_INVALID_ARGUMENT;
    int32_t allowed = 0, denied = 0;
    for (size_t i = 0; i < count; i++) {
        agc_rc rc = evaluate_one(ctx, &requests[i], (struct agc_policy_decision **)&out_decisions[i]);
        if (rc != AGC_OK) {
            for (size_t j = 0; j < i; j++) { agc_policy_decision_free(out_decisions[j]); out_decisions[j] = NULL; }
            return rc;
        }
        if (agc_policy_decision_allowed(out_decisions[i])) allowed++; else denied++;
    }
    if (out_allowed_count) *out_allowed_count = allowed;
    if (out_denied_count) *out_denied_count = denied;
    return AGC_OK;
}

void agc_policy_decision_free(agc_policy_decision *d) { free_decision(d); }

int agc_policy_decision_allowed(const agc_policy_decision *d) { return d ? d->allowed : 0; }
agc_policy_denial_reason agc_policy_decision_denial_reason(const agc_policy_decision *d)
{
    return d ? d->denial_reason : AGC_POLICY_DENIAL_REASON_UNSPECIFIED;
}
const char *agc_policy_decision_message(const agc_policy_decision *d) { return d ? d->message : NULL; }
const char *agc_policy_decision_policy_name(const agc_policy_decision *d) { return d ? d->policy_name : NULL; }
const char *agc_policy_decision_policy_version(const agc_policy_decision *d) { (void)d; return NULL; }
agc_timestamp agc_policy_decision_timestamp(const agc_policy_decision *d) { (void)d; return (agc_timestamp){0}; }
const char *agc_policy_decision_failed_check(const agc_policy_decision *d) { return d ? d->failed_check : NULL; }
size_t agc_policy_decision_check_count(const agc_policy_decision *d) { (void)d; return 0; }
const char *agc_policy_decision_check_at(const agc_policy_decision *d, size_t i) { (void)d; (void)i; return NULL; }
size_t agc_policy_decision_allowed_template_count(const agc_policy_decision *d)
{
    return d ? d->allowed_template_count : 0;
}
const char *agc_policy_decision_allowed_template_at(const agc_policy_decision *d, size_t i)
{
    if (!d || i >= d->allowed_template_count) return NULL;
    return d->allowed_templates[i];
}
