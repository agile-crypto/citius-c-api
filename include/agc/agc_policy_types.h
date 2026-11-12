/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_policy_types.h — CryptoPolicyService: types.
 *
 * The request and response structs of agc_policy.h, separated from the
 * function declarations.
 *
 * Fields verified against the proto (api v0.3.0): a policy carries a
 * `format` tag next to its document, and a `version` that UpdateCryptoPolicy
 * checks through `expected_version` (optimistic concurrency; a stale value
 * fails with AGC_ERR_CRYPTO_POLICY_VERSION_CONFLICT).
 *
 * The policy document itself stays an OPAQUE STRING, exactly as in the
 * proto -- the API deliberately does not know whether a deployment writes
 * JSON, Rego or Cedar. Projecting any policy schema into C would freeze one
 * policy language into the ABI.
 *
 * Every struct here is CALLER-ALLOCATED and begins with struct_size
 * (AGC_INIT): the library writes only into regions the caller placed in the
 * response, allocates nothing the caller sees, and there is nothing to free.
 * Rules: docs/agc_crypto.md.
 *
 * Create, Update and Delete have no response type: their proto responses
 * carry only success/message, which collapse into agc_rc and agc_last_error
 * (D4), leaving nothing to project.
 *
 * STORAGE CONTRACT (applies to every record with a `storage` field)
 * ------------------------------------------------------------------
 * Scalars are written inline. Every variable-length value -- strings and
 * arrays -- is COPIED into the caller-provided `storage` region, and the
 * record's pointers are set into it. `storage_used` receives the bytes
 * consumed. The record is valid for as long as `storage` is; nothing in it
 * references library memory. A by-value copy of the record shares the
 * storage.
 *
 * Size query: if `storage.data` is NULL or `storage.cap` is smaller than
 * required, the call returns AGC_ERR_BUFFER_TOO_SMALL with `storage_used`
 * set to the requirement and writes no other field of the record. Every
 * evaluation and read in this service is read-only, so the requirement is
 * exact.
 *
 * The caller MUST AGC_INIT() every record before the call and may then set
 * only `storage` (and, for the batch response, the results array).
 */

#ifndef AGC_POLICY_TYPES_H
#define AGC_POLICY_TYPES_H

#include "agc_core.h"
#include "agc_scope.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Policy CRUD
 * -------------------------------------------------------------------------- */

/* CreateCryptoPolicyRequest. */
typedef struct agc_create_policy_request {
    size_t      struct_size;
    const char *name;             /* REQUIRED */
    const char *policy_document;  /* REQUIRED -- opaque to this API */
    const char *format;           /* "json", "rego", ...; NULL or "" => the service's default */
} agc_create_policy_request;

/* UpdateCryptoPolicyRequest. The document replaces the existing one
 * entirely; there is no field masking on the wire. */
typedef struct agc_update_policy_request {
    size_t      struct_size;
    const char *name;             /* REQUIRED */
    const char *policy_document;  /* REQUIRED -- replaces the existing document */
    const char *format;           /* NULL or "" => the service's default */
    /* Optimistic concurrency: if > 0, the update applies only when the
     * stored version equals it, else AGC_ERR_CRYPTO_POLICY_VERSION_CONFLICT.
     * 0 means last writer wins (NOT RECOMMENDED for shared policies). */
    int64_t     expected_version;
} agc_update_policy_request;

/* ReadCryptoPolicyResponse {name, policy_document}. Caller-allocated; see
 * STORAGE CONTRACT. ReadCryptoPolicyRequest is {name}, flattened to a bare
 * string at the call site. */
typedef struct agc_read_policy_response {
    size_t      struct_size;
    const char *name;             /* NUL-terminated, in storage */
    const char *policy_document;  /* NUL-terminated, in storage */
    const char *format;           /* NUL-terminated, in storage */
    int64_t     version;          /* pass as expected_version for a safe update */
    agc_timestamp created_at;
    agc_timestamp updated_at;
    agc_buf     storage;          /* IN: caller region */
    size_t      storage_used;     /* OUT: bytes consumed, or required */
} agc_read_policy_response;

/* --------------------------------------------------------------------------
 * ListCryptoPolicies
 * -------------------------------------------------------------------------- */

/* ListCryptoPoliciesRequest. `page_token` is NOT projected: the iterator
 * holds that bookkeeping (D12), and ListCryptoPoliciesResponse's
 * next_page_token is consumed by the same iterator. See
 * docs/divergence_c_vs_proto.md for the pending caller-allocated
 * alternative. */
typedef struct agc_list_policies_request {
    size_t      struct_size;
    const char *name_prefix;  /* NULL or "" => list all */
    uint32_t    page_size;    /* 0 => implementation default */
} agc_list_policies_request;

/* PolicySummary: a lightweight view of one policy. Use agc_read_policy to
 * retrieve the full document.
 *
 * DESCRIPTIVE ONLY: no storage of its own; `name` points into the enclosing
 * agc_policy_summary_response's storage. */
typedef struct agc_policy_summary {
    size_t        struct_size;
    const char   *name;          /* NUL-terminated, in the response's storage */
    agc_timestamp created_at;
    agc_timestamp updated_at;
    int64_t       version;
    const char   *format;        /* NUL-terminated, in the response's storage */
} agc_policy_summary;

/* The single-summary response, filled by the ListCryptoPolicies iterator. It
 * exists because agc_policy_summary is descriptive only and needs a region to
 * be written into; see STORAGE CONTRACT. */
typedef struct agc_policy_summary_response {
    size_t             struct_size;
    agc_policy_summary summary;
    agc_buf            storage;       /* IN: caller region */
    size_t             storage_used;  /* OUT: bytes consumed, or required */
} agc_policy_summary_response;

/* --------------------------------------------------------------------------
 * Policy evaluation
 * -------------------------------------------------------------------------- */

/* EvaluatePolicyRequest. */
typedef struct agc_evaluate_policy_request {
    size_t               struct_size;
    const char          *policy_name;  /* REQUIRED */
    agc_crypto_operation operation;    /* REQUIRED; UNSPECIFIED is rejected */

    /* Context. The proto requires at least one of these to be present (CEL
     * rule "evaluation_context_required"); the same check is applied here. */
    const char           *key_name;     /* key-bound operations: encrypt, sign, ... */
    const char           *template_id;  /* pre-flight check before key creation */
    const agc_scope_spec *scope_spec;   /* what is available for a given intent */
    const char           *provider_id;  /* is this provider policy-allowed */

    /* Properties to validate against policy requirements, e.g.
     * {"security_level": "256-bit", "pqc_ready": "true"}. */
    agc_kv_list           properties;
} agc_evaluate_policy_request;

/* PolicyDecisionDetails: audit information about one decision. Embedded by
 * value; every pointer below points into the enclosing response's storage. */
typedef struct agc_policy_decision_details {
    const char   *policy_name;     /* NUL-terminated, in the response's storage */
    const char   *policy_version;  /* NUL-terminated, in storage; "" if unversioned */
    agc_timestamp evaluation_timestamp;

    /* Checks that were performed. Array of NUL-terminated strings in the
     * response's storage. */
    const char  **checks_performed;
    size_t        checks_performed_count;

    const char   *failed_check;    /* NUL-terminated, in storage; "" if allowed */

    /* Helpful alternatives for a denied decision. Each array lives in the
     * response's storage; all three may be empty. */
    const char                **allowed_templates;
    size_t                      allowed_templates_count;
    const agc_crypto_operation *allowed_operations;
    size_t                      allowed_operations_count;
    const agc_scope_spec       *allowed_scopes;
    size_t                      allowed_scopes_count;
} agc_policy_decision_details;

/* One decision: the projection of EvaluatePolicyResponse. Carries no storage
 * of its own, so that a batch can hold an array of decisions over one shared
 * region. */
typedef struct agc_policy_decision {
    int                         allowed;        /* non-zero if the operation is allowed */
    agc_policy_denial_reason    denial_reason;  /* meaningful only when !allowed */
    const char                 *message;        /* NUL-terminated, in the response's storage */

    /* `details` is a message field on the wire, so absence is distinct from
     * an all-empty record: has_details is 0 when the evaluator published
     * none. */
    int                         has_details;
    agc_policy_decision_details details;
} agc_policy_decision;

typedef struct agc_evaluate_policy_response {
    size_t              struct_size;
    agc_policy_decision decision;
    agc_buf             storage;       /* IN: caller region for the decision's strings and arrays */
    size_t              storage_used;  /* OUT: bytes consumed, or required */
} agc_evaluate_policy_response;

/* BatchEvaluatePolicyRequest: several evaluations in one call, useful for UI
 * initialisation. The array is borrowed for the duration of the call. */
typedef struct agc_batch_evaluate_policy_request {
    size_t                             struct_size;
    const agc_evaluate_policy_request *evaluations;
    size_t                             evaluations_count;
} agc_batch_evaluate_policy_request;

/* BatchEvaluatePolicyResponse. Caller-allocated: the caller supplies both
 * the array of decisions and the one storage region their strings and arrays
 * are copied into.
 *
 * Two-call on the array as well as on storage: if `results` is NULL or
 * `results_cap` is smaller than the number of evaluations, the call returns
 * AGC_ERR_BUFFER_TOO_SMALL with results_count set to the number of entries
 * required and storage_used set to the bytes required, and writes nothing
 * else. */
typedef struct agc_batch_evaluate_policy_response {
    size_t               struct_size;
    agc_policy_decision *results;       /* IN: caller array of results_cap entries.
                                           OUT: filled, in request order */
    size_t               results_cap;   /* IN: capacity of `results`, in entries */
    size_t               results_count; /* OUT: entries written, or required */
    int32_t              allowed_count; /* OUT: how many of `results` are allowed */
    int32_t              denied_count;  /* OUT: how many are denied */
    agc_buf              storage;       /* IN: caller region for every decision's strings and arrays */
    size_t               storage_used;  /* OUT: bytes consumed, or required */
} agc_batch_evaluate_policy_response;

#ifdef __cplusplus
}
#endif
#endif /* AGC_POLICY_TYPES_H */
