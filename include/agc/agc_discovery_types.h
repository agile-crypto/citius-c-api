/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_discovery_types.h — AlgorithmDiscoveryService: types.
 *
 * The request, record and response structs of agc_discovery.h, separated
 * from the function declarations. Every struct here is CALLER-ALLOCATED:
 * the library writes into memory the caller provided and allocates nothing
 * the caller sees. Rules: docs/agc_crypto.md.
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
 * operation in this service is read-only, so the requirement is exact and
 * nothing else happens.
 *
 * The caller MUST AGC_INIT() every record before the call and may then set
 * only `storage` (and, for agc_list_scopes_response, the array).
 *
 * COVERAGE: agc_template_info projects every field of proto TemplateInfo,
 * including the 44-arm AlgorithmDetails oneof (agc_algorithm_params, in
 * agc_algorithm_params.h) and the 14-field CycloneDX record. This reverses
 * the earlier scoping decision of RECONCILIATION_PLAN.md §2.6, which
 * excluded both from the ABI; the cost is that adding an algorithm to the
 * catalog now adds an arm to a public union. See
 * docs/c_vs_proto_constraints.md for the constraints the proto expresses
 * that C cannot.
 */

#ifndef AGC_DISCOVERY_TYPES_H
#define AGC_DISCOVERY_TYPES_H

#include "agc_core.h"
#include "agc_scope.h"
#include "agc_algorithm_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ListTemplates
 * -------------------------------------------------------------------------- */

typedef struct agc_list_templates_params {
    size_t struct_size;

    /* Intent filter, NULL => no scope filter */
    const agc_scope_spec *scope_spec;

    /* Lifecycle filter, NULL => no status filter */
    const agc_template_status *allowed_statuses;
    size_t                     allowed_statuses_count;

    /* A template must reference ALL listed standards. */
    agc_str_list required_standards;

    uint32_t page_size; /* 0 => implementation default */
} agc_list_templates_params;

/* --------------------------------------------------------------------------
 * SecurityGuarantees (proto: SecurityGuarantees, types/common.proto)
 *
 * INFORMATIONAL only: never used for template matching, filtering or policy
 * enforcement. Used for audit trails, CBOM generation and documentation.
 * -------------------------------------------------------------------------- */

/* FormalSecurityNotions. Every field is `optional bool` on the wire, so each
 * is an agc_tribool (D8): AGC_UNSET distinguishes "the catalog makes no
 * claim" from "the catalog claims false". */
typedef struct agc_formal_security_notions {
    /* Encryption notions (proto fields 1-6). */
    agc_tribool ind_cpa;                    /* indistinguishability, chosen-plaintext */
    agc_tribool ind_cca1;                   /* indistinguishability, chosen-ciphertext (lunch-time) */
    agc_tribool ind_cca2;                   /* indistinguishability, adaptive chosen-ciphertext */
    agc_tribool nm_cpa;                     /* non-malleability, chosen-plaintext */
    agc_tribool int_ctxt;                   /* integrity of ciphertext */
    agc_tribool int_ptxt;                   /* integrity of plaintext */

    /* Signature / MAC notions (proto fields 10-12). */
    agc_tribool euf_cma;                    /* existential unforgeability, chosen-message */
    agc_tribool suf_cma;                    /* strong unforgeability, chosen-message */
    agc_tribool prf;                        /* pseudorandom function */

    /* Hash notions (proto fields 20-22). */
    agc_tribool preimage_resistant;
    agc_tribool second_preimage_resistant;
    agc_tribool collision_resistant;

    /* KEM / key-agreement notions (proto fields 30-31). */
    agc_tribool ow_cca;                     /* one-wayness, chosen-ciphertext */
    agc_tribool ind_cca_kem;                /* indistinguishability for KEMs */
} agc_formal_security_notions;

/* PracticalSecurityOutcomes. Plain `bool` on the wire, no presence, so a
 * plain int here: 0 = false. */
typedef struct agc_practical_security_outcomes {
    int confidentiality;   /* unauthorized parties cannot read the data */
    int integrity;         /* modifications are detectable */
    int authenticity;      /* data origin is verifiable */
    int non_repudiation;   /* origin cannot be denied; signatures only */
} agc_practical_security_outcomes;

/* OperationalBounds: safe usage limits. */
typedef struct agc_operational_bounds {
    uint32_t    authentication_strength_bits;  /* e.g. 128 for GCM with a 128-bit tag */
    uint64_t    max_messages_per_key;          /* e.g. 2^32 for AES-GCM with random nonces */
    uint64_t    max_plaintext_bytes_per_key;   /* e.g. 2^36 for AES-GCM */
    const char *attack_success_probability;    /* NUL-terminated, in the enclosing record's storage;
                                                  "2^-32" or "2.33e-10"; "" if unstated */
} agc_operational_bounds;

/* SecurityGuarantees bundles the three above plus an extensibility map.
 * Embedded by value; its strings and map live in the enclosing record's
 * storage. Present at two levels: agc_template_info.security_guarantees is
 * the fallback, agc_scoped_capabilities.security_guarantees overrides it
 * per scope when has_security_guarantees is set. */
typedef struct agc_security_guarantees {
    agc_formal_security_notions     formal;
    agc_practical_security_outcomes practical;
    agc_operational_bounds          bounds;
    agc_kv_list                     additional_properties;  /* items and strings in the enclosing
                                                               record's storage */
} agc_security_guarantees;

/* --------------------------------------------------------------------------
 * ScopedCapabilities (proto: ScopedCapabilities, types/templates.proto)
 * -------------------------------------------------------------------------- */

/* One operational mode of a template: a scope, the operations supported for
 * that scope, and optional per-scope security guarantees. Most templates
 * have exactly one; hybrids and prehashed signatures have several.
 *
 * Array elements of agc_template_info.scoped_capabilities; everything
 * variable-length lives in that record's storage. */
typedef struct agc_scoped_capabilities {
    /* REQUIRED. The scope this capability applies to: scope enum plus filter
     * properties. Inline; the additional_properties of its arm are in the
     * enclosing record's storage. */
    agc_scope_spec               scope;

    /* Operations supported FOR THIS SCOPE; at least one. Array in the
     * enclosing record's storage. Never contains
     * AGC_CRYPTO_OPERATION_UNSPECIFIED. */
    const agc_crypto_operation  *operations;
    size_t                       operations_count;

    /* Per-scope guarantees, overriding agc_template_info.security_guarantees.
     * has_security_guarantees is 0 when the proto field is absent, in which
     * case the template-level value applies. */
    int                          has_security_guarantees;
    agc_security_guarantees      security_guarantees;
} agc_scoped_capabilities;

/* --------------------------------------------------------------------------
 * CycloneDXAlgorithmProperties  (proto: CycloneDXAlgorithmProperties)
 * -------------------------------------------------------------------------- */

 /**
  * Properties of an algorithm in the CycloneDX format.
  * Pointers' value live in the enclosing agc_template_info's storage. The strings are NUL-terminated.
  */
typedef struct {
    const char   *name;
    const char   *primitive;
    const char   *algorithm_family;
    const char   *parameter_set_identifier;
    const char   *elliptic_curve;
    const char   *mode;
    const char   *padding;
    const char  **crypto_functions;
    size_t        crypto_functions_count;
    uint32_t      classical_security_level;
    uint32_t      nist_quantum_security_level;
    const char  **certification_level;
    size_t        certification_level_count;
    const char   *execution_environment;
    const char   *implementation_platform;
    const char   *oid;
} agc_cyclonedx_algorithm_properties;

/* --------------------------------------------------------------------------
 * TemplateInfo (api/types/templates.proto)
 * -------------------------------------------------------------------------- */

/* One algorithm configuration plus its scoped capability.
 *
 * DESCRIPTIVE ONLY: this record carries no storage of its own. Whenever the
 * library fills one, the storage lives in the enclosing
 * agc_template_info_response and every pointer below points into it. */
typedef struct agc_template_info {
    size_t                         struct_size;

    /* Identity. template_id is REQUIRED; the other two may be "". */
    const char                    *template_id;    /* NUL-terminated, in storage */
    const char                    *display_name;   /* NUL-terminated, in storage */
    const char                    *description;    /* NUL-terminated, in storage */

    /* Scope-bundled properties: one entry per operational mode, at least one.
     * Array in storage. */
    const agc_scoped_capabilities *scoped_capabilities;
    size_t                         scoped_capabilities_count;

    /* REQUIRED on the wire, so always written; its strings are in storage. */
    agc_algorithm_details          algorithm;

    agc_template_status            status;
    const char                    *deprecation_notice;  /* NUL-terminated, in storage; REQUIRED
                                                           when status is DEPRECATED */

    /* Applicable standards, e.g. "NIST SP 800-38D", "RFC 8032". Array of
     * NUL-terminated strings in storage. */
    const char                   **standards;
    size_t                         standards_count;

    /* Optional on the wire (proto message presence): has_cyclonedx is 0 when
     * the catalog published none, which is distinct from an all-empty
     * record. */
    int                            has_cyclonedx;
    agc_cyclonedx_algorithm_properties cyclonedx;

    /* Optional on the wire. Template-level fallback: a scope whose
     * agc_scoped_capabilities.has_security_guarantees is set overrides it.
     * has_security_guarantees is 0 when the catalog published none. */
    int                            has_security_guarantees;
    agc_security_guarantees        security_guarantees;
} agc_template_info;

/* The single-template response, shared by agc_get_template and the
 * ListTemplates iterator. It exists because agc_template_info is descriptive
 * only and needs a region to be written into; see STORAGE CONTRACT. */
typedef struct agc_template_info_response {
    size_t            struct_size;
    agc_template_info template_info;
    agc_buf           storage;       /* IN: caller region for every variable-length value */
    size_t            storage_used;  /* OUT: bytes consumed, or required */
} agc_template_info_response;

/* --------------------------------------------------------------------------
 * ListScopes -- no request fields, a bounded ~dozen-entry result set, so a
 * plain array rather than an iterator (D12's stated exception).
 * -------------------------------------------------------------------------- */

/* ScopeInfo (proto: ScopeInfo, types/templates.proto): human-readable
 * information about one scope specification. Carries no storage of its own:
 * everything variable-length lives in the enclosing
 * agc_list_scopes_response's storage. */
typedef struct agc_scope_info {
    /* REQUIRED. The scope specification: the primitive-specific scope enum
     * plus its filter properties. Inline; the additional_properties of its
     * arm are in the response's storage. */
    agc_scope_spec              specification;

    const char                 *name;         /* NUL-terminated, in the response's storage;
                                                 e.g. "Standard Digital Signatures" */
    const char                 *description;  /* NUL-terminated, in the response's storage */

    /* Example use cases for this scope. Array of NUL-terminated strings in
     * the response's storage. */
    const char                **typical_use_cases;
    size_t                      typical_use_cases_count;

    /* Operations typically supported in this scope. Array in the response's
     * storage. */
    const agc_crypto_operation *supported_operations;
    size_t                      supported_operations_count;
} agc_scope_info;

/* ListScopesResponse. Caller-allocated: the caller supplies both the array
 * of records and the storage their strings are copied into.
 *
 * Two-call on the array as well as on storage: if scopes is NULL or
 * scopes_cap is smaller than the number of scopes, the call returns
 * AGC_ERR_BUFFER_TOO_SMALL with scopes_count set to the number of entries
 * required and storage_used set to the bytes required, and writes nothing
 * else. */
typedef struct agc_list_scopes_response {
    size_t          struct_size;
    agc_scope_info *scopes;     /* IN: caller array of scopes_cap entries. OUT: filled */
    size_t          scopes_cap;   /* IN: capacity of scopes, in entries */
    size_t          scopes_count; /* OUT: entries written, or required */
    agc_buf         storage;      /* IN: caller region for the entries' strings */
    size_t          storage_used; /* OUT: bytes consumed, or required */
} agc_list_scopes_response;

#ifdef __cplusplus
}
#endif
#endif /* AGC_DISCOVERY_TYPES_H */
