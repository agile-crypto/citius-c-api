/**
 * @file citius_templates.h
 * @brief Template definitions, algorithm details, scoped capabilities, and CycloneDX properties.
 *
 * Mirrors api/proto/types/templates.proto.
 */

#ifndef CITIUS_TEMPLATES_H
#define CITIUS_TEMPLATES_H

#include "citius_types.h"
#include "citius_common.h"
#include "citius_algorithm_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * TemplateStatus  (proto: TemplateStatus)
 * ========================================================================= */

typedef enum {
    TEMPLATE_STATUS_UNSPECIFIED  = 0,
    TEMPLATE_STATUS_ACTIVE       = 1,
    TEMPLATE_STATUS_ACCEPTABLE   = 2,
    TEMPLATE_STATUS_DEPRECATED   = 3,
    TEMPLATE_STATUS_FORBIDDEN    = 4,
    TEMPLATE_STATUS_EXPERIMENTAL = 5
} citius_template_status_t;

/** Counted array of template statuses — mirrors proto `repeated TemplateStatus`. */
typedef struct {
    const citius_template_status_t *statuses; /**< array; NULL when count == 0 */
    size_t                          count;
} citius_template_status_repeated_t;

/* =========================================================================
 * AlgorithmDetails  (proto: AlgorithmDetails)
 *
 * The algorithm field is the single source of truth for algorithm config.
 * It mirrors the oneof in templates.proto; the primitive field is optional
 * (derivable from the algorithm arm selected).
 * ========================================================================= */

/**
 * AlgorithmDetails  (proto: AlgorithmDetails)
 *
 * citius_algorithm_details_t itself is forward-declared in
 * citius_algorithm_params.h (as an incomplete `struct citius_algorithm_details_s`)
 * so that citius_hybrid_component_t can reference it by pointer — the proto
 * is mutually recursive (AlgorithmDetails.hybrid -> HybridComponent.algorithm
 * -> AlgorithmDetails). This completes that forward declaration.
 */
struct citius_algorithm_details_s {
    const char                *oid;       /**< Algorithm OID; nullable              */
    citius_crypto_primitive_t  primitive; /**< Optional override for CryptoPrimitive */
    citius_algorithm_params_t  algorithm; /**< Single source of truth               */
};

/* =========================================================================
 * HybridAlgorithmParams / HybridComponent  (proto: HybridAlgorithmParams)
 * These are template-level structs; citius_algorithm_params.h stores the
 * algorithm union (citius_hybrid_params_t) and citius_combiner_strategy_t
 * for this purpose, since it's also where the union arm and
 * citius_hybrid_component_t live.
 * ========================================================================= */

/* =========================================================================
 * FormalSecurityNotions / PracticalSecurityOutcomes / OperationalBounds /
 * SecurityGuarantees / *ScopeSpec / ScopeSpecification
 *
 * All of these are already defined in citius_common.h (proto: common.proto),
 * which is also where TemplateInfo/ScopedCapabilities/ScopeInfo need them
 * from. citius_templates.h just reuses them — see citius_scope_specification_t
 * alias below.
 * ========================================================================= */

/** ScopeSpecification  (proto: ScopeSpecification) — alias of citius_common.h's wrapper. */
typedef citius_scope_spec_t citius_scope_specification_t;

/* =========================================================================
 * ScopedCapabilities  (proto: ScopedCapabilities)
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope;
    const citius_crypto_operation_t *operations;
    size_t                           num_operations;
    citius_security_guarantees_t     security_guarantees;
} citius_scoped_capabilities_t;

/* =========================================================================
 * CycloneDXAlgorithmProperties  (proto: CycloneDXAlgorithmProperties)
 * ========================================================================= */

typedef struct {
    const char   *name;
    const char   *primitive;
    const char   *algorithm_family;
    const char   *parameter_set_identifier;
    const char   *elliptic_curve;
    const char   *mode;
    const char   *padding;
    const char  **crypto_functions;
    size_t        num_crypto_functions;
    uint32_t      classical_security_level;
    uint32_t      nist_quantum_security_level;
    const char  **certification_level;
    size_t        num_certification_level;
    const char   *execution_environment;
    const char   *implementation_platform;
    const char   *oid;
} citius_cyclonedx_algorithm_properties_t;

/* =========================================================================
 * TemplateInfo  (proto: TemplateInfo)
 * ========================================================================= */

typedef struct {
    const char                              *template_id;
    const char                              *display_name;    /**< nullable */
    const char                              *description;     /**< nullable */
    const citius_scoped_capabilities_t      *scoped_capabilities;
    size_t                                   num_scoped_capabilities;
    citius_algorithm_details_t               algorithm;
    citius_template_status_t                 status;
    const char                              *deprecation_notice; /**< nullable */
    const char                             **standards;
    size_t                                   num_standards;
    citius_cyclonedx_algorithm_properties_t  cyclonedx;
    citius_security_guarantees_t             security_guarantees;
} citius_template_info_t;

/* =========================================================================
 * ScopeInfo  (proto: ScopeInfo)
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t      specification;
    const char                       *name;        /**< nullable */
    const char                       *description; /**< nullable */
    const char                      **typical_use_cases;
    size_t                            num_typical_use_cases;
    const citius_crypto_operation_t  *supported_operations;
    size_t                            num_supported_operations;
} citius_scope_info_t;

/** Counted array of scope info entries — mirrors proto `repeated ScopeInfo`. */
typedef struct {
    const citius_scope_info_t *scopes; /**< array; NULL when count == 0 */
    size_t                     count;
} citius_scope_info_repeated_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_TEMPLATES_H */
