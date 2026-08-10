/**
 * @file citius_discovery_service.h
 * @brief Algorithm template and scope discovery (AlgorithmDiscoveryService).
 *
 * C mirror of api/proto/services/discovery_service.proto —
 * AlgorithmDiscoveryService.
 *
 * Scope-based discovery mechanism
 * --------------------------------
 * Templates are discovered via citius_scope_specification_t filtering.
 * Clients specify the cryptographic primitive and its requirements;
 * the service returns matching templates.
 *
 * Discovery patterns:
 *
 *   Pattern 1 — Find all AEAD templates with 256-bit security:
 *     citius_list_templates_request_t r = {
 *         .scope_spec = { .aead = { .scope = AEAD_SCOPE_STANDARD,
 *                                   .security = { .security_strength_bits = 256 } } }
 *     };
 *     citius_list_templates(&r, &resp);
 *
 *   Pattern 2 — Find FIPS-approved active signature templates:
 *     citius_list_templates_request_t r = {
 *         .scope_spec = { .signature = { .scope = SIGNATURE_SCOPE_STANDARD,
 *                                        .security = { .fips_approved = 1 } } },
 *         .allowed_statuses = { .statuses = &active, .count = 1 }
 *     };
 *
 *   Pattern 3 — Find post-quantum signature options:
 *     citius_list_templates_request_t r = {
 *         .scope_spec = { .signature = { .security = { .quantum_safe = 1 } } }
 *     };
 *
 * Proto → C mapping
 * -----------------
 *   rpc ListTemplates(ListTemplatesRequest) → ListTemplatesResponse
 *       citius_list_templates(request*, response*)
 *
 *   rpc GetTemplate(GetTemplateRequest) → GetTemplateResponse
 *       citius_get_template(request*, response*)
 *
 *   rpc ListScopes(ListScopesRequest) → ListScopesResponse
 *       citius_list_scopes(request*, response*)
 *
 * HTTP REST paths (from proto annotations):
 *   GET /v1/templates               citius_list_templates()
 *   GET /v1/templates/{template_id} citius_get_template()
 *   GET /v1/scopes                  citius_list_scopes()
 */

#ifndef CITIUS_SERVICES_DISCOVERY_SERVICE_H
#define CITIUS_SERVICES_DISCOVERY_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_templates.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * ListTemplatesRequest / ListTemplatesResponse
 * ========================================================================= */

typedef struct {
    /**
     * Scope specification — primary filter dimension.
     * Zero-initialised (type tag = 0) = no scope filter.
     */
    citius_scope_specification_t      scope_spec;

    /**
     * Allowed template statuses filter.
     * allowed_statuses.count == 0 → all statuses are returned.
     * (proto: repeated TemplateStatus allowed_statuses)
     */
    citius_template_status_repeated_t allowed_statuses;

    /**
     * NULL-terminated array of required standards strings.
     * Templates must reference ALL listed strings.
     * NULL = no standards filter.
     * (proto: repeated string required_standards)
     */
    const char * const               *required_standards;

    int32_t     page_size;   /**< Max results per page; 0 = server default */
    const char *page_token;  /**< Pagination cursor from previous response; nullable */
} citius_list_templates_request_t;

typedef struct {
    const citius_template_info_t *templates;       /**< array */
    size_t                        template_count;
    const char                   *next_page_token; /**< nullable */
} citius_list_templates_response_t;

/* =========================================================================
 * GetTemplateRequest / GetTemplateResponse
 * ========================================================================= */

typedef struct {
    const char *template_id;
} citius_get_template_request_t;

typedef struct {
    citius_template_info_t template_info;
} citius_get_template_response_t;

/* =========================================================================
 * ListScopesRequest / ListScopesResponse
 * ========================================================================= */

typedef struct {
    uint8_t _reserved; /**< empty message — mirrors proto ListScopesRequest {} */
} citius_list_scopes_request_t;

typedef struct {
    citius_scope_info_repeated_t scopes;
} citius_list_scopes_response_t;

/* =========================================================================
 * Service functions
 * ========================================================================= */

/**
 * @brief List available algorithm templates, optionally filtered.
 *
 * Mirrors AlgorithmDiscoveryService.ListTemplates.
 */
CITIUS_RV citius_list_templates(
    const citius_list_templates_request_t  *request,
    citius_list_templates_response_t       *response
);

/**
 * @brief Retrieve full details for a specific template by ID.
 *
 * Mirrors AlgorithmDiscoveryService.GetTemplate.
 *
 * @return CITIUS_OK on success.
 *         CITIUS_TEMPLATE_NOT_FOUND if template_id is not registered.
 */
CITIUS_RV citius_get_template(
    const citius_get_template_request_t   *request,
    citius_get_template_response_t        *response
);

/**
 * @brief List all supported scope types.
 *
 * Mirrors AlgorithmDiscoveryService.ListScopes.
 */
CITIUS_RV citius_list_scopes(
    const citius_list_scopes_request_t  *request,
    citius_list_scopes_response_t       *response
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_DISCOVERY_SERVICE_H */
