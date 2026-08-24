/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_discovery.h — AlgorithmDiscoveryService (3 RPCs;
 * api/services/discovery_service.proto).
 *
 * SCOPING NOTE: TemplateInfo's full shape (api/types/templates.proto)
 * includes a 41-arm AlgorithmDetails oneof and a 14-field CycloneDX
 * projection (RECONCILIATION_PLAN.md §2.6: deliberately excluded from the
 * ABI everywhere in this API, reachable only via agc_template_info_to_json()
 * in a real deployment with a real catalog). This reconciliation's stub
 * catalog has no real per-algorithm parameter data to project in the first
 * place -- there is no real algorithm behind "stub-aead-v1" beyond a scope
 * kind -- so the CycloneDX accessor set is not implemented here. The fields
 * that ARE implemented (id, display_name, description, status, standards,
 * scoped capabilities) are real and wired to an actual static catalog.
 */

#ifndef AGC_DISCOVERY_H
#define AGC_DISCOVERY_H

#include "agc_core.h"
#include "agc_scope.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_list_templates_params {
    size_t struct_size;

    /* Intent filter. NULL => no scope filter. Properties inside the scope
     * spec are MINIMA: a template matches when it meets or exceeds them. */
    const agc_scope_spec *scope_spec;

    /* Lifecycle filter. NULL/0 => all statuses. */
    const agc_template_status *allowed_statuses;
    size_t                     allowed_statuses_count;

    /* A template must reference ALL listed standards. */
    agc_str_list required_standards;

    uint32_t page_size; /* 0 => implementation default */
} agc_list_templates_params;

AGC_API agc_rc agc_list_templates(agc_ctx *ctx, const agc_list_templates_params *p,
                                   agc_template_iter **out_iter);
AGC_API agc_rc agc_template_iter_next(agc_template_iter *it, agc_template_info **out);
AGC_API void   agc_template_iter_free(agc_template_iter *it);

AGC_API agc_rc agc_get_template(agc_ctx *ctx, const char *template_id, agc_template_info **out_template);

AGC_API void agc_template_info_free(agc_template_info *ti);

AGC_API const char         *agc_template_info_id(const agc_template_info *ti);
AGC_API const char         *agc_template_info_display_name(const agc_template_info *ti);
AGC_API const char         *agc_template_info_description(const agc_template_info *ti);
AGC_API agc_template_status agc_template_info_status(const agc_template_info *ti);
AGC_API size_t              agc_template_info_standards_count(const agc_template_info *ti);
AGC_API const char         *agc_template_info_standard_at(const agc_template_info *ti, size_t i);

/* Flattened AlgorithmDetails scalars a caller can act on without the full
 * 41-arm oneof (D6/§2.6). */
AGC_API agc_crypto_primitive agc_template_info_primitive(const agc_template_info *ti);

/* ScopedCapabilities: which scope(s) this template supports. */
AGC_API size_t agc_template_info_capability_count(const agc_template_info *ti);
AGC_API agc_rc agc_template_info_capability_scope(const agc_template_info *ti, size_t i, agc_scope_spec *out);

/* --------------------------------------------------------------------------
 * ListScopes -- no request fields, a bounded ~dozen-entry result set, so a
 * plain array rather than an iterator (D12's stated exception).
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_list_scopes(agc_ctx *ctx, agc_scope_info ***out_scopes, size_t *out_count);
AGC_API void   agc_scope_info_list_free(agc_scope_info **scopes, size_t count);

AGC_API agc_rc      agc_scope_info_specification(const agc_scope_info *si, agc_scope_spec *out);
AGC_API const char *agc_scope_info_name(const agc_scope_info *si);
AGC_API const char *agc_scope_info_description(const agc_scope_info *si);

#ifdef __cplusplus
}
#endif
#endif /* AGC_DISCOVERY_H */
