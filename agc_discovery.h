/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_discovery.h — AlgorithmDiscoveryService (3 RPCs).
 *
 * Template and scope discovery. This is the surface an operator or a migration
 * tool uses to answer "what post-quantum signature options does policy allow me
 * today?" without creating anything.
 */

#ifndef AGC_DISCOVERY_H
#define AGC_DISCOVERY_H

#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agc_list_templates_params {
    size_t struct_size;

    /* Intent filter. NULL => no scope filter. Properties inside the scope spec
     * are MINIMA: a template matches when it meets or exceeds them. */
    const agc_scope_spec *scope_spec;

    /* Lifecycle filter. NULL/0 => all statuses. */
    const agc_template_status *allowed_statuses;
    size_t                     allowed_statuses_count;

    /* Standards filter. A template must reference ALL listed standards.
     * Example: {"FIPS 197", "NIST SP 800-38D"}. */
    agc_str_list required_standards;

    uint32_t page_size;   /* 0 => implementation default */
} agc_list_templates_params;

AGC_API agc_rc agc_list_templates(agc_ctx *ctx,
                                  const agc_list_templates_params *p,
                                  agc_template_iter **out_iter);

AGC_API agc_rc agc_get_template(agc_ctx *ctx, const char *template_id,
                                agc_template_info **out_template);

/* ListScopes has no request fields and returns a small, bounded set, so it is
 * a plain indexed accessor rather than an iterator: pagination machinery for a
 * dozen entries would be cost without benefit. */
AGC_API agc_rc agc_list_scopes(agc_ctx *ctx, agc_scope_info ***out_scopes,
                               size_t *out_count);

/* Frees the array returned by agc_list_scopes and every element in it. */
AGC_API void agc_scope_info_list_free(agc_scope_info **scopes, size_t count);

AGC_API agc_rc      agc_scope_info_specification(const agc_scope_info *si, agc_scope_spec *out);
AGC_API const char *agc_scope_info_name(const agc_scope_info *si);
AGC_API const char *agc_scope_info_description(const agc_scope_info *si);
AGC_API size_t      agc_scope_info_use_case_count(const agc_scope_info *si);
AGC_API const char *agc_scope_info_use_case_at(const agc_scope_info *si, size_t i);
AGC_API size_t      agc_scope_info_operation_count(const agc_scope_info *si);
AGC_API agc_rc      agc_scope_info_operation_at(const agc_scope_info *si, size_t i,
                                                agc_operation *out);

#ifdef __cplusplus
}
#endif
#endif /* AGC_DISCOVERY_H */
