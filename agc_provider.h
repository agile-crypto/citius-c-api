/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_provider.h — ProviderService (8 RPCs).
 *
 * Two distinct things live here, as in the proto:
 *   - ProviderInfo:     a provider TYPE and what it can do (static catalog)
 *   - ProviderInstance: a CONFIGURED provider ready for use (runtime state)
 *
 * In an embedded deployment these calls are the local library's own view of
 * which PKCS#11 modules, OpenSSL providers or KMS clients are loadable. They
 * are still part of the API because the whole point of provider abstraction is
 * that the same code selects an HSM in production and a software provider in a
 * unit test, without a compile-time branch.
 */

#ifndef AGC_PROVIDER_H
#define AGC_PROVIDER_H

#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Provider capabilities (static catalog)
 * -------------------------------------------------------------------------- */

typedef struct agc_list_providers_params {
    size_t                           struct_size;
    const char                      *template_id;    /* NULL => no template filter */
    const agc_provider_requirements *requirements;   /* NULL => no filter */
    uint32_t                         page_size;
} agc_list_providers_params;

AGC_API agc_rc agc_list_providers(agc_ctx *ctx, const agc_list_providers_params *p,
                                  agc_provider_iter **out_iter);

AGC_API agc_rc agc_get_provider(agc_ctx *ctx, const char *provider_id,
                                agc_provider_info **out_provider);

AGC_API void agc_provider_info_free(agc_provider_info *pi);

AGC_API const char       *agc_provider_info_id(const agc_provider_info *pi);
AGC_API const char       *agc_provider_info_display_name(const agc_provider_info *pi);
AGC_API const char       *agc_provider_info_description(const agc_provider_info *pi);
AGC_API agc_provider_type agc_provider_info_type(const agc_provider_info *pi);

/* Provider-wide defaults; per-template overrides are reachable below.
 * Borrowed — do NOT free. */
AGC_API const agc_impl_props *agc_provider_info_default_implementation(const agc_provider_info *pi);

/* capabilities (map<string, string>). */
AGC_API size_t      agc_provider_info_capability_count(const agc_provider_info *pi);
AGC_API agc_rc      agc_provider_info_capability_at(const agc_provider_info *pi, size_t i,
                                                    const char **out_key, const char **out_value);
AGC_API const char *agc_provider_info_capability_get(const agc_provider_info *pi, const char *key);

/* configuration_schema (map<string, ConfigurationParameter>). Iterating the
 * schema is how a management UI or an Ansible module learns what settings a
 * provider instance needs before registering one. */
AGC_API size_t agc_provider_info_config_param_count(const agc_provider_info *pi);
AGC_API agc_rc agc_provider_info_config_param_at(const agc_provider_info *pi, size_t i,
                                                 const char **out_name,
                                                 const char **out_type,
                                                 const char **out_description,
                                                 int *out_required,
                                                 const char **out_default_value);

/* template_support: per-template declarations with optional property overrides.
 * out_implementation is borrowed and may be NULL when the entry inherits the
 * provider default. */
AGC_API size_t agc_provider_info_template_support_count(const agc_provider_info *pi);
AGC_API agc_rc agc_provider_info_template_support_at(const agc_provider_info *pi, size_t i,
                                                     const char **out_template_id,
                                                     const agc_impl_props **out_implementation,
                                                     const char **out_notes,
                                                     int *out_disabled);

/* --------------------------------------------------------------------------
 * Provider instances (runtime configuration)
 * -------------------------------------------------------------------------- */

typedef struct agc_provider_instance_spec {
    size_t                struct_size;
    const char           *instance_id;   /* REQUIRED */
    const char           *provider_id;   /* REQUIRED — must name a known ProviderInfo */
    const char           *display_name;
    const char           *description;
    /* Values matching the provider's configuration_schema. Sensitive values
     * SHOULD use indirection, e.g. {"pin_env", "HSM_PAYMENTS_PIN"} rather than
     * the PIN itself — the same discipline the proto documents. */
    agc_kv_list           configuration;
    int                   disabled;      /* 0 = enabled, matching the proto default */
    /* Optional per-instance override of the provider's default implementation
     * properties (e.g. two HSM partitions at different certification levels).
     * NULL to inherit. */
    const agc_impl_props *implementation_override;
} agc_provider_instance_spec;

AGC_API agc_rc agc_register_provider_instance(agc_ctx *ctx,
                                              const agc_provider_instance_spec *spec,
                                              agc_provider_instance **out_instance);

typedef struct agc_list_provider_instances_params {
    size_t                           struct_size;
    const char                      *provider_id;   /* NULL => any type */
    const agc_provider_requirements *requirements;  /* NULL => no filter */
    int                              enabled_only;  /* 0 => include disabled */
    uint32_t                         page_size;
} agc_list_provider_instances_params;

AGC_API agc_rc agc_list_provider_instances(agc_ctx *ctx,
                                           const agc_list_provider_instances_params *p,
                                           agc_provider_instance_iter **out_iter);

AGC_API agc_rc agc_get_provider_instance(agc_ctx *ctx, const char *instance_id,
                                         agc_provider_instance **out_instance);

/* FULL-REPLACEMENT semantics, as in the proto: the stored instance is replaced
 * entirely, with no field masking. Read-modify-write via
 * agc_get_provider_instance is the intended pattern; the helper below exists so
 * that the read half does not force the caller to reconstruct every field. */
AGC_API agc_rc agc_update_provider_instance(agc_ctx *ctx,
                                            const agc_provider_instance_spec *spec,
                                            agc_provider_instance **out_instance);

/* Populates *out_spec from an existing instance so a caller can modify one
 * field and write it back. The strings in *out_spec are borrowed from
 * `instance` and are invalid once it is freed. */
AGC_API agc_rc agc_provider_instance_to_spec(const agc_provider_instance *instance,
                                             agc_provider_instance_spec *out_spec);

/* Fails while keys still reference this instance. */
AGC_API agc_rc agc_delete_provider_instance(agc_ctx *ctx, const char *instance_id);

AGC_API void agc_provider_instance_free(agc_provider_instance *inst);

AGC_API const char *agc_provider_instance_id(const agc_provider_instance *inst);
AGC_API const char *agc_provider_instance_provider_id(const agc_provider_instance *inst);
AGC_API const char *agc_provider_instance_display_name(const agc_provider_instance *inst);
AGC_API const char *agc_provider_instance_description(const agc_provider_instance *inst);
AGC_API int         agc_provider_instance_disabled(const agc_provider_instance *inst);
AGC_API size_t      agc_provider_instance_config_count(const agc_provider_instance *inst);
AGC_API agc_rc      agc_provider_instance_config_at(const agc_provider_instance *inst, size_t i,
                                                    const char **out_key, const char **out_value);
AGC_API const agc_impl_props *
       agc_provider_instance_implementation_override(const agc_provider_instance *inst);

/* --------------------------------------------------------------------------
 * Provider matching
 * -------------------------------------------------------------------------- */

typedef struct agc_match_providers_params {
    size_t                           struct_size;
    const char                      *template_id;      /* REQUIRED */
    const agc_provider_requirements *requirements;     /* NULL => no filter */
    int                              include_disabled; /* 0 = enabled only */
} agc_match_providers_params;

/* One match. `resolved_implementation` is the merge of the provider's defaults
 * with the instance's overrides — the properties that would actually apply.
 * Both handles are owned by the match list and freed by
 * agc_provider_match_list_free. */
typedef struct agc_provider_match {
    const agc_provider_instance *instance;
    const agc_impl_props        *resolved_implementation;
    int32_t                      match_score;   /* higher is better */
} agc_provider_match;

/* Results are sorted by match_score, highest first. */
AGC_API agc_rc agc_match_providers(agc_ctx *ctx,
                                   const agc_match_providers_params *p,
                                   agc_provider_match **out_matches,
                                   size_t *out_count);

AGC_API void agc_provider_match_list_free(agc_provider_match *matches, size_t count);

#ifdef __cplusplus
}
#endif
#endif /* AGC_PROVIDER_H */
