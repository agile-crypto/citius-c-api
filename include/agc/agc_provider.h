/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_provider.h — ProviderService (8 RPCs; api/services/provider_service.proto).
 *
 * Two distinct concepts, kept distinct as in the proto: ProviderInfo (a
 * provider TYPE and its capabilities -- static catalog) vs. ProviderInstance
 * (a CONFIGURED provider ready for use). This build has exactly one
 * provider type ("stub") and whatever instances a caller registers.
 *
 * SCOPING NOTE: ImplementationProperties has ~13 tribool/string fields in
 * the proto; this reconciliation implements the subset a caller can
 * meaningfully act on for a stub provider (fips/constant-time/memory-safe
 * posture) rather than all of them, since the stub has no real per-field
 * data behind most of the rest (audits, CVE lists, hardware features).
 */

#ifndef AGC_PROVIDER_H
#define AGC_PROVIDER_H

#include "agc_core.h"
#include "agc_scope.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ImplementationProperties
 * -------------------------------------------------------------------------- */

AGC_API void agc_impl_props_free(agc_impl_props *ip);

AGC_API int               agc_impl_props_fips_certified(const agc_impl_props *ip);
AGC_API agc_fips140_level agc_impl_props_fips_level(const agc_impl_props *ip);
AGC_API agc_tribool       agc_impl_props_formally_verified(const agc_impl_props *ip);
AGC_API agc_tribool       agc_impl_props_memory_safe_language(const agc_impl_props *ip);
AGC_API const char       *agc_impl_props_implementation_language(const agc_impl_props *ip);
AGC_API agc_tribool       agc_impl_props_constant_time(const agc_impl_props *ip);
AGC_API agc_tribool       agc_impl_props_side_channel_hardened(const agc_impl_props *ip);
AGC_API agc_tribool       agc_impl_props_hardware_accelerated(const agc_impl_props *ip);

/* --------------------------------------------------------------------------
 * Provider capabilities (static catalog)
 * -------------------------------------------------------------------------- */

typedef struct agc_list_providers_params {
    size_t                            struct_size;
    const char                       *template_id;  /* NULL => no template filter */
    const agc_provider_requirements  *requirements;  /* NULL => no filter */
    uint32_t                          page_size;
} agc_list_providers_params;

AGC_API agc_rc agc_list_providers(agc_ctx *ctx, const agc_list_providers_params *p,
                                   agc_provider_iter **out_iter);
AGC_API agc_rc agc_provider_iter_next(agc_provider_iter *it, agc_provider_info **out);
AGC_API void   agc_provider_iter_free(agc_provider_iter *it);

AGC_API agc_rc agc_get_provider(agc_ctx *ctx, const char *provider_id, agc_provider_info **out_provider);

AGC_API void agc_provider_info_free(agc_provider_info *pi);

AGC_API const char       *agc_provider_info_id(const agc_provider_info *pi);
AGC_API const char       *agc_provider_info_display_name(const agc_provider_info *pi);
AGC_API const char       *agc_provider_info_description(const agc_provider_info *pi);
AGC_API agc_provider_type agc_provider_info_type(const agc_provider_info *pi);

/* Provider-wide defaults. Borrowed -- do NOT free. */
AGC_API const agc_impl_props *agc_provider_info_default_implementation(const agc_provider_info *pi);

/* capabilities (map<string, string>). */
AGC_API size_t      agc_provider_info_capability_count(const agc_provider_info *pi);
AGC_API agc_rc      agc_provider_info_capability_at(const agc_provider_info *pi, size_t i,
                                                     const char **out_key, const char **out_value);
AGC_API const char *agc_provider_info_capability_get(const agc_provider_info *pi, const char *key);

/* --------------------------------------------------------------------------
 * Provider instances (runtime configuration)
 * -------------------------------------------------------------------------- */

typedef struct agc_provider_instance_spec {
    size_t       struct_size;
    const char  *instance_id;    /* REQUIRED */
    const char  *provider_id;    /* REQUIRED -- must name a known ProviderInfo */
    const char  *display_name;
    const char  *description;
    /* Sensitive values SHOULD use indirection, e.g. {"pin_env":
     * "HSM_PAYMENTS_PIN"} rather than the PIN itself -- restating the
     * proto's own documented convention, since a C API is the one most
     * likely to be handed a literal secret in a config map. */
    agc_kv_list  configuration;
    int          enabled;        /* matches the proto's own field and default (true) */
} agc_provider_instance_spec;

AGC_API agc_rc agc_register_provider_instance(agc_ctx *ctx, const agc_provider_instance_spec *spec,
                                               agc_provider_instance **out_instance);

typedef struct agc_list_provider_instances_params {
    size_t                           struct_size;
    const char                      *provider_id;   /* NULL => any type */
    const agc_provider_requirements *requirements;  /* NULL => no filter */
    int                              enabled_only;   /* matches the proto field name and polarity */
    uint32_t                         page_size;
} agc_list_provider_instances_params;

AGC_API agc_rc agc_list_provider_instances(agc_ctx *ctx, const agc_list_provider_instances_params *p,
                                            agc_provider_instance_iter **out_iter);
AGC_API agc_rc agc_provider_instance_iter_next(agc_provider_instance_iter *it, agc_provider_instance **out);
AGC_API void   agc_provider_instance_iter_free(agc_provider_instance_iter *it);

AGC_API agc_rc agc_get_provider_instance(agc_ctx *ctx, const char *instance_id,
                                          agc_provider_instance **out_instance);

/* FULL-REPLACEMENT semantics, as in the proto: no field masking. */
AGC_API agc_rc agc_update_provider_instance(agc_ctx *ctx, const agc_provider_instance_spec *spec,
                                             agc_provider_instance **out_instance);

/* Populates *out_spec from an existing instance so read-modify-write does
 * not force the caller to reconstruct every field by hand -- which is
 * where fields get silently dropped under full-replacement semantics. The
 * strings in *out_spec are borrowed from `instance` and invalid once it is
 * freed. */
AGC_API agc_rc agc_provider_instance_to_spec(const agc_provider_instance *instance,
                                              agc_provider_instance_spec *out_spec);

/* Fails while keys still reference this instance. */
AGC_API agc_rc agc_delete_provider_instance(agc_ctx *ctx, const char *instance_id);

AGC_API void agc_provider_instance_free(agc_provider_instance *inst);

AGC_API const char *agc_provider_instance_id(const agc_provider_instance *inst);
AGC_API const char *agc_provider_instance_provider_id(const agc_provider_instance *inst);
AGC_API const char *agc_provider_instance_display_name(const agc_provider_instance *inst);
AGC_API const char *agc_provider_instance_description(const agc_provider_instance *inst);
AGC_API int         agc_provider_instance_enabled(const agc_provider_instance *inst);
AGC_API size_t      agc_provider_instance_config_count(const agc_provider_instance *inst);
AGC_API agc_rc      agc_provider_instance_config_at(const agc_provider_instance *inst, size_t i,
                                                     const char **out_key, const char **out_value);

/* --------------------------------------------------------------------------
 * Provider matching
 * -------------------------------------------------------------------------- */

typedef struct agc_match_providers_params {
    size_t                            struct_size;
    const char                       *template_id;      /* REQUIRED */
    const agc_provider_requirements  *requirements;      /* NULL => no filter */
    int                               enabled_only;       /* matches the proto field name and polarity */
} agc_match_providers_params;

typedef struct agc_provider_match {
    const agc_provider_instance *instance;
    const agc_impl_props        *resolved_implementation; /* borrowed */
    int32_t                      match_score;             /* higher is better */
} agc_provider_match;

/* Results are sorted by match_score, highest first. */
AGC_API agc_rc agc_match_providers(agc_ctx *ctx, const agc_match_providers_params *p,
                                    agc_provider_match **out_matches, size_t *out_count);
AGC_API void   agc_provider_match_list_free(agc_provider_match *matches, size_t count);

#ifdef __cplusplus
}
#endif
#endif /* AGC_PROVIDER_H */
