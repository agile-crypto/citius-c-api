/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_provider_types.h — ProviderService: types.
 *
 * The request and response structs of agc_provider.h, separated from the
 * function declarations. Fields verified directly against
 * api/services/provider_service.proto, api/types/providers.proto and
 * api/types/implementation.proto.
 *
 * Two distinct concepts, kept distinct as in the proto: ProviderInfo (a
 * provider TYPE and its capabilities -- a static catalog shipped with the
 * service) versus ProviderInstance (a CONFIGURED provider ready for use,
 * stored at runtime). Several instances may exist per type, for example one
 * per HSM slot.
 *
 * Every struct here is CALLER-ALLOCATED and begins with struct_size
 * (AGC_INIT): the library writes only into regions the caller placed in the
 * response, allocates nothing the caller sees, and there is nothing to free.
 * Rules: docs/agc_crypto.md.
 *
 * DeleteProviderInstance has no response type: its proto response carries
 * only success/message, which collapse into agc_rc and agc_last_error (D4).
 * Register and Update carry success/message too; after the collapse only
 * `instance` remains, which is what agc_provider_instance_response holds.
 *
 * STORAGE CONTRACT (applies to every record with a `storage` field)
 * ------------------------------------------------------------------
 * Scalars are written inline. Every variable-length value -- strings, maps
 * and arrays -- is COPIED into the caller-provided `storage` region, and the
 * record's pointers are set into it. `storage_used` receives the bytes
 * consumed. The record is valid for as long as `storage` is; nothing in it
 * references library memory. A by-value copy of the record shares the
 * storage.
 *
 * Size query: if `storage.data` is NULL or `storage.cap` is smaller than
 * required, the call returns AGC_ERR_BUFFER_TOO_SMALL with `storage_used`
 * set to the requirement and writes no other field of the record. The reads
 * and the match query are read-only, so their requirement is exact; for
 * register and update, which mutate the instance store, the requirement is
 * an upper bound computed before the operation runs and the instance is not
 * registered when it is not met.
 *
 * The caller MUST AGC_INIT() every record before the call and may then set
 * only `storage` (and, for the match response, the matches array).
 */

#ifndef AGC_PROVIDER_TYPES_H
#define AGC_PROVIDER_TYPES_H

#include "agc_core.h"
#include "agc_scope.h"
#include "agc_key_types.h"   /* agc_impl_props */

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ProviderInfo and its members (static catalog)
 * -------------------------------------------------------------------------- */

/* ConfigurationParameter: one declared knob of a provider's configuration
 * schema. Every pointer points into the enclosing record's storage. */
typedef struct agc_configuration_parameter {
    const char *name;           /* NUL-terminated, in the enclosing record's storage */
    const char *type;           /* NUL-terminated; e.g. "string", "int", "bool" */
    const char *description;    /* NUL-terminated */
    int         required;
    const char *default_value;  /* NUL-terminated; "" if none */
} agc_configuration_parameter;

/* One entry of ProviderInfo.configuration_schema
 * (map<string, ConfigurationParameter>). The map key and the parameter's own
 * `name` are separate fields in the proto and may differ. */
typedef struct agc_configuration_schema_entry {
    const char                 *key;        /* map key; NUL-terminated, in storage */
    agc_configuration_parameter parameter;  /* map value */
} agc_configuration_schema_entry;

/* ProviderTemplateSupport: which templates a provider type supports, and
 * with which implementation properties. Array element of
 * agc_provider_info.template_support. */
typedef struct agc_provider_template_support {
    const char    *template_id;         /* NUL-terminated, in the enclosing record's storage */
    int            has_implementation;  /* proto message presence */
    agc_impl_props implementation;      /* per-template override of the provider default */
    const char    *notes;               /* NUL-terminated; "" if none */
    int            enabled;             /* matches the proto field name and polarity */
} agc_provider_template_support;

/* ProviderInfo: a provider TYPE and its capabilities. */
typedef struct agc_provider_info {
    size_t            struct_size;

    const char       *provider_id;    /* NUL-terminated, in storage */
    const char       *display_name;   /* NUL-terminated, in storage */
    const char       *description;    /* NUL-terminated, in storage */
    agc_provider_type provider_type;

    /* capabilities (map<string, string>): items and strings in storage. */
    agc_kv_list       capabilities;

    /* configuration_schema (map<string, ConfigurationParameter>): array in
     * storage. */
    const agc_configuration_schema_entry *configuration_schema;
    size_t                                configuration_schema_count;

    /* Provider-wide implementation defaults, overridden per template by
     * template_support and per instance by
     * agc_provider_instance.implementation_override. */
    int               has_default_implementation;  /* proto message presence */
    agc_impl_props    default_implementation;

    /* template_support: array in storage. */
    const agc_provider_template_support *template_support;
    size_t                               template_support_count;
} agc_provider_info;

/* The single-provider response, shared by every call that returns one
 * agc_provider_info: GetProvider and the ListProviders iterator. It exists
 * because agc_provider_info is descriptive only and needs a region to be
 * written into; see STORAGE CONTRACT. */
typedef struct agc_provider_info_response {
    size_t            struct_size;
    agc_provider_info provider;
    agc_buf           storage;       /* IN: caller region for the provider's strings, maps and arrays */
    size_t            storage_used;  /* OUT: bytes consumed, or required */
} agc_provider_info_response;

/* ListProvidersRequest. `page_token` is NOT projected: the iterator holds
 * that bookkeeping (D12), and ListProvidersResponse's next_page_token is
 * consumed by the same iterator. See docs/divergence_c_vs_proto.md for the
 * pending caller-allocated alternative. */
typedef struct agc_list_providers_request {
    size_t                           struct_size;
    const char                      *template_id;   /* NULL => no template filter */
    const agc_provider_requirements *requirements;  /* NULL => no filter */
    uint32_t                         page_size;     /* 0 => implementation default */
} agc_list_providers_request;

/* --------------------------------------------------------------------------
 * ProviderInstance (runtime configuration)
 * -------------------------------------------------------------------------- */

/* ProviderInstance: a CONFIGURED provider ready for use. */
typedef struct agc_provider_instance {
    size_t         struct_size;

    const char    *instance_id;   /* REQUIRED; NUL-terminated */
    const char    *provider_id;   /* REQUIRED; must name a known agc_provider_info */
    const char    *display_name;  /* NUL-terminated */
    const char    *description;   /* NUL-terminated */

    /* configuration (map<string, string>). Sensitive values SHOULD use
     * indirection, e.g. {"pin_env": "HSM_PAYMENTS_PIN"} rather than the PIN
     * itself -- restating the proto's own documented convention, since a C
     * API is the one most likely to be handed a literal secret in a config
     * map. */
    agc_kv_list    configuration;

    int            enabled;       /* matches the proto field name and polarity */

    /* Per-instance override of the provider type's default implementation
     * properties. */
    int            has_implementation_override;  /* proto message presence */
    agc_impl_props implementation_override;
} agc_provider_instance;

/* The single-instance response, shared by every call that returns one
 * agc_provider_instance: GetProviderInstance, RegisterProviderInstance,
 * UpdateProviderInstance, and the ListProviderInstances iterator. It exists
 * because agc_provider_instance is descriptive only and needs a region to be
 * written into; see STORAGE CONTRACT. */
typedef struct agc_provider_instance_response {
    size_t                struct_size;
    agc_provider_instance instance;
    agc_buf               storage;       /* IN: caller region for the instance's strings and map */
    size_t                storage_used;  /* OUT: bytes consumed, or required */
} agc_provider_instance_response;

/* ListProviderInstancesRequest. `page_token` is held by the iterator, as
 * above. */
typedef struct agc_list_provider_instances_request {
    size_t                           struct_size;
    const char                      *provider_id;   /* NULL => any provider type */
    const agc_provider_requirements *requirements;  /* NULL => no filter */
    int                              enabled_only;  /* matches the proto field name and polarity */
    uint32_t                         page_size;     /* 0 => implementation default */
} agc_list_provider_instances_request;

/* --------------------------------------------------------------------------
 * Provider matching
 * -------------------------------------------------------------------------- */

typedef struct agc_match_providers_request {
    size_t                           struct_size;
    const char                      *template_id;   /* REQUIRED */
    const agc_provider_requirements *requirements;  /* NULL => no filter */
    int                              enabled_only;  /* matches the proto field name and polarity */
} agc_match_providers_request;

/* MatchedProvider: one instance that satisfies the requirements. Array
 * element; carries no storage of its own. Everything it and its embedded
 * instance point at lives in the enclosing agc_match_providers_response's
 * storage. */
typedef struct agc_matched_provider {
    agc_provider_instance instance;

    /* ProviderInfo defaults merged with the instance's override. */
    int                   has_resolved_implementation;  /* proto message presence */
    agc_impl_props        resolved_implementation;

    int32_t               match_score;
} agc_matched_provider;

/* MatchProvidersResponse. Caller-allocated: the caller supplies both the
 * array of matches and the one storage region their strings and maps are
 * copied into. Results are sorted by match_score, highest first.
 *
 * Two-call on the array as well as on storage: if `matches` is NULL or
 * `matches_cap` is smaller than the number of matches, the call returns
 * AGC_ERR_BUFFER_TOO_SMALL with matches_count set to the number of entries
 * required and storage_used set to the bytes required, and writes nothing
 * else. */
typedef struct agc_match_providers_response {
    size_t                 struct_size;
    agc_matched_provider  *matches;       /* IN: caller array of matches_cap entries.
                                             OUT: filled, best match first */
    size_t                 matches_cap;   /* IN: capacity of `matches`, in entries */
    size_t                 matches_count; /* OUT: entries written, or required */
    agc_buf                storage;       /* IN: caller region for every match's strings and maps */
    size_t                 storage_used;  /* OUT: bytes consumed, or required */
} agc_match_providers_response;

#ifdef __cplusplus
}
#endif
#endif /* AGC_PROVIDER_TYPES_H */
