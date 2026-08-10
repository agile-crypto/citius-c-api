/**
 * @file citius_provider_service.h
 * @brief Provider discovery and instance management (ProviderService).
 *
 * C mirror of api/proto/services/provider_service.proto — ProviderService.
 *
 * This service provides two main capabilities:
 *
 *   1. Provider Capabilities (static catalog)
 *      citius_provider_list_types()   — ListProviders
 *      citius_provider_get_type()     — GetProvider
 *
 *   2. Provider Instances (runtime configuration)
 *      citius_provider_instance_register()  — RegisterProviderInstance
 *      citius_provider_instance_list()      — ListProviderInstances
 *      citius_provider_instance_get()       — GetProviderInstance
 *      citius_provider_instance_update()    — UpdateProviderInstance
 *      citius_provider_instance_delete()    — DeleteProviderInstance
 *
 *   3. Provider Matching
 *      citius_provider_match()        — MatchProviders
 *
 * Example workflow (mirrors proto comment):
 *   1. Admin queries citius_provider_list_types() to see available types
 *   2. Admin registers instance:
 *        { provider_id: "pkcs11", instance_id: "hsm-payments", config: {...} }
 *   3. User creates key: { scope: ..., requirements: { fips_140_certified: 1 } }
 *   4. System calls citius_provider_match() to rank instances, selects
 *      "hsm-payments"
 *
 * Proto → C mapping
 * -----------------
 *   rpc ListProviders(ListProvidersRequest) → ListProvidersResponse
 *       citius_provider_list_types(filter*, providers_out*, count_inout*)
 *
 *   rpc GetProvider(GetProviderRequest) → GetProviderResponse
 *       citius_provider_get_type(provider_id, info_out*)
 *
 *   rpc RegisterProviderInstance(RegisterProviderInstanceRequest)
 *       citius_provider_instance_register(instance*, registered_out*)
 *
 *   rpc ListProviderInstances(ListProviderInstancesRequest)
 *       citius_provider_instance_list(filter*, instances_out*, count_inout*)
 *
 *   rpc GetProviderInstance(GetProviderInstanceRequest)
 *       citius_provider_instance_get(instance_id, instance_out*)
 *
 *   rpc UpdateProviderInstance(UpdateProviderInstanceRequest) → UpdateProviderInstanceResponse
 *       citius_provider_instance_update(instance*, updated_out*, message_out*)
 *
 *   rpc DeleteProviderInstance(DeleteProviderInstanceRequest) → DeleteProviderInstanceResponse
 *       citius_provider_instance_delete(instance_id, message_out*)
 *
 *   rpc MatchProviders(MatchProvidersRequest) → MatchProvidersResponse
 *       citius_provider_match(request*, matches_out*, count_inout*)
 *
 * HTTP REST paths (from proto annotations):
 *   GET    /v1/providers                             citius_provider_list_types()
 *   GET    /v1/providers/{provider_id}               citius_provider_get_type()
 *   POST   /v1/provider-instances                    citius_provider_instance_register()
 *   GET    /v1/provider-instances                    citius_provider_instance_list()
 *   GET    /v1/provider-instances/{instance_id}      citius_provider_instance_get()
 *   PUT    /v1/provider-instances/{instance.instance_id}  citius_provider_instance_update()
 *   DELETE /v1/provider-instances/{instance_id}      citius_provider_instance_delete()
 *   POST   /v1/providers:match                       citius_provider_match()
 *
 * Local provider backend registration (no proto RPC equivalent)
 * ---------------------------------------------------------------
 * citius_provider_register/unregister/select/list/describe() below are a
 * C-API-only mechanism for plugging a concrete provider implementation
 * (the citius_provider_ops_t vtable) into the library — e.g. a PKCS#11
 * module or the stub — before it can be used. There is no corresponding
 * proto RPC; a real deployment's provider backends are wired up
 * server-side, not by a client message.
 */

#ifndef CITIUS_SERVICES_PROVIDER_SERVICE_H
#define CITIUS_SERVICES_PROVIDER_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_templates.h"
#include "citius/types/citius_implementation.h"
#include "citius/types/citius_providers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Provider type catalog (static, read-only)
 * ========================================================================= */

/** Filter for citius_provider_list_types() (proto: ListProvidersRequest) */
typedef struct {
    /** Optional: Only return providers supporting this template ID; NULL = no filter */
    const char                        *template_id;
    /** Optional: Only return providers meeting these requirements; NULL = no filter */
    const citius_provider_requirements_t *requirements;
    /** Pagination cursor from a previous call; NULL = first page */
    const char                        *page_token;
    /** Max results per page; 0 = return all */
    uint32_t                           page_size;
} citius_provider_type_filter_t;

/**
 * @brief List available provider types from the static catalog.
 *
 * Mirrors ProviderService.ListProviders.
 * HTTP: GET /v1/providers
 *
 * @param filter         Optional filter; NULL = return all provider types.
 * @param providers_out  [out] Caller-allocated array of provider info structs.
 * @param count_inout    [in/out] in: capacity; out: entries written.
 * @return CITIUS_OK on success.
 *         CITIUS_BUFFER_TOO_SMALL if array capacity is insufficient.
 */
CITIUS_RV citius_provider_list_types(
    const citius_provider_type_filter_t *filter,
    citius_provider_info_t            *providers_out,
    size_t                            *count_inout
);

/**
 * @brief Retrieve details about a specific provider type.
 *
 * Mirrors ProviderService.GetProvider.
 * HTTP: GET /v1/providers/{provider_id}
 *
 * @param provider_id  Provider type identifier (e.g. "pkcs11", "openssl").
 * @param info_out     [out] Filled with provider type details on success.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if provider_id is not in the catalog.
 */
CITIUS_RV citius_provider_get_type(
    const char             *provider_id,
    citius_provider_info_t *info_out
);

/* =========================================================================
 * Provider instances (runtime configuration)
 * ========================================================================= */

/** Filter for citius_provider_instance_list() (proto: ListProviderInstancesRequest) */
typedef struct {
    /** Only return instances of this provider type; NULL = all types */
    const char                        *provider_id;
    /** Only return instances meeting these requirements; NULL = no filter */
    const citius_provider_requirements_t *requirements;
    /** If non-zero, only return enabled instances */
    uint8_t                            enabled_only;
    /** Pagination cursor; NULL = first page */
    const char                        *page_token;
    /** Max results per page; 0 = return all */
    uint32_t                           page_size;
} citius_instance_filter_t;

/**
 * @brief Register a new provider instance with configuration.
 *
 * Mirrors ProviderService.RegisterProviderInstance.
 * HTTP: POST /v1/provider-instances
 *
 * The instance's provider_id must reference a valid ProviderInfo entry.
 * On success, registered_out contains the instance as stored (with any
 * provider-applied defaults).
 *
 * @param instance        Instance to register (provider_id and instance_id required).
 * @param registered_out  [out] The registered instance with defaults applied; nullable.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_ALREADY_REGISTERED if instance_id already exists.
 *         CITIUS_PROVIDER_NOT_FOUND if provider_id is not in the catalog.
 */
CITIUS_RV citius_provider_instance_register(
    const citius_provider_instance_t  *instance,
    citius_provider_instance_t        *registered_out
);

/**
 * @brief List registered provider instances.
 *
 * Mirrors ProviderService.ListProviderInstances.
 * HTTP: GET /v1/provider-instances
 *
 * @param filter         Optional filter; NULL = return all instances.
 * @param instances_out  [out] Caller-allocated array of instance structs.
 * @param count_inout    [in/out] in: capacity; out: entries written.
 * @return CITIUS_OK on success.
 *         CITIUS_BUFFER_TOO_SMALL if array capacity is insufficient.
 */
CITIUS_RV citius_provider_instance_list(
    const citius_instance_filter_t *filter,
    citius_provider_instance_t     *instances_out,
    size_t                         *count_inout
);

/**
 * @brief Retrieve a specific provider instance by ID.
 *
 * Mirrors ProviderService.GetProviderInstance.
 * HTTP: GET /v1/provider-instances/{instance_id}
 *
 * @param instance_id   Instance identifier string.
 * @param instance_out  [out] Filled with instance details on success.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if instance_id is not registered.
 */
CITIUS_RV citius_provider_instance_get(
    const char                *instance_id,
    citius_provider_instance_t *instance_out
);

/**
 * @brief Update a provider instance's configuration or properties.
 *
 * Mirrors ProviderService.UpdateProviderInstance.
 * HTTP: PUT /v1/provider-instances/{instance.instance_id}
 *
 * @param instance     Updated instance (instance_id identifies which to update).
 * @param updated_out  [out] The instance as stored after the update; nullable.
 * @param message_out  [out] Human-readable status message from the provider; nullable.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if instance_id is not registered.
 */
CITIUS_RV citius_provider_instance_update(
    const citius_provider_instance_t *instance,
    citius_provider_instance_t       *updated_out,
    const char                      **message_out
);

/**
 * @brief Delete a provider instance.
 *
 * Mirrors ProviderService.DeleteProviderInstance.
 * HTTP: DELETE /v1/provider-instances/{instance_id}
 *
 * Fails if any keys still reference this instance.
 *
 * @param instance_id  Instance identifier string.
 * @param message_out  [out] Human-readable status message from the provider; nullable.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if instance_id is not registered.
 *         CITIUS_PROVIDER_UNAVAILABLE if keys still reference this instance.
 */
CITIUS_RV citius_provider_instance_delete(
    const char           *instance_id,
    const char          **message_out
);

/* =========================================================================
 * Provider matching  (proto: MatchProviders)
 * ========================================================================= */

/**
 * A provider instance that matched a MatchProviders request, with a score.
 * (proto: MatchedProvider)
 */
typedef struct {
    citius_provider_instance_t          instance;
    citius_implementation_properties_t  resolved_implementation;
    /**
     * Score indicating match quality (higher = better).
     * Factors: FIPS level, formal verification, constant-time, HSM, etc.
     */
    int32_t                             match_score;
} citius_matched_provider_t;

/** Request for citius_provider_match() (proto: MatchProvidersRequest) */
typedef struct {
    /** Required: Template ID for the intended operation */
    const char                        *template_id;
    /** Optional: Implementation requirements to filter by; NULL = no filter */
    const citius_provider_requirements_t *requirements;
    /** If non-zero, only return enabled instances (default behaviour) */
    uint8_t                            enabled_only;
} citius_provider_match_request_t;

/**
 * @brief Find provider instances matching a template and requirements.
 *
 * Mirrors ProviderService.MatchProviders.
 * HTTP: POST /v1/providers:match
 *
 * Returns instances sorted by match_score descending (best first).
 *
 * @param request       Match criteria (template_id required).
 * @param matches_out   [out] Caller-allocated array of matched provider structs.
 * @param count_inout   [in/out] in: capacity; out: matches written.
 * @return CITIUS_OK on success (count may be 0 if no providers match).
 *         CITIUS_BUFFER_TOO_SMALL if array capacity is insufficient.
 *         CITIUS_TEMPLATE_NOT_FOUND if template_id is not in the catalog.
 */
CITIUS_RV citius_provider_match(
    const citius_provider_match_request_t *request,
    citius_matched_provider_t            *matches_out,
    size_t                               *count_inout
);

/* =========================================================================
 * Local provider backend registration  (no proto RPC — see file header)
 * ========================================================================= */

/**
 * Provider vtable — concrete providers fill in this struct.  Each
 * service-layer header (citius_key_management_service.h, citius_crypto_service.h,
 * etc.) documents which function pointers it expects.
 *
 * NULL function pointers mean "not supported"; callers receive
 * CITIUS_FUNCTION_NOT_SUPPORTED.
 */
typedef struct citius_provider_ops_s citius_provider_ops_t;

/**
 * @brief Register a provider and its vtable.
 *
 * @param info          Static metadata about the provider.
 * @param ops           Pointer to the provider's vtable (must remain valid
 *                      for the lifetime of the registration).
 * @param instance_out  [out] Receives the registered provider handle; nullable.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_ALREADY_REGISTERED if provider_id already exists.
 */
CITIUS_RV citius_provider_register(
    const citius_provider_info_t *info,
    const citius_provider_ops_t  *ops,
    CITIUS_PROVIDER_HANDLE       *instance_out
);

/**
 * @brief Unregister a provider.
 *
 * @param instance   Handle returned by citius_provider_register().
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if instance is invalid.
 */
CITIUS_RV citius_provider_unregister(
    CITIUS_PROVIDER_HANDLE instance
);

/**
 * @brief Select the best registered provider for a given scope and requirements.
 *
 * @param scope_spec    Algorithm selection scope specification.
 * @param requirements  Provider capability requirements; nullable (no filter).
 * @param instance_out  [out] Receives the chosen provider handle.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if no provider satisfies the requirements.
 */
CITIUS_RV citius_provider_select(
    const citius_scope_specification_t   *scope_spec,
    const citius_provider_requirements_t *requirements,
    CITIUS_PROVIDER_HANDLE               *instance_out
);

/**
 * @brief List all registered providers.
 *
 * @param instances_out  [out] Array of provider handles; caller supplies storage.
 * @param count_inout    [in/out] in: capacity of instances_out array;
 *                                out: number of providers written.
 * @return CITIUS_OK on success.
 *         CITIUS_BUFFER_TOO_SMALL if the array is too small; count_inout
 *         is set to the required capacity.
 */
CITIUS_RV citius_provider_list(
    CITIUS_PROVIDER_HANDLE *instances_out,
    size_t                 *count_inout
);

/**
 * @brief Retrieve info and implementation properties for a registered provider.
 *
 * @param instance   Provider handle.
 * @param info_out   [out] Pointer to a citius_provider_info_t filled on success.
 * @return CITIUS_OK on success.
 *         CITIUS_PROVIDER_NOT_FOUND if instance is invalid.
 */
CITIUS_RV citius_provider_describe(
    CITIUS_PROVIDER_HANDLE   instance,
    citius_provider_info_t  *info_out
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_PROVIDER_SERVICE_H */
