/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_provider.h — ProviderService (8 RPCs;
 * api/services/provider_service.proto).
 *
 * Functions only. Every request and response type they name is defined in
 * agc_provider_types.h, which also states the STORAGE CONTRACT that governs
 * every caller-allocated record below.
 *
 * SHAPE OF EVERY CALL
 * -------------------
 *     agc_rc agc_<op>(agc_ctx *ctx, const agc_<op>_request *req, agc_<op>_response *resp);
 *
 * One request struct, one response struct, both CALLER-ALLOCATED, both
 * beginning with struct_size (AGC_INIT). The library writes only into
 * regions the caller placed in the response; it allocates nothing the caller
 * sees and there is nothing to free, except the two iterator handles.
 * Rules: docs/agc_crypto.md.
 *
 * Three shapes differ, for reasons recorded here:
 *   - DeleteProviderInstance takes no response parameter. Its proto response
 *     carries only success/message, which collapse into agc_rc and
 *     agc_last_error (D4).
 *   - GetProviderResponse, GetProviderInstanceResponse and -- once
 *     success/message collapse -- RegisterProviderInstanceResponse and
 *     UpdateProviderInstanceResponse each hold a single message field. Both
 *     agc_provider_info and agc_provider_instance are descriptive and carry
 *     no storage, so those four flatten onto two shared wrappers that supply
 *     it: agc_provider_info_response and agc_provider_instance_response.
 *   - GetProvider, GetProviderInstance and DeleteProviderInstance take a
 *     bare id string rather than a one-field request struct, and Register
 *     and Update take a bare agc_provider_instance, matching the same
 *     flattening applied in agc_policy.h.
 *
 * STATUS: declarations only. Implementation follows; see
 * docs/implementation_progress.md.
 */

#ifndef AGC_PROVIDER_H
#define AGC_PROVIDER_H

#include "agc_core.h"
#include "agc_provider_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Provider capabilities (static catalog)
 * -------------------------------------------------------------------------- */

/* The iterator is a library-owned handle (it has a lifecycle: paging
 * bookkeeping, D12); the records it yields are caller-allocated. */
AGC_API agc_rc agc_list_providers(agc_ctx *ctx, const agc_list_providers_request *req,
                                   agc_provider_iter **out_iter);

/* Fills *out with the next provider type. On AGC_ERR_BUFFER_TOO_SMALL the
 * cursor does not advance, so the caller may resize out->storage and call
 * again for the same provider. AGC_ERR_ITERATOR_EXHAUSTED at the end. A
 * caller may reuse one record and one storage region across the whole loop.
 * Fills the shared single-provider response, since agc_provider_info carries
 * no storage of its own. */
AGC_API agc_rc agc_provider_iter_next(agc_provider_iter *it, agc_provider_info_response *out);
AGC_API void   agc_provider_iter_free(agc_provider_iter *it);

/* GetProviderRequest is {provider_id} and GetProviderResponse is {provider};
 * both flatten. */
AGC_API agc_rc agc_get_provider(agc_ctx *ctx, const char *provider_id,
                                 agc_provider_info_response *resp);

/* --------------------------------------------------------------------------
 * Provider instances (runtime configuration)
 * -------------------------------------------------------------------------- */

/* `instance` is the caller-built instance to register; its strings and map
 * come from caller memory. *resp receives the registered instance with any
 * defaults applied, into resp->storage, and may be NULL if the caller does
 * not want it back. Configuration is validated against the provider's
 * configuration_schema. */
AGC_API agc_rc agc_register_provider_instance(agc_ctx *ctx,
                                               const agc_provider_instance *instance,
                                               agc_provider_instance_response *resp);

AGC_API agc_rc agc_list_provider_instances(agc_ctx *ctx,
                                            const agc_list_provider_instances_request *req,
                                            agc_provider_instance_iter **out_iter);

/* Same cursor and storage contract as agc_provider_iter_next. Fills the
 * shared single-instance response, since agc_provider_instance carries no
 * storage of its own. */
AGC_API agc_rc agc_provider_instance_iter_next(agc_provider_instance_iter *it,
                                                agc_provider_instance_response *out);
AGC_API void   agc_provider_instance_iter_free(agc_provider_instance_iter *it);

/* GetProviderInstanceRequest is {instance_id} and its response is
 * {instance}; both flatten. */
AGC_API agc_rc agc_get_provider_instance(agc_ctx *ctx, const char *instance_id,
                                          agc_provider_instance_response *resp);

/* FULL-REPLACEMENT semantics, as in the proto: there is no field masking, so
 * every field of `instance` is written. Read the current instance with
 * agc_get_provider_instance first and modify it in place, which is what
 * stops fields being silently dropped. *resp may be NULL. */
AGC_API agc_rc agc_update_provider_instance(agc_ctx *ctx,
                                             const agc_provider_instance *instance,
                                             agc_provider_instance_response *resp);

/* DeleteProviderInstanceRequest is {instance_id}, flattened; its response is
 * {success, message}, which collapses (D4). Fails while keys still reference
 * this instance; the reason is available from agc_last_error(). */
AGC_API agc_rc agc_delete_provider_instance(agc_ctx *ctx, const char *instance_id);

/* --------------------------------------------------------------------------
 * Provider matching
 * -------------------------------------------------------------------------- */

/* Finds the instances satisfying req->requirements for req->template_id,
 * best match first. Read-only, so its storage requirement is exact. */
AGC_API agc_rc agc_match_providers(agc_ctx *ctx, const agc_match_providers_request *req,
                                    agc_match_providers_response *resp);

#ifdef __cplusplus
}
#endif
#endif /* AGC_PROVIDER_H */
