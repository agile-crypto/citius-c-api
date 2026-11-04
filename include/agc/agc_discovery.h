/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_discovery.h — AlgorithmDiscoveryService (3 RPCs;
 * api/services/discovery_service.proto).
 *
 * Functions only. Every request, record and response type they name is
 * defined in agc_discovery_types.h, which also states the STORAGE CONTRACT
 * that governs every caller-allocated record below: a NULL or too-small
 * `storage` region returns AGC_ERR_BUFFER_TOO_SMALL with `storage_used` set
 * to the requirement. Every operation here is read-only, so that
 * requirement is exact.
 *
 * The library allocates nothing the caller sees and there is nothing to
 * free, except the one iterator handle.
 *
 * STATUS: declarations only. Implementation follows; see
 * docs/implementation_progress.md.
 */

#ifndef AGC_DISCOVERY_H
#define AGC_DISCOVERY_H

#include "agc_core.h"
#include "agc_discovery_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ListTemplates / GetTemplate
 * -------------------------------------------------------------------------- */

/* The iterator is a library-owned handle (it has a lifecycle: paging
 * bookkeeping, D12); the records it yields are caller-allocated. */
AGC_API agc_rc agc_list_templates(agc_ctx *ctx, const agc_list_templates_params *p,
                                   agc_template_iter **out_iter);

/* Fills *out with the next template. On AGC_ERR_BUFFER_TOO_SMALL the cursor
 * does not advance, so the caller may resize out->storage and call again for
 * the same template. AGC_ERR_ITERATOR_EXHAUSTED at the end. A caller may
 * reuse one record and one storage region across the whole loop. */
AGC_API agc_rc agc_template_iter_next(agc_template_iter *it, agc_template_info_response *out);
AGC_API void   agc_template_iter_free(agc_template_iter *it);

AGC_API agc_rc agc_get_template(agc_ctx *ctx, const char *template_id,
                                 agc_template_info_response *resp);

/* --------------------------------------------------------------------------
 * ListScopes
 * -------------------------------------------------------------------------- */

/* Fills resp->scopes with every scope the catalog describes. Two-call on
 * both the array and the storage region; see agc_list_scopes_response. */
AGC_API agc_rc agc_list_scopes(agc_ctx *ctx, agc_list_scopes_response *resp);

#ifdef __cplusplus
}
#endif
#endif /* AGC_DISCOVERY_H */
