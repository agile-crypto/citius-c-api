/* SPDX-License-Identifier: Apache-2.0
 *
 * provider.c — ProviderService entry points over providerstore.c.
 *
 * Two catalogs, matching the proto's own split: ProviderInfo (a provider
 * TYPE and its static capabilities) has exactly one entry ("stub") in this
 * build; ProviderInstance (a configured, named provider ready for use) is a
 * real per-context CRUD store a caller populates at runtime.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_provider.h"
#include "agc_discovery.h" /* agc_get_template, to validate template_id in agc_match_providers */

#include <stdlib.h>
#include <string.h>

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

/* --------------------------------------------------------------------------
 * ProviderInfo (static catalog of one)
 * -------------------------------------------------------------------------- */

struct agc_provider_iter {
    agc_generic_iter *inner;
};

agc_rc agc_list_providers(agc_ctx *ctx, const agc_list_providers_params *p, agc_provider_iter **out_iter)
{
    if (!ctx_usable(ctx) || !out_iter) return AGC_ERR_INVALID_ARGUMENT;
    *out_iter = NULL;
    if (p && p->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;

    agc_provider_info **items = calloc(1, sizeof(*items));
    if (!items) return AGC_ERR_OUT_OF_MEMORY;
    items[0] = agc__make_stub_provider_info();
    if (!items[0]) { free(items); return AGC_ERR_OUT_OF_MEMORY; }

    struct agc_provider_iter *it = calloc(1, sizeof(*it));
    if (!it) { agc_provider_info_free(items[0]); free(items); return AGC_ERR_OUT_OF_MEMORY; }
    agc_rc rc = agc__iter_create((void **)items, 1, (agc_generic_item_free_fn)agc_provider_info_free, &it->inner);
    if (rc != AGC_OK) { agc_provider_info_free(items[0]); free(items); free(it); return rc; }
    *out_iter = it;
    return AGC_OK;
}

agc_rc agc_provider_iter_next(agc_provider_iter *it, agc_provider_info **out)
{
    if (!it || !out) return AGC_ERR_INVALID_ARGUMENT;
    void *item = NULL;
    agc_rc rc = agc__iter_next(it->inner, &item);
    *out = item;
    return rc;
}

void agc_provider_iter_free(agc_provider_iter *it)
{
    if (!it) return;
    agc__iter_free(it->inner);
    free(it);
}

agc_rc agc_get_provider(agc_ctx *ctx, const char *provider_id, agc_provider_info **out_provider)
{
    if (!ctx_usable(ctx) || !provider_id || !*provider_id || !out_provider) return AGC_ERR_INVALID_ARGUMENT;
    *out_provider = NULL;
    if (!agc__provider_is_known(provider_id)) return AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND;
    *out_provider = agc__make_stub_provider_info();
    return *out_provider ? AGC_OK : AGC_ERR_OUT_OF_MEMORY;
}

/* --------------------------------------------------------------------------
 * ProviderInstance CRUD
 * -------------------------------------------------------------------------- */

agc_rc agc_register_provider_instance(agc_ctx *ctx, const agc_provider_instance_spec *spec,
                                       agc_provider_instance **out_instance)
{
    if (out_instance) *out_instance = NULL;
    if (!ctx_usable(ctx) || !out_instance) return AGC_ERR_INVALID_ARGUMENT;
    return agc__providerstore_register(ctx, spec, out_instance);
}

struct agc_provider_instance_iter {
    agc_provider_instance **items;
    size_t                   count;
    size_t                   index;
};

agc_rc agc_list_provider_instances(agc_ctx *ctx, const agc_list_provider_instances_params *p,
                                    agc_provider_instance_iter **out_iter)
{
    if (!ctx_usable(ctx) || !out_iter) return AGC_ERR_INVALID_ARGUMENT;
    *out_iter = NULL;
    if (p && p->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;

    const char *provider_id_filter = p ? p->provider_id : NULL;
    int enabled_only = p ? p->enabled_only : 0;

    agc_provider_instance **items = NULL;
    size_t count = 0;
    agc_rc rc = agc__providerstore_list(ctx, provider_id_filter, enabled_only, &items, &count);
    if (rc != AGC_OK) return rc;

    struct agc_provider_instance_iter *it = calloc(1, sizeof(*it));
    if (!it) {
        for (size_t i = 0; i < count; i++) agc_provider_instance_free(items[i]);
        free(items);
        return AGC_ERR_OUT_OF_MEMORY;
    }
    it->items = items;
    it->count = count;
    *out_iter = it;
    return AGC_OK;
}

agc_rc agc_provider_instance_iter_next(agc_provider_instance_iter *it, agc_provider_instance **out)
{
    if (!it || !out) return AGC_ERR_INVALID_ARGUMENT;
    if (it->index >= it->count) return AGC_ERR_ITERATOR_EXHAUSTED;
    *out = it->items[it->index];
    it->index++;
    return AGC_OK;
}

void agc_provider_instance_iter_free(agc_provider_instance_iter *it)
{
    if (!it) return;
    for (size_t i = it->index; i < it->count; i++) agc_provider_instance_free(it->items[i]);
    free(it->items);
    free(it);
}

agc_rc agc_get_provider_instance(agc_ctx *ctx, const char *instance_id, agc_provider_instance **out_instance)
{
    if (out_instance) *out_instance = NULL;
    if (!ctx_usable(ctx) || !instance_id || !*instance_id || !out_instance) return AGC_ERR_INVALID_ARGUMENT;
    return agc__providerstore_get(ctx, instance_id, out_instance);
}

agc_rc agc_update_provider_instance(agc_ctx *ctx, const agc_provider_instance_spec *spec,
                                     agc_provider_instance **out_instance)
{
    if (out_instance) *out_instance = NULL;
    if (!ctx_usable(ctx) || !spec || spec->struct_size == 0 || !spec->instance_id || !out_instance) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    if (!agc__provider_is_known(spec->provider_id)) return AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND;
    return agc__providerstore_update(ctx, spec, out_instance);
}

agc_rc agc_delete_provider_instance(agc_ctx *ctx, const char *instance_id)
{
    if (!ctx_usable(ctx) || !instance_id || !*instance_id) return AGC_ERR_INVALID_ARGUMENT;

    /* No referential-integrity check against keys here (unlike
     * agc_delete_policy()'s check in policystore.c): keystore.c's KeyInfo
     * tracks only the fixed static provider TYPE ("stub"), never a
     * caller-registered provider INSTANCE id, so there is no key-side field
     * that could ever reference this instance_id to check against. */
    return agc__providerstore_delete(ctx, instance_id);
}

/* --------------------------------------------------------------------------
 * Provider matching
 * -------------------------------------------------------------------------- */

static int tribool_ok(agc_tribool required, int actual)
{
    switch (required) {
    case AGC_TRUE:  return actual != 0;
    case AGC_FALSE: return actual == 0;
    default:        return 1; /* AGC_UNSET: no preference */
    }
}

static int requirements_satisfied(const agc_provider_requirements *req, const agc_impl_props *props)
{
    if (!req) return 1;
    if (!tribool_ok(req->fips_140_certified, agc_impl_props_fips_certified(props))) return 0;
    if (req->min_fips_level != AGC_FIPS_140_LEVEL_UNSPECIFIED &&
        agc_impl_props_fips_level(props) < req->min_fips_level) {
        return 0;
    }
    /* Not tracked by the stub's ImplementationProperties (no CC audits, no
     * CVE database): fail closed on an explicit TRUE requirement (D9),
     * satisfy an explicit FALSE (the stub is honestly neither), no-op on
     * UNSET. */
    if (!tribool_ok(req->common_criteria_certified, 0)) return 0;
    if (!tribool_ok(req->formally_verified, agc_impl_props_formally_verified(props) == AGC_TRUE)) return 0;
    if (!tribool_ok(req->memory_safe, agc_impl_props_memory_safe_language(props) == AGC_TRUE)) return 0;
    if (!tribool_ok(req->constant_time, agc_impl_props_constant_time(props) == AGC_TRUE)) return 0;
    if (!tribool_ok(req->side_channel_hardened, agc_impl_props_side_channel_hardened(props) == AGC_TRUE)) return 0;
    /* no_known_cve: trivially satisfiable -- the stub tracks no CVE list to
     * contradict it. */
    return 1;
}

static int32_t score_for(const agc_provider_requirements *req, const agc_impl_props *props)
{
    int32_t score = 100;
    if (req && req->prefer_hardware_accelerated == AGC_TRUE &&
        agc_impl_props_hardware_accelerated(props) == AGC_TRUE) {
        score += 10;
    }
    return score;
}

static int match_cmp(const void *a, const void *b)
{
    const agc_provider_match *ma = a, *mb = b;
    return mb->match_score - ma->match_score; /* highest first */
}

agc_rc agc_match_providers(agc_ctx *ctx, const agc_match_providers_params *p,
                            agc_provider_match **out_matches, size_t *out_count)
{
    if (out_matches) *out_matches = NULL;
    if (out_count) *out_count = 0;
    if (!ctx_usable(ctx) || !p || p->struct_size == 0 || !p->template_id || !*p->template_id ||
        !out_matches || !out_count) {
        return AGC_ERR_INVALID_ARGUMENT;
    }

    /* Confirm the template exists (agc_get_template lives in discovery.c and
     * is part of the same public surface); an unknown template can match no
     * provider by construction. */
    agc_template_info *tmpl = NULL;
    agc_rc rc = agc_get_template(ctx, p->template_id, &tmpl);
    if (rc != AGC_OK) return rc;
    agc_template_info_free(tmpl);

    agc_provider_instance **instances = NULL;
    size_t instance_count = 0;
    rc = agc__providerstore_list(ctx, NULL, p->enabled_only, &instances, &instance_count);
    if (rc != AGC_OK) return rc;

    agc_provider_match *matches = instance_count ? calloc(instance_count, sizeof(*matches)) : NULL;
    size_t n = 0;
    for (size_t i = 0; i < instance_count; i++) {
        agc_impl_props *props = agc__make_stub_impl_props(); /* every known instance uses "stub" */
        if (props && requirements_satisfied(p->requirements, props)) {
            matches[n].instance = instances[i];
            matches[n].resolved_implementation = props;
            matches[n].match_score = score_for(p->requirements, props);
            n++;
        } else {
            agc_impl_props_free(props);
            agc_provider_instance_free(instances[i]);
        }
    }
    free(instances);

    if (n > 1) qsort(matches, n, sizeof(*matches), match_cmp);

    *out_matches = matches;
    *out_count = n;
    return AGC_OK;
}

void agc_provider_match_list_free(agc_provider_match *matches, size_t count)
{
    if (!matches) return;
    for (size_t i = 0; i < count; i++) {
        agc_provider_instance_free((agc_provider_instance *)matches[i].instance);
        agc_impl_props_free((agc_impl_props *)matches[i].resolved_implementation);
    }
    free(matches);
}
