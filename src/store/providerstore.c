/* SPDX-License-Identifier: Apache-2.0
 *
 * providerstore.c — one static ProviderInfo ("stub") plus a real, mutable
 * per-context store of ProviderInstance registrations backing agc_provider.h.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_provider.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * ImplementationProperties -- one real snapshot type, used both as the
 * stub provider's static default and as instance override storage.
 * -------------------------------------------------------------------------- */

struct agc_impl_props {
    int               fips_certified;
    agc_fips140_level fips_level;
    agc_tribool       formally_verified;
    agc_tribool       memory_safe_language;
    char             *implementation_language;
    agc_tribool       constant_time;
    agc_tribool       side_channel_hardened;
    agc_tribool       hardware_accelerated;
};

static agc_impl_props *make_stub_impl_props(void)
{
    struct agc_impl_props *ip = calloc(1, sizeof(*ip));
    if (!ip) return NULL;
    ip->fips_certified = 0;
    ip->fips_level = AGC_FIPS_140_LEVEL_UNSPECIFIED;
    ip->formally_verified = AGC_FALSE;
    ip->memory_safe_language = AGC_FALSE; /* C is not memory-safe */
    ip->implementation_language = strdup("C");
    ip->constant_time = AGC_FALSE; /* the stub's XOR/FNV constructions make no such claim */
    ip->side_channel_hardened = AGC_FALSE;
    ip->hardware_accelerated = AGC_FALSE;
    return ip;
}

void agc_impl_props_free(agc_impl_props *ip)
{
    if (!ip) return;
    free(ip->implementation_language);
    free(ip);
}

int agc_impl_props_fips_certified(const agc_impl_props *ip) { return ip ? ip->fips_certified : 0; }
agc_fips140_level agc_impl_props_fips_level(const agc_impl_props *ip)
{
    return ip ? ip->fips_level : AGC_FIPS_140_LEVEL_UNSPECIFIED;
}
agc_tribool agc_impl_props_formally_verified(const agc_impl_props *ip) { return ip ? ip->formally_verified : AGC_UNSET; }
agc_tribool agc_impl_props_memory_safe_language(const agc_impl_props *ip) { return ip ? ip->memory_safe_language : AGC_UNSET; }
const char *agc_impl_props_implementation_language(const agc_impl_props *ip) { return ip ? ip->implementation_language : NULL; }
agc_tribool agc_impl_props_constant_time(const agc_impl_props *ip) { return ip ? ip->constant_time : AGC_UNSET; }
agc_tribool agc_impl_props_side_channel_hardened(const agc_impl_props *ip) { return ip ? ip->side_channel_hardened : AGC_UNSET; }
agc_tribool agc_impl_props_hardware_accelerated(const agc_impl_props *ip) { return ip ? ip->hardware_accelerated : AGC_UNSET; }

/* --------------------------------------------------------------------------
 * ProviderInfo -- one static entry
 * -------------------------------------------------------------------------- */

struct agc_provider_info {
    char             *id;
    char             *display_name;
    char             *description;
    agc_provider_type type;
    agc_impl_props   *default_implementation;
};

static agc_provider_info *make_stub_provider_info(void)
{
    struct agc_provider_info *pi = calloc(1, sizeof(*pi));
    if (!pi) return NULL;
    pi->id = strdup("stub");
    pi->display_name = strdup("Stub Provider");
    pi->description = strdup("Deterministic, non-cryptographically-secure provider for API testing.");
    pi->type = AGC_PROVIDER_TYPE_SOFTWARE;
    pi->default_implementation = make_stub_impl_props();
    return pi;
}

void agc_provider_info_free(agc_provider_info *pi)
{
    if (!pi) return;
    free(pi->id);
    free(pi->display_name);
    free(pi->description);
    agc_impl_props_free(pi->default_implementation);
    free(pi);
}

const char *agc_provider_info_id(const agc_provider_info *pi) { return pi ? pi->id : NULL; }
const char *agc_provider_info_display_name(const agc_provider_info *pi) { return pi ? pi->display_name : NULL; }
const char *agc_provider_info_description(const agc_provider_info *pi) { return pi ? pi->description : NULL; }
agc_provider_type agc_provider_info_type(const agc_provider_info *pi) { return pi ? pi->type : AGC_PROVIDER_TYPE_UNSPECIFIED; }
const agc_impl_props *agc_provider_info_default_implementation(const agc_provider_info *pi)
{
    return pi ? pi->default_implementation : NULL;
}
size_t agc_provider_info_capability_count(const agc_provider_info *pi) { (void)pi; return 0; }
agc_rc agc_provider_info_capability_at(const agc_provider_info *pi, size_t i, const char **k, const char **v)
{
    (void)pi; (void)i; (void)k; (void)v; return AGC_ERR_INVALID_ARGUMENT;
}
const char *agc_provider_info_capability_get(const agc_provider_info *pi, const char *key) { (void)pi; (void)key; return NULL; }

int agc__provider_is_known(const char *provider_id) { return provider_id && strcmp(provider_id, "stub") == 0; }

/* --------------------------------------------------------------------------
 * ProviderInstance store (real, per-context, mutable)
 * -------------------------------------------------------------------------- */

typedef struct instance_entry {
    char       *instance_id;
    char       *provider_id;
    char       *display_name;
    char       *description;
    agc_kv     *config_items;
    size_t      config_count;
    int         enabled;
} instance_entry;

struct agc_providerstore {
    pthread_mutex_t   mutex;
    instance_entry  **items;
    size_t            count;
    size_t            cap;
};

struct agc_provider_instance {
    char       *instance_id;
    char       *provider_id;
    char       *display_name;
    char       *description;
    agc_kv     *config_items;
    size_t      config_count;
    int         enabled;
};

static void free_instance_entry(instance_entry *e)
{
    if (!e) return;
    free(e->instance_id);
    free(e->provider_id);
    free(e->display_name);
    free(e->description);
    for (size_t i = 0; i < e->config_count; i++) { free((void *)e->config_items[i].key); free((void *)e->config_items[i].value); }
    free(e->config_items);
    free(e);
}

static void *providerstore_create(void)
{
    struct agc_providerstore *ps = calloc(1, sizeof(*ps));
    if (ps) pthread_mutex_init(&ps->mutex, NULL);
    return ps;
}

static void providerstore_destroy(void *p)
{
    struct agc_providerstore *ps = p;
    if (!ps) return;
    for (size_t i = 0; i < ps->count; i++) free_instance_entry(ps->items[i]);
    free(ps->items);
    pthread_mutex_destroy(&ps->mutex);
    free(ps);
}

static struct agc_providerstore *store_for(agc_ctx *ctx)
{
    return agc__ctx_get_or_create_ext(ctx, AGC_CTX_EXT_PROVIDERSTORE, providerstore_create, providerstore_destroy);
}

static agc_rc dup_kv(const agc_kv_list *in, agc_kv **out_items, size_t *out_count)
{
    *out_items = NULL; *out_count = 0;
    if (!in || in->count == 0) return AGC_OK;
    agc_kv *items = calloc(in->count, sizeof(*items));
    if (!items) return AGC_ERR_OUT_OF_MEMORY;
    for (size_t i = 0; i < in->count; i++) {
        items[i].key = strdup(in->items[i].key);
        items[i].value = strdup(in->items[i].value);
    }
    *out_items = items;
    *out_count = in->count;
    return AGC_OK;
}

static instance_entry *find_locked(struct agc_providerstore *ps, const char *id)
{
    for (size_t i = 0; i < ps->count; i++) {
        if (strcmp(ps->items[i]->instance_id, id) == 0) return ps->items[i];
    }
    return NULL;
}

static agc_provider_instance *snapshot_instance(const instance_entry *e)
{
    struct agc_provider_instance *inst = calloc(1, sizeof(*inst));
    if (!inst) return NULL;
    inst->instance_id = strdup(e->instance_id);
    inst->provider_id = strdup(e->provider_id);
    inst->display_name = strdup(e->display_name ? e->display_name : "");
    inst->description = strdup(e->description ? e->description : "");
    inst->enabled = e->enabled;
    if (e->config_count) {
        inst->config_items = calloc(e->config_count, sizeof(*inst->config_items));
        for (size_t i = 0; i < e->config_count; i++) {
            inst->config_items[i].key = strdup(e->config_items[i].key);
            inst->config_items[i].value = strdup(e->config_items[i].value);
        }
        inst->config_count = e->config_count;
    }
    return inst;
}

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

agc_rc agc__providerstore_register(agc_ctx *ctx, const agc_provider_instance_spec *spec,
                                    agc_provider_instance **out_instance)
{
    if (!ctx_usable(ctx) || !spec || !out_instance) return AGC_ERR_INVALID_ARGUMENT;
    *out_instance = NULL;
    if (spec->struct_size == 0 || !spec->instance_id || !*spec->instance_id ||
        !spec->provider_id || !*spec->provider_id) {
        return AGC_ERR_INVALID_ARGUMENT;
    }
    if (!agc__provider_is_known(spec->provider_id)) return AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND;

    struct agc_providerstore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;

    pthread_mutex_lock(&ps->mutex);
    if (find_locked(ps, spec->instance_id)) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_ALREADY_EXISTS; }

    instance_entry *e = calloc(1, sizeof(*e));
    e->instance_id = strdup(spec->instance_id);
    e->provider_id = strdup(spec->provider_id);
    e->display_name = strdup(spec->display_name ? spec->display_name : "");
    e->description = strdup(spec->description ? spec->description : "");
    e->enabled = spec->enabled;
    agc_rc rc = dup_kv(&spec->configuration, &e->config_items, &e->config_count);
    if (rc != AGC_OK) { free_instance_entry(e); pthread_mutex_unlock(&ps->mutex); return rc; }

    if (ps->count == ps->cap) {
        size_t new_cap = ps->cap ? ps->cap * 2 : 8;
        ps->items = realloc(ps->items, new_cap * sizeof(*ps->items));
        ps->cap = new_cap;
    }
    ps->items[ps->count++] = e;

    *out_instance = snapshot_instance(e);
    pthread_mutex_unlock(&ps->mutex);
    return *out_instance ? AGC_OK : AGC_ERR_OUT_OF_MEMORY;
}

agc_rc agc__providerstore_get(agc_ctx *ctx, const char *instance_id, agc_provider_instance **out)
{
    struct agc_providerstore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;
    pthread_mutex_lock(&ps->mutex);
    instance_entry *e = find_locked(ps, instance_id);
    if (!e) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND; }
    *out = snapshot_instance(e);
    pthread_mutex_unlock(&ps->mutex);
    return *out ? AGC_OK : AGC_ERR_OUT_OF_MEMORY;
}

agc_rc agc__providerstore_update(agc_ctx *ctx, const agc_provider_instance_spec *spec,
                                  agc_provider_instance **out_instance)
{
    if (!spec || !spec->instance_id) return AGC_ERR_INVALID_ARGUMENT;
    struct agc_providerstore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;
    pthread_mutex_lock(&ps->mutex);
    instance_entry *e = find_locked(ps, spec->instance_id);
    if (!e) { pthread_mutex_unlock(&ps->mutex); return AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND; }

    /* Full replacement, no field masking (matches the proto). */
    free(e->provider_id); e->provider_id = strdup(spec->provider_id);
    free(e->display_name); e->display_name = strdup(spec->display_name ? spec->display_name : "");
    free(e->description); e->description = strdup(spec->description ? spec->description : "");
    e->enabled = spec->enabled;
    for (size_t i = 0; i < e->config_count; i++) { free((void *)e->config_items[i].key); free((void *)e->config_items[i].value); }
    free(e->config_items);
    agc_rc rc = dup_kv(&spec->configuration, &e->config_items, &e->config_count);
    if (rc != AGC_OK) { pthread_mutex_unlock(&ps->mutex); return rc; }

    *out_instance = snapshot_instance(e);
    pthread_mutex_unlock(&ps->mutex);
    return *out_instance ? AGC_OK : AGC_ERR_OUT_OF_MEMORY;
}

agc_rc agc__providerstore_delete(agc_ctx *ctx, const char *instance_id)
{
    struct agc_providerstore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;
    pthread_mutex_lock(&ps->mutex);
    for (size_t i = 0; i < ps->count; i++) {
        if (strcmp(ps->items[i]->instance_id, instance_id) == 0) {
            free_instance_entry(ps->items[i]);
            ps->items[i] = ps->items[ps->count - 1];
            ps->count--;
            pthread_mutex_unlock(&ps->mutex);
            return AGC_OK;
        }
    }
    pthread_mutex_unlock(&ps->mutex);
    return AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND;
}

agc_rc agc__providerstore_list(agc_ctx *ctx, const char *provider_id_filter, int enabled_only,
                                agc_provider_instance ***out_items, size_t *out_count)
{
    struct agc_providerstore *ps = store_for(ctx);
    if (!ps) return AGC_ERR_OUT_OF_MEMORY;
    pthread_mutex_lock(&ps->mutex);
    agc_provider_instance **items = ps->count ? calloc(ps->count, sizeof(*items)) : NULL;
    size_t n = 0;
    for (size_t i = 0; i < ps->count; i++) {
        instance_entry *e = ps->items[i];
        if (provider_id_filter && strcmp(e->provider_id, provider_id_filter) != 0) continue;
        if (enabled_only && !e->enabled) continue;
        items[n++] = snapshot_instance(e);
    }
    pthread_mutex_unlock(&ps->mutex);
    *out_items = items;
    *out_count = n;
    return AGC_OK;
}

void agc_provider_instance_free(agc_provider_instance *inst)
{
    if (!inst) return;
    free(inst->instance_id);
    free(inst->provider_id);
    free(inst->display_name);
    free(inst->description);
    for (size_t i = 0; i < inst->config_count; i++) { free((void *)inst->config_items[i].key); free((void *)inst->config_items[i].value); }
    free(inst->config_items);
    free(inst);
}

const char *agc_provider_instance_id(const agc_provider_instance *inst) { return inst ? inst->instance_id : NULL; }
const char *agc_provider_instance_provider_id(const agc_provider_instance *inst) { return inst ? inst->provider_id : NULL; }
const char *agc_provider_instance_display_name(const agc_provider_instance *inst) { return inst ? inst->display_name : NULL; }
const char *agc_provider_instance_description(const agc_provider_instance *inst) { return inst ? inst->description : NULL; }
int agc_provider_instance_enabled(const agc_provider_instance *inst) { return inst ? inst->enabled : 0; }
size_t agc_provider_instance_config_count(const agc_provider_instance *inst) { return inst ? inst->config_count : 0; }
agc_rc agc_provider_instance_config_at(const agc_provider_instance *inst, size_t i, const char **k, const char **v)
{
    if (!inst || i >= inst->config_count || !k || !v) return AGC_ERR_INVALID_ARGUMENT;
    *k = inst->config_items[i].key;
    *v = inst->config_items[i].value;
    return AGC_OK;
}

agc_rc agc_provider_instance_to_spec(const agc_provider_instance *instance, agc_provider_instance_spec *out_spec)
{
    if (!instance || !out_spec || out_spec->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    out_spec->instance_id = instance->instance_id;
    out_spec->provider_id = instance->provider_id;
    out_spec->display_name = instance->display_name;
    out_spec->description = instance->description;
    out_spec->configuration.items = instance->config_items;
    out_spec->configuration.count = instance->config_count;
    out_spec->enabled = instance->enabled;
    return AGC_OK;
}

agc_provider_info *agc__make_stub_provider_info(void) { return make_stub_provider_info(); }
agc_impl_props *agc__make_stub_impl_props(void) { return make_stub_impl_props(); }
