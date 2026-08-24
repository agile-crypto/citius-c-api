/* SPDX-License-Identifier: Apache-2.0
 *
 * key.c — KeyManagementService (11 RPCs), thin entry points over
 * src/store/keystore.c. Argument validation and the D4 success/message ->
 * agc_rc collapse happen here; storage logic lives in the keystore.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ctx_usable(agc_ctx *ctx)
{
    return ctx != NULL && !agc__ctx_is_poisoned(ctx);
}

agc_rc agc_create_key(agc_ctx *ctx, const agc_create_key_params *params,
                       agc_key_info **out_key, agc_impl_props **out_impl)
{
    if (out_impl) *out_impl = NULL; /* agc_impl_props lands in commit 11 */
    if (!ctx_usable(ctx) || !params || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (!params->name || !*params->name) return AGC_ERR_INVALID_ARGUMENT;
    if (!params->scope_spec && !params->template_id) return AGC_ERR_INVALID_ARGUMENT;
    if (params->scope_spec && params->template_id &&
        params->scope_spec->kind == AGC_SCOPE_KIND_NONE) {
        return AGC_ERR_INVALID_ARGUMENT;
    }

    return agc__keystore_create_key(ctx, params->name, params->policy,
                                     params->scope_spec, params->template_id, out_key);
}

agc_rc agc_read_key(agc_ctx *ctx, const char *name, uint32_t version, agc_key_info **out_key)
{
    if (!ctx_usable(ctx) || !name || !*name || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    return agc__keystore_read(ctx, name, version, out_key);
}

struct agc_key_iter {
    agc_generic_iter *inner;
};

agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params, agc_key_iter **out_iter)
{
    if (!ctx_usable(ctx) || !out_iter) return AGC_ERR_INVALID_ARGUMENT;
    *out_iter = NULL;
    agc_key_lifecycle_state filter = AGC_KEY_LIFECYCLE_STATE_UNSPECIFIED;
    if (params) {
        if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
        filter = params->lifecycle_state;
    }

    agc_key_info **items = NULL;
    size_t count = 0;
    agc_rc rc = agc__keystore_list(ctx, filter, &items, &count);
    if (rc != AGC_OK) return rc;

    struct agc_key_iter *it = calloc(1, sizeof(*it));
    if (!it) {
        for (size_t i = 0; i < count; i++) agc_key_info_free(items[i]);
        free(items);
        return AGC_ERR_OUT_OF_MEMORY;
    }
    rc = agc__iter_create((void **)items, count, (agc_generic_item_free_fn)agc_key_info_free, &it->inner);
    if (rc != AGC_OK) {
        for (size_t i = 0; i < count; i++) agc_key_info_free(items[i]);
        free(items);
        free(it);
        return rc;
    }
    *out_iter = it;
    return AGC_OK;
}

agc_rc agc_key_iter_next(agc_key_iter *it, agc_key_info **out)
{
    if (!it || !out) return AGC_ERR_INVALID_ARGUMENT;
    void *item = NULL;
    agc_rc rc = agc__iter_next(it->inner, &item);
    *out = item;
    return rc;
}

void agc_key_iter_free(agc_key_iter *it)
{
    if (!it) return;
    agc__iter_free(it->inner);
    free(it);
}

agc_rc agc_delete_key(agc_ctx *ctx, const char *name)
{
    if (!ctx_usable(ctx) || !name || !*name) return AGC_ERR_INVALID_ARGUMENT;
    return agc__keystore_delete(ctx, name);
}

agc_rc agc_rotate_key(agc_ctx *ctx, const char *name, agc_key_info **out_new_key)
{
    if (!ctx_usable(ctx) || !name || !*name || !out_new_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_new_key = NULL;
    return agc__keystore_rotate(ctx, name, out_new_key);
}

agc_rc agc_transform_key(agc_ctx *ctx, const agc_transform_key_params *params, agc_key_info **out_key)
{
    if (!ctx_usable(ctx) || !params || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (!params->name || !*params->name) return AGC_ERR_INVALID_ARGUMENT;

    return agc__keystore_transform(ctx, params->name, params->retain_key_bytes,
                                    params->scope_spec, params->template_id, out_key);
}

agc_rc agc_update_key_policy(agc_ctx *ctx, const char *name, const char *new_policy,
                              agc_key_info **out_key)
{
    if (!ctx_usable(ctx) || !name || !*name || !new_policy || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    return agc__keystore_update_policy(ctx, name, new_policy, out_key);
}

/* --------------------------------------------------------------------------
 * MigrateKey
 * -------------------------------------------------------------------------- */

struct agc_migration_report {
    agc_migration_strategy strategy_used;
    int                    key_bytes_preserved;
    char                  *source_provider_id;
    char                  *target_provider_id;
    char                  *wrapping_key_name;
    int                    has_archived_key;
    char                  *archived_key_name;
    char                  *archived_provider_id;
    agc_timestamp          archived_expiration;
};

agc_rc agc_migrate_key(agc_ctx *ctx, const agc_migrate_key_params *params,
                        agc_key_info **out_key, agc_migration_report **out_report)
{
    if (out_report) *out_report = NULL;
    if (!ctx_usable(ctx) || !params || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (!params->name || !*params->name) return AGC_ERR_INVALID_ARGUMENT;
    if (params->target.kind == AGC_MIGRATE_TARGET_NONE) return AGC_ERR_INVALID_ARGUMENT;
    if (params->strategy == AGC_MIGRATION_STRATEGY_UNSPECIFIED) return AGC_ERR_INVALID_ARGUMENT;

    /* The stub has exactly one provider ("stub"), so every migration is
     * necessarily a same-provider PROVIDER_SWITCH-shaped no-op that produces
     * a fresh version -- there is nowhere else to move the key to. This
     * still exercises the full request shape and the report structure. */
    agc_key_info *new_key = NULL;
    agc_rc rc = agc__keystore_transform(ctx, params->name, 0, params->scope_spec, params->template_id, &new_key);
    if (rc != AGC_OK) return rc;

    if (out_report) {
        struct agc_migration_report *r = calloc(1, sizeof(*r));
        if (r) {
            r->strategy_used = params->strategy;
            r->key_bytes_preserved = 0;
            r->source_provider_id = strdup("stub");
            r->target_provider_id = strdup(params->target.kind == AGC_MIGRATE_TARGET_PROVIDER
                                                ? (params->target.u.provider.provider_id ? params->target.u.provider.provider_id : "stub")
                                                : "stub");
            r->wrapping_key_name = NULL;
            if (params->strategy == AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE) {
                r->has_archived_key = 1;
                char archive_name[256];
                snprintf(archive_name, sizeof(archive_name), "%s.archived.v%u", params->name,
                         agc_key_info_version(new_key) - 1 > 0 ? agc_key_info_version(new_key) - 1 : 1);
                r->archived_key_name = strdup(archive_name);
                r->archived_provider_id = strdup("stub");
                r->archived_expiration.present = 0;
            }
        }
        *out_report = r;
    }

    *out_key = new_key;
    return AGC_OK;
}

void agc_migration_report_free(agc_migration_report *r)
{
    if (!r) return;
    free(r->source_provider_id);
    free(r->target_provider_id);
    free(r->wrapping_key_name);
    free(r->archived_key_name);
    free(r->archived_provider_id);
    free(r);
}

agc_migration_strategy agc_migration_report_strategy_used(const agc_migration_report *r)
{
    return r ? r->strategy_used : AGC_MIGRATION_STRATEGY_UNSPECIFIED;
}
int agc_migration_report_key_bytes_preserved(const agc_migration_report *r) { return r ? r->key_bytes_preserved : 0; }
const char *agc_migration_report_source_provider_id(const agc_migration_report *r) { return r ? r->source_provider_id : NULL; }
const char *agc_migration_report_target_provider_id(const agc_migration_report *r) { return r ? r->target_provider_id : NULL; }
const char *agc_migration_report_wrapping_key_name(const agc_migration_report *r) { return r ? r->wrapping_key_name : NULL; }
int agc_migration_report_has_archived_key(const agc_migration_report *r) { return r ? r->has_archived_key : 0; }
const char *agc_migration_report_archived_key_name(const agc_migration_report *r) { return r ? r->archived_key_name : NULL; }
const char *agc_migration_report_archived_provider_id(const agc_migration_report *r) { return r ? r->archived_provider_id : NULL; }
agc_timestamp agc_migration_report_archived_expiration(const agc_migration_report *r)
{
    return r ? r->archived_expiration : (agc_timestamp){0};
}

/* --------------------------------------------------------------------------
 * ValidateKeyOperation
 * -------------------------------------------------------------------------- */

struct agc_feasibility_report {
    char                  *current_template_id;
    char                  *current_provider_id;
    int                    current_extractable;
    agc_provider_type      current_provider_type;

    agc_migration_strategy option_strategy[8];
    int                    option_feasible[8];
    char                  *option_infeasibility_reason[8];
    int32_t                option_complexity_level[8];
    size_t                 option_count;

    agc_migration_strategy recommended_strategy;
    char                  *recommendation_reason;
};

static const agc_migration_strategy k_all_strategies[] = {
    AGC_MIGRATION_STRATEGY_PROVIDER_SWITCH,
    AGC_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT,
    AGC_MIGRATION_STRATEGY_WRAPPED_TRANSFER,
    AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
    AGC_MIGRATION_STRATEGY_REKEY_AND_DESTROY,
};

agc_rc agc_validate_key_operation(agc_ctx *ctx, const agc_validate_key_op_params *params,
                                   agc_feasibility_report **out_report)
{
    if (!ctx_usable(ctx) || !params || !out_report) return AGC_ERR_INVALID_ARGUMENT;
    if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    *out_report = NULL;
    if (!params->name || !*params->name) return AGC_ERR_INVALID_ARGUMENT;
    if (params->kind == AGC_VALIDATE_INTENT_NONE) return AGC_ERR_INVALID_ARGUMENT;

    agc_key_info *ki = NULL;
    agc_rc rc = agc__keystore_read(ctx, params->name, 0, &ki);
    if (rc != AGC_OK) return rc;

    struct agc_feasibility_report *r = calloc(1, sizeof(*r));
    if (!r) { agc_key_info_free(ki); return AGC_ERR_OUT_OF_MEMORY; }

    r->current_template_id = strdup(agc_key_info_template_id(ki));
    r->current_provider_id = strdup(agc_key_info_provider(ki));
    r->current_extractable = agc_key_info_extractable(ki);
    r->current_provider_type = AGC_PROVIDER_TYPE_SOFTWARE;

    if (params->kind == AGC_VALIDATE_INTENT_TRANSFORM) {
        /* Per the proto: for TRANSFORM, `strategy` is UNSPECIFIED and
         * feasibility rides on feasible/infeasibility_reason alone. One
         * option, matching the single "regenerate or keep bytes" choice
         * TransformKey actually offers. */
        r->option_count = 1;
        r->option_strategy[0] = AGC_MIGRATION_STRATEGY_UNSPECIFIED;
        r->option_feasible[0] = 1;
        r->option_infeasibility_reason[0] = NULL;
        r->option_complexity_level[0] = 1;
        r->recommended_strategy = AGC_MIGRATION_STRATEGY_UNSPECIFIED;
        r->recommendation_reason = strdup("transform is always feasible against the stub provider");
    } else {
        size_t n = sizeof(k_all_strategies) / sizeof(k_all_strategies[0]);
        for (size_t i = 0; i < n && i < 8; i++) {
            r->option_strategy[i] = k_all_strategies[i];
            /* The stub has one provider, so cross-provider strategies are
             * reported infeasible rather than silently treated as no-ops --
             * an honest answer is more useful than a fabricated success. */
            int cross_provider = (k_all_strategies[i] == AGC_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT ||
                                   k_all_strategies[i] == AGC_MIGRATION_STRATEGY_WRAPPED_TRANSFER);
            r->option_feasible[i] = !cross_provider;
            r->option_infeasibility_reason[i] = cross_provider
                ? strdup("only one provider (\"stub\") is registered in this build")
                : NULL;
            r->option_complexity_level[i] = cross_provider ? 3 : 1;
            r->option_count++;
        }
        r->recommended_strategy = AGC_MIGRATION_STRATEGY_PROVIDER_SWITCH;
        r->recommendation_reason = strdup("lowest complexity option available against the stub provider");
    }

    agc_key_info_free(ki);
    *out_report = r;
    return AGC_OK;
}

void agc_feasibility_report_free(agc_feasibility_report *r)
{
    if (!r) return;
    free(r->current_template_id);
    free(r->current_provider_id);
    for (size_t i = 0; i < r->option_count; i++) free(r->option_infeasibility_reason[i]);
    free(r->recommendation_reason);
    free(r);
}

const char *agc_feasibility_current_template_id(const agc_feasibility_report *r) { return r ? r->current_template_id : NULL; }
const char *agc_feasibility_current_provider_id(const agc_feasibility_report *r) { return r ? r->current_provider_id : NULL; }
int agc_feasibility_current_extractable(const agc_feasibility_report *r) { return r ? r->current_extractable : 0; }
agc_provider_type agc_feasibility_current_provider_type(const agc_feasibility_report *r)
{
    return r ? r->current_provider_type : AGC_PROVIDER_TYPE_UNSPECIFIED;
}

size_t agc_feasibility_option_count(const agc_feasibility_report *r) { return r ? r->option_count : 0; }

agc_rc agc_feasibility_option_at(const agc_feasibility_report *r, size_t i,
                                  agc_migration_strategy *out_strategy, int *out_feasible,
                                  const char **out_infeasibility_reason, int32_t *out_complexity_level)
{
    if (!r || i >= r->option_count) return AGC_ERR_INVALID_ARGUMENT;
    if (out_strategy) *out_strategy = r->option_strategy[i];
    if (out_feasible) *out_feasible = r->option_feasible[i];
    if (out_infeasibility_reason) *out_infeasibility_reason = r->option_infeasibility_reason[i];
    if (out_complexity_level) *out_complexity_level = r->option_complexity_level[i];
    return AGC_OK;
}

agc_migration_strategy agc_feasibility_recommended_strategy(const agc_feasibility_report *r)
{
    return r ? r->recommended_strategy : AGC_MIGRATION_STRATEGY_UNSPECIFIED;
}
const char *agc_feasibility_recommendation_reason(const agc_feasibility_report *r)
{
    return r ? r->recommendation_reason : NULL;
}

/* --------------------------------------------------------------------------
 * ExportKey / ImportKey
 * -------------------------------------------------------------------------- */

agc_rc agc_export_key(agc_ctx *ctx, const agc_export_key_params *params,
                       agc_buf out_material, size_t *out_material_len,
                       agc_key_format *out_actual_format, agc_key_info **out_key)
{
    if (!ctx_usable(ctx) || !params || !out_material_len) return AGC_ERR_INVALID_ARGUMENT;
    if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!params->name || !*params->name) return AGC_ERR_INVALID_ARGUMENT;
    if (params->format == AGC_KEY_FORMAT_WRAPPED && (!params->wrapping_key_name || !*params->wrapping_key_name)) {
        return AGC_ERR_INVALID_ARGUMENT;
    }

    uint8_t *material = NULL;
    size_t material_len = 0;
    agc_rc rc = agc__keystore_export(ctx, params->name, &material, &material_len);
    if (rc != AGC_OK) return rc;

    *out_material_len = material_len;
    if (out_material.data != NULL) {
        if (out_material.cap < material_len) {
            rc = AGC_ERR_BUFFER_TOO_SMALL;
        } else {
            memcpy(out_material.data, material, material_len);
        }
    }
    agc_secure_zero(material, material_len);
    free(material);
    if (rc != AGC_OK) return rc;

    if (out_actual_format) *out_actual_format = params->format;
    if (out_key) {
        rc = agc__keystore_read(ctx, params->name, 0, out_key);
        if (rc != AGC_OK) return rc;
    }
    return AGC_OK;
}

agc_rc agc_import_key(agc_ctx *ctx, const agc_import_key_params *params, agc_key_info **out_key)
{
    if (!ctx_usable(ctx) || !params || !out_key) return AGC_ERR_INVALID_ARGUMENT;
    if (params->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = NULL;
    if (!params->name || !*params->name) return AGC_ERR_INVALID_ARGUMENT;
    if (!params->key_material.data || params->key_material.len == 0) return AGC_ERR_INVALID_ARGUMENT;
    if (!params->template_id || !*params->template_id) return AGC_ERR_INVALID_ARGUMENT;
    if (params->format == AGC_KEY_FORMAT_WRAPPED && (!params->unwrapping_key_name || !*params->unwrapping_key_name)) {
        return AGC_ERR_INVALID_ARGUMENT;
    }

    return agc__keystore_import(ctx, params->name, params->policy_name,
                                 params->key_material, params->template_id, out_key);
}
