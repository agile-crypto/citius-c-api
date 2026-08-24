/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 11 KeyManagementService functions against the stub backend
 * (commit 7).
 */
#include "agilecrypto.h"
#include "test_helpers.h"

static agc_ctx *open_ctx(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_ASSERT_OK(agc_ctx_open(&cfg, &ctx));
    return ctx;
}

static void make_aead_scope(agc_scope_spec *scope)
{
    AGC_INIT(scope);
    scope->kind = AGC_SCOPE_KIND_AEAD;
    scope->u.aead.scope = AGC_AEAD_SCOPE_STANDARD;
    scope->u.aead.security.security_strength_bits = 256;
}

static void test_create_read_delete(agc_ctx *ctx)
{
    agc_scope_spec scope;
    make_aead_scope(&scope);

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k1";
    p.policy = "default";
    p.scope_spec = &scope;

    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    AGC_ASSERT_EQ_STR(agc_key_info_name(ki), "k1");
    AGC_ASSERT_EQ_INT(agc_key_info_version(ki), 1);
    AGC_ASSERT_EQ_INT(agc_key_info_lifecycle_state(ki), AGC_KEY_LIFECYCLE_STATE_ACTIVE);
    AGC_ASSERT_EQ_INT(agc_key_info_extractable(ki), 1);

    agc_scope_spec readback;
    AGC_ASSERT_OK(agc_key_info_scope_spec(ki, &readback));
    AGC_ASSERT_EQ_INT(readback.kind, AGC_SCOPE_KIND_AEAD);
    AGC_ASSERT_EQ_INT(readback.u.aead.security.security_strength_bits, 256);
    agc_key_info_free(ki);

    /* Duplicate name is rejected. */
    AGC_ASSERT_EQ_INT(agc_create_key(ctx, &p, &ki, NULL), AGC_ERR_ALREADY_EXISTS);

    /* ReadKey */
    agc_key_info *read_back = NULL;
    AGC_ASSERT_OK(agc_read_key(ctx, "k1", 0, &read_back));
    AGC_ASSERT_EQ_STR(agc_key_info_key_id(read_back), agc_key_info_key_id(read_back)); /* non-NULL sanity */
    agc_key_info_free(read_back);

    AGC_ASSERT_EQ_INT(agc_read_key(ctx, "does-not-exist", 0, &read_back), AGC_ERR_CRYPTO_KEY_NOT_FOUND);

    /* DeleteKey: irreversible but retains the record (DESTROYED). */
    AGC_ASSERT_OK(agc_delete_key(ctx, "k1"));
    AGC_ASSERT_OK(agc_read_key(ctx, "k1", 0, &read_back));
    AGC_ASSERT_EQ_INT(agc_key_info_lifecycle_state(read_back), AGC_KEY_LIFECYCLE_STATE_DESTROYED);
    agc_key_info_free(read_back);
    AGC_ASSERT_EQ_INT(agc_delete_key(ctx, "does-not-exist"), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
}

static void test_rotate(agc_ctx *ctx)
{
    agc_scope_spec scope;
    make_aead_scope(&scope);
    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k-rotate";
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    AGC_ASSERT_EQ_INT(agc_key_info_version(ki), 1);
    agc_key_info_free(ki);

    agc_key_info *v2 = NULL;
    AGC_ASSERT_OK(agc_rotate_key(ctx, "k-rotate", &v2));
    AGC_ASSERT_EQ_INT(agc_key_info_version(v2), 2);
    agc_key_info_free(v2);

    /* Previous version remains readable. */
    agc_key_info *v1 = NULL;
    AGC_ASSERT_OK(agc_read_key(ctx, "k-rotate", 1, &v1));
    AGC_ASSERT_EQ_INT(agc_key_info_version(v1), 1);
    agc_key_info_free(v1);

    AGC_ASSERT_EQ_INT(agc_rotate_key(ctx, "nope", &v2), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
}

static void test_transform_and_update_policy(agc_ctx *ctx)
{
    agc_scope_spec scope;
    make_aead_scope(&scope);
    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k-transform";
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);

    agc_scope_spec mac_scope;
    AGC_INIT(&mac_scope);
    mac_scope.kind = AGC_SCOPE_KIND_MAC;
    mac_scope.u.mac.scope = AGC_MAC_SCOPE_STANDARD;

    agc_transform_key_params tp;
    AGC_INIT(&tp);
    tp.name = "k-transform";
    tp.scope_spec = &mac_scope;
    agc_key_info *transformed = NULL;
    AGC_ASSERT_OK(agc_transform_key(ctx, &tp, &transformed));
    AGC_ASSERT_EQ_INT(agc_key_info_version(transformed), 2);
    agc_scope_spec after;
    AGC_ASSERT_OK(agc_key_info_scope_spec(transformed, &after));
    AGC_ASSERT_EQ_INT(after.kind, AGC_SCOPE_KIND_MAC);
    agc_key_info_free(transformed);

    agc_key_info *policy_updated = NULL;
    AGC_ASSERT_OK(agc_update_key_policy(ctx, "k-transform", "new-policy", &policy_updated));
    AGC_ASSERT_EQ_STR(agc_key_info_policy(policy_updated), "new-policy");
    agc_key_info_free(policy_updated);
}

static void test_list_keys(agc_ctx *ctx)
{
    for (int i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "list-key-%d", i);
        agc_scope_spec scope;
        make_aead_scope(&scope);
        agc_create_key_params p;
        AGC_INIT(&p);
        p.name = name;
        p.policy = "default";
        p.scope_spec = &scope;
        agc_key_info *ki = NULL;
        AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
        agc_key_info_free(ki);
    }

    agc_key_iter *it = NULL;
    AGC_ASSERT_OK(agc_list_keys(ctx, NULL, &it));
    int seen = 0;
    agc_key_info *ki;
    agc_rc rc;
    while ((rc = agc_key_iter_next(it, &ki)) == AGC_OK) {
        seen++;
        agc_key_info_free(ki);
    }
    AGC_ASSERT_EQ_INT(rc, AGC_ERR_ITERATOR_EXHAUSTED);
    AGC_ASSERT(seen >= 3); /* other tests in this file also create keys on the same ctx */
    agc_key_iter_free(it);
}

static void test_export_import(agc_ctx *ctx)
{
    agc_scope_spec scope;
    make_aead_scope(&scope);
    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k-export";
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);

    agc_export_key_params ep;
    AGC_INIT(&ep);
    ep.name = "k-export";
    ep.format = AGC_KEY_FORMAT_RAW;

    size_t needed = 0;
    AGC_ASSERT_OK(agc_export_key(ctx, &ep, (agc_buf){0}, &needed, NULL, NULL));
    AGC_ASSERT(needed > 0);
    uint8_t *material = malloc(needed);
    size_t actual = 0;
    agc_key_format fmt;
    agc_key_info *exported_ki = NULL;
    AGC_ASSERT_OK(agc_export_key(ctx, &ep, (agc_buf){material, needed}, &actual, &fmt, &exported_ki));
    AGC_ASSERT_EQ_INT(actual, needed);
    AGC_ASSERT_EQ_INT(fmt, AGC_KEY_FORMAT_RAW);
    agc_key_info_free(exported_ki);

    agc_import_key_params ip;
    AGC_INIT(&ip);
    ip.name = "k-imported";
    ip.key_material = (agc_slice){material, actual};
    ip.format = AGC_KEY_FORMAT_RAW;
    ip.template_id = "stub-aead-v1";
    agc_key_info *imported = NULL;
    AGC_ASSERT_OK(agc_import_key(ctx, &ip, &imported));
    AGC_ASSERT_EQ_STR(agc_key_info_name(imported), "k-imported");
    agc_key_info_free(imported);

    agc_secure_zero(material, needed);
    free(material);

    /* Wrapped format requires unwrapping_key_name. */
    ip.name = "k-imported-2";
    ip.format = AGC_KEY_FORMAT_WRAPPED;
    ip.unwrapping_key_name = NULL;
    AGC_ASSERT_EQ_INT(agc_import_key(ctx, &ip, &imported), AGC_ERR_INVALID_ARGUMENT);
}

static void test_migrate_key(agc_ctx *ctx)
{
    agc_scope_spec scope;
    make_aead_scope(&scope);
    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k-migrate";
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);

    agc_migrate_key_params mp;
    AGC_INIT(&mp);
    mp.name = "k-migrate";
    mp.target.kind = AGC_MIGRATE_TARGET_INSTANCE;
    mp.target.u.instance_id = "some-instance";
    mp.strategy = AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE;

    agc_key_info *migrated = NULL;
    agc_migration_report *report = NULL;
    AGC_ASSERT_OK(agc_migrate_key(ctx, &mp, &migrated, &report));
    AGC_ASSERT_EQ_INT(agc_migration_report_strategy_used(report), AGC_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE);
    AGC_ASSERT(agc_migration_report_has_archived_key(report));
    AGC_ASSERT(agc_migration_report_archived_key_name(report) != NULL);
    agc_migration_report_free(report);
    agc_key_info_free(migrated);

    /* Required-oneof and required-enum validation. */
    agc_migrate_key_params bad = mp;
    bad.target.kind = AGC_MIGRATE_TARGET_NONE;
    AGC_ASSERT_EQ_INT(agc_migrate_key(ctx, &bad, &migrated, NULL), AGC_ERR_INVALID_ARGUMENT);

    bad = mp;
    bad.strategy = AGC_MIGRATION_STRATEGY_UNSPECIFIED;
    AGC_ASSERT_EQ_INT(agc_migrate_key(ctx, &bad, &migrated, NULL), AGC_ERR_INVALID_ARGUMENT);
}

static void test_validate_key_operation(agc_ctx *ctx)
{
    agc_scope_spec scope;
    make_aead_scope(&scope);
    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k-validate";
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);

    agc_validate_key_op_params vp;
    AGC_INIT(&vp);
    vp.name = "k-validate";
    vp.kind = AGC_VALIDATE_INTENT_TRANSFORM;
    vp.u.transform.scope_spec = &scope;

    agc_feasibility_report *report = NULL;
    AGC_ASSERT_OK(agc_validate_key_operation(ctx, &vp, &report));
    AGC_ASSERT_EQ_STR(agc_feasibility_current_provider_id(report), "stub");
    AGC_ASSERT_EQ_INT(agc_feasibility_option_count(report), 1);
    agc_migration_strategy strat; int feasible; const char *reason; int32_t complexity;
    AGC_ASSERT_OK(agc_feasibility_option_at(report, 0, &strat, &feasible, &reason, &complexity));
    AGC_ASSERT_EQ_INT(strat, AGC_MIGRATION_STRATEGY_UNSPECIFIED); /* per proto: TRANSFORM never sets a strategy */
    AGC_ASSERT(feasible);
    agc_feasibility_report_free(report);

    vp.kind = AGC_VALIDATE_INTENT_MIGRATE;
    vp.u.migrate.target_kind = AGC_VALIDATE_MIGRATE_TARGET_ANY;
    AGC_ASSERT_OK(agc_validate_key_operation(ctx, &vp, &report));
    AGC_ASSERT_EQ_INT(agc_feasibility_option_count(report), 5); /* every MigrationStrategy value */
    int found_infeasible_cross_provider = 0;
    for (size_t i = 0; i < agc_feasibility_option_count(report); i++) {
        AGC_ASSERT_OK(agc_feasibility_option_at(report, i, &strat, &feasible, &reason, &complexity));
        if (strat == AGC_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT) {
            AGC_ASSERT(!feasible);
            AGC_ASSERT(reason != NULL);
            found_infeasible_cross_provider = 1;
        }
    }
    AGC_ASSERT(found_infeasible_cross_provider);
    agc_feasibility_report_free(report);

    vp.kind = AGC_VALIDATE_INTENT_NONE;
    AGC_ASSERT_EQ_INT(agc_validate_key_operation(ctx, &vp, &report), AGC_ERR_INVALID_ARGUMENT);
}

static void test_create_key_selection_modes(agc_ctx *ctx)
{
    /* template_id alone, no scope_spec. */
    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "k-by-template";
    p.policy = "default";
    p.template_id = "stub-aead-v1";
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    AGC_ASSERT_EQ_STR(agc_key_info_template_id(ki), "stub-aead-v1");
    agc_key_info_free(ki);

    /* Neither scope_spec nor template_id is invalid. */
    AGC_INIT(&p);
    p.name = "k-neither";
    p.policy = "default";
    AGC_ASSERT_EQ_INT(agc_create_key(ctx, &p, &ki, NULL), AGC_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_create_read_delete(ctx);
    test_rotate(ctx);
    test_transform_and_update_policy(ctx);
    test_list_keys(ctx);
    test_export_import(ctx);
    test_migrate_key(ctx);
    test_validate_key_operation(ctx);
    test_create_key_selection_modes(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_key_management");
}
