/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 3 AlgorithmDiscoveryService functions (commit 11).
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

static void test_get_template(agc_ctx *ctx)
{
    agc_template_info *ti = NULL;
    AGC_ASSERT_OK(agc_get_template(ctx, "stub-aead-v1", &ti));
    AGC_ASSERT_EQ_STR(agc_template_info_id(ti), "stub-aead-v1");
    AGC_ASSERT_EQ_INT(agc_template_info_status(ti), AGC_TEMPLATE_STATUS_ACTIVE);
    AGC_ASSERT_EQ_INT(agc_template_info_primitive(ti), AGC_CRYPTO_PRIMITIVE_AE);
    AGC_ASSERT_EQ_INT(agc_template_info_standards_count(ti), 1);
    AGC_ASSERT_EQ_STR(agc_template_info_standard_at(ti, 0), "stub-catalog");
    AGC_ASSERT_EQ_INT(agc_template_info_capability_count(ti), 1);

    agc_scope_spec cap;
    AGC_ASSERT_OK(agc_template_info_capability_scope(ti, 0, &cap));
    AGC_ASSERT_EQ_INT(cap.kind, AGC_SCOPE_KIND_AEAD);
    agc_template_info_free(ti);

    AGC_ASSERT_EQ_INT(agc_get_template(ctx, "does-not-exist", &ti), AGC_ERR_CRYPTO_TEMPLATE_NOT_FOUND);
}

/* This is exactly the id that agc_read_key() would report for a key created
 * with an AEAD scope spec and no explicit template_id -- proving the
 * catalog and the keystore's derived template id agree, not just that each
 * looks plausible on its own. */
static void test_catalog_matches_keystore_derivation(agc_ctx *ctx)
{
    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = AGC_SCOPE_KIND_AEAD;
    scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = "discovery-check-key";
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));

    agc_template_info *ti = NULL;
    AGC_ASSERT_OK(agc_get_template(ctx, agc_key_info_template_id(ki), &ti));
    AGC_ASSERT_EQ_STR(agc_template_info_id(ti), "stub-aead-v1");
    agc_template_info_free(ti);
    agc_key_info_free(ki);
}

static void test_list_templates(agc_ctx *ctx)
{
    agc_template_iter *it = NULL;
    AGC_ASSERT_OK(agc_list_templates(ctx, NULL, &it));
    int count = 0;
    agc_template_info *ti = NULL;
    agc_rc rc;
    while ((rc = agc_template_iter_next(it, &ti)) == AGC_OK) {
        count++;
        agc_template_info_free(ti);
    }
    AGC_ASSERT_EQ_INT(rc, AGC_ERR_ITERATOR_EXHAUSTED);
    AGC_ASSERT_EQ_INT(count, 12); /* one per agc_scope_kind */
    agc_template_iter_free(it);

    /* Filter by scope kind. */
    agc_scope_spec filter_scope;
    AGC_INIT(&filter_scope);
    filter_scope.kind = AGC_SCOPE_KIND_MAC;

    agc_list_templates_params params;
    AGC_INIT(&params);
    params.scope_spec = &filter_scope;
    AGC_ASSERT_OK(agc_list_templates(ctx, &params, &it));
    AGC_ASSERT_OK(agc_template_iter_next(it, &ti));
    AGC_ASSERT_EQ_STR(agc_template_info_id(ti), "stub-mac-v1");
    agc_template_info_free(ti);
    AGC_ASSERT_EQ_INT(agc_template_iter_next(it, &ti), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_template_iter_free(it);

    /* required_standards: every entry matches "stub-catalog", nothing else. */
    agc_list_templates_params params2;
    AGC_INIT(&params2);
    const char *std_names[] = {"real-nist-fips"};
    params2.required_standards.items = std_names;
    params2.required_standards.count = 1;
    AGC_ASSERT_OK(agc_list_templates(ctx, &params2, &it));
    AGC_ASSERT_EQ_INT(agc_template_iter_next(it, &ti), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_template_iter_free(it);
}

static void test_list_scopes(agc_ctx *ctx)
{
    agc_scope_info **scopes = NULL;
    size_t count = 0;
    AGC_ASSERT_OK(agc_list_scopes(ctx, &scopes, &count));
    AGC_ASSERT_EQ_INT(count, 12);

    int found_kem = 0;
    for (size_t i = 0; i < count; i++) {
        agc_scope_spec spec;
        AGC_ASSERT_OK(agc_scope_info_specification(scopes[i], &spec));
        if (spec.kind == AGC_SCOPE_KIND_KEM) {
            found_kem = 1;
            AGC_ASSERT(agc_scope_info_name(scopes[i]) != NULL);
            AGC_ASSERT(agc_scope_info_description(scopes[i]) != NULL);
        }
    }
    AGC_ASSERT(found_kem);
    agc_scope_info_list_free(scopes, count);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_get_template(ctx);
    test_catalog_matches_keystore_derivation(ctx);
    test_list_templates(ctx);
    test_list_scopes(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_discovery");
}
