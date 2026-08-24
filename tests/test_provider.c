/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 8 ProviderService functions (commit 11).
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

static void test_list_get_provider(agc_ctx *ctx)
{
    agc_provider_iter *it = NULL;
    AGC_ASSERT_OK(agc_list_providers(ctx, NULL, &it));
    agc_provider_info *pi = NULL;
    AGC_ASSERT_OK(agc_provider_iter_next(it, &pi));
    AGC_ASSERT_EQ_STR(agc_provider_info_id(pi), "stub");
    AGC_ASSERT_EQ_INT(agc_provider_info_type(pi), AGC_PROVIDER_TYPE_SOFTWARE);
    const agc_impl_props *defaults = agc_provider_info_default_implementation(pi);
    AGC_ASSERT(defaults != NULL);
    AGC_ASSERT_EQ_INT(agc_impl_props_fips_certified(defaults), 0);
    AGC_ASSERT_EQ_INT(agc_impl_props_constant_time(defaults), AGC_FALSE);
    agc_provider_info_free(pi);
    AGC_ASSERT_EQ_INT(agc_provider_iter_next(it, &pi), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_provider_iter_free(it);

    AGC_ASSERT_OK(agc_get_provider(ctx, "stub", &pi));
    AGC_ASSERT_EQ_STR(agc_provider_info_id(pi), "stub");
    agc_provider_info_free(pi);
    AGC_ASSERT_EQ_INT(agc_get_provider(ctx, "nope", &pi), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);
}

static void test_instance_crud(agc_ctx *ctx)
{
    agc_kv cfg_items[1] = {{"region", "us-east-1"}};
    agc_provider_instance_spec spec;
    AGC_INIT(&spec);
    spec.instance_id = "inst-1";
    spec.provider_id = "stub";
    spec.display_name = "Instance One";
    spec.description = "test instance";
    spec.configuration.items = cfg_items;
    spec.configuration.count = 1;
    spec.enabled = 1;

    agc_provider_instance *inst = NULL;
    AGC_ASSERT_OK(agc_register_provider_instance(ctx, &spec, &inst));
    AGC_ASSERT_EQ_STR(agc_provider_instance_id(inst), "inst-1");
    AGC_ASSERT_EQ_STR(agc_provider_instance_provider_id(inst), "stub");
    AGC_ASSERT_EQ_INT(agc_provider_instance_enabled(inst), 1);
    AGC_ASSERT_EQ_INT(agc_provider_instance_config_count(inst), 1);
    const char *k = NULL, *v = NULL;
    AGC_ASSERT_OK(agc_provider_instance_config_at(inst, 0, &k, &v));
    AGC_ASSERT_EQ_STR(k, "region");
    AGC_ASSERT_EQ_STR(v, "us-east-1");
    agc_provider_instance_free(inst);

    /* Duplicate registration rejected. */
    AGC_ASSERT_EQ_INT(agc_register_provider_instance(ctx, &spec, &inst), AGC_ERR_ALREADY_EXISTS);

    /* Unknown provider type rejected. */
    agc_provider_instance_spec bad_spec = spec;
    bad_spec.instance_id = "inst-bad";
    bad_spec.provider_id = "not-a-real-provider";
    AGC_ASSERT_EQ_INT(agc_register_provider_instance(ctx, &bad_spec, &inst), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);

    AGC_ASSERT_OK(agc_get_provider_instance(ctx, "inst-1", &inst));
    AGC_ASSERT_EQ_STR(agc_provider_instance_display_name(inst), "Instance One");

    /* Read-modify-write via agc_provider_instance_to_spec(): rmw's strings
     * are borrowed from `inst`, so `inst` must outlive this call, not be
     * freed first. */
    agc_provider_instance_spec rmw;
    AGC_INIT(&rmw);
    AGC_ASSERT_OK(agc_provider_instance_to_spec(inst, &rmw));

    agc_kv cfg_items2[1] = {{"region", "eu-west-1"}};
    rmw.configuration.items = cfg_items2;
    rmw.configuration.count = 1;
    rmw.enabled = 0;

    agc_provider_instance *updated = NULL;
    AGC_ASSERT_OK(agc_update_provider_instance(ctx, &rmw, &updated));
    agc_provider_instance_free(inst);
    AGC_ASSERT_EQ_INT(agc_provider_instance_enabled(updated), 0);
    AGC_ASSERT_OK(agc_provider_instance_config_at(updated, 0, &k, &v));
    AGC_ASSERT_EQ_STR(v, "eu-west-1");
    agc_provider_instance_free(updated);

    AGC_ASSERT_EQ_INT(agc_get_provider_instance(ctx, "nope", &inst), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);

    AGC_ASSERT_OK(agc_delete_provider_instance(ctx, "inst-1"));
    AGC_ASSERT_EQ_INT(agc_delete_provider_instance(ctx, "inst-1"), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);
}

static void test_list_instances(agc_ctx *ctx)
{
    for (int i = 0; i < 3; i++) {
        char id[16];
        snprintf(id, sizeof(id), "list-%d", i);
        agc_provider_instance_spec spec;
        AGC_INIT(&spec);
        spec.instance_id = id;
        spec.provider_id = "stub";
        spec.enabled = (i != 1); /* one disabled */
        agc_provider_instance *inst = NULL;
        AGC_ASSERT_OK(agc_register_provider_instance(ctx, &spec, &inst));
        agc_provider_instance_free(inst);
    }

    agc_provider_instance_iter *it = NULL;
    AGC_ASSERT_OK(agc_list_provider_instances(ctx, NULL, &it));
    int count = 0;
    agc_provider_instance *inst = NULL;
    agc_rc rc;
    while ((rc = agc_provider_instance_iter_next(it, &inst)) == AGC_OK) {
        count++;
        agc_provider_instance_free(inst);
    }
    AGC_ASSERT_EQ_INT(rc, AGC_ERR_ITERATOR_EXHAUSTED);
    AGC_ASSERT(count >= 3);
    agc_provider_instance_iter_free(it);

    agc_list_provider_instances_params p;
    AGC_INIT(&p);
    p.provider_id = "stub";
    p.enabled_only = 1;
    AGC_ASSERT_OK(agc_list_provider_instances(ctx, &p, &it));
    int enabled_count = 0;
    while ((rc = agc_provider_instance_iter_next(it, &inst)) == AGC_OK) {
        AGC_ASSERT_EQ_INT(agc_provider_instance_enabled(inst), 1);
        enabled_count++;
        agc_provider_instance_free(inst);
    }
    AGC_ASSERT(enabled_count >= 2);
    agc_provider_instance_iter_free(it);
}

static void test_match_providers(agc_ctx *ctx)
{
    agc_provider_instance_spec spec;
    AGC_INIT(&spec);
    spec.instance_id = "match-1";
    spec.provider_id = "stub";
    spec.enabled = 1;
    agc_provider_instance *inst = NULL;
    AGC_ASSERT_OK(agc_register_provider_instance(ctx, &spec, &inst));
    agc_provider_instance_free(inst);

    agc_match_providers_params mp;
    AGC_INIT(&mp);
    mp.template_id = "stub-aead-v1";
    mp.enabled_only = 1;

    agc_provider_match *matches = NULL;
    size_t count = 0;
    AGC_ASSERT_OK(agc_match_providers(ctx, &mp, &matches, &count));
    AGC_ASSERT(count >= 1);
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(agc_provider_instance_id(matches[i].instance), "match-1") == 0) found = 1;
        AGC_ASSERT(matches[i].resolved_implementation != NULL);
        AGC_ASSERT(matches[i].match_score > 0);
    }
    AGC_ASSERT(found);
    agc_provider_match_list_free(matches, count);

    /* A requirement the stub cannot satisfy (FIPS-140 certified) yields no
     * matches, not an error -- fail-closed filtering, not a fake pass. */
    agc_provider_requirements reqs;
    AGC_INIT(&reqs);
    reqs.fips_140_certified = AGC_TRUE;
    mp.requirements = &reqs;
    AGC_ASSERT_OK(agc_match_providers(ctx, &mp, &matches, &count));
    AGC_ASSERT_EQ_INT(count, 0);
    agc_provider_match_list_free(matches, count);

    /* Unknown template: fails outright. */
    mp.requirements = NULL;
    mp.template_id = "does-not-exist";
    AGC_ASSERT_EQ_INT(agc_match_providers(ctx, &mp, &matches, &count), AGC_ERR_CRYPTO_TEMPLATE_NOT_FOUND);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_list_get_provider(ctx);
    test_instance_crud(ctx);
    test_list_instances(ctx);
    test_match_providers(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_provider");
}
