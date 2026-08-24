/* SPDX-License-Identifier: Apache-2.0
 *
 * Governance and catalog discovery: create a policy that forbids a specific
 * operation, bind a key to it, evaluate the policy before and after, then
 * discover what templates/scopes/providers are actually available -- the
 * three services added in commit 11 (CryptoPolicyService,
 * AlgorithmDiscoveryService, ProviderService).
 *
 * Run: ./03_policy_and_discovery
 */
#include "example_helpers.h"
#include <string.h>

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_EXAMPLE_CHECK(agc_ctx_open(&cfg, &ctx));

    /* --- Discovery: what's actually available before we ask for anything --- */
    agc_scope_info **scopes = NULL;
    size_t scope_count = 0;
    AGC_EXAMPLE_CHECK(agc_list_scopes(ctx, &scopes, &scope_count));
    printf("this build supports %zu capability scopes:\n", scope_count);
    for (size_t i = 0; i < scope_count; i++) {
        printf("  - %s: %s\n", agc_scope_info_name(scopes[i]), agc_scope_info_description(scopes[i]));
    }
    agc_scope_info_list_free(scopes, scope_count);

    agc_provider_info *provider = NULL;
    AGC_EXAMPLE_CHECK(agc_get_provider(ctx, "stub", &provider));
    printf("\nprovider \"stub\": %s (%s)\n", agc_provider_info_display_name(provider),
           agc_provider_info_description(provider));
    agc_provider_info_free(provider);

    /* --- Policy: this policy denies AGC_CRYPTO_OPERATION_DECRYPT --- */
    AGC_EXAMPLE_CHECK(agc_create_policy(ctx, "no-decrypt", "forbid:CRYPTO_OPERATION_DECRYPT"));

    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = AGC_SCOPE_KIND_AEAD;
    scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;

    agc_create_key_params key_params;
    AGC_INIT(&key_params);
    key_params.name = "governed-key";
    key_params.policy = "no-decrypt";
    key_params.scope_spec = &scope;
    agc_key_info *key = NULL;
    AGC_EXAMPLE_CHECK(agc_create_key(ctx, &key_params, &key, NULL));
    agc_key_info_free(key);

    printf("\nevaluating \"no-decrypt\" for ENCRYPT and DECRYPT on \"governed-key\":\n");
    agc_evaluate_policy_request eval;
    AGC_INIT(&eval);
    eval.policy_name = "no-decrypt";
    eval.key_name = "governed-key";

    for (int i = 0; i < 2; i++) {
        eval.operation = i == 0 ? AGC_CRYPTO_OPERATION_ENCRYPT : AGC_CRYPTO_OPERATION_DECRYPT;
        agc_policy_decision *decision = NULL;
        AGC_EXAMPLE_CHECK(agc_evaluate_policy(ctx, &eval, &decision));
        printf("  %s: %s (%s)\n", agc_crypto_operation_name(eval.operation),
               agc_policy_decision_allowed(decision) ? "ALLOWED" : "DENIED",
               agc_policy_decision_message(decision));
        agc_policy_decision_free(decision);
    }

    /* --- Discovery again: which template did the key actually get, and
     * what does the catalog say about it? --- */
    AGC_EXAMPLE_CHECK(agc_read_key(ctx, "governed-key", 0, &key));
    const char *template_id = agc_key_info_template_id(key);
    agc_template_info *tmpl = NULL;
    AGC_EXAMPLE_CHECK(agc_get_template(ctx, template_id, &tmpl));
    printf("\n\"governed-key\" resolved to template \"%s\" (%s)\n",
           agc_template_info_id(tmpl), agc_template_info_display_name(tmpl));
    agc_template_info_free(tmpl);
    agc_key_info_free(key);

    agc_ctx_close(ctx);
    return 0;
}
