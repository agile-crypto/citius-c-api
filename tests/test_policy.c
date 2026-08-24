/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 7 CryptoPolicyService functions (commit 11).
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

static void create_key(agc_ctx *ctx, const char *name, const char *policy)
{
    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = AGC_SCOPE_KIND_AEAD;
    scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = name;
    p.policy = policy;
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);
}

static void test_crud(agc_ctx *ctx)
{
    AGC_ASSERT_OK(agc_create_policy(ctx, "p1", "allow everything"));
    AGC_ASSERT_EQ_INT(agc_create_policy(ctx, "p1", "duplicate"), AGC_ERR_ALREADY_EXISTS);

    agc_policy_document doc;
    AGC_INIT(&doc);
    AGC_ASSERT_OK(agc_read_policy(ctx, "p1", &doc));
    AGC_ASSERT_EQ_STR(doc.name, "p1");
    AGC_ASSERT_EQ_STR(doc.policy_document, "allow everything");
    agc_policy_document_release(&doc);

    AGC_ASSERT_EQ_INT(agc_read_policy(ctx, "nonexistent", &doc), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);

    AGC_ASSERT_OK(agc_update_policy(ctx, "p1", "deny:CRYPTO_OPERATION_ENCRYPT"));
    AGC_INIT(&doc);
    AGC_ASSERT_OK(agc_read_policy(ctx, "p1", &doc));
    AGC_ASSERT_EQ_STR(doc.policy_document, "deny:CRYPTO_OPERATION_ENCRYPT");
    agc_policy_document_release(&doc);
    AGC_ASSERT_EQ_INT(agc_update_policy(ctx, "nonexistent", "x"), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);

    AGC_ASSERT_OK(agc_create_policy(ctx, "p2", "allow everything"));

    agc_policy_iter *it = NULL;
    AGC_ASSERT_OK(agc_list_policies(ctx, NULL, 0, &it));
    int found_p1 = 0, found_p2 = 0, count = 0;
    agc_policy_summary sum;
    agc_rc rc;
    while ((rc = agc_policy_iter_next(it, &sum)) == AGC_OK) {
        count++;
        if (strcmp(sum.name, "p1") == 0) found_p1 = 1;
        if (strcmp(sum.name, "p2") == 0) found_p2 = 1;
    }
    AGC_ASSERT_EQ_INT(rc, AGC_ERR_ITERATOR_EXHAUSTED);
    AGC_ASSERT_EQ_INT(count, 2);
    AGC_ASSERT(found_p1 && found_p2);
    agc_policy_iter_free(it);

    /* Prefix filter. */
    AGC_ASSERT_OK(agc_list_policies(ctx, "p2", 0, &it));
    AGC_ASSERT_OK(agc_policy_iter_next(it, &sum));
    AGC_ASSERT_EQ_STR(sum.name, "p2");
    AGC_ASSERT_EQ_INT(agc_policy_iter_next(it, &sum), AGC_ERR_ITERATOR_EXHAUSTED);
    agc_policy_iter_free(it);

    AGC_ASSERT_OK(agc_delete_policy(ctx, "p2"));
    AGC_ASSERT_EQ_INT(agc_delete_policy(ctx, "p2"), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);
}

static void test_delete_referential_integrity(agc_ctx *ctx)
{
    AGC_ASSERT_OK(agc_create_policy(ctx, "bound", "allow everything"));
    create_key(ctx, "keyed", "bound");
    AGC_ASSERT_EQ_INT(agc_delete_policy(ctx, "bound"), AGC_ERR_CRYPTO_POLICY_VIOLATION);
    AGC_ASSERT_OK(agc_delete_key(ctx, "keyed"));
    AGC_ASSERT_OK(agc_delete_policy(ctx, "bound"));
}

static void test_evaluate(agc_ctx *ctx)
{
    AGC_ASSERT_OK(agc_create_policy(ctx, "allow-all", "no restrictions"));
    AGC_ASSERT_OK(agc_create_policy(ctx, "deny-encrypt", "deny:CRYPTO_OPERATION_ENCRYPT applies here"));

    agc_evaluate_policy_request req;
    AGC_INIT(&req);
    req.policy_name = "allow-all";
    req.operation = AGC_CRYPTO_OPERATION_ENCRYPT;
    req.key_name = "some-key";

    agc_policy_decision *d = NULL;
    AGC_ASSERT_OK(agc_evaluate_policy(ctx, &req, &d));
    AGC_ASSERT(agc_policy_decision_allowed(d));
    AGC_ASSERT_EQ_STR(agc_policy_decision_policy_name(d), "allow-all");
    agc_policy_decision_free(d);

    req.policy_name = "deny-encrypt";
    AGC_ASSERT_OK(agc_evaluate_policy(ctx, &req, &d));
    AGC_ASSERT(!agc_policy_decision_allowed(d));
    AGC_ASSERT_EQ_INT(agc_policy_decision_denial_reason(d), AGC_POLICY_DENIAL_REASON_OPERATION_NOT_ALLOWED);
    AGC_ASSERT_EQ_STR(agc_policy_decision_failed_check(d), "CRYPTO_OPERATION_ENCRYPT");
    agc_policy_decision_free(d);

    /* Missing evaluation context (no key/template/scope/provider/properties)
     * is rejected rather than silently evaluated against nothing. */
    agc_evaluate_policy_request bare;
    AGC_INIT(&bare);
    bare.policy_name = "allow-all";
    bare.operation = AGC_CRYPTO_OPERATION_ENCRYPT;
    AGC_ASSERT_EQ_INT(agc_evaluate_policy(ctx, &bare, &d), AGC_ERR_INVALID_ARGUMENT);

    req.policy_name = "does-not-exist";
    AGC_ASSERT_EQ_INT(agc_evaluate_policy(ctx, &req, &d), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);
}

static void test_batch_evaluate(agc_ctx *ctx)
{
    AGC_ASSERT_OK(agc_create_policy(ctx, "batch-allow", "no restrictions"));
    AGC_ASSERT_OK(agc_create_policy(ctx, "batch-deny", "forbid:CRYPTO_OPERATION_DECRYPT here"));

    agc_evaluate_policy_request reqs[2];
    AGC_INIT(&reqs[0]);
    reqs[0].policy_name = "batch-allow";
    reqs[0].operation = AGC_CRYPTO_OPERATION_ENCRYPT;
    reqs[0].key_name = "k";
    AGC_INIT(&reqs[1]);
    reqs[1].policy_name = "batch-deny";
    reqs[1].operation = AGC_CRYPTO_OPERATION_DECRYPT;
    reqs[1].key_name = "k";

    agc_policy_decision *decisions[2] = {0};
    int32_t allowed = 0, denied = 0;
    AGC_ASSERT_OK(agc_batch_evaluate_policy(ctx, reqs, 2, decisions, &allowed, &denied));
    AGC_ASSERT_EQ_INT(allowed, 1);
    AGC_ASSERT_EQ_INT(denied, 1);
    AGC_ASSERT(agc_policy_decision_allowed(decisions[0]));
    AGC_ASSERT(!agc_policy_decision_allowed(decisions[1]));
    agc_policy_decision_free(decisions[0]);
    agc_policy_decision_free(decisions[1]);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_crud(ctx);
    test_delete_referential_integrity(ctx);
    test_evaluate(ctx);
    test_batch_evaluate(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_policy");
}
