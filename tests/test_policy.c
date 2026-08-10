/**
 * @file test_policy.c
 * @brief Tests for crypto policy CRUD and evaluation.
 */

#include "test_helpers.h"

static void create_policy(const char *name)
{
    citius_create_crypto_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.name            = name;
    req.policy_document = "{\"min_security_strength_bits\": 128}";

    citius_create_crypto_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_create_crypto_policy(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.success == 1);
}

static void test_create_and_read(void)
{
    citius_test_init();
    create_policy("pol-1");

    citius_read_crypto_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.name = "pol-1";

    citius_read_crypto_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_read_crypto_policy(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.name != NULL);

    citius_test_cleanup();
}

static void test_duplicate_create(void)
{
    citius_test_init();

    citius_create_crypto_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.name            = "pol-dup";
    req.policy_document = "{}";

    citius_create_crypto_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_create_crypto_policy(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT_RV(citius_create_crypto_policy(&req, &resp), CITIUS_POLICY_ALREADY_EXISTS);

    citius_test_cleanup();
}

static void test_read_nonexistent(void)
{
    citius_test_init();

    citius_read_crypto_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.name = "no-such-policy";

    citius_read_crypto_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_read_crypto_policy(&req, &resp), CITIUS_POLICY_NOT_FOUND);

    citius_test_cleanup();
}

static void test_list_policies(void)
{
    citius_test_init();
    create_policy("p1");
    create_policy("p2");
    create_policy("p3");

    citius_list_crypto_policies_request_t req;
    memset(&req, 0, sizeof(req));

    citius_list_crypto_policies_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_list_crypto_policies(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.policy_count == 3);

    citius_test_cleanup();
}

static void test_delete(void)
{
    citius_test_init();
    create_policy("del-pol");

    citius_delete_crypto_policy_request_t del_req;
    memset(&del_req, 0, sizeof(del_req));
    del_req.name = "del-pol";

    citius_delete_crypto_policy_response_t del_resp;
    memset(&del_resp, 0, sizeof(del_resp));
    CITIUS_ASSERT_RV(citius_delete_crypto_policy(&del_req, &del_resp), CITIUS_OK);

    citius_read_crypto_policy_request_t read_req;
    memset(&read_req, 0, sizeof(read_req));
    read_req.name = "del-pol";
    citius_read_crypto_policy_response_t read_resp;
    memset(&read_resp, 0, sizeof(read_resp));
    CITIUS_ASSERT_RV(citius_read_crypto_policy(&read_req, &read_resp), CITIUS_POLICY_NOT_FOUND);

    CITIUS_ASSERT_RV(citius_delete_crypto_policy(&del_req, &del_resp), CITIUS_POLICY_NOT_FOUND);
    citius_test_cleanup();
}

static void test_update(void)
{
    citius_test_init();
    create_policy("upd-pol");

    citius_update_crypto_policy_request_t upd_req;
    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.name            = "upd-pol";
    upd_req.policy_document = "{\"require_quantum_safe\": true}";

    citius_update_crypto_policy_response_t upd_resp;
    memset(&upd_resp, 0, sizeof(upd_resp));
    CITIUS_ASSERT_RV(citius_update_crypto_policy(&upd_req, &upd_resp), CITIUS_OK);

    citius_read_crypto_policy_request_t read_req;
    memset(&read_req, 0, sizeof(read_req));
    read_req.name = "upd-pol";
    citius_read_crypto_policy_response_t read_resp;
    memset(&read_resp, 0, sizeof(read_resp));
    CITIUS_ASSERT_RV(citius_read_crypto_policy(&read_req, &read_resp), CITIUS_OK);
    CITIUS_ASSERT(strstr(read_resp.policy_document, "require_quantum_safe") != NULL);

    citius_test_cleanup();
}

static void test_update_nonexistent(void)
{
    citius_test_init();

    citius_update_crypto_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.name            = "ghost-pol";
    req.policy_document = "{}";

    citius_update_crypto_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_update_crypto_policy(&req, &resp), CITIUS_POLICY_NOT_FOUND);

    citius_test_cleanup();
}

static void test_evaluate_allowed(void)
{
    citius_test_init();
    create_policy("eval-pol");

    citius_evaluate_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.policy_name             = "eval-pol";
    req.operation                = CRYPTO_OPERATION_ENCRYPT;
    req.scope_spec.type          = CITIUS_SCOPE_SPEC_AEAD;
    req.scope_spec.spec.aead.scope = AEAD_SCOPE_STANDARD;

    citius_evaluate_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_evaluate_policy(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.allowed == 1);

    citius_test_cleanup();
}

static void test_batch_evaluate(void)
{
    citius_test_init();
    create_policy("batch-pol");

    citius_evaluate_policy_request_t evals[2];
    memset(evals, 0, sizeof(evals));
    evals[0].policy_name = "batch-pol";
    evals[0].operation    = CRYPTO_OPERATION_ENCRYPT;
    evals[1].policy_name = "batch-pol";
    evals[1].operation    = CRYPTO_OPERATION_DECRYPT;

    citius_batch_evaluate_policy_request_t req;
    memset(&req, 0, sizeof(req));
    req.evaluations      = evals;
    req.evaluation_count = 2;

    citius_batch_evaluate_policy_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_batch_evaluate_policy(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.result_count == 2);
    CITIUS_ASSERT(resp.allowed_count == 2);

    citius_test_cleanup();
}

int main(void)
{
    test_create_and_read();
    test_duplicate_create();
    test_read_nonexistent();
    test_list_policies();
    test_delete();
    test_update();
    test_update_nonexistent();
    test_evaluate_allowed();
    test_batch_evaluate();
    printf("test_policy: all tests passed\n");
    return 0;
}
