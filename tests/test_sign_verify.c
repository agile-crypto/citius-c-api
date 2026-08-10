/**
 * @file test_sign_verify.c
 * @brief Tests for citius_sign(), citius_verify(), citius_digest_sign(),
 *        citius_digest_verify().
 */

#include "test_helpers.h"

static void test_sign_size_query(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("sig-key");

    citius_sign_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name = key;
    const uint8_t msg[] = "Hello, Citius!";
    req.input.data      = msg;
    req.input.length    = sizeof(msg) - 1;
    req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_sign_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_sign(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.signature.length == 64);

    citius_test_cleanup();
}

static void test_sign_and_verify(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("sig-key2");

    const uint8_t msg[] = "Message to sign";

    citius_sign_request_t sign_req;
    memset(&sign_req, 0, sizeof(sign_req));
    sign_req.key_name           = key;
    sign_req.input.data         = msg;
    sign_req.input.length       = sizeof(msg) - 1;
    sign_req.scope_params.type  = CITIUS_SIGN_PARAMS_NONE;

    uint8_t sig_buf[64];
    citius_sign_response_t sign_resp;
    memset(&sign_resp, 0, sizeof(sign_resp));
    sign_resp.signature.data     = sig_buf;
    sign_resp.signature.capacity = 64;
    CITIUS_ASSERT_RV(citius_sign(&sign_req, &sign_resp), CITIUS_OK);
    CITIUS_ASSERT(sign_resp.signature.length == 64);

    /* Verify — pass the metadata back */
    citius_verify_request_t ver_req;
    memset(&ver_req, 0, sizeof(ver_req));
    ver_req.key_name          = key;
    ver_req.input.data        = msg;
    ver_req.input.length      = sizeof(msg) - 1;
    ver_req.signature.data    = sig_buf;
    ver_req.signature.length  = sign_resp.signature.length;
    ver_req.metadata          = sign_resp.metadata;
    ver_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_verify_response_t ver_resp;
    memset(&ver_resp, 0, sizeof(ver_resp));
    CITIUS_ASSERT_RV(citius_verify(&ver_req, &ver_resp), CITIUS_OK);
    CITIUS_ASSERT(ver_resp.valid == 1);

    citius_test_cleanup();
}

static void test_digest_sign_verify(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("dsig-key");

    uint8_t digest_bytes[32] = {0xAB};

    citius_digest_sign_request_t ds_req;
    memset(&ds_req, 0, sizeof(ds_req));
    ds_req.key_name          = key;
    ds_req.digest.data       = digest_bytes;
    ds_req.digest.length     = 32;
    ds_req.hash_algorithm    = CITIUS_HASH_SHA2_256;
    ds_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    uint8_t sig_buf[64];
    citius_digest_sign_response_t ds_resp;
    memset(&ds_resp, 0, sizeof(ds_resp));
    ds_resp.signature.data     = sig_buf;
    ds_resp.signature.capacity = 64;
    CITIUS_ASSERT_RV(citius_digest_sign(&ds_req, &ds_resp), CITIUS_OK);
    CITIUS_ASSERT(ds_resp.signature.length == 64);

    citius_digest_verify_request_t dv_req;
    memset(&dv_req, 0, sizeof(dv_req));
    dv_req.key_name          = key;
    dv_req.digest.data       = digest_bytes;
    dv_req.digest.length     = 32;
    dv_req.hash_algorithm    = CITIUS_HASH_SHA2_256;
    dv_req.signature.data    = sig_buf;
    dv_req.signature.length  = ds_resp.signature.length;
    dv_req.metadata          = ds_resp.metadata;
    dv_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_digest_verify_response_t dv_resp;
    memset(&dv_resp, 0, sizeof(dv_resp));
    CITIUS_ASSERT_RV(citius_digest_verify(&dv_req, &dv_resp), CITIUS_OK);
    CITIUS_ASSERT(dv_resp.valid == 1);

    citius_test_cleanup();
}

static void test_sign_with_context(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("ctx-key");

    const uint8_t ctx_bytes[] = "domain";
    citius_sign_params_t op;
    memset(&op, 0, sizeof(op));
    op.type = CITIUS_SIGN_PARAMS_DOMAIN_CONTEXT;
    op.params.domain_context.context.data   = ctx_bytes;
    op.params.domain_context.context.length = sizeof(ctx_bytes) - 1;

    const uint8_t msg[] = "context-bound message";
    citius_sign_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name      = key;
    req.input.data    = msg;
    req.input.length  = sizeof(msg) - 1;
    req.scope_params  = op;

    uint8_t sig_buf[64];
    citius_sign_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.signature.data     = sig_buf;
    resp.signature.capacity = 64;
    CITIUS_ASSERT_RV(citius_sign(&req, &resp), CITIUS_OK);

    citius_test_cleanup();
}

static void test_sign_buffer_too_small(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("small-sig-key");

    const uint8_t msg[] = "msg";
    citius_sign_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name      = key;
    req.input.data    = msg;
    req.input.length  = sizeof(msg) - 1;
    req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    uint8_t tiny[4];
    citius_sign_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.signature.data     = tiny;
    resp.signature.capacity = 4;
    CITIUS_ASSERT_RV(citius_sign(&req, &resp), CITIUS_BUFFER_TOO_SMALL);
    CITIUS_ASSERT(resp.signature.length == 64);

    citius_test_cleanup();
}

int main(void)
{
    test_sign_size_query();
    test_sign_and_verify();
    test_digest_sign_verify();
    test_sign_with_context();
    test_sign_buffer_too_small();
    printf("test_sign_verify: all tests passed\n");
    return 0;
}
