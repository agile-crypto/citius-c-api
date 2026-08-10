/**
 * @file test_mac_digest.c
 * @brief Tests for MAC generation/verification, digest, XOF, and random generation.
 */

#include "test_helpers.h"

static void test_generate_and_verify_mac(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("mac-key");

    const uint8_t msg[] = "authenticate me";
    citius_generate_mac_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name       = key;
    req.message.data   = msg;
    req.message.length = sizeof(msg) - 1;
    req.scope_params.type = CITIUS_MAC_PARAMS_NONE;

    uint8_t tag_buf[32];
    citius_generate_mac_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.mac.data     = tag_buf;
    resp.mac.capacity = 32;
    CITIUS_ASSERT_RV(citius_generate_mac(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.mac.length == 32);

    citius_verify_mac_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    vreq.key_name       = key;
    vreq.message.data   = msg;
    vreq.message.length = sizeof(msg) - 1;
    vreq.mac.data       = tag_buf;
    vreq.mac.length     = resp.mac.length;
    vreq.metadata       = &resp.metadata;
    vreq.scope_params.type = CITIUS_MAC_PARAMS_NONE;

    citius_verify_mac_response_t vresp;
    memset(&vresp, 0, sizeof(vresp));
    CITIUS_ASSERT_RV(citius_verify_mac(&vreq, &vresp), CITIUS_OK);
    CITIUS_ASSERT(vresp.valid == 1);

    citius_test_cleanup();
}

static void test_mac_size_query(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("mac-key2");

    const uint8_t msg[] = "size query";
    citius_generate_mac_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name       = key;
    req.message.data   = msg;
    req.message.length = sizeof(msg) - 1;
    req.scope_params.type = CITIUS_MAC_PARAMS_NONE;

    /* Size query — no buffer */
    citius_generate_mac_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_generate_mac(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.mac.length == 32);

    citius_test_cleanup();
}

static void test_kmac_customization(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("kmac-key");

    const uint8_t custom[] = "My KMAC application";
    citius_mac_params_t op;
    memset(&op, 0, sizeof(op));
    op.type = CITIUS_MAC_PARAMS_CUSTOMIZABLE;
    op.params.customizable.customization.data   = custom;
    op.params.customizable.customization.length = sizeof(custom) - 1;

    const uint8_t msg[] = "data";
    citius_generate_mac_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name       = key;
    req.message.data   = msg;
    req.message.length = sizeof(msg) - 1;
    req.scope_params   = op;

    uint8_t tag_buf[32];
    citius_generate_mac_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.mac.data     = tag_buf;
    resp.mac.capacity = 32;
    CITIUS_ASSERT_RV(citius_generate_mac(&req, &resp), CITIUS_OK);

    citius_test_cleanup();
}

static void test_digest(void)
{
    citius_test_init();

    const uint8_t data[] = "hash this string";
    citius_digest_request_t req;
    memset(&req, 0, sizeof(req));
    req.scope_spec.type              = CITIUS_SCOPE_SPEC_HASH;
    req.scope_spec.spec.hash.scope   = HASH_SCOPE_STANDARD;
    req.data.data   = data;
    req.data.length = sizeof(data) - 1;

    uint8_t hash_buf[32];
    citius_digest_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.digest.data     = hash_buf;
    resp.digest.capacity = 32;
    CITIUS_ASSERT_RV(citius_digest(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.digest.length == 32);

    citius_test_cleanup();
}

static void test_digest_size_query(void)
{
    citius_test_init();

    const uint8_t data[] = "query";
    citius_digest_request_t req;
    memset(&req, 0, sizeof(req));
    req.scope_spec.type            = CITIUS_SCOPE_SPEC_HASH;
    req.data.data   = data;
    req.data.length = sizeof(data) - 1;

    citius_digest_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_digest(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.digest.length == 32);

    citius_test_cleanup();
}

static void test_xof_variable_output(void)
{
    citius_test_init();

    const uint8_t data[] = "xof input";
    citius_xof_request_t req;
    memset(&req, 0, sizeof(req));
    req.scope_spec.type                 = CITIUS_SCOPE_SPEC_HASH;
    req.scope_spec.spec.hash.scope      = HASH_SCOPE_XOF;
    req.data.data                       = data;
    req.data.length                     = sizeof(data) - 1;
    req.output_length_bytes             = 64;

    uint8_t out_buf[64];
    citius_xof_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.output.data     = out_buf;
    resp.output.capacity = 64;
    CITIUS_ASSERT_RV(citius_xof(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.output.length == 64);

    citius_test_cleanup();
}

static void test_generate_random(void)
{
    citius_test_init();

    citius_generate_random_request_t req;
    memset(&req, 0, sizeof(req));
    req.num_bytes = 32;

    uint8_t rand_buf[32];
    citius_generate_random_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.random_bytes.data     = rand_buf;
    resp.random_bytes.capacity = 32;
    CITIUS_ASSERT_RV(citius_generate_random(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.random_bytes.length == 32);
    CITIUS_ASSERT(resp.provider_id != NULL);

    citius_test_cleanup();
}

static void test_generate_random_size_query(void)
{
    citius_test_init();

    citius_generate_random_request_t req;
    memset(&req, 0, sizeof(req));
    req.num_bytes = 16;

    citius_generate_random_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_generate_random(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.random_bytes.length == 16);

    citius_test_cleanup();
}

static void test_seed_random(void)
{
    citius_test_init();

    const uint8_t seed[] = "entropy entropy entropy entropy!!";
    citius_seed_random_request_t req;
    memset(&req, 0, sizeof(req));
    req.seed.data   = seed;
    req.seed.length = 32;

    citius_seed_random_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_seed_random(&req, &resp), CITIUS_OK);

    citius_test_cleanup();
}

int main(void)
{
    test_generate_and_verify_mac();
    test_mac_size_query();
    test_kmac_customization();
    test_digest();
    test_digest_size_query();
    test_xof_variable_output();
    test_generate_random();
    test_generate_random_size_query();
    test_seed_random();
    printf("test_mac_digest: all tests passed\n");
    return 0;
}
