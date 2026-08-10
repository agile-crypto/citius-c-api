/**
 * @file test_key_establishment.c
 * @brief Tests for key derivation, KEM, key agreement, wrap/unwrap.
 */

#include "test_helpers.h"

static void test_derive_key_hkdf(void)
{
    citius_test_init();
    const char           *base = citius_test_create_key("ikm-key");

    const uint8_t salt_bytes[32] = {0x01};
    const uint8_t info_bytes[]   = "application context";
    citius_kdf_params_t op;
    memset(&op, 0, sizeof(op));
    op.type = CITIUS_KDF_PARAMS_HKDF;
    op.params.hkdf.salt.data                = salt_bytes;
    op.params.hkdf.salt.length              = 32;
    op.params.hkdf.info.data                = info_bytes;
    op.params.hkdf.info.length              = sizeof(info_bytes) - 1;
    op.params.hkdf.salt_type                = CITIUS_HKDF_SALT_TYPE_DATA;

    citius_derive_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.base_key_name    = base;
    req.derived_key_name = "hkdf-derived";
    req.kdf_params        = op;

    citius_derive_key_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_derive_key(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.key_metadata.key_id != NULL);

    citius_test_cleanup();
}

static void test_derive_key_pbkdf2(void)
{
    citius_test_init();
    const char           *base = citius_test_create_key("pwd-key");

    const uint8_t pwd[]  = "my-password";
    const uint8_t salt[] = "random-salt-16by";
    citius_kdf_params_t op;
    memset(&op, 0, sizeof(op));
    op.type = CITIUS_KDF_PARAMS_PBKDF2;
    op.params.pbkdf2.password.data   = pwd;
    op.params.pbkdf2.password.length = sizeof(pwd) - 1;
    op.params.pbkdf2.salt.data       = salt;
    op.params.pbkdf2.salt.length     = sizeof(salt) - 1;

    citius_derive_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.base_key_name    = base;
    req.derived_key_name = "pbkdf2-derived";
    req.kdf_params        = op;

    citius_derive_key_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_derive_key(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.key_metadata.key_id != NULL);

    citius_test_cleanup();
}

static void test_kem_encap_decap(void)
{
    citius_test_init();
    const char           *pub  = citius_test_create_key("kem-pub");
    const char           *priv = citius_test_create_key("kem-priv");

    /* Encapsulate */
    citius_encapsulate_key_request_t enc_req;
    memset(&enc_req, 0, sizeof(enc_req));
    enc_req.recipient_public_key_name = pub;
    enc_req.shared_secret_name        = "ss-enc";

    uint8_t ct_buf[1088];
    citius_encapsulate_key_response_t enc_resp;
    memset(&enc_resp, 0, sizeof(enc_resp));
    enc_resp.ciphertext.data     = ct_buf;
    enc_resp.ciphertext.capacity = 1088;
    CITIUS_ASSERT_RV(citius_encapsulate_key(&enc_req, &enc_resp), CITIUS_OK);
    CITIUS_ASSERT(enc_resp.ciphertext.length == 1088);

    /* Decapsulate */
    citius_decapsulate_key_request_t dec_req;
    memset(&dec_req, 0, sizeof(dec_req));
    dec_req.private_key_name         = priv;
    dec_req.ciphertext.data          = ct_buf;
    dec_req.ciphertext.length        = enc_resp.ciphertext.length;
    dec_req.shared_secret_name       = "ss-dec";
    dec_req.metadata                 = enc_resp.metadata;

    citius_decapsulate_key_response_t dec_resp;
    memset(&dec_resp, 0, sizeof(dec_resp));
    CITIUS_ASSERT_RV(citius_decapsulate_key(&dec_req, &dec_resp), CITIUS_OK);

    citius_test_cleanup();
}

static void test_kem_size_query(void)
{
    citius_test_init();
    const char           *pub  = citius_test_create_key("kem-pub2");

    citius_encapsulate_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.recipient_public_key_name = pub;

    /* Size query: ciphertext buffer NULL */
    citius_encapsulate_key_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_encapsulate_key(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.ciphertext.length == 1088);

    citius_test_cleanup();
}

static void test_key_agreement(void)
{
    citius_test_init();
    const char           *priv = citius_test_create_key("ecdh-priv");

    const uint8_t peer_pub[65] = {0x04};
    citius_key_agreement_params_t op;
    memset(&op, 0, sizeof(op));
    op.type = CITIUS_KEY_AGREEMENT_PARAMS_ECDH;

    citius_key_agreement_request_t req;
    memset(&req, 0, sizeof(req));
    req.private_key_name       = priv;
    req.peer_public_key.data   = peer_pub;
    req.peer_public_key.length = 65;
    req.shared_secret_name     = "shared-secret";
    req.agreement_params       = op;

    citius_key_agreement_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_key_agreement(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.key_metadata.key_id != NULL);

    citius_test_cleanup();
}

static void test_wrap_unwrap(void)
{
    citius_test_init();
    const char           *data_key = citius_test_create_key("data-key");
    const char           *kek      = citius_test_create_key("kek");

    /* Wrap */
    citius_wrap_key_request_t wreq;
    memset(&wreq, 0, sizeof(wreq));
    wreq.key_to_wrap_name  = data_key;
    wreq.wrapping_key_name = kek;
    wreq.format             = WRAP_FORMAT_RAW;
    wreq.scope_params.type  = CITIUS_WRAP_PARAMS_NONE;

    uint8_t wrapped_buf[40];
    citius_wrap_key_response_t wresp;
    memset(&wresp, 0, sizeof(wresp));
    wresp.wrapped_key.data     = wrapped_buf;
    wresp.wrapped_key.capacity = 40;
    CITIUS_ASSERT_RV(citius_wrap_key(&wreq, &wresp), CITIUS_OK);
    CITIUS_ASSERT(wresp.wrapped_key.length == 40);

    /* Wrap — size query */
    citius_wrap_key_response_t wresp_q;
    memset(&wresp_q, 0, sizeof(wresp_q));
    CITIUS_ASSERT_RV(citius_wrap_key(&wreq, &wresp_q), CITIUS_OK);
    CITIUS_ASSERT(wresp_q.wrapped_key.length == 40);

    /* Unwrap */
    citius_unwrap_key_request_t ureq;
    memset(&ureq, 0, sizeof(ureq));
    ureq.wrapped_key.data      = wrapped_buf;
    ureq.wrapped_key.length    = wresp.wrapped_key.length;
    ureq.wrapping_key_name     = kek;
    ureq.unwrapped_key_name    = "unwrapped-key";
    ureq.format                = WRAP_FORMAT_RAW;
    ureq.metadata              = wresp.metadata;
    ureq.scope_params.type     = CITIUS_WRAP_PARAMS_NONE;

    citius_unwrap_key_response_t uresp;
    memset(&uresp, 0, sizeof(uresp));
    CITIUS_ASSERT_RV(citius_unwrap_key(&ureq, &uresp), CITIUS_OK);
    CITIUS_ASSERT(uresp.key_metadata.key_id != NULL);

    citius_test_cleanup();
}

int main(void)
{
    test_derive_key_hkdf();
    test_derive_key_pbkdf2();
    test_kem_encap_decap();
    test_kem_size_query();
    test_key_agreement();
    test_wrap_unwrap();
    printf("test_key_establishment: all tests passed\n");
    return 0;
}
