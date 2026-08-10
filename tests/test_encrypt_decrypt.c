/**
 * @file test_encrypt_decrypt.c
 * @brief Tests for citius_encrypt() and citius_decrypt().
 */

#include "test_helpers.h"

static citius_encrypt_params_t aead_no_params(void)
{
    citius_encrypt_params_t p;
    memset(&p, 0, sizeof(p));
    p.type = CITIUS_ENCRYPT_PARAMS_NONE;
    return p;
}

static citius_encrypt_params_t aead_params_with_aad(
    const uint8_t *aad, size_t aad_len)
{
    citius_encrypt_params_t op;
    memset(&op, 0, sizeof(op));
    op.type = CITIUS_ENCRYPT_PARAMS_AEAD;
    op.params.aead.aad.data   = aad;
    op.params.aead.aad.length = aad_len;
    return op;
}

static void test_encrypt_size_query(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("enc-key");

    citius_encrypt_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name               = key;
    const uint8_t pt_bytes[16] = {0};
    req.plaintext.data         = pt_bytes;
    req.plaintext.length       = 16;
    req.scope_params           = aead_no_params();

    /* Size query: ciphertext buffer is NULL */
    citius_encrypt_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_encrypt(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.ciphertext.length == 32); /* 16 plaintext + 16 tag */

    citius_test_cleanup();
}

static void test_encrypt_buffer_too_small(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("enc-key2");

    citius_encrypt_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name = key;
    const uint8_t pt_bytes[32] = {0};
    req.plaintext.data   = pt_bytes;
    req.plaintext.length = 32;
    req.scope_params     = aead_no_params();

    uint8_t small[4];
    citius_encrypt_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.ciphertext.data     = small;
    resp.ciphertext.capacity = 4;
    CITIUS_ASSERT_RV(citius_encrypt(&req, &resp), CITIUS_BUFFER_TOO_SMALL);
    CITIUS_ASSERT(resp.ciphertext.length == 48);

    citius_test_cleanup();
}

static void test_encrypt_decrypt_roundtrip(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("enc-key3");

    const uint8_t aad_bytes[] = "context";
    citius_encrypt_params_t op = aead_params_with_aad(
        aad_bytes, sizeof(aad_bytes) - 1);

    /* Encrypt */
    citius_encrypt_request_t enc_req;
    memset(&enc_req, 0, sizeof(enc_req));
    enc_req.key_name = key;
    const uint8_t pt_bytes[64] = {0x55};
    enc_req.plaintext.data   = pt_bytes;
    enc_req.plaintext.length = 64;
    enc_req.scope_params     = op;

    uint8_t ct_buf[80];
    citius_encrypt_response_t enc_resp;
    memset(&enc_resp, 0, sizeof(enc_resp));
    enc_resp.ciphertext.data     = ct_buf;
    enc_resp.ciphertext.capacity = 80;
    CITIUS_ASSERT_RV(citius_encrypt(&enc_req, &enc_resp), CITIUS_OK);
    CITIUS_ASSERT(enc_resp.ciphertext.length == 80);

    /* Verify metadata was set */
    CITIUS_ASSERT(enc_resp.metadata.api_version != NULL);

    /* Decrypt — pass back the metadata */
    citius_decrypt_request_t dec_req;
    memset(&dec_req, 0, sizeof(dec_req));
    dec_req.key_name           = key;
    dec_req.ciphertext.data    = ct_buf;
    dec_req.ciphertext.length  = enc_resp.ciphertext.length;
    dec_req.metadata           = enc_resp.metadata;
    dec_req.scope_params       = op;

    uint8_t pt_out_buf[80];
    citius_decrypt_response_t dec_resp;
    memset(&dec_resp, 0, sizeof(dec_resp));
    dec_resp.plaintext.data     = pt_out_buf;
    dec_resp.plaintext.capacity = 80;
    CITIUS_ASSERT_RV(citius_decrypt(&dec_req, &dec_resp), CITIUS_OK);
    CITIUS_ASSERT(dec_resp.plaintext.length == 64);

    citius_test_cleanup();
}

static void test_encrypt_null_args(void)
{
    citius_encrypt_response_t resp;
    memset(&resp, 0, sizeof(resp));
    /* NULL request */
    CITIUS_ASSERT_RV(citius_encrypt(NULL, &resp), CITIUS_NULL_ARGUMENT);
}

int main(void)
{
    test_encrypt_size_query();
    test_encrypt_buffer_too_small();
    test_encrypt_decrypt_roundtrip();
    test_encrypt_null_args();
    printf("test_encrypt_decrypt: all tests passed\n");
    return 0;
}
