/**
 * @file test_streaming.c
 * @brief Tests for Init/Update/Final streaming operations.
 */

#include "test_helpers.h"

/* --- Encrypt streaming --------------------------------------------------- */

static void test_encrypt_streaming(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("stream-enc");

    citius_encrypt_init_request_t init_req;
    memset(&init_req, 0, sizeof(init_req));
    init_req.key_name     = key;
    init_req.operation_id = "enc-op-1";
    init_req.scope_params.type = CITIUS_ENCRYPT_PARAMS_NONE;

    citius_encrypt_init_response_t init_resp;
    memset(&init_resp, 0, sizeof(init_resp));
    citius_op_ctx_t ctx = NULL;
    CITIUS_ASSERT_RV(citius_encrypt_init(&init_req, &init_resp, &ctx), CITIUS_OK);
    CITIUS_ASSERT(ctx != NULL);

    const uint8_t chunk1[16] = {0x11};
    const uint8_t chunk2[16] = {0x22};

    citius_encrypt_update_request_t upd_req;
    citius_encrypt_update_response_t upd_resp;
    uint8_t out1_buf[16], out2_buf[16];

    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id          = "enc-op-1";
    upd_req.plaintext_chunk.data   = chunk1;
    upd_req.plaintext_chunk.length = 16;
    memset(&upd_resp, 0, sizeof(upd_resp));
    upd_resp.ciphertext_chunk.data     = out1_buf;
    upd_resp.ciphertext_chunk.capacity = 16;
    CITIUS_ASSERT_RV(citius_encrypt_update(ctx, &upd_req, &upd_resp), CITIUS_OK);

    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id          = "enc-op-1";
    upd_req.plaintext_chunk.data   = chunk2;
    upd_req.plaintext_chunk.length = 16;
    memset(&upd_resp, 0, sizeof(upd_resp));
    upd_resp.ciphertext_chunk.data     = out2_buf;
    upd_resp.ciphertext_chunk.capacity = 16;
    CITIUS_ASSERT_RV(citius_encrypt_update(ctx, &upd_req, &upd_resp), CITIUS_OK);

    citius_encrypt_final_request_t final_req;
    memset(&final_req, 0, sizeof(final_req));
    final_req.operation_id = "enc-op-1";

    uint8_t tail_buf[16];
    citius_encrypt_final_response_t final_resp;
    memset(&final_resp, 0, sizeof(final_resp));
    final_resp.ciphertext_final.data     = tail_buf;
    final_resp.ciphertext_final.capacity = 16;
    CITIUS_ASSERT_RV(citius_encrypt_final(ctx, &final_req, &final_resp), CITIUS_OK);
    CITIUS_ASSERT_RV(citius_op_ctx_free(ctx), CITIUS_OK);

    citius_test_cleanup();
}

/* --- Decrypt streaming --------------------------------------------------- */

static void test_decrypt_streaming(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("stream-dec");

    citius_decrypt_init_request_t init_req;
    memset(&init_req, 0, sizeof(init_req));
    init_req.key_name     = key;
    init_req.operation_id = "dec-op-1";
    init_req.scope_params.type = CITIUS_ENCRYPT_PARAMS_NONE;

    citius_decrypt_init_response_t init_resp;
    memset(&init_resp, 0, sizeof(init_resp));
    citius_op_ctx_t ctx = NULL;
    CITIUS_ASSERT_RV(citius_decrypt_init(&init_req, &init_resp, &ctx), CITIUS_OK);

    const uint8_t ct[32] = {0};
    citius_decrypt_update_request_t upd_req;
    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id          = "dec-op-1";
    upd_req.ciphertext_chunk.data   = ct;
    upd_req.ciphertext_chunk.length = 32;

    uint8_t out_buf[32];
    citius_decrypt_update_response_t upd_resp;
    memset(&upd_resp, 0, sizeof(upd_resp));
    upd_resp.plaintext_chunk.data     = out_buf;
    upd_resp.plaintext_chunk.capacity = 32;
    CITIUS_ASSERT_RV(citius_decrypt_update(ctx, &upd_req, &upd_resp), CITIUS_OK);

    citius_decrypt_final_request_t final_req;
    memset(&final_req, 0, sizeof(final_req));
    final_req.operation_id = "dec-op-1";

    uint8_t tail_buf[16];
    citius_decrypt_final_response_t final_resp;
    memset(&final_resp, 0, sizeof(final_resp));
    final_resp.plaintext_final.data     = tail_buf;
    final_resp.plaintext_final.capacity = 16;
    CITIUS_ASSERT_RV(citius_decrypt_final(ctx, &final_req, &final_resp), CITIUS_OK);
    CITIUS_ASSERT_RV(citius_op_ctx_free(ctx), CITIUS_OK);

    citius_test_cleanup();
}

/* --- Sign streaming ------------------------------------------------------- */

static void test_sign_streaming(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("stream-sign");

    citius_sign_init_request_t init_req;
    memset(&init_req, 0, sizeof(init_req));
    init_req.key_name     = key;
    init_req.operation_id = "sign-op-1";
    init_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_sign_init_response_t init_resp;
    memset(&init_resp, 0, sizeof(init_resp));
    citius_op_ctx_t ctx = NULL;
    CITIUS_ASSERT_RV(citius_sign_init(&init_req, &init_resp, &ctx), CITIUS_OK);

    const uint8_t data[] = "streaming message part one";
    citius_sign_update_request_t upd_req;
    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id      = "sign-op-1";
    upd_req.data_chunk.data   = data;
    upd_req.data_chunk.length = sizeof(data) - 1;

    citius_sign_update_response_t upd_resp;
    memset(&upd_resp, 0, sizeof(upd_resp));
    CITIUS_ASSERT_RV(citius_sign_update(ctx, &upd_req, &upd_resp), CITIUS_OK);

    citius_sign_final_request_t final_req;
    memset(&final_req, 0, sizeof(final_req));
    final_req.operation_id = "sign-op-1";

    uint8_t sig_buf[64];
    citius_sign_final_response_t final_resp;
    memset(&final_resp, 0, sizeof(final_resp));
    final_resp.signature.data     = sig_buf;
    final_resp.signature.capacity = 64;
    CITIUS_ASSERT_RV(citius_sign_final(ctx, &final_req, &final_resp), CITIUS_OK);
    CITIUS_ASSERT(final_resp.signature.length == 64);
    CITIUS_ASSERT_RV(citius_op_ctx_free(ctx), CITIUS_OK);

    citius_test_cleanup();
}

/* --- Verify streaming ----------------------------------------------------- */

static void test_verify_streaming(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("stream-verify");

    citius_verify_init_request_t init_req;
    memset(&init_req, 0, sizeof(init_req));
    init_req.key_name     = key;
    init_req.operation_id = "verify-op-1";
    init_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_verify_init_response_t init_resp;
    memset(&init_resp, 0, sizeof(init_resp));
    citius_op_ctx_t ctx = NULL;
    CITIUS_ASSERT_RV(citius_verify_init(&init_req, &init_resp, &ctx), CITIUS_OK);

    const uint8_t data[] = "streaming verify data";
    citius_verify_update_request_t upd_req;
    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id      = "verify-op-1";
    upd_req.data_chunk.data   = data;
    upd_req.data_chunk.length = sizeof(data) - 1;

    citius_verify_update_response_t upd_resp;
    memset(&upd_resp, 0, sizeof(upd_resp));
    CITIUS_ASSERT_RV(citius_verify_update(ctx, &upd_req, &upd_resp), CITIUS_OK);

    uint8_t sig_bytes[64] = {0};
    citius_verify_final_request_t final_req;
    memset(&final_req, 0, sizeof(final_req));
    final_req.operation_id     = "verify-op-1";
    final_req.signature.data   = sig_bytes;
    final_req.signature.length = 64;

    citius_verify_final_response_t final_resp;
    memset(&final_resp, 0, sizeof(final_resp));
    CITIUS_ASSERT_RV(citius_verify_final(ctx, &final_req, &final_resp), CITIUS_OK);
    CITIUS_ASSERT(final_resp.valid == 1);
    CITIUS_ASSERT_RV(citius_op_ctx_free(ctx), CITIUS_OK);

    citius_test_cleanup();
}

/* --- Digest streaming ----------------------------------------------------- */

static void test_digest_streaming(void)
{
    citius_test_init();

    citius_digest_init_request_t init_req;
    memset(&init_req, 0, sizeof(init_req));
    init_req.scope_spec.type            = CITIUS_SCOPE_SPEC_HASH;
    init_req.scope_spec.spec.hash.scope = HASH_SCOPE_STANDARD;
    init_req.operation_id               = "digest-op-1";

    citius_digest_init_response_t init_resp;
    memset(&init_resp, 0, sizeof(init_resp));
    citius_op_ctx_t ctx = NULL;
    CITIUS_ASSERT_RV(citius_digest_init(&init_req, &init_resp, &ctx), CITIUS_OK);

    const uint8_t d[] = "data to hash";
    citius_digest_update_request_t upd_req;
    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id      = "digest-op-1";
    upd_req.data_chunk.data   = d;
    upd_req.data_chunk.length = sizeof(d) - 1;

    citius_digest_update_response_t upd_resp;
    memset(&upd_resp, 0, sizeof(upd_resp));
    CITIUS_ASSERT_RV(citius_digest_update(ctx, &upd_req, &upd_resp), CITIUS_OK);

    citius_digest_final_request_t final_req;
    memset(&final_req, 0, sizeof(final_req));
    final_req.operation_id = "digest-op-1";

    uint8_t hash_buf[32];
    citius_digest_final_response_t final_resp;
    memset(&final_resp, 0, sizeof(final_resp));
    final_resp.digest.data     = hash_buf;
    final_resp.digest.capacity = 32;
    CITIUS_ASSERT_RV(citius_digest_final(ctx, &final_req, &final_resp), CITIUS_OK);
    CITIUS_ASSERT(final_resp.digest.length == 32);
    CITIUS_ASSERT_RV(citius_op_ctx_free(ctx), CITIUS_OK);

    citius_test_cleanup();
}

/* --- ctx_free on NULL ----------------------------------------------------- */

static void test_ctx_free_null(void)
{
    CITIUS_ASSERT_RV(citius_op_ctx_free(NULL), CITIUS_OK);
}

/* --- Message-based AEAD streaming ---------------------------------------- */

static void test_message_encrypt_decrypt(void)
{
    citius_test_init();
    const char           *key  = citius_test_create_key("msg-stream");

    citius_encrypt_message_init_request_t enc_init_req;
    memset(&enc_init_req, 0, sizeof(enc_init_req));
    enc_init_req.key_name     = key;
    enc_init_req.operation_id = "msg-enc-op-1";
    enc_init_req.scope_params.type = CITIUS_ENCRYPT_PARAMS_NONE;

    citius_encrypt_message_init_response_t enc_init_resp;
    memset(&enc_init_resp, 0, sizeof(enc_init_resp));
    citius_op_ctx_t enc_ctx = NULL;
    CITIUS_ASSERT_RV(citius_message_encrypt_init(&enc_init_req, &enc_init_resp, &enc_ctx), CITIUS_OK);

    const uint8_t pt[32] = {0xCC};
    citius_encrypt_message_request_t enc_req;
    memset(&enc_req, 0, sizeof(enc_req));
    enc_req.key_name         = key;
    enc_req.plaintext.data   = pt;
    enc_req.plaintext.length = 32;

    uint8_t ct_buf[48];
    citius_encrypt_message_response_t enc_resp;
    memset(&enc_resp, 0, sizeof(enc_resp));
    enc_resp.ciphertext.data     = ct_buf;
    enc_resp.ciphertext.capacity = 48;
    CITIUS_ASSERT_RV(citius_message_encrypt(enc_ctx, &enc_req, &enc_resp), CITIUS_OK);
    CITIUS_ASSERT(enc_resp.ciphertext.length == 48);

    citius_encrypt_message_final_request_t enc_final_req;
    memset(&enc_final_req, 0, sizeof(enc_final_req));
    enc_final_req.operation_id = "msg-enc-op-1";
    citius_encrypt_message_final_response_t enc_final_resp;
    memset(&enc_final_resp, 0, sizeof(enc_final_resp));
    uint8_t enc_tail_buf[16];
    enc_final_resp.ciphertext_final.data     = enc_tail_buf;
    enc_final_resp.ciphertext_final.capacity = 16;
    CITIUS_ASSERT_RV(citius_message_encrypt_final(enc_ctx, &enc_final_req, &enc_final_resp), CITIUS_OK);
    CITIUS_ASSERT_RV(citius_op_ctx_free(enc_ctx), CITIUS_OK);

    /* Decrypt */
    citius_decrypt_message_init_request_t dec_init_req;
    memset(&dec_init_req, 0, sizeof(dec_init_req));
    dec_init_req.key_name     = key;
    dec_init_req.operation_id = "msg-dec-op-1";
    dec_init_req.scope_params.type = CITIUS_ENCRYPT_PARAMS_NONE;

    citius_decrypt_message_init_response_t dec_init_resp;
    memset(&dec_init_resp, 0, sizeof(dec_init_resp));
    citius_op_ctx_t dec_ctx = NULL;
    CITIUS_ASSERT_RV(citius_message_decrypt_init(&dec_init_req, &dec_init_resp, &dec_ctx), CITIUS_OK);

    citius_decrypt_message_request_t dec_req;
    memset(&dec_req, 0, sizeof(dec_req));
    dec_req.key_name         = key;
    dec_req.ciphertext.data   = ct_buf;
    dec_req.ciphertext.length = enc_resp.ciphertext.length;

    uint8_t pt_out_buf[48];
    citius_decrypt_message_response_t dec_resp;
    memset(&dec_resp, 0, sizeof(dec_resp));
    dec_resp.plaintext.data     = pt_out_buf;
    dec_resp.plaintext.capacity = 48;
    CITIUS_ASSERT_RV(citius_message_decrypt(dec_ctx, &dec_req, &dec_resp), CITIUS_OK);
    CITIUS_ASSERT(dec_resp.plaintext.length == 32);

    citius_decrypt_message_final_request_t dec_final_req;
    memset(&dec_final_req, 0, sizeof(dec_final_req));
    dec_final_req.operation_id = "msg-dec-op-1";
    citius_decrypt_message_final_response_t dec_final_resp;
    memset(&dec_final_resp, 0, sizeof(dec_final_resp));
    uint8_t dec_tail_buf[16];
    dec_final_resp.plaintext_final.data     = dec_tail_buf;
    dec_final_resp.plaintext_final.capacity = 16;
    CITIUS_ASSERT_RV(citius_message_decrypt_final(dec_ctx, &dec_final_req, &dec_final_resp), CITIUS_OK);
    CITIUS_ASSERT_RV(citius_op_ctx_free(dec_ctx), CITIUS_OK);

    citius_test_cleanup();
}

int main(void)
{
    test_encrypt_streaming();
    test_decrypt_streaming();
    test_sign_streaming();
    test_verify_streaming();
    test_digest_streaming();
    test_ctx_free_null();
    test_message_encrypt_decrypt();
    printf("test_streaming: all tests passed\n");
    return 0;
}
