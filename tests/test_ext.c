/* SPDX-License-Identifier: Apache-2.0
 * Exercises agc_ext.h (commit 13): RFC-01 UpdateKeyState, RFC-14
 * CancelOperation, RFC-13 MAC streaming. Only built when
 * AGC_ENABLE_PROPOSED_EXTENSIONS is on -- see tests/CMakeLists.txt.
 */
#include "agilecrypto.h"
#include "agc_ext.h"
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

static void create_key(agc_ctx *ctx, const char *name, agc_scope_kind kind)
{
    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = kind;
    if (kind == AGC_SCOPE_KIND_MAC) scope.u.mac.scope = AGC_MAC_SCOPE_STANDARD;
    if (kind == AGC_SCOPE_KIND_AEAD) scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = name;
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);
}

static void test_update_key_state(agc_ctx *ctx)
{
    create_key(ctx, "state-key", AGC_SCOPE_KIND_AEAD);

    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_ext_update_key_state(ctx, "state-key", AGC_KEY_LIFECYCLE_STATE_SUSPENDED, NULL, &ki));
    AGC_ASSERT_EQ_INT(agc_key_info_lifecycle_state(ki), AGC_KEY_LIFECYCLE_STATE_SUSPENDED);
    agc_key_info_free(ki);

    /* COMPROMISED requires a reason. */
    AGC_ASSERT_EQ_INT(
        agc_ext_update_key_state(ctx, "state-key", AGC_KEY_LIFECYCLE_STATE_COMPROMISED, NULL, &ki),
        AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT_OK(agc_ext_update_key_state(ctx, "state-key", AGC_KEY_LIFECYCLE_STATE_COMPROMISED,
                                            "suspected HSM firmware issue", &ki));
    AGC_ASSERT_EQ_INT(agc_key_info_lifecycle_state(ki), AGC_KEY_LIFECYCLE_STATE_COMPROMISED);
    agc_key_info_free(ki);

    AGC_ASSERT_EQ_INT(agc_ext_update_key_state(ctx, "no-such-key", AGC_KEY_LIFECYCLE_STATE_ACTIVE, NULL, &ki),
                       AGC_ERR_CRYPTO_KEY_NOT_FOUND);
}

static void test_cancel_operation(agc_ctx *ctx)
{
    create_key(ctx, "cancel-key", AGC_SCOPE_KIND_AEAD);

    agc_digest_init_params dp;
    AGC_INIT(&dp);
    agc_scope_spec hash_scope;
    AGC_INIT(&hash_scope);
    hash_scope.kind = AGC_SCOPE_KIND_HASH;
    hash_scope.u.hash.scope = AGC_HASH_SCOPE_STANDARD;
    dp.scope_spec = &hash_scope;
    dp.operation_id = "my-op-id-1";

    agc_session *s = NULL;
    AGC_ASSERT_OK(agc_digest_init(ctx, &dp, &s));
    AGC_ASSERT_EQ_STR(agc_session_id(s), "my-op-id-1");

    AGC_ASSERT_OK(agc_ext_cancel_operation(ctx, "my-op-id-1", "no longer needed"));

    /* Cancelled: further use must fail, matching agc_session_cancel()'s own contract. */
    AGC_ASSERT_EQ_INT(agc_digest_update(s, (agc_slice){(const uint8_t *)"x", 1}), AGC_ERR_INVALID_HANDLE);

    agc_session_free(s);

    AGC_ASSERT_EQ_INT(agc_ext_cancel_operation(ctx, "does-not-exist", NULL), AGC_ERR_CRYPTO_OPERATION_EXPIRED);
}

static void test_mac_streaming_roundtrip(agc_ctx *ctx)
{
    create_key(ctx, "mac-key", AGC_SCOPE_KIND_MAC);

    agc_mac_params mp;
    AGC_INIT(&mp);
    mp.kind = AGC_MAC_PARAMS_NO_PARAMS;

    agc_ext_mac_init_params ip;
    AGC_INIT(&ip);
    ip.key_name = "mac-key";
    ip.params = &mp;

    agc_session *gen = NULL;
    AGC_ASSERT_OK(agc_ext_generate_mac_init(ctx, &ip, &gen));
    AGC_ASSERT_OK(agc_ext_generate_mac_update(gen, (agc_slice){(const uint8_t *)"hello, ", 7}));
    AGC_ASSERT_OK(agc_ext_generate_mac_update(gen, (agc_slice){(const uint8_t *)"world", 5}));

    size_t needed = 0;
    AGC_ASSERT_OK(agc_ext_generate_mac_final(gen, (agc_buf){0}, &needed, NULL));
    AGC_ASSERT(needed > 0);
    uint8_t *mac = malloc(needed);
    size_t mac_len = 0;
    AGC_ASSERT_OK(agc_ext_generate_mac_final(gen, (agc_buf){mac, needed}, &mac_len, NULL));
    AGC_ASSERT_EQ_INT(mac_len, needed);
    agc_session_free(gen);

    /* Chunk boundaries must not matter: same total bytes, different split. */
    agc_session *gen2 = NULL;
    AGC_ASSERT_OK(agc_ext_generate_mac_init(ctx, &ip, &gen2));
    AGC_ASSERT_OK(agc_ext_generate_mac_update(gen2, (agc_slice){(const uint8_t *)"hello, world", 12}));
    uint8_t *mac2 = malloc(needed);
    size_t mac2_len = 0;
    AGC_ASSERT_OK(agc_ext_generate_mac_final(gen2, (agc_buf){mac2, needed}, &mac2_len, NULL));
    AGC_ASSERT_EQ_INT(mac2_len, mac_len);
    AGC_ASSERT_MEM_EQ(mac, mac2, mac_len);
    agc_session_free(gen2);
    free(mac2);

    agc_session *ver = NULL;
    AGC_ASSERT_OK(agc_ext_verify_mac_init(ctx, &ip, &ver));
    AGC_ASSERT_OK(agc_ext_verify_mac_update(ver, (agc_slice){(const uint8_t *)"hello, ", 7}));
    AGC_ASSERT_OK(agc_ext_verify_mac_update(ver, (agc_slice){(const uint8_t *)"world", 5}));
    int valid = 0;
    AGC_ASSERT_OK(agc_ext_verify_mac_final(ver, (agc_slice){mac, mac_len}, &valid, NULL));
    AGC_ASSERT(valid);
    agc_session_free(ver);

    /* Tampered MAC must fail closed (D9): rc non-OK AND valid left false. */
    mac[0] ^= 0xFF;
    agc_session *ver2 = NULL;
    AGC_ASSERT_OK(agc_ext_verify_mac_init(ctx, &ip, &ver2));
    AGC_ASSERT_OK(agc_ext_verify_mac_update(ver2, (agc_slice){(const uint8_t *)"hello, world", 12}));
    valid = 1;
    AGC_ASSERT_EQ_INT(agc_ext_verify_mac_final(ver2, (agc_slice){mac, mac_len}, &valid, NULL),
                       AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    AGC_ASSERT(!valid);
    agc_session_free(ver2);

    free(mac);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_update_key_state(ctx);
    test_cancel_operation(ctx);
    test_mac_streaming_roundtrip(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_ext");
}
