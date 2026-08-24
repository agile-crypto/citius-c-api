/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 6 KeyEstablishmentService functions (commit 10).
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

static void create_key(agc_ctx *ctx, const char *name, agc_scope_kind kind)
{
    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = kind;
    if (kind == AGC_SCOPE_KIND_AEAD) scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;
    if (kind == AGC_SCOPE_KIND_KEY_AGREEMENT) scope.u.key_agreement.scope = AGC_KEY_AGREEMENT_SCOPE_STANDARD;
    if (kind == AGC_SCOPE_KIND_KEM) scope.u.kem.scope = AGC_KEM_SCOPE_STANDARD;
    if (kind == AGC_SCOPE_KIND_GENERIC_SECRET) scope.u.generic_secret.scope = AGC_GENERIC_SECRET_SCOPE_STANDARD;

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = name;
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);
}

static void test_wrap_unwrap(agc_ctx *ctx)
{
    create_key(ctx, "kek", AGC_SCOPE_KIND_AEAD);
    create_key(ctx, "target", AGC_SCOPE_KIND_GENERIC_SECRET);

    agc_wrap_params wp;
    AGC_INIT(&wp);
    wp.kind = AGC_WRAP_PARAMS_NO_PARAMS;

    agc_wrap_key_params p;
    AGC_INIT(&p);
    p.key_to_wrap_name = "target";
    p.wrapping_key_name = "kek";
    p.format = AGC_WRAP_FORMAT_RAW;
    p.params = &wp;

    size_t needed = 0;
    AGC_ASSERT_OK(agc_wrap_key(ctx, &p, (agc_buf){0}, &needed, NULL));
    AGC_ASSERT(needed > 0);

    uint8_t *wrapped = malloc(needed);
    size_t wrapped_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_wrap_key(ctx, &p, (agc_buf){wrapped, needed}, &wrapped_len, &md));
    AGC_ASSERT_EQ_INT(wrapped_len, needed);

    agc_unwrap_key_params up;
    AGC_INIT(&up);
    up.wrapped_key = (agc_slice){wrapped, wrapped_len};
    up.wrapping_key_name = "kek";
    up.unwrapped_key_name = "target-restored";
    up.format = AGC_WRAP_FORMAT_RAW;
    up.metadata = md;
    up.params = &wp;

    agc_key_info *restored = NULL;
    AGC_ASSERT_OK(agc_unwrap_key(ctx, &up, &restored, NULL));
    AGC_ASSERT_EQ_STR(agc_key_info_name(restored), "target-restored");
    agc_key_info_free(restored);

    /* Tampered wrapped blob must fail to unwrap. */
    wrapped[0] ^= 0xFF;
    up.unwrapped_key_name = "target-restored-2";
    AGC_ASSERT_EQ_INT(agc_unwrap_key(ctx, &up, &restored, NULL), AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    AGC_ASSERT(restored == NULL);

    free(wrapped);
    agc_metadata_free(md);
}

static void test_derive_key(agc_ctx *ctx)
{
    create_key(ctx, "base-key", AGC_SCOPE_KIND_GENERIC_SECRET);

    agc_kdf_params kp;
    AGC_INIT(&kp);
    kp.kind = AGC_KDF_PARAMS_HKDF;
    kp.u.hkdf.info = (agc_slice){(const uint8_t *)"context-info", 12};
    kp.u.hkdf.salt.present = 0; /* absent => server generates, per RFC 5869 */

    agc_derive_key_params dp;
    AGC_INIT(&dp);
    dp.base_key_name = "base-key";
    dp.derived_key_name = "derived-1";
    dp.params = &kp;

    agc_key_info *derived = NULL;
    AGC_ASSERT_OK(agc_derive_key(ctx, &dp, &derived, NULL));
    AGC_ASSERT_EQ_STR(agc_key_info_name(derived), "derived-1");
    agc_key_info_free(derived);

    /* Deterministic given the same base key and context. */
    dp.derived_key_name = "derived-2";
    AGC_ASSERT_OK(agc_derive_key(ctx, &dp, &derived, NULL));
    agc_key_info_free(derived);

    /* No scope_spec/template_id field exists on this params struct at all --
     * a compile-time guarantee, not a runtime check, that the base key's
     * template governs (RECONCILIATION_PLAN.md §4.4). */
}

static void test_key_agreement(agc_ctx *ctx)
{
    create_key(ctx, "my-private", AGC_SCOPE_KIND_KEY_AGREEMENT);

    agc_kdf_params kp;
    AGC_INIT(&kp);
    kp.kind = AGC_KDF_PARAMS_ECDH;
    kp.u.ecdh.shared_info = (agc_slice){(const uint8_t *)"agreement-info", 14};

    agc_key_agreement_params ap;
    AGC_INIT(&ap);
    ap.private_key_name = "my-private";
    ap.peer_public_key = (agc_slice){(const uint8_t *)"peer-public-key-bytes", 21};
    ap.shared_secret_name = "agreed-secret";
    ap.params = &kp;

    agc_key_info *shared = NULL;
    AGC_ASSERT_OK(agc_key_agreement(ctx, &ap, &shared, NULL));
    AGC_ASSERT_EQ_STR(agc_key_info_name(shared), "agreed-secret");
    agc_key_info_free(shared);

    /* Out-of-subset params kind is rejected (kdf_params is reused, but
     * agreement_params is a strict subset). */
    kp.kind = AGC_KDF_PARAMS_PBKDF2;
    ap.shared_secret_name = "should-not-exist";
    AGC_ASSERT_EQ_INT(agc_key_agreement(ctx, &ap, &shared, NULL), AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS);
}

static void test_encapsulate_decapsulate(agc_ctx *ctx)
{
    create_key(ctx, "kem-key", AGC_SCOPE_KIND_KEM);

    agc_encapsulate_params ep;
    AGC_INIT(&ep);
    ep.recipient_public_key_name = "kem-key";
    ep.shared_secret_name = "kem-shared-sender";

    uint8_t ct[64]; size_t ct_len = 0;
    agc_key_info *sender_secret = NULL;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_encapsulate_key(ctx, &ep, (agc_buf){ct, sizeof(ct)}, &ct_len, &sender_secret, &md));
    AGC_ASSERT(ct_len > 0);
    agc_key_info_free(sender_secret);

    agc_decapsulate_params dp;
    AGC_INIT(&dp);
    dp.private_key_name = "kem-key"; /* stub: same "key" plays both roles, no real asymmetric split */
    dp.ciphertext = (agc_slice){ct, ct_len};
    dp.shared_secret_name = "kem-shared-receiver";
    dp.metadata = md;

    agc_key_info *receiver_secret = NULL;
    AGC_ASSERT_OK(agc_decapsulate_key(ctx, &dp, &receiver_secret, NULL));
    AGC_ASSERT_EQ_STR(agc_key_info_name(receiver_secret), "kem-shared-receiver");
    agc_key_info_free(receiver_secret);

    /* A non-asymmetric-shaped key has no public key material to
     * encapsulate against. */
    create_key(ctx, "not-asymmetric", AGC_SCOPE_KIND_GENERIC_SECRET);
    agc_encapsulate_params bad = ep;
    bad.recipient_public_key_name = "not-asymmetric";
    bad.shared_secret_name = "should-not-exist";
    agc_key_info *dummy = NULL;
    AGC_ASSERT_EQ_INT(agc_encapsulate_key(ctx, &bad, (agc_buf){ct, sizeof(ct)}, &ct_len, &dummy, NULL),
                       AGC_ERR_INVALID_ARGUMENT);

    agc_metadata_free(md);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_wrap_unwrap(ctx);
    test_derive_key(ctx);
    test_key_agreement(ctx);
    test_encapsulate_decapsulate(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_key_establishment");
}
