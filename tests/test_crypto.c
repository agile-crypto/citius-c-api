/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 12 CryptoService functions against the stub backend
 * (commit 8): real round-trips, real tamper detection, fail-closed
 * verification.
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
    switch (kind) {
    case AGC_SCOPE_KIND_AEAD: scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD; break;
    case AGC_SCOPE_KIND_SIGNATURE: scope.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD; break;
    case AGC_SCOPE_KIND_MAC: scope.u.mac.scope = AGC_MAC_SCOPE_STANDARD; break;
    case AGC_SCOPE_KIND_SYMMETRIC_CIPHER: scope.u.symmetric_cipher.scope = AGC_SYMMETRIC_CIPHER_SCOPE_BLOCK; break;
    case AGC_SCOPE_KIND_DISK_ENCRYPTION: scope.u.disk_encryption.scope = AGC_DISK_ENCRYPTION_SCOPE_STANDARD; break;
    case AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION: scope.u.asymmetric_encryption.scope = AGC_ASYMMETRIC_ENCRYPTION_SCOPE_STANDARD; break;
    default: break;
    }

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = name;
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);
}

static void test_encrypt_decrypt_aead_roundtrip(agc_ctx *ctx)
{
    create_key(ctx, "enc-key", AGC_SCOPE_KIND_AEAD);

    const char *plaintext = "the quick brown fox jumps over the lazy dog";
    const char *aad_str = "context-v1";

    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    ep.u.aead.aad = (agc_slice){(const uint8_t *)aad_str, strlen(aad_str)};

    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "enc-key";
    er.plaintext = (agc_slice){(const uint8_t *)plaintext, strlen(plaintext)};
    er.params = &ep;

    size_t needed = 0;
    AGC_ASSERT_OK(agc_encrypt(ctx, &er, (agc_buf){0}, &needed, NULL));
    AGC_ASSERT_EQ_INT(needed, strlen(plaintext) + 16); /* AEAD tag is 16 bytes in this stub */

    uint8_t *ct = malloc(needed);
    size_t ct_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_encrypt(ctx, &er, (agc_buf){ct, needed}, &ct_len, &md));
    AGC_ASSERT_EQ_INT(ct_len, needed);
    AGC_ASSERT(md != NULL);
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_AEAD);

    /* Ciphertext must not equal the plaintext bytes it encodes. */
    AGC_ASSERT(memcmp(ct, plaintext, strlen(plaintext)) != 0);

    /* Round-trip: decrypt must recover the exact plaintext. */
    agc_decrypt_request dr;
    AGC_INIT(&dr);
    dr.key_name = "enc-key";
    dr.ciphertext = (agc_slice){ct, ct_len};
    dr.metadata = md;
    dr.params = &ep;

    size_t pt_needed = 0;
    AGC_ASSERT_OK(agc_decrypt(ctx, &dr, (agc_buf){0}, &pt_needed, NULL));
    AGC_ASSERT_EQ_INT(pt_needed, strlen(plaintext));

    uint8_t *pt = malloc(pt_needed + 1);
    size_t pt_len = 0;
    AGC_ASSERT_OK(agc_decrypt(ctx, &dr, (agc_buf){pt, pt_needed}, &pt_len, NULL));
    pt[pt_len] = '\0';
    AGC_ASSERT_EQ_STR((const char *)pt, plaintext);

    /* Tamper with one ciphertext byte -> authentication must fail, and
     * nothing resembling the plaintext may be left in the output buffer. */
    ct[0] ^= 0x01;
    memset(pt, 0xFF, pt_needed);
    AGC_ASSERT_EQ_INT(agc_decrypt(ctx, &dr, (agc_buf){pt, pt_needed}, &pt_len, NULL),
                       AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    AGC_ASSERT(memcmp(pt, plaintext, pt_needed) != 0); /* the wrong plaintext, not silently released */
    ct[0] ^= 0x01; /* restore */

    /* Tampering with the tag (last 16 bytes) must also fail. */
    memset(pt, 0xFF, pt_needed);
    ct[ct_len - 1] ^= 0x01;
    AGC_ASSERT_EQ_INT(agc_decrypt(ctx, &dr, (agc_buf){pt, pt_needed}, &pt_len, NULL),
                       AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    ct[ct_len - 1] ^= 0x01;

    /* Wrong AAD must also fail (it's authenticated context, not just
     * transported alongside). */
    agc_encrypt_params wrong_aad = ep;
    wrong_aad.u.aead.aad = (agc_slice){(const uint8_t *)"different", 9};
    dr.params = &wrong_aad;
    AGC_ASSERT_EQ_INT(agc_decrypt(ctx, &dr, (agc_buf){pt, pt_needed}, &pt_len, NULL),
                       AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);

    free(ct);
    free(pt);
    agc_metadata_free(md);
}

static void test_encrypt_buffer_too_small(agc_ctx *ctx)
{
    create_key(ctx, "enc-key-2", AGC_SCOPE_KIND_AEAD);
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "enc-key-2";
    er.plaintext = (agc_slice){(const uint8_t *)"hello", 5};
    er.params = &ep;

    uint8_t tiny[1];
    size_t out_len = 0;
    AGC_ASSERT_EQ_INT(agc_encrypt(ctx, &er, (agc_buf){tiny, sizeof(tiny)}, &out_len, NULL),
                       AGC_ERR_BUFFER_TOO_SMALL);
    AGC_ASSERT_EQ_INT(out_len, 5 + 16);
}

static void test_sign_verify(agc_ctx *ctx)
{
    create_key(ctx, "sign-key", AGC_SCOPE_KIND_SIGNATURE);

    const char *msg = "message to sign";
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;

    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "sign-key";
    sr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    sr.params = &sp;

    uint8_t sig[64];
    size_t sig_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_sign(ctx, &sr, (agc_buf){sig, sizeof(sig)}, &sig_len, &md));
    AGC_ASSERT(sig_len > 0);

    agc_verify_request vr;
    AGC_INIT(&vr);
    vr.key_name = "sign-key";
    vr.input = sr.input;
    vr.signature = (agc_slice){sig, sig_len};
    vr.metadata = md;
    vr.params = &sp;

    int valid = 0;
    AGC_ASSERT_OK(agc_verify(ctx, &vr, &valid, NULL));
    AGC_ASSERT(valid);

    /* Fail-closed (D9): tampered message -> error code AND out_valid == 0. */
    vr.input = (agc_slice){(const uint8_t *)"different message", 18};
    valid = 1; /* deliberately pre-set to prove it gets cleared */
    AGC_ASSERT_EQ_INT(agc_verify(ctx, &vr, &valid, NULL), AGC_ERR_CRYPTO_SIGNATURE_INVALID);
    AGC_ASSERT_EQ_INT(valid, 0);

    /* out_valid may be NULL; rc alone must still be authoritative. */
    AGC_ASSERT_EQ_INT(agc_verify(ctx, &vr, NULL, NULL), AGC_ERR_CRYPTO_SIGNATURE_INVALID);

    agc_metadata_free(md);
}

static void test_digest_sign_verify(agc_ctx *ctx)
{
    create_key(ctx, "digest-sign-key", AGC_SCOPE_KIND_SIGNATURE);

    uint8_t fake_sha256_digest[32];
    memset(fake_sha256_digest, 0xAB, sizeof(fake_sha256_digest));

    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;

    agc_digest_sign_request dsr;
    AGC_INIT(&dsr);
    dsr.key_name = "digest-sign-key";
    dsr.digest = (agc_slice){fake_sha256_digest, sizeof(fake_sha256_digest)};
    dsr.params = &sp;
    dsr.hash_algorithm = AGC_HASH_ALGORITHM_SHA256;

    uint8_t sig[64];
    size_t sig_len = 0;
    AGC_ASSERT_OK(agc_digest_sign(ctx, &dsr, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL));

    /* Wrong declared length for the algorithm is rejected -- this is the
     * check that stops a SHA-1 digest being presented as SHA-256. */
    dsr.hash_algorithm = AGC_HASH_ALGORITHM_SHA384; /* expects 48 bytes, digest is 32 */
    AGC_ASSERT_EQ_INT(agc_digest_sign(ctx, &dsr, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL),
                       AGC_ERR_INVALID_ARGUMENT);

    dsr.hash_algorithm = AGC_HASH_ALGORITHM_UNSPECIFIED;
    AGC_ASSERT_EQ_INT(agc_digest_sign(ctx, &dsr, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL),
                       AGC_ERR_INVALID_ARGUMENT);

    dsr.hash_algorithm = AGC_HASH_ALGORITHM_SHA256;
    AGC_ASSERT_OK(agc_digest_sign(ctx, &dsr, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL));

    agc_digest_verify_request dvr;
    AGC_INIT(&dvr);
    dvr.key_name = "digest-sign-key";
    dvr.digest = dsr.digest;
    dvr.signature = (agc_slice){sig, sig_len};
    dvr.params = &sp;
    dvr.hash_algorithm = AGC_HASH_ALGORITHM_SHA256;

    int valid = 0;
    AGC_ASSERT_OK(agc_digest_verify(ctx, &dvr, &valid, NULL));
    AGC_ASSERT(valid);
}

static void test_mac(agc_ctx *ctx)
{
    create_key(ctx, "mac-key", AGC_SCOPE_KIND_MAC);

    agc_mac_params mp;
    AGC_INIT(&mp);
    mp.kind = AGC_MAC_PARAMS_NO_PARAMS;

    agc_mac_request mr;
    AGC_INIT(&mr);
    mr.key_name = "mac-key";
    mr.message = (agc_slice){(const uint8_t *)"authenticate me", 15};
    mr.params = &mp;

    uint8_t mac[64];
    size_t mac_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_generate_mac(ctx, &mr, (agc_buf){mac, sizeof(mac)}, &mac_len, &md));

    agc_verify_mac_request vmr;
    AGC_INIT(&vmr);
    vmr.key_name = "mac-key";
    vmr.message = mr.message;
    vmr.mac = (agc_slice){mac, mac_len};
    vmr.metadata = md;
    vmr.params = &mp;

    int valid = 0;
    AGC_ASSERT_OK(agc_verify_mac(ctx, &vmr, &valid, NULL));
    AGC_ASSERT(valid);

    mac[0] ^= 0x01;
    valid = 1;
    AGC_ASSERT_EQ_INT(agc_verify_mac(ctx, &vmr, &valid, NULL), AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    AGC_ASSERT_EQ_INT(valid, 0);

    agc_metadata_free(md);
}

static void test_digest_and_xof(agc_ctx *ctx)
{
    /* Digest/Xof are genuinely keyless on the wire -- no key_name field
     * exists on DigestRequest/XofRequest at all. */
    agc_scope_spec hash_scope;
    AGC_INIT(&hash_scope);
    hash_scope.kind = AGC_SCOPE_KIND_HASH;
    hash_scope.u.hash.scope = AGC_HASH_SCOPE_STANDARD;

    agc_digest_request dr;
    AGC_INIT(&dr);
    dr.scope_spec = &hash_scope;
    dr.data = (agc_slice){(const uint8_t *)"hash me", 7};

    uint8_t digest_a[64], digest_b[64];
    size_t len_a = 0, len_b = 0;
    AGC_ASSERT_OK(agc_digest(ctx, &dr, (agc_buf){digest_a, sizeof(digest_a)}, &len_a, NULL));

    /* Deterministic: same input, same digest. */
    AGC_ASSERT_OK(agc_digest(ctx, &dr, (agc_buf){digest_b, sizeof(digest_b)}, &len_b, NULL));
    AGC_ASSERT_EQ_INT(len_a, len_b);
    AGC_ASSERT_MEM_EQ(digest_a, digest_b, len_a);

    /* Different input, different digest. */
    dr.data = (agc_slice){(const uint8_t *)"hash me differently", 19};
    AGC_ASSERT_OK(agc_digest(ctx, &dr, (agc_buf){digest_b, sizeof(digest_b)}, &len_b, NULL));
    AGC_ASSERT(memcmp(digest_a, digest_b, len_a) != 0);

    /* Neither scope_spec nor template_id is invalid. */
    agc_digest_request bad;
    AGC_INIT(&bad);
    AGC_ASSERT_EQ_INT(agc_digest(ctx, &bad, (agc_buf){digest_a, sizeof(digest_a)}, &len_a, NULL),
                       AGC_ERR_INVALID_ARGUMENT);

    /* Xof: caller-chosen output length, deterministic given the same input. */
    agc_scope_spec xof_scope = hash_scope;
    xof_scope.u.hash.scope = AGC_HASH_SCOPE_XOF;
    agc_xof_request xr;
    AGC_INIT(&xr);
    xr.scope_spec = &xof_scope;
    xr.data = (agc_slice){(const uint8_t *)"expand me", 9};
    xr.output_length_bytes = 100;

    uint8_t xof_out[100];
    size_t xof_len = 0;
    AGC_ASSERT_OK(agc_xof(ctx, &xr, (agc_buf){xof_out, sizeof(xof_out)}, &xof_len, NULL));
    AGC_ASSERT_EQ_INT(xof_len, 100);

    xr.output_length_bytes = 0;
    AGC_ASSERT_EQ_INT(agc_xof(ctx, &xr, (agc_buf){xof_out, sizeof(xof_out)}, &xof_len, NULL),
                       AGC_ERR_INVALID_ARGUMENT);
}

static void test_random(agc_ctx *ctx)
{
    uint8_t a[32], b[32];
    AGC_ASSERT_OK(agc_random_bytes(ctx, a, sizeof(a)));
    AGC_ASSERT_OK(agc_random_bytes(ctx, b, sizeof(b)));
    AGC_ASSERT(memcmp(a, b, sizeof(a)) != 0); /* astronomically unlikely to collide */

    agc_random_request rr;
    AGC_INIT(&rr);
    rr.num_bytes = 16;
    uint8_t buf[16];
    const char *provider_id = NULL;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_generate_random(ctx, &rr, (agc_buf){buf, sizeof(buf)}, &provider_id, &md));
    AGC_ASSERT_EQ_STR(provider_id, "stub");
    agc_metadata_free(md);

    /* GenerateRandom deliberately breaks the two-call convention: a NULL/
     * undersized buffer is a hard error, not a size query. */
    AGC_ASSERT_EQ_INT(agc_generate_random(ctx, &rr, (agc_buf){0}, &provider_id, NULL), AGC_ERR_INVALID_ARGUMENT);

    agc_seed_random_request seedreq;
    AGC_INIT(&seedreq);
    seedreq.seed = (agc_slice){(const uint8_t *)"entropy", 7};
    int accepted = 1;
    const char *message = NULL;
    AGC_ASSERT_OK(agc_seed_random(ctx, &seedreq, &accepted, &message));
    AGC_ASSERT_EQ_INT(accepted, 0); /* honest decline, not a failure (rc == AGC_OK) */
    AGC_ASSERT(message != NULL);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_encrypt_decrypt_aead_roundtrip(ctx);
    test_encrypt_buffer_too_small(ctx);
    test_sign_verify(ctx);
    test_digest_sign_verify(ctx);
    test_mac(ctx);
    test_digest_and_xof(ctx);
    test_random(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_crypto");
}
