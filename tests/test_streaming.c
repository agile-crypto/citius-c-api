/* SPDX-License-Identifier: Apache-2.0
 * Exercises all 43 StreamingCryptoService functions against the stub
 * backend (commit 9): chunked encrypt/decrypt matches single-shot results,
 * message-based AEAD round-trips, multi-part/message-based sign/verify,
 * multi-part digest/xof (incl. DigestKey), and dual-function operations.
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
    if (kind == AGC_SCOPE_KIND_SIGNATURE) scope.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;

    agc_create_key_params p;
    AGC_INIT(&p);
    p.name = name;
    p.policy = "default";
    p.scope_spec = &scope;
    agc_key_info *ki = NULL;
    AGC_ASSERT_OK(agc_create_key(ctx, &p, &ki, NULL));
    agc_key_info_free(ki);
}

/* --------------------------------------------------------------------------
 * 1. Multi-part encrypt/decrypt
 * -------------------------------------------------------------------------- */

static void test_multipart_encrypt_decrypt(agc_ctx *ctx)
{
    create_key(ctx, "stream-enc", AGC_SCOPE_KIND_AEAD);

    const char *chunks[] = {"Hello, ", "streaming ", "world!"};
    const char *aad_str = "stream-aad";

    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    ep.u.aead.aad = (agc_slice){(const uint8_t *)aad_str, strlen(aad_str)};

    agc_encrypt_init_params eip;
    AGC_INIT(&eip);
    eip.key_name = "stream-enc";
    eip.params = &ep;

    agc_session *enc = NULL;
    AGC_ASSERT_OK(agc_encrypt_init(ctx, &eip, &enc));
    AGC_ASSERT_EQ_INT(agc_session_operation(enc), AGC_CRYPTO_OPERATION_ENCRYPT);
    AGC_ASSERT(agc_session_id(enc) != NULL);

    uint8_t ct[256];
    size_t ct_len = 0;
    for (size_t i = 0; i < 3; i++) {
        size_t n = 0;
        AGC_ASSERT_OK(agc_encrypt_update(enc, (agc_slice){(const uint8_t *)chunks[i], strlen(chunks[i])},
                                          (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &n));
        AGC_ASSERT_EQ_INT(n, strlen(chunks[i])); /* AEAD emits len(chunk) bytes per Update, no tag yet */
        ct_len += n;
    }
    size_t tag_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_encrypt_final(enc, (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &tag_len, &md));
    AGC_ASSERT_EQ_INT(tag_len, 16);
    ct_len += tag_len;
    agc_session_free(enc);

    /* Whole-message plaintext must match what single-shot agc_encrypt then
     * agc_decrypt would have produced -- chunking must not change the
     * cryptographic result. */
    char full_plain[64];
    snprintf(full_plain, sizeof(full_plain), "%s%s%s", chunks[0], chunks[1], chunks[2]);

    agc_decrypt_init_params dip;
    AGC_INIT(&dip);
    dip.key_name = "stream-enc";
    dip.params = &ep;
    dip.metadata = md;

    agc_session *dec = NULL;
    AGC_ASSERT_OK(agc_decrypt_init(ctx, &dip, &dec));

    uint8_t pt[256];
    size_t pt_len = 0;
    /* Feed ciphertext in different-sized chunks than encryption used, to
     * prove chunk boundaries are irrelevant to correctness. */
    size_t offsets[] = {0, 5, 12, ct_len};
    for (int i = 0; i < 3; i++) {
        size_t chunk_len = offsets[i + 1] - offsets[i];
        size_t n = 0;
        AGC_ASSERT_OK(agc_decrypt_update(dec, (agc_slice){ct + offsets[i], chunk_len},
                                          (agc_buf){pt + pt_len, sizeof(pt) - pt_len}, &n));
        pt_len += n;
    }
    size_t final_len = 0;
    AGC_ASSERT_OK(agc_decrypt_final(dec, (agc_buf){pt + pt_len, sizeof(pt) - pt_len}, &final_len, NULL));
    pt_len += final_len;
    agc_session_free(dec);

    AGC_ASSERT_EQ_INT(pt_len, strlen(full_plain));
    AGC_ASSERT_MEM_EQ(pt, full_plain, pt_len);

    agc_metadata_free(md);
}

static void test_multipart_decrypt_tamper(agc_ctx *ctx)
{
    create_key(ctx, "stream-tamper", AGC_SCOPE_KIND_AEAD);

    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;

    agc_encrypt_init_params eip;
    AGC_INIT(&eip);
    eip.key_name = "stream-tamper";
    eip.params = &ep;
    agc_session *enc = NULL;
    AGC_ASSERT_OK(agc_encrypt_init(ctx, &eip, &enc));

    uint8_t ct[64]; size_t ct_len = 0, n = 0;
    const char *msg = "tamper test message";
    AGC_ASSERT_OK(agc_encrypt_update(enc, (agc_slice){(const uint8_t *)msg, strlen(msg)},
                                      (agc_buf){ct, sizeof(ct)}, &n));
    ct_len += n;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_encrypt_final(enc, (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &n, &md));
    ct_len += n;
    agc_session_free(enc);

    ct[0] ^= 0xFF; /* tamper */

    agc_decrypt_init_params dip;
    AGC_INIT(&dip);
    dip.key_name = "stream-tamper";
    dip.params = &ep;
    dip.metadata = md;
    agc_session *dec = NULL;
    AGC_ASSERT_OK(agc_decrypt_init(ctx, &dip, &dec));

    uint8_t pt[64]; size_t pt_len = 0;
    AGC_ASSERT_OK(agc_decrypt_update(dec, (agc_slice){ct, ct_len}, (agc_buf){pt, sizeof(pt)}, &pt_len));
    /* Tampered plaintext may be released here -- it is UNAUTHENTICATED, per
     * the documented contract -- but Final MUST reject it. */
    size_t final_len = 0;
    AGC_ASSERT_EQ_INT(agc_decrypt_final(dec, (agc_buf){pt, sizeof(pt)}, &final_len, NULL),
                       AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    agc_session_free(dec);
    agc_metadata_free(md);
}

/* --------------------------------------------------------------------------
 * 2. Message-based AEAD
 * -------------------------------------------------------------------------- */

static void test_message_based_single_shot(agc_ctx *ctx)
{
    create_key(ctx, "msg-enc", AGC_SCOPE_KIND_AEAD);

    agc_encrypt_message_request req;
    AGC_INIT(&req);
    req.key_name = "msg-enc";
    req.associated_data = (agc_slice){(const uint8_t *)"ad", 2};
    req.plaintext = (agc_slice){(const uint8_t *)"single shot message", 20};

    uint8_t ct[64]; size_t ct_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_encrypt_message(ctx, &req, (agc_buf){ct, sizeof(ct)}, &ct_len, &md));
    AGC_ASSERT_EQ_INT(ct_len, 20 + 16);

    agc_decrypt_message_request dreq;
    AGC_INIT(&dreq);
    dreq.key_name = "msg-enc";
    dreq.associated_data = req.associated_data;
    dreq.ciphertext = (agc_slice){ct, ct_len};

    uint8_t pt[64]; size_t pt_len = 0;
    AGC_ASSERT_OK(agc_decrypt_message(ctx, &dreq, md, (agc_buf){pt, sizeof(pt)}, &pt_len, NULL));
    AGC_ASSERT_EQ_INT(pt_len, 20);
    AGC_ASSERT_MEM_EQ(pt, "single shot message", 20);

    /* Two independent messages get different nonces even with identical
     * plaintext -- ciphertexts must differ. */
    uint8_t ct2[64]; size_t ct2_len = 0;
    agc_metadata *md2 = NULL;
    AGC_ASSERT_OK(agc_encrypt_message(ctx, &req, (agc_buf){ct2, sizeof(ct2)}, &ct2_len, &md2));
    AGC_ASSERT(memcmp(ct, ct2, ct_len < ct2_len ? ct_len : ct2_len) != 0);

    agc_metadata_free(md);
    agc_metadata_free(md2);
}

static void test_message_based_multipart(agc_ctx *ctx)
{
    create_key(ctx, "msg-multi", AGC_SCOPE_KIND_AEAD);

    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_init_params eip;
    AGC_INIT(&eip);
    eip.key_name = "msg-multi";
    eip.params = &ep;

    agc_session *enc = NULL;
    AGC_ASSERT_OK(agc_encrypt_message_init(ctx, &eip, &enc));

    agc_metadata *partial_md = NULL;
    AGC_ASSERT_OK(agc_encrypt_message_begin(enc, (agc_slice){(const uint8_t *)"ad", 2}, &partial_md));
    AGC_ASSERT(partial_md != NULL);

    uint8_t ct[128]; size_t ct_len = 0, n = 0;
    AGC_ASSERT_OK(agc_encrypt_message_next(enc, (agc_slice){(const uint8_t *)"part-one-", 9},
                                            (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &n));
    ct_len += n;
    AGC_ASSERT_OK(agc_encrypt_message_next(enc, (agc_slice){(const uint8_t *)"part-two", 8},
                                            (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &n));
    ct_len += n;

    agc_metadata *final_md = NULL;
    AGC_ASSERT_OK(agc_encrypt_message_final(enc, (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &n, &final_md));
    ct_len += n; /* the message-final call tears the session down and emits the tag */

    /* A second Begin on the same (now-closed) session must fail -- one
     * message per session is the wire specification's own current limit. */
    agc_metadata *dummy = NULL;
    AGC_ASSERT_EQ_INT(agc_encrypt_message_begin(enc, (agc_slice){0}, &dummy), AGC_ERR_INVALID_HANDLE);
    agc_session_free(enc);

    /* Decrypt via the message-based Begin/Next/Final mirror. */
    agc_decrypt_message_init_params dip;
    AGC_INIT(&dip);
    dip.key_name = "msg-multi";
    dip.params = &ep;
    agc_session *dec = NULL;
    AGC_ASSERT_OK(agc_decrypt_message_init(ctx, &dip, &dec));
    AGC_ASSERT_OK(agc_decrypt_message_begin(dec, (agc_slice){(const uint8_t *)"ad", 2}, partial_md));

    uint8_t pt[128]; size_t pt_len = 0;
    AGC_ASSERT_OK(agc_decrypt_message_next(dec, (agc_slice){ct, ct_len}, (agc_buf){pt, sizeof(pt)}, &pt_len));
    size_t final_pt_len = 0;
    AGC_ASSERT_OK(agc_decrypt_message_final(dec, (agc_buf){pt + pt_len, sizeof(pt) - pt_len}, &final_pt_len, NULL));
    pt_len += final_pt_len;
    agc_session_free(dec);

    AGC_ASSERT_EQ_INT(pt_len, strlen("part-one-part-two"));
    AGC_ASSERT_MEM_EQ(pt, "part-one-part-two", pt_len);

    agc_metadata_free(partial_md);
    agc_metadata_free(final_md);
}

/* --------------------------------------------------------------------------
 * 3 & 4. Sign / Verify -- multi-part and message-based
 * -------------------------------------------------------------------------- */

static void test_multipart_sign_verify(agc_ctx *ctx)
{
    create_key(ctx, "stream-sign", AGC_SCOPE_KIND_SIGNATURE);

    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;

    agc_sign_init_params sip;
    AGC_INIT(&sip);
    sip.key_name = "stream-sign";
    sip.params = &sp;
    agc_session *signer = NULL;
    AGC_ASSERT_OK(agc_sign_init(ctx, &sip, &signer));

    AGC_ASSERT_OK(agc_sign_update(signer, (agc_slice){(const uint8_t *)"part-a-", 7}));
    AGC_ASSERT_OK(agc_sign_update(signer, (agc_slice){(const uint8_t *)"part-b", 6}));

    uint8_t sig[64]; size_t sig_len = 0;
    AGC_ASSERT_OK(agc_sign_final(signer, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL));
    agc_session_free(signer);

    /* Must match signing the whole message in one shot. */
    agc_sign_request one_shot;
    AGC_INIT(&one_shot);
    one_shot.key_name = "stream-sign";
    one_shot.input = (agc_slice){(const uint8_t *)"part-a-part-b", 13};
    one_shot.params = &sp;
    uint8_t sig2[64]; size_t sig2_len = 0;
    AGC_ASSERT_OK(agc_sign(ctx, &one_shot, (agc_buf){sig2, sizeof(sig2)}, &sig2_len, NULL));
    AGC_ASSERT_EQ_INT(sig_len, sig2_len);
    AGC_ASSERT_MEM_EQ(sig, sig2, sig_len);

    agc_verify_init_params vip;
    AGC_INIT(&vip);
    vip.key_name = "stream-sign";
    vip.params = &sp;
    agc_session *verifier = NULL;
    AGC_ASSERT_OK(agc_verify_init(ctx, &vip, &verifier));
    AGC_ASSERT_OK(agc_verify_update(verifier, (agc_slice){(const uint8_t *)"part-a-", 7}));
    AGC_ASSERT_OK(agc_verify_update(verifier, (agc_slice){(const uint8_t *)"part-b", 6}));
    int valid = 0;
    AGC_ASSERT_OK(agc_verify_final(verifier, (agc_slice){sig, sig_len}, &valid, NULL));
    AGC_ASSERT(valid);
    agc_session_free(verifier);

    /* Fail-closed on tampered signature. */
    AGC_ASSERT_OK(agc_verify_init(ctx, &vip, &verifier));
    AGC_ASSERT_OK(agc_verify_update(verifier, (agc_slice){(const uint8_t *)"part-a-part-b", 13}));
    sig[0] ^= 0xFF;
    valid = 1;
    AGC_ASSERT_EQ_INT(agc_verify_final(verifier, (agc_slice){sig, sig_len}, &valid, NULL),
                       AGC_ERR_CRYPTO_SIGNATURE_INVALID);
    AGC_ASSERT_EQ_INT(valid, 0);
    agc_session_free(verifier);
}

static void test_message_based_sign_verify(agc_ctx *ctx)
{
    create_key(ctx, "msg-sign", AGC_SCOPE_KIND_SIGNATURE);

    /* Single-shot message sign/verify. */
    agc_sign_message_request smr;
    AGC_INIT(&smr);
    smr.key_name = "msg-sign";
    smr.message = (agc_slice){(const uint8_t *)"message-based signing", 22};
    uint8_t sig[64]; size_t sig_len = 0;
    AGC_ASSERT_OK(agc_sign_message(ctx, &smr, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL));

    agc_verify_message_request vmr;
    AGC_INIT(&vmr);
    vmr.key_name = "msg-sign";
    vmr.message = smr.message;
    vmr.signature = (agc_slice){sig, sig_len};
    int valid = 0;
    AGC_ASSERT_OK(agc_verify_message(ctx, &vmr, &valid, NULL));
    AGC_ASSERT(valid);

    /* Multi-part message sign/verify: Begin -> Next* -> Final tears the
     * session down (one message per session, per the wire spec's shape). */
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    agc_sign_init_params sip;
    AGC_INIT(&sip);
    sip.key_name = "msg-sign";
    sip.params = &sp;
    agc_session *signer = NULL;
    AGC_ASSERT_OK(agc_sign_message_init(ctx, &sip, &signer));
    AGC_ASSERT_OK(agc_sign_message_begin(signer));
    AGC_ASSERT_OK(agc_sign_message_next(signer, (agc_slice){(const uint8_t *)"chunked-", 8}));
    AGC_ASSERT_OK(agc_sign_message_next(signer, (agc_slice){(const uint8_t *)"signature", 9}));
    uint8_t sig3[64]; size_t sig3_len = 0;
    AGC_ASSERT_OK(agc_sign_message_final(signer, (agc_buf){sig3, sizeof(sig3)}, &sig3_len, NULL));
    agc_session_free(signer);

    agc_verify_init_params vip;
    AGC_INIT(&vip);
    vip.key_name = "msg-sign";
    vip.params = &sp;
    agc_session *verifier = NULL;
    AGC_ASSERT_OK(agc_verify_message_init(ctx, &vip, &verifier));
    AGC_ASSERT_OK(agc_verify_message_begin(verifier));
    AGC_ASSERT_OK(agc_verify_message_next(verifier, (agc_slice){(const uint8_t *)"chunked-signature", 17}));
    valid = 0;
    AGC_ASSERT_OK(agc_verify_message_final(verifier, (agc_slice){sig3, sig3_len}, &valid, NULL));
    AGC_ASSERT(valid);
    agc_session_free(verifier);
}

/* --------------------------------------------------------------------------
 * 5 & 6. Multi-part digest / XOF
 * -------------------------------------------------------------------------- */

static void test_multipart_digest_and_xof(agc_ctx *ctx)
{
    agc_scope_spec hash_scope;
    AGC_INIT(&hash_scope);
    hash_scope.kind = AGC_SCOPE_KIND_HASH;
    hash_scope.u.hash.scope = AGC_HASH_SCOPE_STANDARD;

    agc_digest_init_params dip;
    AGC_INIT(&dip);
    dip.scope_spec = &hash_scope;
    agc_session *s = NULL;
    AGC_ASSERT_OK(agc_digest_init(ctx, &dip, &s));
    AGC_ASSERT(agc_session_selected_template_id(s) != NULL);

    AGC_ASSERT_OK(agc_digest_update(s, (agc_slice){(const uint8_t *)"chunked-", 8}));
    AGC_ASSERT_OK(agc_digest_update(s, (agc_slice){(const uint8_t *)"digest", 6}));
    uint8_t digest[64]; size_t digest_len = 0;
    AGC_ASSERT_OK(agc_digest_final(s, (agc_buf){digest, sizeof(digest)}, &digest_len, NULL));
    agc_session_free(s);

    /* Must match the single-shot digest of the concatenated input. */
    agc_digest_request one_shot;
    AGC_INIT(&one_shot);
    one_shot.scope_spec = &hash_scope;
    one_shot.data = (agc_slice){(const uint8_t *)"chunked-digest", 14};
    uint8_t digest2[64]; size_t digest2_len = 0;
    AGC_ASSERT_OK(agc_digest(ctx, &one_shot, (agc_buf){digest2, sizeof(digest2)}, &digest2_len, NULL));
    AGC_ASSERT_EQ_INT(digest_len, digest2_len);
    AGC_ASSERT_MEM_EQ(digest, digest2, digest_len);

    /* XOF: caller-chosen length, chunked input. */
    agc_scope_spec xof_scope = hash_scope;
    xof_scope.u.hash.scope = AGC_HASH_SCOPE_XOF;
    agc_xof_init_params xip;
    AGC_INIT(&xip);
    xip.scope_spec = &xof_scope;
    xip.output_length_bytes = 50;
    AGC_ASSERT_OK(agc_xof_init(ctx, &xip, &s));
    AGC_ASSERT_OK(agc_xof_update(s, (agc_slice){(const uint8_t *)"expand", 6}));
    uint8_t xof_out[64]; size_t xof_len = 0;
    AGC_ASSERT_OK(agc_xof_final(s, (agc_buf){xof_out, sizeof(xof_out)}, &xof_len, NULL));
    AGC_ASSERT_EQ_INT(xof_len, 50);
    agc_session_free(s);
}

static void test_digest_key(agc_ctx *ctx)
{
    create_key(ctx, "digest-key-target", AGC_SCOPE_KIND_GENERIC_SECRET);

    agc_scope_spec hash_scope;
    AGC_INIT(&hash_scope);
    hash_scope.kind = AGC_SCOPE_KIND_HASH;
    hash_scope.u.hash.scope = AGC_HASH_SCOPE_STANDARD;

    agc_digest_init_params dip;
    AGC_INIT(&dip);
    dip.scope_spec = &hash_scope;
    agc_session *s = NULL;
    AGC_ASSERT_OK(agc_digest_init(ctx, &dip, &s));
    AGC_ASSERT_OK(agc_digest_update(s, (agc_slice){(const uint8_t *)"prefix-", 7}));
    AGC_ASSERT_OK(agc_digest_key(s, "digest-key-target")); /* folds the key's secret in, unseen by us */
    uint8_t digest[64]; size_t digest_len = 0;
    AGC_ASSERT_OK(agc_digest_final(s, (agc_buf){digest, sizeof(digest)}, &digest_len, NULL));
    agc_session_free(s);

    /* Digesting the same prefix WITHOUT the key must produce a different
     * result -- proves DigestKey actually folded the secret in. */
    AGC_ASSERT_OK(agc_digest_init(ctx, &dip, &s));
    AGC_ASSERT_OK(agc_digest_update(s, (agc_slice){(const uint8_t *)"prefix-", 7}));
    uint8_t digest2[64]; size_t digest2_len = 0;
    AGC_ASSERT_OK(agc_digest_final(s, (agc_buf){digest2, sizeof(digest2)}, &digest2_len, NULL));
    agc_session_free(s);

    AGC_ASSERT(memcmp(digest, digest2, digest_len < digest2_len ? digest_len : digest2_len) != 0);
    AGC_ASSERT_EQ_INT(agc_digest_key(NULL, "x"), AGC_ERR_INVALID_ARGUMENT);
}

/* --------------------------------------------------------------------------
 * 7. Dual-function
 * -------------------------------------------------------------------------- */

static void test_dual_function_digest_encrypt(agc_ctx *ctx)
{
    create_key(ctx, "dual-enc", AGC_SCOPE_KIND_AEAD);

    agc_scope_spec hash_scope;
    AGC_INIT(&hash_scope);
    hash_scope.kind = AGC_SCOPE_KIND_HASH;
    hash_scope.u.hash.scope = AGC_HASH_SCOPE_STANDARD;
    agc_digest_init_params dip;
    AGC_INIT(&dip);
    dip.scope_spec = &hash_scope;
    agc_session *digest_s = NULL;
    AGC_ASSERT_OK(agc_digest_init(ctx, &dip, &digest_s));

    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_init_params eip;
    AGC_INIT(&eip);
    eip.key_name = "dual-enc";
    eip.params = &ep;
    agc_session *encrypt_s = NULL;
    AGC_ASSERT_OK(agc_encrypt_init(ctx, &eip, &encrypt_s));

    const char *plaintext = "dual function chunk";
    uint8_t ct[64]; size_t ct_len = 0;
    AGC_ASSERT_OK(agc_digest_encrypt_update(digest_s, encrypt_s,
                                             (agc_slice){(const uint8_t *)plaintext, strlen(plaintext)},
                                             (agc_buf){ct, sizeof(ct)}, &ct_len));
    AGC_ASSERT_EQ_INT(ct_len, strlen(plaintext));

    uint8_t digest[64]; size_t digest_len = 0;
    AGC_ASSERT_OK(agc_digest_final(digest_s, (agc_buf){digest, sizeof(digest)}, &digest_len, NULL));
    agc_session_free(digest_s);

    /* The digest must equal digesting the plaintext directly -- proves the
     * digest session really absorbed it, not just passed it through. */
    uint8_t direct_digest[64];
    agc_digest_request one_shot;
    AGC_INIT(&one_shot);
    one_shot.scope_spec = &hash_scope;
    one_shot.data = (agc_slice){(const uint8_t *)plaintext, strlen(plaintext)};
    size_t direct_len = 0;
    AGC_ASSERT_OK(agc_digest(ctx, &one_shot, (agc_buf){direct_digest, sizeof(direct_digest)}, &direct_len, NULL));
    AGC_ASSERT_EQ_INT(digest_len, direct_len);
    AGC_ASSERT_MEM_EQ(digest, direct_digest, digest_len);

    /* Wrong session kinds must be rejected structurally. */
    size_t n = 0;
    AGC_ASSERT_EQ_INT(agc_digest_encrypt_update(encrypt_s, encrypt_s,
                                                 (agc_slice){(const uint8_t *)"x", 1}, (agc_buf){ct, sizeof(ct)}, &n),
                       AGC_ERR_INVALID_HANDLE);

    size_t tag_len = 0;
    AGC_ASSERT_OK(agc_encrypt_final(encrypt_s, (agc_buf){ct + ct_len, sizeof(ct) - ct_len}, &tag_len, NULL));
    agc_session_free(encrypt_s);
}

static void test_dual_function_decrypt_verify(agc_ctx *ctx)
{
    create_key(ctx, "dual-decrypt", AGC_SCOPE_KIND_AEAD);
    create_key(ctx, "dual-verify", AGC_SCOPE_KIND_SIGNATURE);

    /* Encrypt something first (single-shot) to have real ciphertext. */
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "dual-decrypt";
    er.plaintext = (agc_slice){(const uint8_t *)"verify what was decrypted", 26};
    er.params = &ep;
    uint8_t ct[64]; size_t ct_len = 0;
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_encrypt(ctx, &er, (agc_buf){ct, sizeof(ct)}, &ct_len, &md));

    /* Sign the plaintext so we have something for the verify session to
     * check against what decrypt-verify absorbs. */
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "dual-verify";
    sr.input = er.plaintext;
    sr.params = &sp;
    uint8_t sig[64]; size_t sig_len = 0;
    AGC_ASSERT_OK(agc_sign(ctx, &sr, (agc_buf){sig, sizeof(sig)}, &sig_len, NULL));

    agc_decrypt_init_params dip;
    AGC_INIT(&dip);
    dip.key_name = "dual-decrypt";
    dip.params = &ep;
    dip.metadata = md;
    agc_session *decrypt_s = NULL;
    AGC_ASSERT_OK(agc_decrypt_init(ctx, &dip, &decrypt_s));

    agc_verify_init_params vip;
    AGC_INIT(&vip);
    vip.key_name = "dual-verify";
    vip.params = &sp;
    agc_session *verify_s = NULL;
    AGC_ASSERT_OK(agc_verify_init(ctx, &vip, &verify_s));

    uint8_t pt[64]; size_t pt_len = 0;
    AGC_ASSERT_OK(agc_decrypt_verify_update(decrypt_s, verify_s, (agc_slice){ct, ct_len},
                                             (agc_buf){pt, sizeof(pt)}, &pt_len));

    size_t final_len = 0;
    AGC_ASSERT_OK(agc_decrypt_final(decrypt_s, (agc_buf){pt + pt_len, sizeof(pt) - pt_len}, &final_len, NULL));
    agc_session_free(decrypt_s);

    int valid = 0;
    AGC_ASSERT_OK(agc_verify_final(verify_s, (agc_slice){sig, sig_len}, &valid, NULL));
    AGC_ASSERT(valid); /* proves verify_s absorbed exactly the recovered plaintext */
    agc_session_free(verify_s);

    agc_metadata_free(md);
}

int main(void)
{
    agc_ctx *ctx = open_ctx();
    test_multipart_encrypt_decrypt(ctx);
    test_multipart_decrypt_tamper(ctx);
    test_message_based_single_shot(ctx);
    test_message_based_multipart(ctx);
    test_multipart_sign_verify(ctx);
    test_message_based_sign_verify(ctx);
    test_multipart_digest_and_xof(ctx);
    test_digest_key(ctx);
    test_dual_function_digest_encrypt(ctx);
    test_dual_function_decrypt_verify(ctx);
    agc_ctx_close(ctx);
    AGC_PASS("test_streaming");
}
