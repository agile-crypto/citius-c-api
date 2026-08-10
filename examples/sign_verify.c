/**
 * @file sign_verify.c
 * @brief Example: Sign a message and verify the signature.
 *
 * Demonstrates:
 *   1. Streaming sign (Init → Update → Final) for large or multi-part messages
 *   2. Single-shot citius_digest_sign() for a pre-computed digest with an
 *      explicit hash algorithm binding (caller is responsible for hashing)
 *   3. citius_verify_final() to confirm the streamed signature
 *
 * Build (from citius-c-api root):
 *   cmake -S . -B build && cmake --build build
 *   ./build/examples/sign_verify
 */

#include <citius/citius.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(rv) do {                                                       \
    CITIUS_RV _rv = (rv);                                                    \
    if (_rv != CITIUS_OK) {                                                  \
        fprintf(stderr, "FATAL at %s:%d — %s\n",                            \
                __FILE__, __LINE__, citius_rv_to_string(_rv));               \
        exit(EXIT_FAILURE);                                                  \
    }                                                                        \
} while (0)

/* ---------------------------------------------------------------------------
 * Part 1: Streaming sign of a message supplied in two chunks
 * ------------------------------------------------------------------------- */
static void example_streaming_sign(const char *signing_key)
{
    puts("\n--- Streaming sign ---");

    /* Init — classical scheme, no domain-context params needed */
    citius_sign_init_request_t init_req;
    memset(&init_req, 0, sizeof(init_req));
    init_req.key_name          = signing_key;
    init_req.operation_id      = "sign-op-1";
    init_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_sign_init_response_t init_resp;
    memset(&init_resp, 0, sizeof(init_resp));
    citius_op_ctx_t ctx = NULL;
    CHECK(citius_sign_init(&init_req, &init_resp, &ctx));
    printf("Sign context initialised\n");

    /* Update — feed data in two chunks */
    const char *part1 = "Hello, ";
    const char *part2 = "Citius!";

    citius_sign_update_request_t upd_req;
    citius_sign_update_response_t upd_resp;

    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id           = "sign-op-1";
    upd_req.data_chunk.data        = (const uint8_t *)part1;
    upd_req.data_chunk.length      = strlen(part1);
    memset(&upd_resp, 0, sizeof(upd_resp));
    CHECK(citius_sign_update(ctx, &upd_req, &upd_resp));

    memset(&upd_req, 0, sizeof(upd_req));
    upd_req.operation_id           = "sign-op-1";
    upd_req.data_chunk.data        = (const uint8_t *)part2;
    upd_req.data_chunk.length      = strlen(part2);
    memset(&upd_resp, 0, sizeof(upd_resp));
    CHECK(citius_sign_update(ctx, &upd_req, &upd_resp));

    /* Final — produce signature */
    citius_sign_final_request_t final_req;
    memset(&final_req, 0, sizeof(final_req));
    final_req.operation_id = "sign-op-1";

    uint8_t sig_buf[128];
    citius_sign_final_response_t final_resp;
    memset(&final_resp, 0, sizeof(final_resp));
    final_resp.signature.data     = sig_buf;
    final_resp.signature.capacity = sizeof(sig_buf);
    CHECK(citius_sign_final(ctx, &final_req, &final_resp));
    printf("Signature produced: %zu bytes\n", final_resp.signature.length);

    CHECK(citius_op_ctx_free(ctx));

    /* Streaming verify */
    citius_verify_init_request_t vinit_req;
    memset(&vinit_req, 0, sizeof(vinit_req));
    vinit_req.key_name          = signing_key;
    vinit_req.operation_id      = "verify-op-1";
    vinit_req.scope_params.type = CITIUS_SIGN_PARAMS_NONE;

    citius_verify_init_response_t vinit_resp;
    memset(&vinit_resp, 0, sizeof(vinit_resp));
    CHECK(citius_verify_init(&vinit_req, &vinit_resp, &ctx));

    citius_verify_update_request_t vupd_req;
    citius_verify_update_response_t vupd_resp;

    memset(&vupd_req, 0, sizeof(vupd_req));
    vupd_req.operation_id      = "verify-op-1";
    vupd_req.data_chunk.data   = (const uint8_t *)part1;
    vupd_req.data_chunk.length = strlen(part1);
    memset(&vupd_resp, 0, sizeof(vupd_resp));
    CHECK(citius_verify_update(ctx, &vupd_req, &vupd_resp));

    memset(&vupd_req, 0, sizeof(vupd_req));
    vupd_req.operation_id      = "verify-op-1";
    vupd_req.data_chunk.data   = (const uint8_t *)part2;
    vupd_req.data_chunk.length = strlen(part2);
    memset(&vupd_resp, 0, sizeof(vupd_resp));
    CHECK(citius_verify_update(ctx, &vupd_req, &vupd_resp));

    citius_verify_final_request_t vfinal_req;
    memset(&vfinal_req, 0, sizeof(vfinal_req));
    vfinal_req.operation_id      = "verify-op-1";
    vfinal_req.signature.data    = sig_buf;
    vfinal_req.signature.length  = final_resp.signature.length;

    citius_verify_final_response_t vfinal_resp;
    memset(&vfinal_resp, 0, sizeof(vfinal_resp));
    CHECK(citius_verify_final(ctx, &vfinal_req, &vfinal_resp));
    CHECK(citius_op_ctx_free(ctx));

    printf("Streaming sign+verify: valid=%d\n", vfinal_resp.valid);
}

/* ---------------------------------------------------------------------------
 * Part 2: Single-shot DigestSign with pre-computed digest + hash binding
 *
 * DigestSign is for callers that already hold a digest produced externally
 * (e.g. Ed25519ph, large-file pre-hashing, HSM-offloaded digest).
 * The caller supplies the raw digest bytes and declares which hash produced
 * them via hash_algorithm.  The provider enforces size consistency and
 * prevents a SHA-1 digest from masquerading as SHA-256.
 *
 * In real code you would call your crypto library here, e.g.:
 *   SHA256(message, len, digest_buf);
 * The stub accepts any digest bytes, so we use a fixed 32-byte dummy.
 * ------------------------------------------------------------------------- */
static void example_digest_sign(const char *signing_key)
{
    puts("\n--- Single-shot DigestSign (pre-computed digest) ---");

    /*
     * Simulate: digest = SHA-256("The quick brown fox jumps over the lazy dog")
     * In production this would come from a real hash call.
     * Stub ignores the actual bytes; the 32-byte length matches SHA-256.
     */
    static const uint8_t digest_buf[32] = {
        0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94,
        0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
        0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
        0x2d, 0x02, 0xef, 0xf3, 0xd8, 0x76, 0xdf, 0xe6
    };

    citius_digest_sign_request_t req;
    memset(&req, 0, sizeof(req));
    req.key_name             = signing_key;
    req.digest.data          = digest_buf;
    req.digest.length        = sizeof(digest_buf);
    req.hash_algorithm       = CITIUS_HASH_SHA2_256;
    /* scope_params left zero (NONE): provider picks default signature scope */

    uint8_t sig_buf[128];
    citius_digest_sign_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.signature.data     = sig_buf;
    resp.signature.capacity = sizeof(sig_buf);
    CHECK(citius_digest_sign(&req, &resp));
    printf("DigestSign: %zu-byte signature over %zu-byte digest\n",
           resp.signature.length, req.digest.length);

    /* Verify using DigestVerify — pass the same digest + returned signature */
    citius_digest_verify_request_t vreq;
    memset(&vreq, 0, sizeof(vreq));
    vreq.key_name            = signing_key;
    vreq.digest              = req.digest;   /* same pre-computed digest */
    vreq.signature.data      = sig_buf;
    vreq.signature.length    = resp.signature.length;
    vreq.hash_algorithm      = req.hash_algorithm;
    vreq.metadata            = resp.metadata;
    /* scope_params left zero: must match what was used at sign time */

    citius_digest_verify_response_t vresp;
    memset(&vresp, 0, sizeof(vresp));
    CHECK(citius_digest_verify(&vreq, &vresp));
    printf("DigestVerify: valid=%d\n", vresp.valid);
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(void)
{
    CHECK(citius_init());

    citius_create_key_request_t create_req;
    memset(&create_req, 0, sizeof(create_req));
    create_req.name                     = "demo-signing-key";
    create_req.policy                   = "default-policy";
    create_req.scope_spec.type          = CITIUS_SCOPE_SPEC_SIGNATURE;
    create_req.scope_spec.spec.signature.scope = SIGNATURE_SCOPE_STANDARD;

    citius_create_key_response_t create_resp;
    memset(&create_resp, 0, sizeof(create_resp));
    CHECK(citius_key_create(&create_req, &create_resp));
    const char *key = create_resp.key_metadata.key_id;
    printf("Signing key created: name = \"%s\"\n", key);

    example_streaming_sign(key);
    example_digest_sign(key);

    CHECK(citius_finalize());

    puts("\nsign_verify example: PASSED");
    return EXIT_SUCCESS;
}
