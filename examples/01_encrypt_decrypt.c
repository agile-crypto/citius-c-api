/* SPDX-License-Identifier: Apache-2.0
 *
 * The smallest complete round-trip through this API: open a context,
 * create a key by INTENT (a scope specification, not an algorithm name),
 * encrypt, then decrypt using the metadata the encrypt call produced.
 *
 * Run: ./01_encrypt_decrypt
 */
#include "example_helpers.h"
#include <string.h>

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_EXAMPLE_CHECK(agc_ctx_open(&cfg, &ctx));

    /* Intent, not algorithm: "authenticated encryption, default strength".
     * Policy (or, absent one, the stub's own catalog) picks the concrete
     * template -- see agc_key_info_template_id() below for what it chose. */
    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = AGC_SCOPE_KIND_AEAD;
    scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;

    agc_create_key_params key_params;
    AGC_INIT(&key_params);
    key_params.name = "example-aead-key";
    key_params.policy = "default";
    key_params.scope_spec = &scope;

    agc_key_info *key = NULL;
    AGC_EXAMPLE_CHECK(agc_create_key(ctx, &key_params, &key, NULL));
    printf("created key %s (template %s)\n", agc_key_info_name(key), agc_key_info_template_id(key));
    agc_key_info_free(key);

    /* Encrypt. */
    agc_encrypt_params enc_params;
    AGC_INIT(&enc_params);
    enc_params.kind = AGC_ENCRYPT_PARAMS_AEAD;
    enc_params.u.aead.aad = (agc_slice){(const uint8_t *)"example-aad", 11};

    const char *plaintext = "the quick brown fox jumps over the lazy dog";
    agc_encrypt_request enc_req;
    AGC_INIT(&enc_req);
    enc_req.key_name = "example-aead-key";
    enc_req.plaintext = (agc_slice){(const uint8_t *)plaintext, strlen(plaintext)};
    enc_req.params = &enc_params;

    size_t ct_len_needed = 0;
    AGC_EXAMPLE_CHECK(agc_encrypt(ctx, &enc_req, (agc_buf){0}, &ct_len_needed, NULL));
    uint8_t *ciphertext = malloc(ct_len_needed);
    size_t ct_len = 0;
    agc_metadata *md = NULL;
    AGC_EXAMPLE_CHECK(agc_encrypt(ctx, &enc_req, (agc_buf){ciphertext, ct_len_needed}, &ct_len, &md));
    printf("encrypted %zu bytes of plaintext into %zu bytes of ciphertext\n", strlen(plaintext), ct_len);

    /* The metadata from encrypt is not optional: it carries the
     * system-generated nonce. A real application persists agc_metadata's
     * encoded bytes (see agc_metadata_encode() in agc_core.h) alongside the
     * ciphertext; this example keeps the in-memory handle since it decrypts
     * in the same process. */

    /* Decrypt, using the SAME aad -- AEAD authenticates it without
     * encrypting it, so both sides must supply the identical bytes. */
    agc_decrypt_request dec_req;
    AGC_INIT(&dec_req);
    dec_req.key_name = "example-aead-key";
    dec_req.ciphertext = (agc_slice){ciphertext, ct_len};
    dec_req.metadata = md;
    dec_req.params = &enc_params;

    size_t pt_len_needed = 0;
    AGC_EXAMPLE_CHECK(agc_decrypt(ctx, &dec_req, (agc_buf){0}, &pt_len_needed, NULL));
    uint8_t *decrypted = malloc(pt_len_needed);
    size_t pt_len = 0;
    AGC_EXAMPLE_CHECK(agc_decrypt(ctx, &dec_req, (agc_buf){decrypted, pt_len_needed}, &pt_len, NULL));

    if (pt_len != strlen(plaintext) || memcmp(decrypted, plaintext, pt_len) != 0) {
        fprintf(stderr, "round-trip mismatch!\n");
        return 1;
    }
    printf("decrypted successfully: \"%.*s\"\n", (int)pt_len, decrypted);

    /* Tamper with one ciphertext byte and confirm decryption fails closed. */
    ciphertext[0] ^= 0xFF;
    dec_req.ciphertext = (agc_slice){ciphertext, ct_len};
    agc_rc rc = agc_decrypt(ctx, &dec_req, (agc_buf){decrypted, pt_len_needed}, &pt_len, NULL);
    printf("tampered ciphertext correctly rejected: %s\n", agc_rc_name(rc));

    free(ciphertext);
    free(decrypted);
    agc_metadata_free(md);
    agc_ctx_close(ctx);
    return 0;
}
