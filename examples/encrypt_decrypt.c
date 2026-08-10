/**
 * @file encrypt_decrypt.c
 * @brief Example: AEAD encrypt a message and decrypt it back.
 *
 * Demonstrates:
 *   1. citius_init() / citius_finalize()
 *   2. citius_key_create()
 *   3. citius_encrypt() with AAD — size-query then actual call
 *   4. Preserving OperationMetadata between encrypt and decrypt
 *   5. citius_decrypt() — recovering the original plaintext
 *
 * The example links against the zero-filling stub provider.  All outputs are
 * zero bytes, but the structural flow is identical to a real provider.
 *
 * Build (from citius-c-api root):
 *   cmake -S . -B build && cmake --build build
 *   ./build/examples/encrypt_decrypt
 */

#include <citius/citius.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Helper: abort on unexpected return value
 * ------------------------------------------------------------------------- */
#define CHECK(rv) do {                                                       \
    CITIUS_RV _rv = (rv);                                                    \
    if (_rv != CITIUS_OK) {                                                  \
        fprintf(stderr, "FATAL at %s:%d — %s\n",                            \
                __FILE__, __LINE__, citius_rv_to_string(_rv));               \
        exit(EXIT_FAILURE);                                                  \
    }                                                                        \
} while (0)

int main(void)
{
    /* ------------------------------------------------------------------
     * 1. Initialise the library
     * ------------------------------------------------------------------ */
    CHECK(citius_init());

    /* ------------------------------------------------------------------
     * 2. Create an encryption key
     * ------------------------------------------------------------------ */
    citius_create_key_request_t create_req;
    memset(&create_req, 0, sizeof(create_req));
    create_req.name                  = "demo-aes-key";
    create_req.policy                = "default-policy";
    create_req.scope_spec.type       = CITIUS_SCOPE_SPEC_AEAD;
    create_req.scope_spec.spec.aead.scope = AEAD_SCOPE_STANDARD;

    citius_create_key_response_t create_resp;
    memset(&create_resp, 0, sizeof(create_resp));
    CHECK(citius_key_create(&create_req, &create_resp));
    const char *key = create_resp.key_metadata.key_id;
    printf("Key created: name = \"%s\"\n", key);

    /* ------------------------------------------------------------------
     * 3. Build encrypt request: AEAD with associated data
     * ------------------------------------------------------------------ */
    const char *plaintext_str = "Hello, Citius!";
    const size_t plaintext_len = strlen(plaintext_str);
    const char *aad_str = "example-context-v1";

    citius_encrypt_request_t enc_req;
    memset(&enc_req, 0, sizeof(enc_req));
    enc_req.key_name                = key;
    enc_req.plaintext.data          = (const uint8_t *)plaintext_str;
    enc_req.plaintext.length        = plaintext_len;
    enc_req.scope_params.type       = CITIUS_ENCRYPT_PARAMS_AEAD;
    enc_req.scope_params.params.aead.aad.data   = (const uint8_t *)aad_str;
    enc_req.scope_params.params.aead.aad.length = strlen(aad_str);

    /* 4a. Size query: pass NULL data to learn required ciphertext buffer size */
    citius_encrypt_response_t enc_resp;
    memset(&enc_resp, 0, sizeof(enc_resp));
    /* enc_resp.ciphertext.data == NULL → size-query mode */
    CITIUS_RV rv = citius_encrypt(&enc_req, &enc_resp);
    if (rv != CITIUS_OK && rv != CITIUS_BUFFER_TOO_SMALL) { CHECK(rv); }
    size_t ct_size = enc_resp.ciphertext.length;
    printf("Ciphertext size required: %zu bytes\n", ct_size);

    /* 4b. Allocate ciphertext buffer and encrypt for real */
    uint8_t *ct_buf = calloc(ct_size, 1);
    if (!ct_buf) { fputs("Out of memory\n", stderr); return EXIT_FAILURE; }

    memset(&enc_resp, 0, sizeof(enc_resp));
    enc_resp.ciphertext.data     = ct_buf;
    enc_resp.ciphertext.capacity = ct_size;
    CHECK(citius_encrypt(&enc_req, &enc_resp));
    printf("Encrypted %zu bytes → %zu bytes ciphertext\n",
           plaintext_len, enc_resp.ciphertext.length);
    printf("Metadata: api_version=%s\n",
           enc_resp.metadata.api_version ? enc_resp.metadata.api_version : "(null)");

    /* ------------------------------------------------------------------
     * 4. Decrypt — pass ciphertext + stored metadata back to the provider
     * ------------------------------------------------------------------ */
    citius_decrypt_request_t dec_req;
    memset(&dec_req, 0, sizeof(dec_req));
    dec_req.key_name          = key;
    dec_req.ciphertext.data   = ct_buf;
    dec_req.ciphertext.length = enc_resp.ciphertext.length;
    dec_req.metadata          = enc_resp.metadata;   /* MUST be stored + passed back */
    dec_req.scope_params      = enc_req.scope_params;

    /* Size query for plaintext buffer */
    citius_decrypt_response_t dec_resp;
    memset(&dec_resp, 0, sizeof(dec_resp));
    rv = citius_decrypt(&dec_req, &dec_resp);
    if (rv != CITIUS_OK && rv != CITIUS_BUFFER_TOO_SMALL) { CHECK(rv); }
    size_t pt_size = dec_resp.plaintext.length;

    uint8_t *pt_buf = calloc(pt_size + 1, 1);   /* +1 for NUL terminator */
    if (!pt_buf) { fputs("Out of memory\n", stderr); free(ct_buf); return EXIT_FAILURE; }

    memset(&dec_resp, 0, sizeof(dec_resp));
    dec_resp.plaintext.data     = pt_buf;
    dec_resp.plaintext.capacity = pt_size;
    CHECK(citius_decrypt(&dec_req, &dec_resp));
    printf("Decrypted %zu bytes → \"%.*s\"\n",
           dec_resp.plaintext.length,
           (int)dec_resp.plaintext.length, (const char *)pt_buf);

    /* ------------------------------------------------------------------
     * 5. Tear down
     * ------------------------------------------------------------------ */
    free(ct_buf);
    free(pt_buf);

    CHECK(citius_finalize());

    puts("encrypt_decrypt example: PASSED");
    return EXIT_SUCCESS;
}
