/* SPDX-License-Identifier: Apache-2.0
 *
 * Streaming (multi-part) sign/verify: sign a message too large -- or too
 * awkward, e.g. read incrementally off a socket -- to hold in memory as one
 * buffer, by feeding it through a session in chunks (Init/Update.../Final)
 * instead of one single-shot agc_sign() call.
 *
 * Run: ./02_streaming_sign
 */
#include "example_helpers.h"
#include <string.h>

static const char *k_chunks[] = {
    "In the beginning ", "the C API mimicked ", "the wire format exactly, ",
    "line for line, ", "field for field.",
};
#define K_CHUNK_COUNT (sizeof(k_chunks) / sizeof(k_chunks[0]))

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_EXAMPLE_CHECK(agc_ctx_open(&cfg, &ctx));

    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = AGC_SCOPE_KIND_SIGNATURE;
    scope.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;

    agc_create_key_params key_params;
    AGC_INIT(&key_params);
    key_params.name = "example-signing-key";
    key_params.policy = "default";
    key_params.scope_spec = &scope;
    agc_key_info *key = NULL;
    AGC_EXAMPLE_CHECK(agc_create_key(ctx, &key_params, &key, NULL));
    agc_key_info_free(key);

    agc_sign_params sign_params;
    AGC_INIT(&sign_params);
    sign_params.kind = AGC_SIGN_PARAMS_NO_CONTEXT;

    /* --- Sign, one chunk at a time --- */
    agc_sign_init_params sign_init;
    AGC_INIT(&sign_init);
    sign_init.key_name = "example-signing-key";
    sign_init.params = &sign_params;
    sign_init.operation_id = "example-sign-op-1"; /* caller-chosen, per D10 */

    agc_session *sign_session = NULL;
    AGC_EXAMPLE_CHECK(agc_sign_init(ctx, &sign_init, &sign_session));
    printf("started signing session %s\n", agc_session_id(sign_session));

    for (size_t i = 0; i < K_CHUNK_COUNT; i++) {
        AGC_EXAMPLE_CHECK(agc_sign_update(sign_session, (agc_slice){(const uint8_t *)k_chunks[i], strlen(k_chunks[i])}));
    }

    size_t sig_len_needed = 0;
    AGC_EXAMPLE_CHECK(agc_sign_final(sign_session, (agc_buf){0}, &sig_len_needed, NULL));
    uint8_t *signature = malloc(sig_len_needed);
    size_t sig_len = 0;
    AGC_EXAMPLE_CHECK(agc_sign_final(sign_session, (agc_buf){signature, sig_len_needed}, &sig_len, NULL));
    agc_session_free(sign_session);
    printf("produced a %zu-byte signature over %zu chunks\n", sig_len, K_CHUNK_COUNT);

    /* --- Verify, fed back in DIFFERENT-sized chunks: streaming primitives
     * must not care where the chunk boundaries fall, only the total bytes. --- */
    agc_verify_init_params verify_init;
    AGC_INIT(&verify_init);
    verify_init.key_name = "example-signing-key";
    verify_init.params = &sign_params;

    agc_session *verify_session = NULL;
    AGC_EXAMPLE_CHECK(agc_verify_init(ctx, &verify_init, &verify_session));

    char whole_message[512] = {0};
    for (size_t i = 0; i < K_CHUNK_COUNT; i++) strcat(whole_message, k_chunks[i]);
    size_t total_len = strlen(whole_message);
    size_t offset = 0, step = 17; /* deliberately does not divide the chunk boundaries above */
    while (offset < total_len) {
        size_t n = step < (total_len - offset) ? step : (total_len - offset);
        AGC_EXAMPLE_CHECK(agc_verify_update(verify_session, (agc_slice){(const uint8_t *)whole_message + offset, n}));
        offset += n;
    }

    int valid = 0;
    AGC_EXAMPLE_CHECK(agc_verify_final(verify_session, (agc_slice){signature, sig_len}, &valid, NULL));
    agc_session_free(verify_session);
    printf("signature verified across differently-chunked input: %s\n", valid ? "valid" : "INVALID");

    free(signature);
    agc_ctx_close(ctx);
    return valid ? 0 : 1;
}
