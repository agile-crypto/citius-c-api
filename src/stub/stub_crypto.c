/* SPDX-License-Identifier: Apache-2.0 */
#include "stub_crypto.h"

#include "agc_core.h" /* agc_ct_equal */

#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a(const uint8_t *data, size_t len, uint64_t seed)
{
    uint64_t h = seed ^ 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

void agc__stub_expand(const uint8_t *key, size_t key_len,
                       const uint8_t *context, size_t context_len,
                       uint8_t *out, size_t out_len)
{
    uint64_t seed = fnv1a(key, key_len, 0x9E3779B97F4A7C15ULL);
    seed = fnv1a(context, context_len, seed);
    for (size_t i = 0; i < out_len; i++) {
        uint8_t counter_bytes[8];
        for (int b = 0; b < 8; b++) counter_bytes[b] = (uint8_t)(i >> (8 * b));
        uint64_t block = fnv1a(counter_bytes, sizeof(counter_bytes), seed);
        out[i] = (uint8_t)(block ^ (block >> 32) ^ (block >> 16) ^ (block >> 8));
    }
}

/* Keystream byte at absolute position `pos`, seeded from (key, nonce). This
 * is the primitive both the one-shot (commit 8) and streaming (commit 9)
 * AEAD paths are built from: a pure function of (key, nonce, position), so
 * a session can compute any chunk's ciphertext independently of any other
 * chunk having been processed yet. */
static uint8_t keystream_byte_at(uint64_t seed, uint64_t pos)
{
    uint8_t counter_bytes[8];
    for (int b = 0; b < 8; b++) counter_bytes[b] = (uint8_t)(pos >> (8 * b));
    uint64_t block = fnv1a(counter_bytes, sizeof(counter_bytes), seed);
    return (uint8_t)(block ^ (block >> 32) ^ (block >> 16) ^ (block >> 8));
}

static uint64_t nonce_seed(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len)
{
    uint64_t seed = fnv1a(key, key_len, 0x9E3779B97F4A7C15ULL);
    return fnv1a(nonce, nonce_len, seed);
}

static void xor_at(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len,
                    uint64_t offset, const uint8_t *in, size_t len, uint8_t *out)
{
    uint64_t seed = nonce_seed(key, key_len, nonce, nonce_len);
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(in[i] ^ keystream_byte_at(seed, offset + i));
    }
}

void agc__stub_aead_encrypt_at(const uint8_t *key, size_t key_len,
                                const uint8_t *nonce, size_t nonce_len,
                                uint64_t offset, const uint8_t *in, size_t len, uint8_t *out)
{
    xor_at(key, key_len, nonce, nonce_len, offset, in, len, out);
}

void agc__stub_aead_decrypt_at(const uint8_t *key, size_t key_len,
                                const uint8_t *nonce, size_t nonce_len,
                                uint64_t offset, const uint8_t *in, size_t len, uint8_t *out)
{
    xor_at(key, key_len, nonce, nonce_len, offset, in, len, out);
}

void agc__stub_tag_from_parts(const uint8_t *key, size_t key_len,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t out_tag[AGC_STUB_TAG_LEN])
{
    size_t ctx_len = nonce_len + aad_len + ciphertext_len;
    uint8_t *ctx_buf = ctx_len ? malloc(ctx_len) : NULL;
    if (ctx_len && !ctx_buf) { memset(out_tag, 0, AGC_STUB_TAG_LEN); return; }
    size_t off = 0;
    if (nonce_len) { memcpy(ctx_buf + off, nonce, nonce_len); off += nonce_len; }
    if (aad_len) { memcpy(ctx_buf + off, aad, aad_len); off += aad_len; }
    if (ciphertext_len) { memcpy(ctx_buf + off, ciphertext, ciphertext_len); off += ciphertext_len; }
    agc__stub_expand(key, key_len, ctx_buf, ctx_len, out_tag, AGC_STUB_TAG_LEN);
    free(ctx_buf);
}

void agc__stub_aead_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out_ciphertext, uint8_t *out_tag)
{
    agc__stub_aead_encrypt_at(key, key_len, nonce, nonce_len, 0, plaintext, plaintext_len, out_ciphertext);
    agc__stub_tag_from_parts(key, key_len, nonce, nonce_len, aad, aad_len, out_ciphertext, plaintext_len, out_tag);
}

int agc__stub_aead_decrypt(const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *tag,
                            uint8_t *out_plaintext)
{
    uint8_t expected_tag[AGC_STUB_TAG_LEN];
    agc__stub_tag_from_parts(key, key_len, nonce, nonce_len, aad, aad_len, ciphertext, ciphertext_len, expected_tag);
    int ok = agc_ct_equal(expected_tag, tag, AGC_STUB_TAG_LEN);
    agc__stub_aead_decrypt_at(key, key_len, nonce, nonce_len, 0, ciphertext, ciphertext_len, out_plaintext);
    return ok;
}

void agc__stub_sign(const uint8_t *key, size_t key_len,
                     const uint8_t *context, size_t context_len,
                     const uint8_t *message, size_t message_len,
                     uint8_t out_signature[AGC_STUB_SIG_LEN])
{
    size_t ctx_len = 4 /* "sign" */ + context_len + message_len;
    uint8_t *buf = malloc(ctx_len);
    if (!buf) { memset(out_signature, 0, AGC_STUB_SIG_LEN); return; }
    size_t off = 0;
    memcpy(buf, "sign", 4); off += 4;
    if (context_len) { memcpy(buf + off, context, context_len); off += context_len; }
    if (message_len) { memcpy(buf + off, message, message_len); off += message_len; }
    agc__stub_expand(key, key_len, buf, ctx_len, out_signature, AGC_STUB_SIG_LEN);
    free(buf);
}

int agc__stub_verify(const uint8_t *key, size_t key_len,
                      const uint8_t *context, size_t context_len,
                      const uint8_t *message, size_t message_len,
                      const uint8_t *signature, size_t signature_len)
{
    if (signature_len != AGC_STUB_SIG_LEN) return 0;
    uint8_t expected[AGC_STUB_SIG_LEN];
    agc__stub_sign(key, key_len, context, context_len, message, message_len, expected);
    return agc_ct_equal(expected, signature, AGC_STUB_SIG_LEN);
}

void agc__stub_mac(const uint8_t *key, size_t key_len,
                    const uint8_t *customization, size_t customization_len,
                    const uint8_t *message, size_t message_len,
                    uint8_t out_mac[AGC_STUB_MAC_LEN])
{
    size_t ctx_len = 3 /* "mac" */ + customization_len + message_len;
    uint8_t *buf = malloc(ctx_len);
    if (!buf) { memset(out_mac, 0, AGC_STUB_MAC_LEN); return; }
    size_t off = 0;
    memcpy(buf, "mac", 3); off += 3;
    if (customization_len) { memcpy(buf + off, customization, customization_len); off += customization_len; }
    if (message_len) { memcpy(buf + off, message, message_len); off += message_len; }
    agc__stub_expand(key, key_len, buf, ctx_len, out_mac, AGC_STUB_MAC_LEN);
    free(buf);
}

int agc__stub_mac_verify(const uint8_t *key, size_t key_len,
                          const uint8_t *customization, size_t customization_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *mac, size_t mac_len)
{
    if (mac_len != AGC_STUB_MAC_LEN) return 0;
    uint8_t expected[AGC_STUB_MAC_LEN];
    agc__stub_mac(key, key_len, customization, customization_len, message, message_len, expected);
    return agc_ct_equal(expected, mac, AGC_STUB_MAC_LEN);
}

void agc__stub_digest(const uint8_t *data, size_t data_len, uint8_t out[AGC_STUB_DIGEST_LEN])
{
    agc__stub_expand(NULL, 0, data, data_len, out, AGC_STUB_DIGEST_LEN);
}

void agc__stub_xof(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
{
    agc__stub_expand(NULL, 0, data, data_len, out, out_len);
}
