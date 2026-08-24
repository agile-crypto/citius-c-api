/* SPDX-License-Identifier: Apache-2.0
 *
 * stub_crypto.h — deterministic, dependency-free primitives backing
 * CryptoService (commit 8) and StreamingCryptoService (commit 9).
 *
 * ============================================================================
 * NOT CRYPTOGRAPHICALLY SECURE. Do not use for anything but exercising this
 * API's shapes, ownership rules, and round-trips. There is no key schedule,
 * no diffusion, no resistance to related-key or chosen-plaintext attacks --
 * an attacker who sees one ciphertext can trivially recover the keystream
 * and decrypt every other message encrypted under the same key and nonce.
 * ============================================================================
 *
 * What IS real: entropy (agc__stub_random(), src/stub/stub_random.c, backed
 * by the OS CSPRNG) and the API contract every function here upholds --
 * genuine tamper detection (a flipped ciphertext byte really does fail
 * authentication), genuine round-trips (decrypt(encrypt(x)) really does
 * equal x), genuine constant-time comparison on the verify path. Wiring a
 * real provider (OpenSSL, PKCS#11) behind the same src/services entry
 * points is out of scope for this reconciliation -- see README.md.
 */
#ifndef AGC_STUB_CRYPTO_H
#define AGC_STUB_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AGC_STUB_TAG_LEN    16
#define AGC_STUB_NONCE_LEN  12
#define AGC_STUB_DIGEST_LEN 32
#define AGC_STUB_SIG_LEN    32
#define AGC_STUB_MAC_LEN    32

/* Keyed pseudorandom expansion: deterministic given (key, nonce_or_context),
 * used both as an XOR keystream (AEAD) and as an arbitrary-length digest/XOF
 * expansion. Every output byte depends on every input byte. */
void agc__stub_expand(const uint8_t *key, size_t key_len,
                       const uint8_t *context, size_t context_len,
                       uint8_t *out, size_t out_len);

/* AEAD-shaped encrypt: ciphertext = plaintext XOR keystream(key, nonce);
 * tag = expand(key, nonce || aad || ciphertext)[0:AGC_STUB_TAG_LEN]. Nonce is
 * freshly generated (agc__stub_random) and returned to the caller -- it is
 * NOT an input, matching every AEAD scope in the real proto where the nonce
 * is system-generated. `out` and `plaintext` may overlap (in-place XOR). */
void agc__stub_aead_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out_ciphertext, uint8_t *out_tag);

/* Returns 1 (authentic) or 0 (tampered/wrong key/wrong nonce/wrong aad),
 * decided by a constant-time tag comparison. Plaintext is written to `out`
 * regardless (XOR is its own inverse) but the CALLER (src/services/crypto.c)
 * must discard it on a 0 return -- mirroring the real AEAD contract that
 * nothing is released on authentication failure. */
int agc__stub_aead_decrypt(const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *tag,
                            uint8_t *out_plaintext);

/* Sign-shaped: signature = expand(key, "sign" || domain_context || message)
 * truncated/extended to AGC_STUB_SIG_LEN. Deterministic (no randomness),
 * unlike a real ECDSA signature -- irrelevant for structural round-trip
 * testing and avoids needing a DRBG-backed nonce per signature here. */
void agc__stub_sign(const uint8_t *key, size_t key_len,
                     const uint8_t *context, size_t context_len,
                     const uint8_t *message, size_t message_len,
                     uint8_t out_signature[AGC_STUB_SIG_LEN]);

int agc__stub_verify(const uint8_t *key, size_t key_len,
                      const uint8_t *context, size_t context_len,
                      const uint8_t *message, size_t message_len,
                      const uint8_t *signature, size_t signature_len);

/* MAC-shaped: same construction as sign, kept as a separate name so the two
 * families can diverge later (e.g. if a customization string is added)
 * without an implicit coupling. */
void agc__stub_mac(const uint8_t *key, size_t key_len,
                    const uint8_t *customization, size_t customization_len,
                    const uint8_t *message, size_t message_len,
                    uint8_t out_mac[AGC_STUB_MAC_LEN]);

int agc__stub_mac_verify(const uint8_t *key, size_t key_len,
                          const uint8_t *customization, size_t customization_len,
                          const uint8_t *message, size_t message_len,
                          const uint8_t *mac, size_t mac_len);

/* Keyless digest: digest = expand(NULL key, data), fixed AGC_STUB_DIGEST_LEN. */
void agc__stub_digest(const uint8_t *data, size_t data_len, uint8_t out[AGC_STUB_DIGEST_LEN]);

/* XOF: same construction, caller-chosen output length. */
void agc__stub_xof(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/* --------------------------------------------------------------------------
 * Streaming support (StreamingCryptoService, commit 9)
 *
 * The keystream used by agc__stub_aead_encrypt/decrypt is a pure function of
 * (key, nonce, absolute byte offset from the start of the message) -- see
 * agc__stub_expand's per-byte counter construction. That means a session can
 * emit real, correct ciphertext for each Update chunk as it arrives, simply
 * by tracking a running offset, with no need to buffer plaintext across
 * calls for the ENCRYPTION half. Only the authentication tag needs the
 * complete message, so the session still buffers ciphertext bytes purely
 * for the Final tag computation -- exactly mirroring the proto's own
 * "plaintext released by Update/Next before Final is UNAUTHENTICATED" rule,
 * which is what this two-part design naturally produces rather than
 * something bolted on to match the spec after the fact.
 * -------------------------------------------------------------------------- */

/* Encrypts `len` bytes starting at absolute message offset `offset`,
 * writing ciphertext to `out` (`in`/`out` may alias for in-place XOR). Does
 * NOT touch the tag -- call agc__stub_tag_from_accum() once, at Final, over
 * the full accumulated (nonce || aad || ciphertext). */
void agc__stub_aead_encrypt_at(const uint8_t *key, size_t key_len,
                                const uint8_t *nonce, size_t nonce_len,
                                uint64_t offset,
                                const uint8_t *in, size_t len, uint8_t *out);

/* Same construction as agc__stub_aead_encrypt_at (XOR is its own inverse);
 * named separately so call sites read correctly. */
void agc__stub_aead_decrypt_at(const uint8_t *key, size_t key_len,
                                const uint8_t *nonce, size_t nonce_len,
                                uint64_t offset,
                                const uint8_t *in, size_t len, uint8_t *out);

/* tag = expand(key, nonce || aad || full_ciphertext)[0:AGC_STUB_TAG_LEN],
 * exactly the single-shot tag construction, exposed for a session's Final
 * to call once the complete ciphertext has been assembled from repeated
 * agc__stub_aead_*_at() calls. */
void agc__stub_tag_from_parts(const uint8_t *key, size_t key_len,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t out_tag[AGC_STUB_TAG_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* AGC_STUB_CRYPTO_H */
