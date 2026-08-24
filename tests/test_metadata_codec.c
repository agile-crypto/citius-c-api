/* SPDX-License-Identifier: Apache-2.0
 *
 * Whitebox test (commit 6): validates the hand-written OperationMetadata
 * codec (src/wire/metadata_codec.c, src/wire/protobuf_wire.c) two ways:
 *
 *  1. DECODE direction: tests/golden/operation_metadata_vectors.json bytes
 *     were produced by the REAL protobuf library (Python, against the
 *     pinned descriptor) in gen_metadata_vectors.py, not by this codec.
 *     Decoding them here and checking field values proves the decoder is
 *     wire-compatible with a real implementation, not merely
 *     self-consistent.
 *
 *  2. ENCODE direction: constructs equivalent metadata via the internal
 *     agc__metadata_create() (available here because this links against
 *     agilecrypto_whitebox, not the public shared library -- see the
 *     whitebox target comment in the top-level CMakeLists.txt), encodes it,
 *     and writes the bytes to c_encoded_vectors/*.bin. A separate CTest
 *     entry (verify_c_encoded, golden/verify_c_encoded.py) decodes those
 *     files with the real protobuf library afterward and checks the field
 *     values match, proving the ENCODER is wire-compatible too.
 */
#include "agilecrypto.h"
#include "agc_internal.h"
#include "test_helpers.h"

#include <sys/stat.h>
#include <sys/types.h>

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t n = strlen(hex) / 2;
    AGC_ASSERT(n <= out_cap);
    for (size_t i = 0; i < n; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
    return n;
}

static void write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    AGC_ASSERT(f != NULL);
    if (len) AGC_ASSERT(fwrite(data, 1, len, f) == len);
    fclose(f);
}

/* --------------------------------------------------------------------------
 * 1. Decode direction: real-protobuf-produced bytes -> our decoder
 * -------------------------------------------------------------------------- */

static void decode_check_aead(void)
{
    /* {"aead": {"bytes": "080312170a037261775a100a0c0102030405060708090a0b0c10101a03312e30220e0a0674656e616e74120461636d65", ...}} */
    uint8_t raw[256];
    size_t n = hex_decode(
        "080312170a037261775a100a0c0102030405060708090a0b0c10101a03312e30220e0a0674656e616e74120461636d65",
        raw, sizeof(raw));

    agc_metadata *md = NULL;
    agc_slice s = { raw, n };
    AGC_ASSERT_OK(agc_metadata_decode(NULL, s, &md));

    AGC_ASSERT_EQ_INT(agc_metadata_key_version(md), 3);
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_AEAD);
    AGC_ASSERT_EQ_STR(agc_metadata_encoding(md), "raw");
    AGC_ASSERT_EQ_STR(agc_metadata_api_version(md), "1.0");

    uint32_t tag_len = 0;
    AGC_ASSERT_OK(agc_metadata_aead_tag_len(md, &tag_len));
    AGC_ASSERT_EQ_INT(tag_len, 16);

    uint8_t nonce[64];
    size_t nonce_len = 0;
    AGC_ASSERT_OK(agc_metadata_aead_nonce(md, (agc_buf){nonce, sizeof(nonce)}, &nonce_len));
    uint8_t expected_nonce[12];
    hex_decode("0102030405060708090a0b0c", expected_nonce, sizeof(expected_nonce));
    AGC_ASSERT_EQ_INT(nonce_len, 12);
    AGC_ASSERT_MEM_EQ(nonce, expected_nonce, 12);

    AGC_ASSERT_EQ_INT(agc_metadata_user_context_count(md), 1);
    AGC_ASSERT_EQ_STR(agc_metadata_user_context_get(md, "tenant"), "acme");
    AGC_ASSERT(agc_metadata_user_context_get(md, "missing") == NULL);

    agc_metadata_free(md);
}

static void decode_check_no_output(void)
{
    /* {"no_output": {"bytes": "0801120252001a03312e30", "key_version": 1, "api_version": "1.0"}} */
    uint8_t raw[64];
    size_t n = hex_decode("0801120252001a03312e30", raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_key_version(md), 1);
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_NO_OUTPUT);
    AGC_ASSERT_EQ_STR(agc_metadata_api_version(md), "1.0");
    AGC_ASSERT_EQ_INT(agc_metadata_user_context_count(md), 0);
    agc_metadata_free(md);
}

static void decode_check_block_cipher(void)
{
    uint8_t raw[64];
    size_t n = hex_decode("0807121462120a10000102030405060708090a0b0c0d0e0f", raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_key_version(md), 7);
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER);

    uint8_t iv[64]; size_t iv_len = 0;
    AGC_ASSERT_OK(agc_metadata_block_iv(md, (agc_buf){iv, sizeof(iv)}, &iv_len));
    uint8_t expected[16];
    hex_decode("000102030405060708090a0b0c0d0e0f", expected, sizeof(expected));
    AGC_ASSERT_EQ_INT(iv_len, 16);
    AGC_ASSERT_MEM_EQ(iv, expected, 16);
    agc_metadata_free(md);
}

static void decode_check_counter_mode(void)
{
    uint8_t raw[64];
    size_t n = hex_decode("12166a140a10000102030405060708090a0b0c0d0e0f1040", raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_COUNTER_MODE);
    uint32_t bits = 0;
    AGC_ASSERT_OK(agc_metadata_counter_bits(md, &bits));
    AGC_ASSERT_EQ_INT(bits, 64);
    agc_metadata_free(md);
}

static void decode_check_stream_cipher(void)
{
    uint8_t raw[64];
    size_t n = hex_decode("121272100a08aaaaaaaaaaaaaaaa120400000001", raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_STREAM_CIPHER);

    uint8_t nonce[64]; size_t nonce_len = 0;
    AGC_ASSERT_OK(agc_metadata_stream_nonce(md, (agc_buf){nonce, sizeof(nonce)}, &nonce_len));
    AGC_ASSERT_EQ_INT(nonce_len, 8);
    for (size_t i = 0; i < 8; i++) AGC_ASSERT_EQ_INT(nonce[i], 0xAA);

    uint8_t bc[64]; size_t bc_len = 0;
    AGC_ASSERT_OK(agc_metadata_stream_block_counter(md, (agc_buf){bc, sizeof(bc)}, &bc_len));
    uint8_t expected_bc[4] = {0, 0, 0, 1};
    AGC_ASSERT_EQ_INT(bc_len, 4);
    AGC_ASSERT_MEM_EQ(bc, expected_bc, 4);
    agc_metadata_free(md);
}

static void decode_check_kdf(void)
{
    uint8_t raw[64];
    size_t n = hex_decode("121a7a180a1001010101010101010101010101010101120402020202", raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_KDF);

    uint8_t salt[64]; size_t salt_len = 0;
    AGC_ASSERT_OK(agc_metadata_kdf_salt(md, (agc_buf){salt, sizeof(salt)}, &salt_len));
    AGC_ASSERT_EQ_INT(salt_len, 16);
    for (size_t i = 0; i < 16; i++) AGC_ASSERT_EQ_INT(salt[i], 0x01);

    uint8_t iv[64]; size_t iv_len = 0;
    AGC_ASSERT_OK(agc_metadata_kdf_iv(md, (agc_buf){iv, sizeof(iv)}, &iv_len));
    AGC_ASSERT_EQ_INT(iv_len, 4);
    for (size_t i = 0; i < 4; i++) AGC_ASSERT_EQ_INT(iv[i], 0x02);
    agc_metadata_free(md);
}

static void decode_check_vendor(void)
{
    uint8_t raw[128];
    size_t n = hex_decode(
        "12248201210a130a0b6174746573746174696f6e1204deadbeef0a0a0a04736c6f7412020001",
        raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(md), AGC_ALGORITHM_OUTPUT_VENDOR);
    AGC_ASSERT_EQ_INT(agc_metadata_vendor_param_count(md), 2);

    int found_attestation = 0, found_slot = 0;
    for (size_t i = 0; i < agc_metadata_vendor_param_count(md); i++) {
        const char *key = NULL;
        uint8_t val[16]; size_t val_len = 0;
        AGC_ASSERT_OK(agc_metadata_vendor_param_at(md, i, &key, (agc_buf){val, sizeof(val)}, &val_len));
        if (strcmp(key, "attestation") == 0) {
            uint8_t expected[4] = {0xDE, 0xAD, 0xBE, 0xEF};
            AGC_ASSERT_EQ_INT(val_len, 4);
            AGC_ASSERT_MEM_EQ(val, expected, 4);
            found_attestation = 1;
        } else if (strcmp(key, "slot") == 0) {
            uint8_t expected[2] = {0x00, 0x01};
            AGC_ASSERT_EQ_INT(val_len, 2);
            AGC_ASSERT_MEM_EQ(val, expected, 2);
            found_slot = 1;
        }
    }
    AGC_ASSERT(found_attestation && found_slot);
    agc_metadata_free(md);
}

static void decode_check_multi_user_context(void)
{
    uint8_t raw[128];
    size_t n = hex_decode(
        "082a12070a0364657252001a03312e3022150a0a726571756573745f696412076162632d313233220e0a0674656e616e74120461636d65",
        raw, sizeof(raw));
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){raw, n}, &md));
    AGC_ASSERT_EQ_INT(agc_metadata_key_version(md), 42);
    AGC_ASSERT_EQ_STR(agc_metadata_encoding(md), "der");
    AGC_ASSERT_EQ_INT(agc_metadata_user_context_count(md), 2);
    AGC_ASSERT_EQ_STR(agc_metadata_user_context_get(md, "tenant"), "acme");
    AGC_ASSERT_EQ_STR(agc_metadata_user_context_get(md, "request_id"), "abc-123");
    agc_metadata_free(md);
}

/* --------------------------------------------------------------------------
 * 2. Malformed input handling
 * -------------------------------------------------------------------------- */

static void decode_check_malformed_and_contract_violation(void)
{
    agc_metadata *md = (agc_metadata *)0x1;

    /* Truncated varint (0x80 says "more bytes follow" but the buffer ends). */
    uint8_t truncated[] = {0x08, 0x80};
    AGC_ASSERT_EQ_INT(agc_metadata_decode(NULL, (agc_slice){truncated, sizeof(truncated)}, &md),
                       AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT(md == NULL);

    /* Length-delimited field claiming more bytes than actually follow. */
    uint8_t bad_len[] = {0x1a, 0x7f, 0x01}; /* field 3 (string), claims 127 bytes, has 1 */
    md = (agc_metadata *)0x1;
    AGC_ASSERT_EQ_INT(agc_metadata_decode(NULL, (agc_slice){bad_len, sizeof(bad_len)}, &md),
                       AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT(md == NULL);

    /* Empty input: no provider_output ever appeared -> oneof unset -> the
     * same contract violation a live provider forgetting to set it would
     * trigger (D9 / RECONCILIATION_PLAN.md §3.3). */
    md = (agc_metadata *)0x1;
    AGC_ASSERT_EQ_INT(agc_metadata_decode(NULL, (agc_slice){NULL, 0}, &md),
                       AGC_ERR_PROVIDER_CONTRACT_VIOLATION);
    AGC_ASSERT(md == NULL);
}

/* --------------------------------------------------------------------------
 * 3. Encode direction: construct via the internal API, encode, write to disk
 *    for the Python side (verify_c_encoded.py) to check with real protobuf.
 * -------------------------------------------------------------------------- */

static void write_encoded(const char *name, const agc__metadata_build *b)
{
    agc_metadata *md = NULL;
    AGC_ASSERT_OK(agc__metadata_create(b, &md));

    size_t needed = 0;
    AGC_ASSERT_OK(agc_metadata_encode(md, (agc_buf){0}, &needed));
    uint8_t *buf = malloc(needed ? needed : 1);
    size_t actual = 0;
    AGC_ASSERT_OK(agc_metadata_encode(md, (agc_buf){buf, needed}, &actual));
    AGC_ASSERT_EQ_INT(actual, needed);

    /* Round-trip through our OWN decoder too, independent of the Python
     * cross-check: value equality, not byte-identity (proto map field
     * ordering is unspecified by the wire format, so this is the correct
     * invariant to hold rather than expecting the same bytes back). */
    agc_metadata *roundtrip = NULL;
    AGC_ASSERT_OK(agc_metadata_decode(NULL, (agc_slice){buf, actual}, &roundtrip));
    AGC_ASSERT_EQ_INT(agc_metadata_key_version(roundtrip), agc_metadata_key_version(md));
    AGC_ASSERT_EQ_INT(agc_metadata_output_kind(roundtrip), agc_metadata_output_kind(md));
    agc_metadata_free(roundtrip);

    mkdir("c_encoded_vectors", 0755); /* ignore EEXIST */
    char path[256];
    snprintf(path, sizeof(path), "c_encoded_vectors/%s.bin", name);
    write_file(path, buf, actual);

    free(buf);
    agc_metadata_free(md);
}

static void encode_and_export_vectors(void)
{
    agc__metadata_build b;

    memset(&b, 0, sizeof(b));
    b.key_version = 9;
    b.api_version = "1.0";
    b.encoding = "raw";
    b.kind = AGC_ALGORITHM_OUTPUT_AEAD;
    uint8_t nonce[12] = {9,8,7,6,5,4,3,2,1,0,0xFF,0xEE};
    b.out.aead.nonce = (agc_slice){nonce, sizeof(nonce)};
    b.out.aead.tag_length_bytes = 16;
    agc_kv ctx_kv = { "purpose", "test" };
    b.user_context.items = &ctx_kv;
    b.user_context.count = 1;
    write_encoded("c_aead", &b);

    memset(&b, 0, sizeof(b));
    b.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
    b.api_version = "1.0";
    write_encoded("c_no_output", &b);

    memset(&b, 0, sizeof(b));
    b.key_version = 5;
    b.kind = AGC_ALGORITHM_OUTPUT_VENDOR;
    agc_kb vendor_kv = { "note", { (const uint8_t *)"hi", 2 } };
    b.out.vendor.items = &vendor_kv;
    b.out.vendor.count = 1;
    write_encoded("c_vendor", &b);
}

/* --------------------------------------------------------------------------
 * 4. Internal constructor argument validation
 * -------------------------------------------------------------------------- */

static void constructor_rejects_unset_kind(void)
{
    agc__metadata_build b;
    memset(&b, 0, sizeof(b));
    b.kind = AGC_ALGORITHM_OUTPUT_NONE;
    agc_metadata *md = (agc_metadata *)0x1;
    AGC_ASSERT_EQ_INT(agc__metadata_create(&b, &md), AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT(md == NULL);
}

int main(void)
{
    decode_check_aead();
    decode_check_no_output();
    decode_check_block_cipher();
    decode_check_counter_mode();
    decode_check_stream_cipher();
    decode_check_kdf();
    decode_check_vendor();
    decode_check_multi_user_context();
    decode_check_malformed_and_contract_violation();
    constructor_rejects_unset_kind();
    encode_and_export_vectors();
    AGC_PASS("test_metadata_codec");
}
