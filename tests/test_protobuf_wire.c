/* SPDX-License-Identifier: Apache-2.0
 * Unit tests for the generic varint/length-delimited primitives (commit 6),
 * independent of OperationMetadata. Whitebox: protobuf_wire.h is internal.
 */
#include "agilecrypto.h"
#include "protobuf_wire.h"
#include "test_helpers.h"

static void test_varint_roundtrip(void)
{
    uint64_t values[] = {0, 1, 127, 128, 300, 16384, UINT32_MAX, UINT64_MAX};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        agc_wire_writer w;
        agc_wire_writer_init(&w);
        agc_wire_put_varint(&w, values[i]);
        AGC_ASSERT(!w.oom);

        agc_wire_reader r;
        agc_wire_reader_init(&r, w.data, w.len);
        uint64_t out = 0;
        AGC_ASSERT(agc_wire_get_varint(&r, &out) == 0);
        AGC_ASSERT(agc_wire_reader_at_end(&r));
        if (out != values[i]) {
            fprintf(stderr, "varint roundtrip failed for %llu -> %llu\n",
                    (unsigned long long)values[i], (unsigned long long)out);
            exit(1);
        }
        agc_wire_writer_free(&w);
    }
}

/* Known single-byte and multi-byte encodings, so a bug that happens to
 * round-trip through our own reader/writer pair still gets caught against
 * literal expected bytes. */
static void test_varint_known_encodings(void)
{
    agc_wire_writer w;

    agc_wire_writer_init(&w);
    agc_wire_put_varint(&w, 1);
    AGC_ASSERT_EQ_INT(w.len, 1);
    AGC_ASSERT_EQ_INT(w.data[0], 0x01);
    agc_wire_writer_free(&w);

    agc_wire_writer_init(&w);
    agc_wire_put_varint(&w, 300); /* 300 = 0b1_0010_1100 -> 0xAC 0x02 */
    AGC_ASSERT_EQ_INT(w.len, 2);
    AGC_ASSERT_EQ_INT(w.data[0], 0xAC);
    AGC_ASSERT_EQ_INT(w.data[1], 0x02);
    agc_wire_writer_free(&w);
}

static void test_proto3_omit_default(void)
{
    agc_wire_writer w;

    agc_wire_writer_init(&w);
    agc_wire_put_varint_field(&w, 1, 0);
    AGC_ASSERT_EQ_INT(w.len, 0); /* zero is the default; proto3 omits it */
    agc_wire_writer_free(&w);

    agc_wire_writer_init(&w);
    agc_wire_put_string_field(&w, 1, "");
    AGC_ASSERT_EQ_INT(w.len, 0);
    agc_wire_writer_free(&w);

    agc_wire_writer_init(&w);
    agc_wire_put_string_field(&w, 1, NULL);
    AGC_ASSERT_EQ_INT(w.len, 0);
    agc_wire_writer_free(&w);

    agc_wire_writer_init(&w);
    agc_wire_put_bytes_field(&w, 1, NULL, 0);
    AGC_ASSERT_EQ_INT(w.len, 0);
    agc_wire_writer_free(&w);

    agc_wire_writer_init(&w);
    agc_wire_put_string_field(&w, 1, "x");
    AGC_ASSERT(w.len > 0); /* a non-default value IS written */
    agc_wire_writer_free(&w);
}

static void test_len_delim_roundtrip(void)
{
    const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    agc_wire_writer w;
    agc_wire_writer_init(&w);
    agc_wire_put_len_delim(&w, 5, payload, sizeof(payload));

    agc_wire_reader r;
    agc_wire_reader_init(&r, w.data, w.len);
    uint32_t field_no; int wire_type;
    AGC_ASSERT(agc_wire_get_tag(&r, &field_no, &wire_type) == 0);
    AGC_ASSERT_EQ_INT(field_no, 5);
    AGC_ASSERT_EQ_INT(wire_type, AGC_WIRE_LEN);

    const uint8_t *p; size_t n;
    AGC_ASSERT(agc_wire_get_len_delim(&r, &p, &n) == 0);
    AGC_ASSERT_EQ_INT(n, sizeof(payload));
    AGC_ASSERT_MEM_EQ(p, payload, n);
    AGC_ASSERT(agc_wire_reader_at_end(&r));
    agc_wire_writer_free(&w);
}

static void test_malformed_inputs_rejected(void)
{
    /* Truncated varint: continuation bit set on the last byte. */
    uint8_t truncated[] = {0x80};
    agc_wire_reader r;
    agc_wire_reader_init(&r, truncated, sizeof(truncated));
    uint64_t v;
    AGC_ASSERT(agc_wire_get_varint(&r, &v) != 0);

    /* Length-delimited field whose declared length overruns the buffer. */
    uint8_t bad[] = {0x0A}; /* varint 10, but zero bytes follow */
    agc_wire_reader_init(&r, bad, sizeof(bad));
    const uint8_t *p; size_t n;
    AGC_ASSERT(agc_wire_get_len_delim(&r, &p, &n) != 0);

    /* Empty buffer has no tag to read. */
    agc_wire_reader_init(&r, NULL, 0);
    uint32_t fn; int wt;
    AGC_ASSERT(agc_wire_get_tag(&r, &fn, &wt) != 0);
}

int main(void)
{
    test_varint_roundtrip();
    test_varint_known_encodings();
    test_proto3_omit_default();
    test_len_delim_roundtrip();
    test_malformed_inputs_rejected();
    AGC_PASS("test_protobuf_wire");
}
