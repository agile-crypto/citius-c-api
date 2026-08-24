/* SPDX-License-Identifier: Apache-2.0
 *
 * protobuf_wire.h — minimal internal protobuf wire-format primitives.
 *
 * Not a general protobuf library: just enough varint / length-delimited
 * encode and decode to hand-implement OperationMetadata (src/wire/
 * metadata_codec.c), which is the one message this API needs to round-trip
 * byte-for-byte with the Go service (RECONCILIATION_PLAN.md D11). Taking a
 * full protobuf-c/nanopb/libprotobuf dependency for one seven-field message
 * inside a prospective FIPS boundary was judged not worth it — see
 * RECONCILIATION_PLAN.md §9.2.
 *
 * Wire format reference: https://protobuf.dev/programming-guides/encoding/
 */
#ifndef AGC_PROTOBUF_WIRE_H
#define AGC_PROTOBUF_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AGC_WIRE_VARINT 0
#define AGC_WIRE_64BIT  1
#define AGC_WIRE_LEN    2
#define AGC_WIRE_32BIT  5

/* --------------------------------------------------------------------------
 * Writer: a growable byte buffer. Always actually writes (no separate
 * "dry-run size" mode) -- callers needing the two-call agc_buf convention at
 * the public API build into one of these first and copy out, which is far
 * simpler than duplicating the encoding logic in a size-only pass and cheap
 * for a message this small.
 * -------------------------------------------------------------------------- */
typedef struct agc_wire_writer {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    int      oom; /* sticky: set on any allocation failure, checked once at the end */
} agc_wire_writer;

void agc_wire_writer_init(agc_wire_writer *w);
void agc_wire_writer_free(agc_wire_writer *w); /* frees w->data; safe on a zeroed writer */

void agc_wire_put_varint(agc_wire_writer *w, uint64_t v);
void agc_wire_put_tag(agc_wire_writer *w, uint32_t field_no, int wire_type);
void agc_wire_put_bytes_raw(agc_wire_writer *w, const uint8_t *p, size_t n);

/* Length-delimited field: tag + varint(len) + payload. */
void agc_wire_put_len_delim(agc_wire_writer *w, uint32_t field_no, const uint8_t *p, size_t n);

/* proto3 scalar omit-if-default semantics: a zero/empty value is not
 * written at all, matching what a real protobuf encoder produces and what
 * this codec must match for byte-for-byte interop. */
void agc_wire_put_string_field(agc_wire_writer *w, uint32_t field_no, const char *s);
void agc_wire_put_bytes_field(agc_wire_writer *w, uint32_t field_no, const uint8_t *p, size_t n);
void agc_wire_put_varint_field(agc_wire_writer *w, uint32_t field_no, uint64_t v);

/* --------------------------------------------------------------------------
 * Reader: a bounds-checked cursor over a borrowed byte slice.
 * -------------------------------------------------------------------------- */
typedef struct agc_wire_reader {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} agc_wire_reader;

void agc_wire_reader_init(agc_wire_reader *r, const uint8_t *data, size_t len);
int  agc_wire_reader_at_end(const agc_wire_reader *r);

/* Every read function returns 0 on success, -1 on malformed/truncated
 * input. On -1 the reader's position is left in an unspecified but still
 * in-bounds state; callers should abort decoding entirely rather than try
 * to recover mid-stream. */
int agc_wire_get_varint(agc_wire_reader *r, uint64_t *out);
int agc_wire_get_tag(agc_wire_reader *r, uint32_t *field_no, int *wire_type);
int agc_wire_get_len_delim(agc_wire_reader *r, const uint8_t **out_p, size_t *out_len);

/* Skips one value of the given wire type, for forward-compatible tolerance
 * of unknown fields (a future minor version may add one; this build must
 * not reject artifacts it merely doesn't fully understand). */
int agc_wire_skip(agc_wire_reader *r, int wire_type);

#ifdef __cplusplus
}
#endif
#endif /* AGC_PROTOBUF_WIRE_H */
