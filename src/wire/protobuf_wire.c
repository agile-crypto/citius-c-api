/* SPDX-License-Identifier: Apache-2.0 */
#include "protobuf_wire.h"

#include <stdlib.h>
#include <string.h>

void agc_wire_writer_init(agc_wire_writer *w)
{
    w->data = NULL;
    w->len = 0;
    w->cap = 0;
    w->oom = 0;
}

void agc_wire_writer_free(agc_wire_writer *w)
{
    if (!w) return;
    free(w->data);
    w->data = NULL;
    w->len = w->cap = 0;
}

static void reserve(agc_wire_writer *w, size_t extra)
{
    if (w->oom) return;
    if (w->len + extra <= w->cap) return;
    size_t new_cap = w->cap ? w->cap * 2 : 32;
    while (new_cap < w->len + extra) new_cap *= 2;
    uint8_t *grown = realloc(w->data, new_cap);
    if (!grown) {
        w->oom = 1;
        return;
    }
    w->data = grown;
    w->cap = new_cap;
}

void agc_wire_put_bytes_raw(agc_wire_writer *w, const uint8_t *p, size_t n)
{
    if (n == 0) return;
    reserve(w, n);
    if (w->oom) return;
    memcpy(w->data + w->len, p, n);
    w->len += n;
}

void agc_wire_put_varint(agc_wire_writer *w, uint64_t v)
{
    uint8_t tmp[10];
    size_t n = 0;
    do {
        uint8_t byte = (uint8_t)(v & 0x7f);
        v >>= 7;
        if (v) byte |= 0x80;
        tmp[n++] = byte;
    } while (v);
    agc_wire_put_bytes_raw(w, tmp, n);
}

void agc_wire_put_tag(agc_wire_writer *w, uint32_t field_no, int wire_type)
{
    agc_wire_put_varint(w, ((uint64_t)field_no << 3) | (uint64_t)wire_type);
}

void agc_wire_put_len_delim(agc_wire_writer *w, uint32_t field_no, const uint8_t *p, size_t n)
{
    agc_wire_put_tag(w, field_no, AGC_WIRE_LEN);
    agc_wire_put_varint(w, n);
    agc_wire_put_bytes_raw(w, p, n);
}

void agc_wire_put_string_field(agc_wire_writer *w, uint32_t field_no, const char *s)
{
    if (!s || !*s) return; /* proto3: default (empty) string is not encoded */
    agc_wire_put_len_delim(w, field_no, (const uint8_t *)s, strlen(s));
}

void agc_wire_put_bytes_field(agc_wire_writer *w, uint32_t field_no, const uint8_t *p, size_t n)
{
    if (n == 0) return; /* proto3: default (empty) bytes is not encoded */
    agc_wire_put_len_delim(w, field_no, p, n);
}

void agc_wire_put_varint_field(agc_wire_writer *w, uint32_t field_no, uint64_t v)
{
    if (v == 0) return; /* proto3: default (zero) scalar is not encoded */
    agc_wire_put_tag(w, field_no, AGC_WIRE_VARINT);
    agc_wire_put_varint(w, v);
}

/* --------------------------------------------------------------------------
 * Reader
 * -------------------------------------------------------------------------- */

void agc_wire_reader_init(agc_wire_reader *r, const uint8_t *data, size_t len)
{
    r->data = data;
    r->len = len;
    r->pos = 0;
}

int agc_wire_reader_at_end(const agc_wire_reader *r)
{
    return r->pos >= r->len;
}

int agc_wire_get_varint(agc_wire_reader *r, uint64_t *out)
{
    uint64_t result = 0;
    int shift = 0;
    while (1) {
        if (r->pos >= r->len) return -1;         /* truncated */
        if (shift >= 64) return -1;               /* malformed: too many bytes */
        uint8_t byte = r->data[r->pos++];
        result |= (uint64_t)(byte & 0x7f) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    *out = result;
    return 0;
}

int agc_wire_get_tag(agc_wire_reader *r, uint32_t *field_no, int *wire_type)
{
    uint64_t v;
    if (agc_wire_get_varint(r, &v) != 0) return -1;
    *field_no = (uint32_t)(v >> 3);
    *wire_type = (int)(v & 7);
    return 0;
}

int agc_wire_get_len_delim(agc_wire_reader *r, const uint8_t **out_p, size_t *out_len)
{
    uint64_t n;
    if (agc_wire_get_varint(r, &n) != 0) return -1;
    if (n > r->len - r->pos) return -1; /* would read past the buffer */
    *out_p = r->data + r->pos;
    *out_len = (size_t)n;
    r->pos += (size_t)n;
    return 0;
}

int agc_wire_skip(agc_wire_reader *r, int wire_type)
{
    switch (wire_type) {
    case AGC_WIRE_VARINT: {
        uint64_t v;
        return agc_wire_get_varint(r, &v);
    }
    case AGC_WIRE_64BIT:
        if (r->len - r->pos < 8) return -1;
        r->pos += 8;
        return 0;
    case AGC_WIRE_LEN: {
        const uint8_t *p;
        size_t n;
        return agc_wire_get_len_delim(r, &p, &n);
    }
    case AGC_WIRE_32BIT:
        if (r->len - r->pos < 4) return -1;
        r->pos += 4;
        return 0;
    default:
        return -1;
    }
}
