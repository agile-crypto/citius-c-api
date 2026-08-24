/* SPDX-License-Identifier: Apache-2.0
 *
 * metadata_codec.c — agc_metadata: handle, protobuf wire codec, accessors.
 *
 * Wire layout (api/messages/metadata.proto, verified against the proto
 * source directly -- not against a field-dumping script, which had
 * previously mis-attributed NoAlgorithmOutput's fields; see
 * RECONCILIATION_PLAN.md's correction note in §2.5):
 *
 *   OperationMetadata { uint32 key_version=1; ProviderOutput provider_output=2;
 *                        string api_version=3; map<string,string> user_context=4; }
 *   ProviderOutput { oneof algorithm_output {
 *                       NoAlgorithmOutput no_output=10;    // {} -- truly empty
 *                       AeadOutput aead_output=11;          // {bytes nonce=1; uint32 tag_length_bytes=2;}
 *                       BlockCipherOutput block_cipher_output=12;  // {bytes iv=1;}
 *                       CounterModeOutput counter_mode_output=13;  // {bytes counter_block=1; uint32 counter_bits=2;}
 *                       StreamCipherOutput stream_cipher_output=14; // {bytes nonce=1; bytes block_counter=2;}
 *                       KdfOutput kdf_output=15;             // {bytes salt=1; bytes iv=2;}
 *                       VendorOutput vendor_output=16;       // {map<string,bytes> parameters=1;}
 *                     }
 *                     string encoding=1; }
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "protobuf_wire.h"

#include <stdlib.h>
#include <string.h>

struct agc_metadata {
    uint32_t key_version;
    char    *api_version;      /* owned, never NULL (may be "") */
    char    *encoding;         /* owned, never NULL (may be "") */

    agc_kv  *user_context;     /* owned array of owned-string kv pairs */
    size_t   user_context_count;

    agc_algorithm_output_kind kind;
    union {
        struct { uint8_t *nonce; size_t nonce_len; uint32_t tag_length_bytes; } aead;
        struct { uint8_t *iv; size_t iv_len; }                                  block_cipher;
        struct { uint8_t *counter_block; size_t counter_block_len; uint32_t counter_bits; } counter_mode;
        struct { uint8_t *nonce; size_t nonce_len; uint8_t *block_counter; size_t block_counter_len; } stream_cipher;
        struct { uint8_t *salt; size_t salt_len; uint8_t *iv; size_t iv_len; } kdf;
        struct { agc_kb *items; size_t count; }                                vendor; /* owned; each value's bytes owned */
    } out;
};

/* --------------------------------------------------------------------------
 * Teardown
 * -------------------------------------------------------------------------- */

static void free_output_payload(struct agc_metadata *md)
{
    switch (md->kind) {
    case AGC_ALGORITHM_OUTPUT_AEAD:
        free(md->out.aead.nonce);
        break;
    case AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER:
        free(md->out.block_cipher.iv);
        break;
    case AGC_ALGORITHM_OUTPUT_COUNTER_MODE:
        free(md->out.counter_mode.counter_block);
        break;
    case AGC_ALGORITHM_OUTPUT_STREAM_CIPHER:
        free(md->out.stream_cipher.nonce);
        free(md->out.stream_cipher.block_counter);
        break;
    case AGC_ALGORITHM_OUTPUT_KDF:
        free(md->out.kdf.salt);
        free(md->out.kdf.iv);
        break;
    case AGC_ALGORITHM_OUTPUT_VENDOR:
        for (size_t i = 0; i < md->out.vendor.count; i++) {
            free((void *)md->out.vendor.items[i].key);
            free((void *)md->out.vendor.items[i].value.data);
        }
        free(md->out.vendor.items);
        break;
    case AGC_ALGORITHM_OUTPUT_NONE:
    case AGC_ALGORITHM_OUTPUT_NO_OUTPUT:
    default:
        break;
    }
    memset(&md->out, 0, sizeof(md->out));
}

void agc_metadata_free(agc_metadata *md)
{
    if (!md) return;
    free_output_payload(md);
    free(md->api_version);
    free(md->encoding);
    for (size_t i = 0; i < md->user_context_count; i++) {
        free((void *)md->user_context[i].key);
        free((void *)md->user_context[i].value);
    }
    free(md->user_context);
    free(md);
}

/* --------------------------------------------------------------------------
 * Construction (internal: only a provider backend assembles metadata from
 * scratch; everyone else gets it from agc_metadata_decode()).
 * -------------------------------------------------------------------------- */

static char *dup_or_empty(const char *s)
{
    return strdup(s ? s : "");
}

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
    if (n == 0) return NULL;
    uint8_t *out = malloc(n);
    if (out) memcpy(out, p, n);
    return out;
}

static agc_rc dup_kv_list_as_kv(const agc_kv_list *in, agc_kv **out_items, size_t *out_count)
{
    *out_items = NULL;
    *out_count = 0;
    if (!in || in->count == 0) return AGC_OK;

    agc_kv *items = calloc(in->count, sizeof(*items));
    if (!items) return AGC_ERR_OUT_OF_MEMORY;

    for (size_t i = 0; i < in->count; i++) {
        items[i].key = strdup(in->items[i].key ? in->items[i].key : "");
        items[i].value = strdup(in->items[i].value ? in->items[i].value : "");
        if (!items[i].key || !items[i].value) {
            for (size_t j = 0; j <= i; j++) {
                free((void *)items[j].key);
                free((void *)items[j].value);
            }
            free(items);
            return AGC_ERR_OUT_OF_MEMORY;
        }
    }
    *out_items = items;
    *out_count = in->count;
    return AGC_OK;
}

agc_rc agc__metadata_create(const agc__metadata_build *b, agc_metadata **out_md)
{
    if (!b || !out_md) return AGC_ERR_INVALID_ARGUMENT;
    *out_md = NULL;
    if (b->kind == AGC_ALGORITHM_OUTPUT_NONE) return AGC_ERR_INVALID_ARGUMENT;

    struct agc_metadata *md = calloc(1, sizeof(*md));
    if (!md) return AGC_ERR_OUT_OF_MEMORY;

    md->key_version = b->key_version;
    md->api_version = dup_or_empty(b->api_version);
    md->encoding = dup_or_empty(b->encoding);
    md->kind = b->kind;

    agc_rc rc = dup_kv_list_as_kv(&b->user_context, &md->user_context, &md->user_context_count);
    if (rc != AGC_OK) {
        agc_metadata_free(md);
        return rc;
    }
    if (!md->api_version || !md->encoding) {
        agc_metadata_free(md);
        return AGC_ERR_OUT_OF_MEMORY;
    }

    switch (b->kind) {
    case AGC_ALGORITHM_OUTPUT_NO_OUTPUT:
        break;
    case AGC_ALGORITHM_OUTPUT_AEAD:
        md->out.aead.nonce = dup_bytes(b->out.aead.nonce.data, b->out.aead.nonce.len);
        md->out.aead.nonce_len = b->out.aead.nonce.len;
        md->out.aead.tag_length_bytes = b->out.aead.tag_length_bytes;
        break;
    case AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER:
        md->out.block_cipher.iv = dup_bytes(b->out.block_cipher.iv.data, b->out.block_cipher.iv.len);
        md->out.block_cipher.iv_len = b->out.block_cipher.iv.len;
        break;
    case AGC_ALGORITHM_OUTPUT_COUNTER_MODE:
        md->out.counter_mode.counter_block = dup_bytes(b->out.counter_mode.counter_block.data,
                                                         b->out.counter_mode.counter_block.len);
        md->out.counter_mode.counter_block_len = b->out.counter_mode.counter_block.len;
        md->out.counter_mode.counter_bits = b->out.counter_mode.counter_bits;
        break;
    case AGC_ALGORITHM_OUTPUT_STREAM_CIPHER:
        md->out.stream_cipher.nonce = dup_bytes(b->out.stream_cipher.nonce.data, b->out.stream_cipher.nonce.len);
        md->out.stream_cipher.nonce_len = b->out.stream_cipher.nonce.len;
        md->out.stream_cipher.block_counter = dup_bytes(b->out.stream_cipher.block_counter.data,
                                                          b->out.stream_cipher.block_counter.len);
        md->out.stream_cipher.block_counter_len = b->out.stream_cipher.block_counter.len;
        break;
    case AGC_ALGORITHM_OUTPUT_KDF:
        md->out.kdf.salt = dup_bytes(b->out.kdf.salt.data, b->out.kdf.salt.len);
        md->out.kdf.salt_len = b->out.kdf.salt.len;
        md->out.kdf.iv = dup_bytes(b->out.kdf.iv.data, b->out.kdf.iv.len);
        md->out.kdf.iv_len = b->out.kdf.iv.len;
        break;
    case AGC_ALGORITHM_OUTPUT_VENDOR: {
        size_t n = b->out.vendor.count;
        if (n > 0) {
            md->out.vendor.items = calloc(n, sizeof(*md->out.vendor.items));
            if (!md->out.vendor.items) {
                agc_metadata_free(md);
                return AGC_ERR_OUT_OF_MEMORY;
            }
            for (size_t i = 0; i < n; i++) {
                md->out.vendor.items[i].key = strdup(b->out.vendor.items[i].key ? b->out.vendor.items[i].key : "");
                md->out.vendor.items[i].value.data = dup_bytes(b->out.vendor.items[i].value.data,
                                                                 b->out.vendor.items[i].value.len);
                md->out.vendor.items[i].value.len = b->out.vendor.items[i].value.len;
                md->out.vendor.count = i + 1;
                if (!md->out.vendor.items[i].key) {
                    agc_metadata_free(md);
                    return AGC_ERR_OUT_OF_MEMORY;
                }
            }
        }
        break;
    }
    default:
        agc_metadata_free(md);
        return AGC_ERR_INVALID_ARGUMENT;
    }

    *out_md = md;
    return AGC_OK;
}

agc_rc agc_metadata_new(agc_ctx *ctx, agc_metadata **out_md)
{
    (void)ctx;
    if (!out_md) return AGC_ERR_INVALID_ARGUMENT;
    agc__metadata_build b;
    memset(&b, 0, sizeof(b));
    b.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
    b.api_version = AGC_API_VERSION_STRING;
    return agc__metadata_create(&b, out_md);
}

/* --------------------------------------------------------------------------
 * Encode
 * -------------------------------------------------------------------------- */

static void encode_provider_output(const struct agc_metadata *md, agc_wire_writer *po)
{
    switch (md->kind) {
    case AGC_ALGORITHM_OUTPUT_NO_OUTPUT:
        agc_wire_put_len_delim(po, 10, NULL, 0); /* NoAlgorithmOutput{}: present, zero-length */
        break;
    case AGC_ALGORITHM_OUTPUT_AEAD: {
        agc_wire_writer inner;
        agc_wire_writer_init(&inner);
        agc_wire_put_bytes_field(&inner, 1, md->out.aead.nonce, md->out.aead.nonce_len);
        agc_wire_put_varint_field(&inner, 2, md->out.aead.tag_length_bytes);
        agc_wire_put_len_delim(po, 11, inner.data, inner.len);
        agc_wire_writer_free(&inner);
        break;
    }
    case AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER: {
        agc_wire_writer inner;
        agc_wire_writer_init(&inner);
        agc_wire_put_bytes_field(&inner, 1, md->out.block_cipher.iv, md->out.block_cipher.iv_len);
        agc_wire_put_len_delim(po, 12, inner.data, inner.len);
        agc_wire_writer_free(&inner);
        break;
    }
    case AGC_ALGORITHM_OUTPUT_COUNTER_MODE: {
        agc_wire_writer inner;
        agc_wire_writer_init(&inner);
        agc_wire_put_bytes_field(&inner, 1, md->out.counter_mode.counter_block, md->out.counter_mode.counter_block_len);
        agc_wire_put_varint_field(&inner, 2, md->out.counter_mode.counter_bits);
        agc_wire_put_len_delim(po, 13, inner.data, inner.len);
        agc_wire_writer_free(&inner);
        break;
    }
    case AGC_ALGORITHM_OUTPUT_STREAM_CIPHER: {
        agc_wire_writer inner;
        agc_wire_writer_init(&inner);
        agc_wire_put_bytes_field(&inner, 1, md->out.stream_cipher.nonce, md->out.stream_cipher.nonce_len);
        agc_wire_put_bytes_field(&inner, 2, md->out.stream_cipher.block_counter, md->out.stream_cipher.block_counter_len);
        agc_wire_put_len_delim(po, 14, inner.data, inner.len);
        agc_wire_writer_free(&inner);
        break;
    }
    case AGC_ALGORITHM_OUTPUT_KDF: {
        agc_wire_writer inner;
        agc_wire_writer_init(&inner);
        agc_wire_put_bytes_field(&inner, 1, md->out.kdf.salt, md->out.kdf.salt_len);
        agc_wire_put_bytes_field(&inner, 2, md->out.kdf.iv, md->out.kdf.iv_len);
        agc_wire_put_len_delim(po, 15, inner.data, inner.len);
        agc_wire_writer_free(&inner);
        break;
    }
    case AGC_ALGORITHM_OUTPUT_VENDOR: {
        agc_wire_writer inner;
        agc_wire_writer_init(&inner);
        for (size_t i = 0; i < md->out.vendor.count; i++) {
            agc_wire_writer entry;
            agc_wire_writer_init(&entry);
            agc_wire_put_string_field(&entry, 1, md->out.vendor.items[i].key);
            agc_wire_put_bytes_field(&entry, 2, md->out.vendor.items[i].value.data, md->out.vendor.items[i].value.len);
            agc_wire_put_len_delim(&inner, 1, entry.data, entry.len); /* VendorOutput.parameters map entry */
            agc_wire_writer_free(&entry);
        }
        agc_wire_put_len_delim(po, 16, inner.data, inner.len);
        agc_wire_writer_free(&inner);
        break;
    }
    case AGC_ALGORITHM_OUTPUT_NONE:
    default:
        /* Caller-held handles never have this kind (enforced at construction
         * and decode time); nothing to emit if it somehow occurred. */
        break;
    }

    agc_wire_put_string_field(po, 1, md->encoding);
}

agc_rc agc_metadata_encode(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || !out_len) return AGC_ERR_INVALID_ARGUMENT;

    agc_wire_writer w;
    agc_wire_writer_init(&w);

    agc_wire_put_varint_field(&w, 1, md->key_version);

    agc_wire_writer po;
    agc_wire_writer_init(&po);
    encode_provider_output(md, &po);
    agc_wire_put_len_delim(&w, 2, po.data, po.len);
    agc_wire_writer_free(&po);

    agc_wire_put_string_field(&w, 3, md->api_version);

    for (size_t i = 0; i < md->user_context_count; i++) {
        agc_wire_writer entry;
        agc_wire_writer_init(&entry);
        agc_wire_put_string_field(&entry, 1, md->user_context[i].key);
        agc_wire_put_string_field(&entry, 2, md->user_context[i].value);
        agc_wire_put_len_delim(&w, 4, entry.data, entry.len);
        agc_wire_writer_free(&entry);
    }

    if (w.oom) {
        agc_wire_writer_free(&w);
        return AGC_ERR_OUT_OF_MEMORY;
    }

    *out_len = w.len;
    agc_rc rc = AGC_OK;
    if (out.data != NULL) {
        if (out.cap < w.len) {
            rc = AGC_ERR_BUFFER_TOO_SMALL;
        } else {
            memcpy(out.data, w.data, w.len);
        }
    }
    agc_wire_writer_free(&w);
    return rc;
}

/* --------------------------------------------------------------------------
 * Decode
 * -------------------------------------------------------------------------- */

static char *dup_len(const uint8_t *p, size_t n)
{
    char *s = malloc(n + 1);
    if (!s) return NULL;
    if (n) memcpy(s, p, n);
    s[n] = '\0';
    return s;
}

static agc_rc decode_provider_output(struct agc_metadata *md, const uint8_t *data, size_t len)
{
    agc_wire_reader r;
    agc_wire_reader_init(&r, data, len);

    while (!agc_wire_reader_at_end(&r)) {
        uint32_t field_no;
        int wire_type;
        if (agc_wire_get_tag(&r, &field_no, &wire_type) != 0) return AGC_ERR_INVALID_ARGUMENT;

        if (field_no == 1 && wire_type == AGC_WIRE_LEN) {
            const uint8_t *p; size_t n;
            if (agc_wire_get_len_delim(&r, &p, &n) != 0) return AGC_ERR_INVALID_ARGUMENT;
            free(md->encoding);
            md->encoding = dup_len(p, n);
            if (!md->encoding) return AGC_ERR_OUT_OF_MEMORY;
            continue;
        }

        if (field_no >= 10 && field_no <= 16 && wire_type == AGC_WIRE_LEN) {
            const uint8_t *p; size_t n;
            if (agc_wire_get_len_delim(&r, &p, &n) != 0) return AGC_ERR_INVALID_ARGUMENT;

            /* Last-arm-wins, matching real protobuf oneof decode semantics
             * if a malformed/foreign stream sets more than one. */
            free_output_payload(md);
            md->kind = (agc_algorithm_output_kind)field_no;

            switch (field_no) {
            case 10: /* NoAlgorithmOutput {} */
                break;
            case 11: { /* AeadOutput {bytes nonce=1; uint32 tag_length_bytes=2;} */
                agc_wire_reader ir; agc_wire_reader_init(&ir, p, n);
                while (!agc_wire_reader_at_end(&ir)) {
                    uint32_t fn; int wt;
                    if (agc_wire_get_tag(&ir, &fn, &wt) != 0) return AGC_ERR_INVALID_ARGUMENT;
                    if (fn == 1 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.aead.nonce);
                        md->out.aead.nonce = dup_bytes(bp, bn);
                        md->out.aead.nonce_len = bn;
                    } else if (fn == 2 && wt == AGC_WIRE_VARINT) {
                        uint64_t v;
                        if (agc_wire_get_varint(&ir, &v) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        md->out.aead.tag_length_bytes = (uint32_t)v;
                    } else if (agc_wire_skip(&ir, wt) != 0) {
                        return AGC_ERR_INVALID_ARGUMENT;
                    }
                }
                break;
            }
            case 12: { /* BlockCipherOutput {bytes iv=1;} */
                agc_wire_reader ir; agc_wire_reader_init(&ir, p, n);
                while (!agc_wire_reader_at_end(&ir)) {
                    uint32_t fn; int wt;
                    if (agc_wire_get_tag(&ir, &fn, &wt) != 0) return AGC_ERR_INVALID_ARGUMENT;
                    if (fn == 1 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.block_cipher.iv);
                        md->out.block_cipher.iv = dup_bytes(bp, bn);
                        md->out.block_cipher.iv_len = bn;
                    } else if (agc_wire_skip(&ir, wt) != 0) {
                        return AGC_ERR_INVALID_ARGUMENT;
                    }
                }
                break;
            }
            case 13: { /* CounterModeOutput {bytes counter_block=1; uint32 counter_bits=2;} */
                agc_wire_reader ir; agc_wire_reader_init(&ir, p, n);
                while (!agc_wire_reader_at_end(&ir)) {
                    uint32_t fn; int wt;
                    if (agc_wire_get_tag(&ir, &fn, &wt) != 0) return AGC_ERR_INVALID_ARGUMENT;
                    if (fn == 1 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.counter_mode.counter_block);
                        md->out.counter_mode.counter_block = dup_bytes(bp, bn);
                        md->out.counter_mode.counter_block_len = bn;
                    } else if (fn == 2 && wt == AGC_WIRE_VARINT) {
                        uint64_t v;
                        if (agc_wire_get_varint(&ir, &v) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        md->out.counter_mode.counter_bits = (uint32_t)v;
                    } else if (agc_wire_skip(&ir, wt) != 0) {
                        return AGC_ERR_INVALID_ARGUMENT;
                    }
                }
                break;
            }
            case 14: { /* StreamCipherOutput {bytes nonce=1; bytes block_counter=2;} */
                agc_wire_reader ir; agc_wire_reader_init(&ir, p, n);
                while (!agc_wire_reader_at_end(&ir)) {
                    uint32_t fn; int wt;
                    if (agc_wire_get_tag(&ir, &fn, &wt) != 0) return AGC_ERR_INVALID_ARGUMENT;
                    if (fn == 1 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.stream_cipher.nonce);
                        md->out.stream_cipher.nonce = dup_bytes(bp, bn);
                        md->out.stream_cipher.nonce_len = bn;
                    } else if (fn == 2 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.stream_cipher.block_counter);
                        md->out.stream_cipher.block_counter = dup_bytes(bp, bn);
                        md->out.stream_cipher.block_counter_len = bn;
                    } else if (agc_wire_skip(&ir, wt) != 0) {
                        return AGC_ERR_INVALID_ARGUMENT;
                    }
                }
                break;
            }
            case 15: { /* KdfOutput {bytes salt=1; bytes iv=2;} */
                agc_wire_reader ir; agc_wire_reader_init(&ir, p, n);
                while (!agc_wire_reader_at_end(&ir)) {
                    uint32_t fn; int wt;
                    if (agc_wire_get_tag(&ir, &fn, &wt) != 0) return AGC_ERR_INVALID_ARGUMENT;
                    if (fn == 1 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.kdf.salt);
                        md->out.kdf.salt = dup_bytes(bp, bn);
                        md->out.kdf.salt_len = bn;
                    } else if (fn == 2 && wt == AGC_WIRE_LEN) {
                        const uint8_t *bp; size_t bn;
                        if (agc_wire_get_len_delim(&ir, &bp, &bn) != 0) return AGC_ERR_INVALID_ARGUMENT;
                        free(md->out.kdf.iv);
                        md->out.kdf.iv = dup_bytes(bp, bn);
                        md->out.kdf.iv_len = bn;
                    } else if (agc_wire_skip(&ir, wt) != 0) {
                        return AGC_ERR_INVALID_ARGUMENT;
                    }
                }
                break;
            }
            case 16: { /* VendorOutput {map<string,bytes> parameters=1;} */
                agc_wire_reader ir; agc_wire_reader_init(&ir, p, n);
                size_t cap = 0;
                while (!agc_wire_reader_at_end(&ir)) {
                    uint32_t fn; int wt;
                    if (agc_wire_get_tag(&ir, &fn, &wt) != 0) return AGC_ERR_INVALID_ARGUMENT;
                    if (fn == 1 && wt == AGC_WIRE_LEN) {
                        const uint8_t *ep; size_t en;
                        if (agc_wire_get_len_delim(&ir, &ep, &en) != 0) return AGC_ERR_INVALID_ARGUMENT;

                        char *key = NULL;
                        uint8_t *val = NULL;
                        size_t val_len = 0;
                        agc_wire_reader er; agc_wire_reader_init(&er, ep, en);
                        while (!agc_wire_reader_at_end(&er)) {
                            uint32_t efn; int ewt;
                            if (agc_wire_get_tag(&er, &efn, &ewt) != 0) { free(key); free(val); return AGC_ERR_INVALID_ARGUMENT; }
                            if (efn == 1 && ewt == AGC_WIRE_LEN) {
                                const uint8_t *kp; size_t kn;
                                if (agc_wire_get_len_delim(&er, &kp, &kn) != 0) { free(key); free(val); return AGC_ERR_INVALID_ARGUMENT; }
                                free(key);
                                key = dup_len(kp, kn);
                            } else if (efn == 2 && ewt == AGC_WIRE_LEN) {
                                const uint8_t *vp; size_t vn;
                                if (agc_wire_get_len_delim(&er, &vp, &vn) != 0) { free(key); free(val); return AGC_ERR_INVALID_ARGUMENT; }
                                free(val);
                                val = dup_bytes(vp, vn);
                                val_len = vn;
                            } else if (agc_wire_skip(&er, ewt) != 0) {
                                free(key); free(val);
                                return AGC_ERR_INVALID_ARGUMENT;
                            }
                        }
                        if (!key) key = dup_len(NULL, 0); /* proto3: absent key field => "" */
                        if (!key) { free(val); return AGC_ERR_OUT_OF_MEMORY; }

                        if (md->out.vendor.count == cap) {
                            size_t new_cap = cap ? cap * 2 : 4;
                            agc_kb *grown = realloc(md->out.vendor.items, new_cap * sizeof(*grown));
                            if (!grown) { free(key); free(val); return AGC_ERR_OUT_OF_MEMORY; }
                            md->out.vendor.items = grown;
                            cap = new_cap;
                        }
                        md->out.vendor.items[md->out.vendor.count].key = key;
                        md->out.vendor.items[md->out.vendor.count].value.data = val;
                        md->out.vendor.items[md->out.vendor.count].value.len = val_len;
                        md->out.vendor.count++;
                    } else if (agc_wire_skip(&ir, wt) != 0) {
                        return AGC_ERR_INVALID_ARGUMENT;
                    }
                }
                break;
            }
            default:
                break;
            }
            continue;
        }

        if (agc_wire_skip(&r, wire_type) != 0) return AGC_ERR_INVALID_ARGUMENT;
    }

    return AGC_OK;
}

agc_rc agc_metadata_decode(agc_ctx *ctx, agc_slice encoded, agc_metadata **out_md)
{
    (void)ctx;
    if (!out_md) return AGC_ERR_INVALID_ARGUMENT;
    *out_md = NULL;
    if (encoded.len > 0 && !encoded.data) return AGC_ERR_INVALID_ARGUMENT;

    struct agc_metadata *md = calloc(1, sizeof(*md));
    if (!md) return AGC_ERR_OUT_OF_MEMORY;
    md->api_version = dup_or_empty(NULL);
    md->encoding = dup_or_empty(NULL);
    if (!md->api_version || !md->encoding) {
        agc_metadata_free(md);
        return AGC_ERR_OUT_OF_MEMORY;
    }

    agc_wire_reader r;
    agc_wire_reader_init(&r, encoded.data, encoded.len);
    agc_kv *ctx_items = NULL;
    size_t ctx_count = 0, ctx_cap = 0;
    agc_rc rc = AGC_OK;

    while (!agc_wire_reader_at_end(&r) && rc == AGC_OK) {
        uint32_t field_no; int wire_type;
        if (agc_wire_get_tag(&r, &field_no, &wire_type) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }

        if (field_no == 1 && wire_type == AGC_WIRE_VARINT) {
            uint64_t v;
            if (agc_wire_get_varint(&r, &v) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }
            md->key_version = (uint32_t)v;
        } else if (field_no == 2 && wire_type == AGC_WIRE_LEN) {
            const uint8_t *p; size_t n;
            if (agc_wire_get_len_delim(&r, &p, &n) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }
            rc = decode_provider_output(md, p, n);
        } else if (field_no == 3 && wire_type == AGC_WIRE_LEN) {
            const uint8_t *p; size_t n;
            if (agc_wire_get_len_delim(&r, &p, &n) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }
            free(md->api_version);
            md->api_version = dup_len(p, n);
            if (!md->api_version) { rc = AGC_ERR_OUT_OF_MEMORY; break; }
        } else if (field_no == 4 && wire_type == AGC_WIRE_LEN) {
            const uint8_t *p; size_t n;
            if (agc_wire_get_len_delim(&r, &p, &n) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }

            char *key = NULL, *val = NULL;
            agc_wire_reader er; agc_wire_reader_init(&er, p, n);
            while (!agc_wire_reader_at_end(&er)) {
                uint32_t efn; int ewt;
                if (agc_wire_get_tag(&er, &efn, &ewt) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }
                if (efn == 1 && ewt == AGC_WIRE_LEN) {
                    const uint8_t *kp; size_t kn;
                    if (agc_wire_get_len_delim(&er, &kp, &kn) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }
                    free(key);
                    key = dup_len(kp, kn);
                } else if (efn == 2 && ewt == AGC_WIRE_LEN) {
                    const uint8_t *vp; size_t vn;
                    if (agc_wire_get_len_delim(&er, &vp, &vn) != 0) { rc = AGC_ERR_INVALID_ARGUMENT; break; }
                    free(val);
                    val = dup_len(vp, vn);
                } else if (agc_wire_skip(&er, ewt) != 0) {
                    rc = AGC_ERR_INVALID_ARGUMENT;
                    break;
                }
            }
            if (rc == AGC_OK) {
                if (!key) key = dup_len(NULL, 0);
                if (!val) val = dup_len(NULL, 0);
                if (!key || !val) {
                    rc = AGC_ERR_OUT_OF_MEMORY;
                } else if (ctx_count == ctx_cap) {
                    size_t new_cap = ctx_cap ? ctx_cap * 2 : 4;
                    agc_kv *grown = realloc(ctx_items, new_cap * sizeof(*grown));
                    if (!grown) { rc = AGC_ERR_OUT_OF_MEMORY; }
                    else { ctx_items = grown; ctx_cap = new_cap; }
                }
            }
            if (rc == AGC_OK) {
                ctx_items[ctx_count].key = key;
                ctx_items[ctx_count].value = val;
                ctx_count++;
            } else {
                free(key);
                free(val);
            }
        } else {
            if (agc_wire_skip(&r, wire_type) != 0) rc = AGC_ERR_INVALID_ARGUMENT;
        }
    }

    if (rc == AGC_OK && md->kind == AGC_ALGORITHM_OUTPUT_NONE) {
        /* Same contract as a live provider response: an unset oneof is not
         * a valid artifact, whether it never appeared in the stream or the
         * stream is simply empty. */
        rc = AGC_ERR_PROVIDER_CONTRACT_VIOLATION;
    }

    if (rc != AGC_OK) {
        for (size_t i = 0; i < ctx_count; i++) { free((void *)ctx_items[i].key); free((void *)ctx_items[i].value); }
        free(ctx_items);
        agc_metadata_free(md);
        return rc;
    }

    md->user_context = ctx_items;
    md->user_context_count = ctx_count;
    *out_md = md;
    return AGC_OK;
}

/* --------------------------------------------------------------------------
 * Accessors
 * -------------------------------------------------------------------------- */

uint32_t agc_metadata_key_version(const agc_metadata *md) { return md ? md->key_version : 0; }
const char *agc_metadata_api_version(const agc_metadata *md) { return md ? md->api_version : ""; }
const char *agc_metadata_encoding(const agc_metadata *md) { return md ? md->encoding : ""; }
agc_algorithm_output_kind agc_metadata_output_kind(const agc_metadata *md)
{
    return md ? md->kind : AGC_ALGORITHM_OUTPUT_NONE;
}

static agc_rc copy_out(const uint8_t *p, size_t n, agc_buf out, size_t *out_len)
{
    if (!out_len) return AGC_ERR_INVALID_ARGUMENT;
    *out_len = n;
    if (out.data == NULL) return AGC_OK;
    if (out.cap < n) return AGC_ERR_BUFFER_TOO_SMALL;
    if (n) memcpy(out.data, p, n);
    return AGC_OK;
}

agc_rc agc_metadata_aead_nonce(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_AEAD) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.aead.nonce, md->out.aead.nonce_len, out, out_len);
}

agc_rc agc_metadata_aead_tag_len(const agc_metadata *md, uint32_t *out_bytes)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_AEAD || !out_bytes) return AGC_ERR_INVALID_ARGUMENT;
    *out_bytes = md->out.aead.tag_length_bytes;
    return AGC_OK;
}

agc_rc agc_metadata_block_iv(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.block_cipher.iv, md->out.block_cipher.iv_len, out, out_len);
}

agc_rc agc_metadata_counter_block(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_COUNTER_MODE) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.counter_mode.counter_block, md->out.counter_mode.counter_block_len, out, out_len);
}

agc_rc agc_metadata_counter_bits(const agc_metadata *md, uint32_t *out_bits)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_COUNTER_MODE || !out_bits) return AGC_ERR_INVALID_ARGUMENT;
    *out_bits = md->out.counter_mode.counter_bits;
    return AGC_OK;
}

agc_rc agc_metadata_stream_nonce(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_STREAM_CIPHER) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.stream_cipher.nonce, md->out.stream_cipher.nonce_len, out, out_len);
}

agc_rc agc_metadata_stream_block_counter(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_STREAM_CIPHER) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.stream_cipher.block_counter, md->out.stream_cipher.block_counter_len, out, out_len);
}

agc_rc agc_metadata_kdf_salt(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_KDF) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.kdf.salt, md->out.kdf.salt_len, out, out_len);
}

agc_rc agc_metadata_kdf_iv(const agc_metadata *md, agc_buf out, size_t *out_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_KDF) return AGC_ERR_INVALID_ARGUMENT;
    return copy_out(md->out.kdf.iv, md->out.kdf.iv_len, out, out_len);
}

size_t agc_metadata_vendor_param_count(const agc_metadata *md)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_VENDOR) return 0;
    return md->out.vendor.count;
}

agc_rc agc_metadata_vendor_param_at(const agc_metadata *md, size_t index,
                                     const char **out_key, agc_buf out_value, size_t *out_value_len)
{
    if (!md || md->kind != AGC_ALGORITHM_OUTPUT_VENDOR || index >= md->out.vendor.count || !out_key)
        return AGC_ERR_INVALID_ARGUMENT;
    *out_key = md->out.vendor.items[index].key;
    return copy_out(md->out.vendor.items[index].value.data, md->out.vendor.items[index].value.len,
                     out_value, out_value_len);
}

size_t agc_metadata_user_context_count(const agc_metadata *md)
{
    return md ? md->user_context_count : 0;
}

agc_rc agc_metadata_user_context_at(const agc_metadata *md, size_t index,
                                     const char **out_key, const char **out_value)
{
    if (!md || index >= md->user_context_count || !out_key || !out_value) return AGC_ERR_INVALID_ARGUMENT;
    *out_key = md->user_context[index].key;
    *out_value = md->user_context[index].value;
    return AGC_OK;
}

const char *agc_metadata_user_context_get(const agc_metadata *md, const char *key)
{
    if (!md || !key) return NULL;
    for (size_t i = 0; i < md->user_context_count; i++) {
        if (strcmp(md->user_context[i].key, key) == 0) return md->user_context[i].value;
    }
    return NULL;
}
