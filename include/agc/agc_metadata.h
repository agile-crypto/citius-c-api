/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_metadata.h — OperationMetadata: caller-allocated representation and
 * its two byte encodings.
 *
 * HAND-WRITTEN. Replaces the opaque agc_metadata handle and its accessors
 * that agc_core.h carried up to commit 14. Design: docs/representing_metadata.md
 * (option A-view for responses, option C with pointer arms for the decoded
 * form); rules: docs/agc_crypto.md.
 *
 * TWO FORMS, ONE RULE
 * -------------------
 * Every operation that produces metadata returns it ENCODED, in the byte
 * encoding the request named (agc_encoding), into a caller region, with
 * key_version copied out as a scalar. That is the form the caller stores
 * next to the ciphertext and hands back to decrypt/verify. Callers that need
 * fields decode those bytes into a caller-allocated agc_metadata with
 * agc_metadata_decode(). Nothing here is allocated by the library.
 *
 * STATUS: declarations only. Implementation follows in the next step; see
 * docs/implementation_progress.md.
 */

#ifndef AGC_METADATA_H
#define AGC_METADATA_H

#include "agc_abi.h"
#include "agc_types.h"
#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Encodings
 * -------------------------------------------------------------------------- */

/* Byte encoding of OperationMetadata. Its numeric value IS byte 0 of every
 * encoded metadata and of every envelope (docs/representing_metadata.md §6.1,
 * §7). UNSPECIFIED is rejected wherever an encoding is required. */
typedef enum agc_encoding {
    AGC_ENCODING_UNSPECIFIED = 0,
    AGC_ENCODING_PROTOBUF    = 1,   /* OperationMetadata protobuf wire encoding */
    AGC_ENCODING_WIRE_V1     = 2    /* fixed layout, canonical, O(1) to parse; see docs/representing_metadata.md §6 */
    AGC_ENUM32(agc_encoding)
} agc_encoding;


/* --------------------------------------------------------------------------
 * ProviderOutput, decoded
 * -------------------------------------------------------------------------- */

/* C projection of ProviderOutput {string encoding; oneof algorithm_output}.
 *
 * Every agc_slice and agc_kb_list below POINTS INTO THE CALLER'S STORAGE
 * REGION (agc_metadata.storage) when produced by agc_metadata_decode(), and
 * into whatever caller memory the caller chose when the struct is built by
 * hand for agc_metadata_encode(). The library never allocates behind them
 * and never frees them. Exactly one arm of `u` is live, selected by `kind`;
 * AGC_INIT() leaves the others zero. agc_metadata_decode() never produces a
 * `kind` this header does not name (contract point 7).
 *
 * Slice arms are a v1 choice (docs/agc_crypto.md); they keep the struct
 * size independent of any single algorithm's output length at the cost of
 * requiring storage on every decode. This may change once needs and
 * constraints have been evaluated in use. */
typedef struct agc_provider_output {
    char                      encoding[AGC_OUTPUT_ENCODING_MAX_LEN]; /* formatting of ciphertext and outputs */
    agc_algorithm_output_kind kind;                          /* 10..16; NONE never appears after a successful decode */
    union {
        /* AGC_ALGORITHM_OUTPUT_NO_OUTPUT: no fields. */

        struct {
            agc_slice nonce;      /* data in caller storage */
            uint32_t  tag_len;    /* authentication tag length in bytes */
        } aead;

        struct {
            agc_slice iv;         /* data in caller storage */
        } block_cipher;

        struct {
            agc_slice counter_block;  /* data in caller storage */
            uint32_t  counter_bits;
        } counter_mode;

        struct {
            agc_slice nonce;          /* data in caller storage */
            agc_slice block_counter;  /* data in caller storage */
        } stream_cipher;

        struct {
            agc_slice salt;       /* data in caller storage */
            agc_slice iv;         /* data in caller storage */
        } kdf;

        struct {
            /* VendorOutput.parameters (map<string, bytes>), decoded. The
             * agc_kb items array, the NUL-terminated keys and the value bytes
             * all live in caller storage. */
            agc_kb_list params;
        } vendor;
    } u;
} agc_provider_output;

/* --------------------------------------------------------------------------
 * OperationMetadata, decoded
 * -------------------------------------------------------------------------- */

/* Caller-allocated decoded form of OperationMetadata. Produced by
 * agc_metadata_decode(); consumed by agc_metadata_encode(); may also be
 * built by hand for the rare case of synthesising metadata.
 *
 * DESCRIPTIVE ONLY: this record carries no storage of its own. Everything
 * variable-length -- the bytes behind every agc_slice of provider_output and
 * the items and strings behind user_context -- lives in the enclosing
 * agc_decode_metadata_result's storage when the library fills it, and in
 * caller memory when the caller builds one by hand. */
typedef struct agc_metadata {
    size_t              struct_size;                        /* AGC_INIT() sets it */
    uint32_t            key_version;                        /* version of the key that produced the artifact */
    char                api_version[AGC_API_VERSION_MAX_LEN];/* "major.minor", NUL-terminated */
    agc_provider_output provider_output;
    agc_kv_list         user_context;   /* items array and NUL-terminated strings in the result's
                                         * storage after decode; caller memory when built by hand */
} agc_metadata;

/* The decode result: the record plus the region it points into. Every
 * function that produces an agc_metadata fills one of these. */
typedef struct agc_decode_metadata_result {
    size_t       struct_size;
    agc_metadata metadata;
    agc_buf      storage;       /* IN: caller region for every variable-length value */
    size_t       storage_used;  /* OUT: bytes consumed, or required */
} agc_decode_metadata_result;

/* --------------------------------------------------------------------------
 * Codec
 * -------------------------------------------------------------------------- */

/* Encodes *md in `enc`. Output begins with the encoding byte.
 *
 * Two-call: if out.data is NULL or out.cap < required, returns
 * AGC_ERR_BUFFER_TOO_SMALL with *out_len set to the required length and
 * writes nothing; otherwise writes *out_len bytes and returns AGC_OK.
 * Reads md->provider_output and md->user_context through their pointers
 * wherever they live. Fails with
 * AGC_ERR_INVALID_ARGUMENT for a value the encoding cannot express (e.g. an
 * api_version that is not "major.minor" with both parts in 0..255, or an
 * encoding token outside {"", "raw", "der", "jws", "cbor"} under WIRE_V1). */
AGC_API agc_rc agc_metadata_encode(const agc_metadata *md, agc_encoding enc,
                                   agc_buf out, size_t *out_len);

/* Decodes `encoded` -- encoding byte first -- into *out.
 *
 * CONTRACT
 *  1. `enc` must equal encoded.data[0]; otherwise AGC_ERR_INVALID_ARGUMENT.
 *     The byte is authoritative in storage; the argument is a cross-check
 *     against a caller that lost track of what it stored.
 *  2. Validation precedes every write. Every length field within the slice,
 *     every length within the width of its field, and -- for PROTOBUF --
 *     canonical form (ascending fields, no duplicates, minimal varints;
 *     docs/representing_metadata.md §4.1). There is no maximum encoded
 *     length. On failure no field of *out is written except as stated in 4.
 *  3. Scalars are written inline into out->metadata: key_version,
 *     api_version, provider_output.encoding, provider_output.kind.
 *  4. Every variable-length value is COPIED into out->storage, and the
 *     corresponding agc_slice, out->metadata.user_context.items or
 *     vendor.params.items is set to point into it: first the agc_kv and
 *     agc_kb item arrays (8-byte aligned), then the NUL-terminated
 *     user-context strings and
 *     vendor keys, then the byte values (nonce, IV, salt, counter block,
 *     vendor parameter values). out->storage_used receives the bytes
 *     consumed. A VENDOR arm is decoded into agc_kb_list by the vendor
 *     provider's own decoder (protobuf: the VendorOutput message; WIRE_V1:
 *     the vendor-defined layout, docs/representing_metadata.md §6.3); a
 *     VENDOR arm whose provider is not registered is rejected with
 *     AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND.
 *       - If out->storage.data is NULL, or out->storage.cap is smaller than
 *         required: AGC_ERR_BUFFER_TOO_SMALL, out->storage_used = bytes
 *         required, nothing else written. NULL is therefore the size query.
 *       - Metadata with kind NO_OUTPUT and no user context requires 0 bytes
 *         and succeeds with storage.data NULL; storage_used is 0.
 *  5. Nothing in *out references `encoded` after return. *out is valid for
 *     as long as out->storage is, and may be read concurrently provided
 *     storage is not modified.
 *  6. The caller MUST AGC_INIT(out) before the call and may then set only
 *     out->storage.
 *  7. A `kind` this header does not name is rejected with
 *     AGC_ERR_INVALID_ARGUMENT: no arm exists to receive it, and the wire
 *     format forbids unknown kinds by design (docs/representing_metadata.md
 *     §6). Fail-closed; an older library could not have used the algorithm
 *     anyway. */
AGC_API agc_rc agc_metadata_decode(agc_encoding enc, agc_slice encoded,
                                   agc_decode_metadata_result *out);

/* As agc_metadata_decode, for a body that lacks its encoding byte -- the
 * pair agc_envelope_split() returns. Identical contract otherwise. */
AGC_API agc_rc agc_metadata_decode_body(agc_encoding enc, agc_slice body,
                                        agc_decode_metadata_result *out);

/* Exact number of storage bytes agc_metadata_decode() would require for
 * `encoded` (encoding byte first), computed from its length fields alone.
 * 0 when no storage is needed. Performs the same validation as decode and
 * fails the same way; never allocates. */
AGC_API agc_rc agc_metadata_storage_len(agc_encoding enc, agc_slice encoded, size_t *out_len);

/* key_version of `encoded` (encoding byte first) without a full decode.
 * WIRE_V1: a bounds check and one big-endian load. PROTOBUF: the same
 * strict canonical scan decode performs -- there is no cheaper read that
 * agrees with the decoder on every input. Cross-checks `enc` as decode does. */
AGC_API agc_rc agc_metadata_peek_key_version(agc_encoding enc, agc_slice encoded, uint32_t *out);

/* Upper bound on the encoded length (encoding byte included) that an
 * operation on `key_name` will produce in `enc` with `user_context`, for
 * callers that pre-size and never size-query. Consults the key's template
 * for the arm and the provider for vendor output. Returns 0 if the key is
 * unknown. */
AGC_API size_t agc_metadata_max_encoded_len(agc_ctx *ctx, const char *key_name,
                                            agc_encoding enc, agc_kv_list user_context);

/* --------------------------------------------------------------------------
 * Envelope: encoding byte ‖ metadata_len u16 BE ‖ metadata body ‖ ciphertext
 * (docs/representing_metadata.md §7). Pure slicing: three loads, two bounds
 * checks, no copy, no parse of the body.
 * -------------------------------------------------------------------------- */

/* Splits `envelope` into its encoding, its metadata body (WITHOUT the
 * encoding byte; feed it to agc_metadata_decode_body) and its ciphertext.
 * Both output slices point into `envelope`. AGC_ERR_INVALID_ARGUMENT if the
 * envelope is shorter than its header claims or byte 0 is not a known
 * encoding. */
AGC_API agc_rc agc_envelope_split(agc_slice envelope, agc_encoding *out_encoding,
                                  agc_slice *out_metadata_body, agc_slice *out_ciphertext);

#ifdef __cplusplus
}
#endif
#endif /* AGC_METADATA_H */
