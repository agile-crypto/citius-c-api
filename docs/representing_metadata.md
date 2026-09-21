# Representing `OperationMetadata` in the C API

Status: design study. Companion to `RECONCILIATION_PLAN.md` D6/D11 and to
`tink-wire-format-vs-protobuf.md`. Numbers quoted here were measured on this
tree (`src/wire/metadata_codec.c`, stub backend) compiled with clang at `-O2`
on an Apple Silicon laptop; sources and instructions are in
`measurements/metadata_discussion/`. They are indicative, not a benchmark
suite.

## 1. Scope

Every data-plane operation (`agc_encrypt`, `agc_sign`, `agc_wrap_key`, ...)
produces an `OperationMetadata` alongside its primary bytes. The caller must
persist it with the artifact and hand it back at decrypt/verify time. Today it
is an opaque, library-allocated handle (`agc_metadata *`) with ~30 accessors
and a protobuf codec behind `agc_metadata_encode` / `agc_metadata_decode`.

This document fixes two things that were open:

1. **Representation** -- what the response of an encrypt-shaped call carries,
   given that everything is caller-allocated. Three options: **A** encoded
   bytes (bare, or with a `key_version` convenience field), **B** a partial
   struct whose algorithm output is still encoded, **C** a fully projected
   struct.
2. **Encoding** -- the byte form the caller stores. Two encodings coexist,
   selected per request by an enum: **protobuf** (`OperationMetadata` from
   `github.com/agile-crypto/api`, for compatibility with the Go service) and a
   **fixed wire format** specified in §6.

### 1.1 Terminology

- **Provider**: the cryptographic backend -- the stub in this tree, OpenSSL,
  an HSM, a cloud KMS. A provider returns native values: a nonce from
  `RAND_bytes`, a tag length from the cipher parameters, an HSM mechanism's
  output.
- **Provider adapter**: the library code that turns those native values into
  the C projection below. In this tree the stub fills `agc__metadata_build`
  (`src/agc_internal.h`) and the core wraps it.
- **`ProviderOutput`**: the proto message at `OperationMetadata.provider_output`
  = `{ string encoding; oneof algorithm_output }`. Its C projection is
  `agc_provider_output` (§2).
- **`AlgorithmOutput`**: the `algorithm_output` oneof alone, one of seven arms
  tagged 10..16.

Every representation starts from the same point: the adapter has produced an
`agc_provider_output`. That step costs the same under A, B and C and is
outside the comparison. `agc_metadata_decode()` decodes both encodings into
option C's struct regardless of which representation the response carries.

## 2. The three representations

Common definitions, all in the public headers:

```c
typedef enum agc_encoding {
    AGC_ENCODING_UNSPECIFIED = 0,   /* rejected wherever an encoding is required */
    AGC_ENCODING_PROTOBUF    = 1,   /* OperationMetadata protobuf wire encoding */
    AGC_ENCODING_WIRE_V1     = 2    /* fixed layout, §6 */
    AGC_ENUM32(agc_encoding)
} agc_encoding;

#define AGC_MD_API_VERSION_MAX   8   /* "major.minor" + NUL */
#define AGC_MD_ENCODING_MAX     16   /* ProviderOutput.encoding token + NUL */
#define AGC_MD_NONCE_MAX        32
#define AGC_MD_IV_MAX           32
#define AGC_MD_COUNTER_MAX      32
#define AGC_MD_SALT_MAX         64
#define AGC_MD_MAX_ENCODED_LEN  4096 /* decode refuses longer input */

/* ProviderOutput projected. `encoding` describes the formatting of the
 * ciphertext and algorithm output ("raw", "der", "jws", "cbor"). */
typedef struct agc_provider_output {
    char                      encoding[AGC_MD_ENCODING_MAX];
    agc_algorithm_output_kind kind;
    union {
        struct { uint8_t nonce[AGC_MD_NONCE_MAX]; uint8_t nonce_len; uint32_t tag_len; }              aead;
        struct { uint8_t iv[AGC_MD_IV_MAX]; uint8_t iv_len; }                                          block_cipher;
        struct { uint8_t counter_block[AGC_MD_COUNTER_MAX]; uint8_t counter_block_len;
                 uint32_t counter_bits; }                                                              counter_mode;
        struct { uint8_t nonce[AGC_MD_NONCE_MAX]; uint8_t nonce_len;
                 uint8_t block_counter[16]; uint8_t block_counter_len; }                              stream_cipher;
        struct { uint8_t salt[AGC_MD_SALT_MAX]; uint8_t salt_len;
                 uint8_t iv[AGC_MD_IV_MAX]; uint8_t iv_len; }                                          kdf;
        struct { agc_slice params; }   /* encoded VendorOutput.parameters; after decode, a copy
                                          in the caller's storage region (§5.3) */                   vendor;
    } u;
} agc_provider_output;
```

Measured: `sizeof(agc_provider_output) == 128`; the union is 104 (the
98-byte kdf arm rounded up to the 8-byte alignment the vendor pointer
imposes). Arms: aead 40, block 33, counter 40, stream 50, kdf 98, vendor 16.
Only one arm is live, selected by `kind`; `AGC_INIT()` zeroes the rest.

The array bounds cover every algorithm named in `agc_types.h` with margin:

| Bound | Largest real need |
|---|---|
| nonce 32 | 24 (XChaCha20); 16 (Ascon, GCM with non-standard nonce) |
| iv 32 | 16 (AES, Camellia, ARIA, SM4, Kuznyechik); 8 (3DES, Magma) |
| counter block 32 | 16 (block size) |
| salt 64 | 64 (HKDF-SHA512 hash-length salt); 16-32 (Argon2, PBKDF2) |

They are ABI. Growing one is a `struct_size` event (`AGC_FIELD_FITS`); a
provider value that does not fit an older caller's struct returns
`AGC_ERR_ABI_MISMATCH`, never a truncated nonce.

### 2.1 Option A -- encoded bytes

The response carries the metadata already encoded in the encoding the request
asked for, encoding byte first. This is the representation the API returns
(§5.2, §8). Two variants:

- **A-bare**: bytes only. Scalars are read with `agc_metadata_peek_*` or, under
  the wire format, at documented offsets.
- **A-view**: bytes plus a `key_version` convenience field, a copy of the value
  inside the bytes. Nothing else is projected.

```c
typedef struct agc_encrypt_response {
    size_t   struct_size;
    agc_buf  ciphertext;      /* in: caller region; out: ciphertext_len */
    size_t   ciphertext_len;
    agc_buf  metadata;        /* in: caller region; out: encoded metadata, encoding byte first */
    size_t   metadata_len;
    uint32_t key_version;     /* A-view only; equals the value inside `metadata` */
} agc_encrypt_response;
```

Measured: the metadata descriptor (`agc_buf` + length) is 24 bytes; the
A-view field adds 8 after padding.

### 2.2 Option B -- partial struct, algorithm output encoded

Scalars are C fields. Only the `AlgorithmOutput` arm stays encoded, in a
caller region, in the encoding the request asked for; a field records which.
Nothing appears twice: `kind` is inside the arm bytes under both encodings
(§6.4), `encoding` is a field and not in the region. A separate
`agc_metadata_encode()` call assembles the final bytes.

```c
typedef struct agc_metadata_partial {
    size_t       struct_size;
    uint32_t     key_version;
    char         api_version[AGC_MD_API_VERSION_MAX];
    char         encoding[AGC_MD_ENCODING_MAX];   /* ProviderOutput.encoding */
    agc_kv_list  user_context;                    /* borrowed from the request */
    agc_encoding algorithm_output_encoding;       /* format of the region below */
    agc_buf      algorithm_output;                /* in: caller region; out: encoded AlgorithmOutput (§6.4) */
    size_t       algorithm_output_len;
} agc_metadata_partial;

typedef struct agc_encrypt_response {
    size_t               struct_size;
    agc_buf              ciphertext;
    size_t               ciphertext_len;
    agc_metadata_partial metadata;
} agc_encrypt_response;
```

Measured: `sizeof(agc_metadata_partial) == 88`. The region holds 18 bytes
(protobuf arm) or 17 bytes (wire arm) in the reference case.

The "owned pointer" fields of the internal handle (`char *api_version` etc.)
must not appear here: owned pointers in a caller-allocated struct mean
library heap allocation and a free function, which is what the exercise
removes.

### 2.3 Option C -- fully projected struct

Nothing is encoded in memory. Every fixed-size field, including every
standard algorithm arm, lives inline. The two things that cannot be bounded
-- user-context strings and vendor parameters -- live in a caller-provided
`storage` region: on decode the library copies them there, and
`user_context` and the vendor arm point into it. The struct never references
the encoded bytes it was decoded from. This is the decoded form that
`agc_metadata_decode()` produces under both encodings (§5.3); it was also
studied as a response type, and the response struct below is that variant.

```c
typedef struct agc_metadata {
    size_t              struct_size;
    uint32_t            key_version;
    char                api_version[AGC_MD_API_VERSION_MAX];
    agc_provider_output provider_output;   /* vendor arm's params: in storage after decode */
    agc_kv_list         user_context;      /* items and NUL-terminated strings: in storage after decode;
                                              borrowed from the caller when constructing by hand */
    agc_buf             storage;           /* IN to decode: region for user context and vendor params */
    size_t              storage_used;      /* OUT from decode */
} agc_metadata;

/* The response variant studied as option C. Not what the API returns. */
typedef struct agc_encrypt_response_c {
    size_t       struct_size;
    agc_buf      ciphertext;
    size_t       ciphertext_len;
    agc_metadata metadata;
} agc_encrypt_response_c;
```

Measured: `sizeof(agc_metadata) == 192`, of which `provider_output` is 128
at offset 24 and the `storage` descriptor is the last 24; 168 without it.
A decoded metadata with a standard arm and no user context is fully
self-contained and leaves `storage` untouched.

## 3. Comparison

Reference case for every row: AEAD, 12-byte nonce, `tag_length_bytes = 16`,
`key_version = 3`, `api_version = "1.0"`, `encoding = "raw"`, empty
`user_context`, no vendor parameters. A second figure, where given, is for
two `user_context` pairs (`tenant=acme`, `request-id=7f3a9c2e-1b4d-4e8f`).
Encoded sizes for the reference case: protobuf 33 B standalone (32 body +
encoding byte), wire 26 B (25 + byte). In tables where a cell holds a result
and an explanation, the result is on the first line.

### 3.1 Total size of the metadata

Caller-visible footprint: bytes the caller must hold for the metadata to be
complete and usable, before any separate encoded copy.

| | Protobuf encoding | Wire format |
|---|---|---|
| **A-bare** | **57 B**<br>24 B descriptor + 33 B encoded | **50 B**<br>24 B + 26 B |
| **A-view** | **65 B**<br>A-bare + 8 B for the padded field | **58 B** |
| **B** | **106 B**<br>88 B struct + 18 B encoded arm; a further 33 B buffer when encoded | **105 B**<br>88 B + 17 B; a further 26 B when encoded |
| **C** | **192 B**<br>self-contained for standard arms; 168 B without the storage descriptor; a further 33 B when encoded | **192 B**<br>a further 26 B when encoded |

With two user-context pairs the encoded forms grow to 83 B (protobuf) and
72 B (wire); B and C borrow the request's list and do not grow in memory.

C reserves the worst-case arm. A is the smallest because the encoded form
*is* the only copy. B is between the two; it holds no field twice.

### 3.2 Accessing `key_version` in process, after encryption, protobuf encoding

| | Cost |
|---|---|
| **A-bare** | **4.6 ns** (7.6 ns with 2 user-context pairs)<br>decoder-equivalent strict scan of the whole message. A 0.46 ns "read the first field" shortcut exists but is **not decoder-equivalent** and must not be used (§4.1). |
| **A-view** | **field, ~0** |
| **B** | **field, ~0** |
| **C** | **field, ~0** |

### 3.3 Accessing `key_version` in process, wire format

| | Cost |
|---|---|
| **A-bare** | **0.22 ns**<br>bounds check + big-endian 32-bit load at the fixed offset of §6.2 |
| **A-view** | **field, ~0** |
| **B** | **field, ~0** |
| **C** | **field, ~0** |

Under the wire format the encoded bytes expose every scalar at a documented
offset; A-bare's peek is as cheap as a field read.

### 3.4 Cost of full encoding

"Full encoding" is producing the final stored bytes, starting from the
`agc_provider_output` the adapter produced (common to all rows, excluded).

| | Protobuf | Wire format |
|---|---|---|
| **A** (bare or view) | **15-20 ns**<br>one pass into the caller buffer, no allocation (measured 19.5 ns two-pass, 14.5 ns pre-sized) | **5.0 ns**<br>one pass |
| **B**, region in the target encoding | **~20-25 ns**<br>encode the arm into the region at encrypt time, then `encode_metadata` concatenates scalars around the arm bytes verbatim -- no parse of the arm | **9.0 ns**<br>copy the arm into the region (2.8 ns), then `encode_metadata` writes the header and copies the arm into place |
| **B**, region in the other encoding | **+ ~5 ns**<br>`encode_metadata` must parse the arm and re-encode it | **+ ~5 ns** |
| **B'**, reserved header | n/a | **3.9 ns**<br>the adapter writes the arm straight into the final buffer past the fixed-size header slot; `encode_metadata` fills the header in place, no second copy |
| **C** | **15-20 ns**, + ~3 ns if `provider_output` is copied into the response rather than written in place | **5 ns**, + ~3 ns likewise |

Protobuf is concatenative: an embedded message is `tag ‖ varint(len) ‖
bytes`. B's `encode_metadata` builds `ProviderOutput` as `0a ‖ len ‖ encoding`
followed by the arm bytes verbatim, wraps it as `12 ‖ len ‖ ProviderOutput`,
and never looks inside the arm. That is the "build only what is missing"
property; both lengths are arithmetic on known sizes. Under the wire format
the arm bytes (§6.4) are the header bytes 7..10+L, so `encode_metadata`
places them with one copy at a fixed offset. The explicit
`algorithm_output_encoding` field makes the cross-encoding case detectable
rather than implicit; with the region written in the request's encoding the
common path never takes it.

For comparison, the current handle path (create handle, two-call encode,
free) costs 303 ns for the same 32 bytes and 812 ns with two user-context
pairs, because it performs 4+ heap allocations and re-runs the encoder for
the size query.

### 3.5 Cost of full decoding

"Full decoding" is bytes → `agc_metadata` (option C's struct) via
`agc_metadata_decode`, the same function under every representation.

| | Protobuf | Wire format |
|---|---|---|
| **bytes → `agc_metadata`** | **8.5-11 ns**<br>strict parse into a stack struct, no allocation; the reference case has no user context, so nothing is written to storage | **2-3 ns**<br>fixed loads + one `memcpy` of the arm |
| same, with user context or vendor params | **+ ~1 ns per 16 B copied**<br>strings become NUL-terminated `agc_kv` pairs in storage; vendor bytes copied once | **same** |
| **bytes → `agc_metadata_partial`** (B only, if wanted) | **~6 ns**<br>scan the top level and one level into `ProviderOutput` to split `encoding` from the arm; the arm itself is sliced, not parsed | **~2 ns**<br>header loads + 17-byte copy |

Decode is the same function under every representation; A, B and C differ
only in what the response carried before it.

For comparison, the current handle decode (allocate handle, parse, read nonce
via accessor, free) is 147 ns, 291 ns with two user-context pairs, and its
allocation count is driven by attacker-controlled entry counts.

### 3.6 Cost of reading the provider output

Reading `kind` and the nonce from the representation the response carries.

| | Protobuf | Wire format |
|---|---|---|
| **A-bare / A-view** | **~9 ns**<br>a parse is required; there is no fixed offset | **~1 ns**<br>fixed offsets (§6.2, §6.3) |
| **B** | **kind ~1 ns, nonce ~5 ns**<br>`kind` is the arm's tag, a 1-2 byte varint at region offset 0; the nonce needs the arm parsed | **~1 ns**<br>`kind` at region offset 0, nonce at offset 4 |
| **C** | **field, ~0**<br>`md.provider_output.u.aead.nonce`, no library call | **field, ~0** |

C is the only representation in which the caller reads the nonce with no
library call and no format knowledge.

### 3.7 Complexity of memory allocation by the caller

**Scenario A: encrypt with `ciphertext.data == NULL` and `metadata.data ==
NULL`; the library returns both lengths, performs no cryptography, and draws
no randomness.**

- One size query, then one or two regions (the caller may carve both from
  one allocation to keep ciphertext and metadata adjacent), then one call.
- The metadata length for standard arms has a compile-time bound,
  `AGC_MD_MAX_ENCODED_LEN_STD` (§6.6), and the ciphertext length is
  `plaintext_len + tag_len`, so a caller that uses the bounds skips the
  query entirely: zero queries, one allocation or a stack buffer.
- Failure mode: `AGC_ERR_BUFFER_TOO_SMALL` before any provider work.

**Scenario B: encrypt with `ciphertext.data == NULL` and
`metadata.algorithm_output.data == NULL`; the library returns both lengths.**

- Same query count as Scenario A for the encrypt call; the struct itself
  lives on the stack and only the arm region is sized. Its bound is static
  and small (`AGC_MD_ARM_MAX_STD`, §6.6).
- Producing the stored bytes then needs a **second** region for
  `agc_metadata_encode`, sized by a second query or by
  `AGC_MD_MAX_ENCODED_LEN_STD`. So B costs two caller regions for the
  metadata against A's one, unless the B' reserved-header layout is used, in
  which case the region *is* the final buffer and B collapses into A.

**Option C as a response**, for completeness: no metadata region at all for
standard arms; the struct is on the stack. One allocation (ciphertext) plus
a statically bounded buffer if and when the caller encodes. A region is
needed only for a vendor key (bound from the provider's declared
`max_metadata_bytes` capability, or the two-call fallback).

**Decoding into C**, under every representation: `storage` is needed only
when the encoded metadata carries user context or vendor parameters. A
standard arm with no user context decodes with `storage.data == NULL`, the
`AGC_INIT` default. When storage is needed, its exact size is available
three ways: `agc_metadata_decode` with an absent or too-small region returns
`AGC_ERR_BUFFER_TOO_SMALL` with `storage_used` set to the requirement;
`agc_metadata_storage_len(encoded)` computes it from the length fields alone
(a few loads under the wire format); or the static bound
`AGC_MD_STORAGE_BOUND(encoded_len) = 6 * encoded_len`, since each map entry
costs at least 4 encoded bytes and at most 2 NULs plus one 16-byte `agc_kv`
in storage, and vendor bytes copy one-for-one. A caller reading back its own
artifacts knows whether it wrote user context and sizes a stack buffer from
the blob length.

### 3.8 Summary

| Axis | A-bare | A-view | B | C |
|---|---|---|---|---|
| in-memory size, wire / protobuf | 50 / 57 B | 58 / 65 B | 105 / 106 B<br>+ final buffer | 192 B<br>+ final buffer |
| key_version, protobuf, in process | 4.6 ns peek | field | field | field |
| key_version, wire, in process | 0.22 ns | field | field | field |
| full encode, protobuf / wire | 15-20 / 5 ns | same | ~22 / 9 ns<br>4 ns as B'; +5 ns cross-encoding | 15-20 / 5 ns<br>+3 ns if copied |
| full decode to `agc_metadata`, protobuf / wire | 9-11 / 2-3 ns | same | same | same |
| read nonce, protobuf / wire | 9 / 1 ns | 9 / 1 ns | 5 / 1 ns | field |
| caller regions for metadata | 1 | 1 | 2<br>1 as B' | 0 standard<br>1 vendor; decode: 1 if user context or vendor present |
| caller reads fields without the library | wire offsets only | key_version | scalars yes, arm no | yes |
| state held twice | none | key_version | none | none |

Every cost above is under 25 ns and under 2% of the ~1.3 µs `agc_encrypt`
call measured on the stub backend. **Cost does not decide between A, B and
C.** What does: A is the smallest, has one source of truth, and hands the
caller exactly what the caller does next with metadata, which is store it;
C is the only transparent one; B sits between, transparent for scalars and
opaque for the arm, at the price of a second caller region unless B' is
used. A and C compose: the response carries A-view, and `agc_metadata_decode`
turns A's bytes into C for the caller who wants fields.

## 4. Protobuf versus the wire format

| Property | Protobuf `OperationMetadata` | Wire format v1 (§6) |
|---|---|---|
| Interop with the Go service | **yes**<br>the reason it exists (D11) | **no**<br>until specified in `github.com/agile-crypto/api` |
| Size, reference case | 33 B | 26 B |
| Size growth | varint lengths, tags per field | fixed header; per-entry length prefixes only for user context |
| Encoding uniqueness | **no**<br>field order, non-minimal varints, duplicates, unknown fields all yield distinct byte strings for one value | **yes**<br>exactly one byte string per value |
| Canonical form for use as AEAD associated data | needs a defined canonicalisation (sorted maps, minimal varints) that protobuf does not guarantee across libraries | canonical by construction |
| Parse cost on untrusted bytes | **O(fields), attacker-chosen**<br>4.6 ns normal, 410 ns on a valid 1 KiB message of 512 tiny fields | **O(1)**<br>header and fixed fields |
| Peek `key_version` | full strict scan, to be decoder-equivalent (§4.1) | one load |
| Allocation before authentication | none in this library's zero-copy decoder; the current handle decoder allocates per map entry | none |
| Schema evolution | unknown fields skipped: an old binary passes newer metadata through storage untouched | version byte; new fields need a new version and a parser branch |
| Variable-length fields (`user_context`, vendor map) | native | length-prefixed trailer; vendor arm in a vendor-defined fixed layout (§6.3) |
| `ProviderOutput.encoding` string | open set | closed byte enum (§6.2); unknown tokens cannot be expressed |
| Cross-implementation agreement on `key_version` | only if every decoder applies identical last-wins / duplicate rules | by construction |

The security argument from `tink-wire-format-vs-protobuf.md` applies
one-to-one: metadata is parsed before any key is selected and before
anything is authenticated, so a unique, offset-addressable encoding with no
length-driven parsing is preferable there. The compatibility argument keeps
protobuf: a C-encrypted artifact must decrypt in Go. Hence both, selected per
request.

### 4.1 Decoder policy for protobuf input

The library's protobuf decoder is **strict canonical**: ascending field
numbers, no duplicate fields, minimal varints, `uint32` values within range,
total length ≤ `AGC_MD_MAX_ENCODED_LEN`. Anything else is
`AGC_ERR_INVALID_ARGUMENT`. This is a declared divergence from Go's decoder
(which accepts any order and applies last-wins) and is recorded in
`conformance/DIVERGENCES.yaml`. It is fail-closed: every blob Go's own
encoder produces is canonical and passes; only hand-crafted blobs are
refused, and on those the two implementations would otherwise disagree about
which key version a ciphertext belongs to.

## 5. API

### 5.1 Requests

Every request that produces metadata gains one field:

```c
typedef struct agc_encrypt_request {
    size_t                    struct_size;
    const char               *key_name;
    agc_slice                 plaintext;
    const agc_encrypt_params *params;
    agc_kv_list               user_context;
    agc_encoding              metadata_encoding;   /* REQUIRED; UNSPECIFIED is rejected */
} agc_encrypt_request;
```

Same for sign, digest_sign, generate_mac, digest, xof, wrap_key,
encapsulate, derive, key_agreement, decapsulate, and every streaming `*_init`.
Requests that *consume* metadata (`agc_decrypt_request.metadata`,
`agc_verify_request.metadata`, ...) take an `agc_slice` of encoded bytes; the
encoding is read from the first byte, so no enum is needed there.

### 5.2 Response

Option A-view, per §3.8 and §8:

```c
typedef struct agc_encrypt_response {
    size_t   struct_size;
    agc_buf  ciphertext;      /* in: caller region; out: ciphertext_len */
    size_t   ciphertext_len;
    agc_buf  metadata;        /* in: caller region; out: encoded metadata in req->metadata_encoding,
                                 encoding byte first, ready to store or to place in an envelope (§7) */
    size_t   metadata_len;
    uint32_t key_version;     /* copy of the value inside `metadata` */
} agc_encrypt_response;

AGC_API agc_rc agc_encrypt(agc_ctx *ctx, const agc_encrypt_request *req,
                           agc_encrypt_response *resp);
```

Size query: if either `ciphertext.data` or `metadata.data` is NULL, the call
fills both `*_len` fields, performs no provider work, draws no randomness,
and returns `AGC_OK`. If a region is present but too small, the call returns
`AGC_ERR_BUFFER_TOO_SMALL` with both `*_len` fields set, again before any
provider work. Callers that pre-size from `AGC_MD_MAX_ENCODED_LEN_STD` (§6.6)
or `agc_metadata_max_encoded_len()` never query.

### 5.3 Metadata functions

```c
/* Encode `md` in `enc`. Two-call. Output begins with the encoding byte.
 * Accepts a decoded or caller-constructed struct alike; user_context and
 * vendor params are read through their pointers wherever they live. */
AGC_API agc_rc agc_metadata_encode(const agc_metadata *md, agc_encoding enc,
                                   agc_buf out, size_t *out_len);

/* Decode either encoding (dispatch on byte 0) into *out.
 *
 * CONTRACT
 *  1. Validation first. `encoded` is checked in full before any field of
 *     *out is written: encoding byte known, total length <=
 *     AGC_MD_MAX_ENCODED_LEN, every length field within the slice, every
 *     bound of §2 respected, protobuf input canonical per §4.1. On failure
 *     *out is left as the caller passed it and the return code says why.
 *  2. Fixed-size fields are written INLINE: key_version, api_version,
 *     provider_output.encoding, provider_output.kind, and the whole of any
 *     standard arm (10..15).
 *  3. Variable-size fields -- user-context entries and vendor parameters
 *     (arm 16) -- are COPIED into out->storage:
 *       - user context becomes an array of agc_kv followed by NUL-terminated
 *         key and value strings; out->user_context.items points at the
 *         array, .count is the entry count.
 *       - vendor parameters are copied verbatim;
 *         out->provider_output.u.vendor.params points at the copy.
 *     out->storage_used receives the bytes consumed. If `encoded` carries
 *     neither, storage is not read or written, may be {NULL, 0}, and
 *     storage_used is 0. If it carries either and storage.cap is too small
 *     (including {NULL, 0}): AGC_ERR_BUFFER_TOO_SMALL, storage_used = bytes
 *     required, no other field of *out written.
 *  4. Nothing in *out references `encoded` after return. *out is valid for
 *     as long as out->storage is; a result with a standard arm and no user
 *     context references nothing outside *out at all.
 *  5. The caller MUST AGC_INIT(out) before the call and may then set only
 *     storage. *out may be read concurrently after return provided storage
 *     is not modified.
 *  6. Copies of *out by value share the same storage; the caller owns that
 *     aliasing. */
AGC_API agc_rc agc_metadata_decode(agc_slice encoded, agc_metadata *out);

/* Decode from an (encoding, body) pair, as produced by agc_envelope_split.
 * Identical contract to agc_metadata_decode on `encoding byte ‖ body`. */
AGC_API agc_rc agc_metadata_decode_body(agc_encoding enc, agc_slice body, agc_metadata *out);

/* Bytes `storage` must hold to decode `encoded`: exact, computed from the
 * length fields alone; no allocation. 0 when no storage is needed. */
AGC_API agc_rc agc_metadata_storage_len(agc_slice encoded, size_t *out_len);
#define AGC_MD_STORAGE_BOUND(encoded_len) (6 * (encoded_len))   /* static upper bound */

/* key_version without a full decode. Wire: one load. Protobuf: the strict
 * scan of §4.1 -- there is no cheaper decoder-equivalent read. */
AGC_API agc_rc agc_metadata_peek_key_version(agc_slice encoded, uint32_t *out);

/* Bounds, for callers that pre-size and never query. */
AGC_API size_t agc_metadata_max_encoded_len(agc_ctx *ctx, const char *key_name,
                                            agc_encoding enc, agc_kv_list user_context);

/* Envelope helpers, §7. Pure slicing; no copy, no parse of the body. */
AGC_API agc_rc agc_envelope_split(agc_slice envelope, agc_encoding *out_encoding,
                                  agc_slice *out_metadata_body, agc_slice *out_ciphertext);
```

`agc_metadata_encode` and `agc_metadata_decode` replace the handle-based
functions of the same name; `agc_metadata_free` and the ~30 accessors are
removed.

## 6. Wire format v1 specification

All multi-byte integers are big-endian. All lengths are in bytes. The format
is fixed: there is exactly one valid byte string for a given value, and a
decoder MUST reject any input that does not match this grammar exactly
(trailing bytes, out-of-range lengths, unknown `kind`, unknown
`encoding_id`).

### 6.1 Standalone encoded metadata

```
offset  size  field
0       1     encoding byte = 0x02 (AGC_ENCODING_WIRE_V1)
1       ...   body (§6.2)
```

For protobuf the same position holds `0x01` followed by the
`OperationMetadata` protobuf bytes. The byte is always present, in front of
both encodings; protobuf's own first byte (`0x08` for field 1) never appears
at offset 0.

### 6.2 Body header

```
offset  size  field                          source
0       1     api_major        u8            OperationMetadata.api_version "major.minor"
1       1     api_minor        u8            (encoding fails if the string is not two integers 0..255)
2       4     key_version      u32 BE        OperationMetadata.key_version
6       1     encoding_id      u8            ProviderOutput.encoding: 0 = "" (unspecified), 1 = "raw",
                                             2 = "der", 3 = "jws", 4 = "cbor"; other tokens cannot be
                                             expressed in v1 and make encoding fail
7       1     kind             u8            AlgorithmOutput tag: 10..16 (agc_algorithm_output_kind);
                                             0 is invalid
8       2     output_len       u16 BE        length of the output section (§6.3)
10      L     output           [output_len]  per-kind layout, §6.3
10+L    1     uc_count         u8            number of user_context entries (0..255)
11+L    ...   uc_entries       §6.5
```

Body length = `11 + output_len + Σ entry lengths`. Header size is fixed at
10 bytes so the library can place the output section before the header
values are known (the B' layout of §3.4). Bytes 7..10+L are exactly the
standalone `AlgorithmOutput` encoding of §6.4.

### 6.3 Output section, by `kind`

| kind | name | layout | output_len |
|---|---|---|---|
| 10 | NO_OUTPUT | empty | 0 |
| 11 | AEAD | `nonce_len u8 ‖ nonce[nonce_len] ‖ tag_len u8` | 2 + nonce_len |
| 12 | BLOCK_CIPHER | `iv_len u8 ‖ iv[iv_len]` | 1 + iv_len |
| 13 | COUNTER_MODE | `counter_block_len u8 ‖ counter_block[..] ‖ counter_bits u8` | 2 + counter_block_len |
| 14 | STREAM_CIPHER | `nonce_len u8 ‖ nonce[..] ‖ block_counter_len u8 ‖ block_counter[..]` | 2 + nonce_len + block_counter_len |
| 15 | KDF | `salt_len u8 ‖ salt[..] ‖ iv_len u8 ‖ iv[..]` | 2 + salt_len + iv_len |
| 16 | VENDOR | vendor-defined layout of its `VendorOutput.parameters` map (see below) | as the vendor defines |

Length fields are bounded by the §2 constants (`nonce_len ≤ AGC_MD_NONCE_MAX`
etc.); a decoder rejects larger values. `tag_len` and `counter_bits` are
`uint32` in the proto but never exceed 255 for any defined algorithm; v1
narrows them to `u8` and encoding fails otherwise.

**Vendor arm.** Under the wire format a vendor MUST define its own wire
layout for its proprietary algorithm outputs; protobuf does not appear
inside wire v1. The layout must be fixed and unique in the same sense as the
rest of §6: one byte string per value, every length bounded and checked, no
unknown-field mechanism. The vendor provider supplies the encoder and
decoder for its arm through the provider interface, mapping between its
bytes and the decoded `agc_kb_list` of `agc_provider_output.algorithm_output.vendor.params`;
the core places the bytes at body offset 10 and copies them verbatim, and
rejects a VENDOR arm whose provider is not registered. Under protobuf the
arm remains the `VendorOutput` message as the proto defines it, so a vendor
that supports both encodings implements two layouts of the same map.

For the reference case the output section is `0C ‖ nonce[12] ‖ 10`
(14 bytes) and the standalone encoded metadata is 26 bytes:

```
02                       encoding byte
01 00                    api 1.0
00 00 00 03              key_version 3
01                       encoding_id raw
0B                       kind AEAD
00 0E                    output_len 14
0C <12 bytes> 10         nonce_len, nonce, tag_len
00                       uc_count 0
```

### 6.4 Standalone `AlgorithmOutput` encoding (option B region)

Option B stores the arm alone, self-describing, in the encoding named by
`algorithm_output_encoding`:

| Encoding | Bytes | Reference case |
|---|---|---|
| `AGC_ENCODING_WIRE_V1` | `kind u8 ‖ output_len u16 BE ‖ output` -- identical to body bytes 7..10+L of §6.2 | 17 B: `0B 00 0E 0C <12> 10` |
| `AGC_ENCODING_PROTOBUF` | the oneof arm as it appears inside `ProviderOutput`: `tag ‖ varint(len) ‖ payload`, tag = `(kind << 3) | 2` | 18 B: `5A 10 0A 0C <12> 10 10` |

Under both, `kind` is recoverable from offset 0 (a byte, or a 1-2 byte
varint tag), so the struct does not carry it. `encode_metadata` copies the
wire form to body offset 7, or wraps the protobuf form as described in §3.4,
without parsing either.

### 6.5 User-context entries

Each entry: `key_len u16 BE ‖ key[key_len] ‖ value_len u16 BE ‖
value[value_len]`. Strings are UTF-8 without NUL terminators. Entries MUST
be sorted by key (bytewise) so that the encoding is unique; duplicate keys
are rejected, matching `agc_kv_list`'s contract. `uc_count` may be 0; the
field itself is always present.

### 6.6 Bounds

```c
/* Largest standalone wire-format metadata for a standard (non-vendor) arm
 * with no user context: 1 + 11 + (2 + AGC_MD_SALT_MAX + AGC_MD_IV_MAX) */
#define AGC_MD_MAX_ENCODED_LEN_STD  (1 + 11 + 2 + AGC_MD_SALT_MAX + AGC_MD_IV_MAX)   /* 110 */
/* Largest standalone wire-format AlgorithmOutput (§6.4) for a standard arm */
#define AGC_MD_ARM_MAX_STD          (3 + 2 + AGC_MD_SALT_MAX + AGC_MD_IV_MAX)        /* 101 */
```

A caller that never uses vendor keys or user context can allocate
`AGC_MD_MAX_ENCODED_LEN_STD` bytes on the stack and never size-query. With
user context, add `Σ (4 + key_len + value_len)`, which the caller can compute
because it supplied the list. `agc_metadata_max_encoded_len()` (§5.3) does
the same arithmetic and consults the provider for vendor keys.

### 6.7 Versioning

`0x02` is wire v1. A future layout gets a new `agc_encoding` value and byte;
v1 bytes are never reinterpreted. Growth within v1 is not possible by design:
the format has no unknown-field mechanism, which is the property that makes
it unique and O(1) to parse.

## 7. Envelope: metadata and ciphertext in one blob

Metadata and the artifact it describes are always one-to-one (the nonce is
per ciphertext), so a single blob is the natural stored form. The envelope
is:

```
offset  size  field
0       1     encoding byte      0x01 protobuf / 0x02 wire v1 -- same byte as §6.1
1       2     metadata_len       u16 BE, length of `metadata` (≤ AGC_MD_MAX_ENCODED_LEN)
3       M     metadata           the body: protobuf OperationMetadata bytes, or the §6.2 body
3+M     ...   ciphertext         the primary output, to the end of the blob
```

`metadata` in the envelope is the body **without** its own encoding byte;
the envelope's byte 0 serves both. The standalone form (§6.1) is therefore
`envelope[0] ‖ envelope[3 : 3+M]`. Because those two pieces are not
contiguous, `agc_envelope_split()` returns them as an `agc_encoding` value
plus a body slice, and `agc_metadata_decode_body()` (§5.3) consumes exactly
that pair; `out_ciphertext` is `envelope[3+M :]`. Splitting is three loads
and two bounds checks, with no parse of the body. The caller who prefers
separate storage columns stores the standalone form and the ciphertext
individually and never builds an envelope; the encoders are the same.

Streaming: multi-part encryption emits ciphertext from `*_update` before the
tag and metadata exist at `*_final`, so an envelope writer must reserve
`3 + metadata_len` bytes at the front (known after `*_init`, since the nonce
is generated there) and fill them at `*_final`. `agc_metadata_max_encoded_len`
gives the reservation; the header is fixed-size precisely so this is
possible.

Authentication: the envelope header and metadata are **not** authenticated
by the AEAD in this version, for compatibility with the Go service, which
does not include them in the associated data. The wire format is canonical,
so including `envelope[0 : 3+M]` as implicit associated data is possible
without a canonicalisation step; doing so is a specification decision for
`github.com/agile-crypto/api` (see `docs/PROTO_RFCS.md`), not a local one.
Until then, `key_version` and `kind` are routing hints, not authenticated
claims, under both encodings.

## 8. Assessment

- **Representation.** Return **A-view** in every response: the encoded
  bytes in the request's encoding, plus `key_version` as a field. The
  caller's universal next step with metadata is to store it next to the
  ciphertext, and A-view hands over exactly that, in one region with a
  static bound, with no further call. C's advantages -- reading the nonce and
  kind as fields -- serve the rare inspecting caller, who gets C in 2 to 11 ns
  through `agc_metadata_decode`, with a `storage` region only when the
  metadata carries user context or vendor parameters. Returning C would
  instead charge every caller an
  encode call and a second buffer on the common path. B is a coherent middle
  ground -- transparent scalars, no duplicated state, an explicit encoding
  field that makes transcoding visible -- but it also needs a second caller
  region unless the B' layout is used, and B' is A with a different name.
- **Encoding.** Both, per request. Protobuf for anything the Go service must
  read; wire v1 otherwise, and as the default the examples show. The strict
  protobuf decoder of §4.1 is mandatory under either choice.
- **Cost.** Every representation and both encodings cost under 25 ns per
  operation with no heap allocation. The current handle path costs 300-800 ns
  and 4+ allocations per operation, fails *after* the provider has done its
  work when allocation fails, and drives allocation count from
  attacker-controlled input on decode. Removing it is the change that
  matters; the choice among A, B, C is secondary and should be made on API
  clarity.

## 9. What was implemented

This document is the exploration; the sections above are kept as they were
written and do not track the headers. The decisions taken, as of commit
`c4e7a1a` and its follow-ups, are these. `include/agc/agc_crypto.h`,
`include/agc/agc_metadata.h` and `docs/agc_crypto.md` are the source of
truth where they differ from the text above.

- **Response representation: A-view**, as §8 recommends. Keyed operations
  return the encoded metadata in the request's encoding plus `key_version`.
- **Keyless operations (digest, xof, random) return no metadata.** Instead
  their requests carry provider and template selection inputs and a required
  policy, and their responses report `api_version`, the selected
  `provider_id` and `template_id`, and `policy_version`, with strings
  pointing at the request or into a response `storage` region. §5.1's list of
  requests gaining `metadata_encoding` therefore excludes digest and xof.
- **Decoded form: option C with pointer arms, not the fixed arrays of §2.**
  `agc_provider_output` holds `nonce`, `iv`, `salt`, `counter_block`,
  `block_counter`, each an `agc_slice` into `agc_metadata.storage`;
  the vendor arm is a decoded `agc_kb_list`, not an encoded slice. The union
  is named `u`. Measured sizes are those of `considerations.md` §1: 56 bytes
  for `agc_provider_output`, 120 for `agc_metadata`.
- **No bounds.** None of the `AGC_MD_*` constants of §2, §4.1, §5.3 and §6.6
  exist: no maximum encoded length, no nonce/IV/salt/counter bound beyond
  the width of the wire length field, no `AGC_MD_MAX_ENCODED_LEN_STD`, no
  `AGC_MD_STORAGE_BOUND`. Callers size-query or call
  `agc_metadata_max_encoded_len`. The string bounds moved to `agc_abi.h` as
  `AGC_API_VERSION_MAX_LEN` and `AGC_OUTPUT_ENCODING_MAX_LEN`.
- **Decode signature takes the encoding first:**
  `agc_metadata_decode(agc_encoding enc, agc_slice encoded, agc_metadata *out)`,
  with `enc` cross-checked against byte 0. Same for `_storage_len` and
  `_peek_key_version`. A NULL or too-small `storage` returns
  `AGC_ERR_BUFFER_TOO_SMALL` with `storage_used` set; that is the size query.
- **Unknown output kinds are rejected on decode**, not treated as opaque.
- **Vendor arm under wire v1 is vendor-defined**, as §6.3 already states.
- **Seed-random reports `success`**, not `accepted`.

## Appendix: measurements

Reference case unless noted. Best of five runs, 1-5 million iterations each.
Sources: `measurements/metadata_discussion/`.

| Measurement | ns/op |
|---|---|
| handle create + free (current) | 72 |
| handle create + two-call encode + free (current encrypt caller path) | 303 |
| same, 2 user-context pairs | 812 |
| handle decode + read nonce + free (current decrypt caller path) | 147 |
| same, 2 user-context pairs | 291 |
| protobuf flat encode into caller buffer, size pass + write | 19.5 |
| protobuf flat encode, pre-sized | 14.5 |
| protobuf zero-copy parse to stack struct | 8.5 |
| same, 2 user-context pairs | 11.1 |
| wire encode, all at once (A) | 5.0 |
| wire: fill partial struct only (B, never encoded) | 2.8 |
| wire: fill partial + `encode_metadata` (B) | 9.0 |
| wire: reserved header, encode in place (B') | 3.9 |
| wire: A / B / B' with 2 user-context pairs | 21.4 / 25.0 / 16.3 |
| wire: A / B / B', KDF 64-byte salt | 4.3 / 8.9 / 5.5 |
| peek key_version, protobuf, first-field shortcut (not decoder-equivalent) | 0.46 |
| peek key_version, protobuf, decoder-equivalent full scan | 4.6 |
| peek key_version, protobuf strict canonical | 4.8 |
| peek key_version, protobuf, 1 KiB of 512 unknown fields, field 1 last: full / strict | 410 / 2.3 (rejects) |
| peek key_version, wire fixed offset, any length | 0.22 |
| `agc_encrypt` 64 B via public API, no metadata handle / with handle + encode + free | 1290 / 1632 |
| `agc_encrypt` 1 KiB, same | 3721 / 4021 |

Struct sizes (LP64, `struct_layout`): `agc_provider_output` 128,
`agc_metadata` 192 (168 without the storage descriptor),
`agc_metadata_partial` 88, A metadata descriptor 24, A-view field +8.

The wire-format timing figures were taken on a prototype with a 9-byte
header and `u8` lengths; the specified layout adds one byte to the header
and one to `output_len`, which is one additional store. The protobuf
`encode_metadata` cost for B (~20-25 ns) is an estimate from the A figure
plus the measured copy; it was not run separately.
