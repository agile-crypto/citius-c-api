# CryptoService ABI: rules and decisions

Normative for `include/agc/agc_crypto.h`, `include/agc/agc_metadata.h` and
`include/agc/agc_key.h`.
The reasoning behind each rule is in `representing_metadata.md` and
`considerations.md`; this file states the rules and the decisions taken, with
one line of justification each. The headers are the source of truth; this
file follows them.

## Rules

**The data path is always caller-allocated.** Every request, every response,
every output region and every decoded metadata struct is memory the caller
provided. The library writes into it and never allocates, retains, or frees
anything the caller sees. There is no `_free` function on the data path.
*Why:* a caller-owned response cannot fail to materialise after the provider
has done its work, can be placed in locked, pooled or stack memory, has a
statically bounded size, and needs no allocator inside the library on the
operation path.

**Everything the caller sees is caller-allocated; the exceptions are the
things that hold secret state or a lifecycle.** `agc_ctx`, `agc_session`,
the key store and the iterators stay library-owned opaque handles.
*Why:* they hold key material or operation state that must be zeroized by
the library, may live in hardware, and are created, used across calls and
destroyed on a schedule the library controls. This is the PKCS#11 line:
handles for keys, sessions and objects; caller buffers for everything else.

**Records the caller reads are caller-allocated structs, on and off the data
path.** `agc_key_info`, `agc_migration_report`, `agc_template_info`,
`agc_policy_summary`, `agc_provider_info`, `agc_provider_instance` and
`agc_metadata` are public snapshots with no lifecycle: reading one twice
gives two independent copies and releasing one does nothing to the key.
*Why:* the exception above is for secrets and lifecycles, not for cost; a key
record holds neither, and the PKCS#11 analogue is `C_GetAttributeValue`
writing attributes into caller memory while the key object stays a handle.

**A response holding variable-length output holds the pointer to the caller's
storage, and only a response type ever does.** Records are DESCRIPTIVE ONLY:
they carry the fields and the pointers, never the `agc_buf storage` and
`size_t storage_used` pair those pointers reference. Every call that returns
such a record returns it inside a response that owns one storage region for
everything it contains, and one region serves every record in that response,
including the elements of an array. Where several calls return the same lone
record, they share one wrapper: `agc_key_info_response`,
`agc_template_info_response`, `agc_policy_summary_response`,
`agc_provider_info_response`, `agc_provider_instance_response` and
`agc_decode_metadata_result`. *Why:* a record that owns its storage cannot be
placed in an array without either N regions or a dead field in every element,
and the two shapes cannot both be right; putting storage in the response
makes one rule cover the single case and the array case, and it keeps the
size query in one place per call.

**A size query on a mutating operation returns a bound and does not
mutate.** For create, rotate, transform, update_policy, migrate, import and
export, a NULL or too-small `storage` returns `AGC_ERR_BUFFER_TOO_SMALL`
with `storage_used` set to an upper bound computed from the request, the
policy and the selected template and provider, without performing the
operation; the real call may consume less. For read-only operations the
requirement is exact. *Why:* the operation must never run for a caller that
cannot store its result, and a record's exact size is not known until the
operation has run.

**NIL buffers ask the library for a size.** An output `agc_buf` with
`data == NULL`, or one present but too small, makes the call return
`AGC_ERR_BUFFER_TOO_SMALL` with **every** length field of the response set to
its requirement. No provider work is performed and no randomness is drawn
before this check, so one retry always suffices and a failed size query
costs nothing cryptographic. The same rule applies to every `storage`
region: the `storage` of every response type, where `storage_used` receives
the requirement. *Why:* one convention for
every output, and the provider is never invoked for a call that cannot store
its result. *Exception:* a decrypt- or verify-shaped response may opt out of
its metadata output by passing `{NULL, 0}`, because the caller already holds
the input metadata; the header says so at each such field.

**Every struct passed by pointer begins with `struct_size`.** `AGC_INIT()`
zeroes it and sets the size; the library writes a field only if it fits
(`AGC_FIELD_FITS`). *Why:* additive evolution without a soname bump (D7).
*Limit:* `struct_size` versions length only; a change inside a union that
leaves `sizeof` unchanged is invisible to it, which is why the union arms
below are slices and why existing arms are never modified.

**One request struct, one response struct, one function per operation.**
`agc_rc agc_<op>(agc_ctx *, const agc_<op>_request *, agc_<op>_response *)`.
*Why:* maps one-to-one onto the proto's request and response messages, so
the generator and the conformance tiers key on the same shape; and every
output of an operation materialises in one place, so there is no partial
success.

**Keyed operations return metadata encoded, in the encoding the request
named, with `key_version` copied out.** This is option A-view of
`representing_metadata.md`. The response's `metadata` region holds the
encoded `OperationMetadata`, encoding byte first, ready to store or to place
in an envelope; `key_version` is a scalar copy for the routing lookup every
consumer does first. Applies to encrypt, decrypt, sign, digest_sign, verify,
digest_verify, generate_mac and verify_mac. *Why:* storing the bytes is the
universal next step and A-view hands over exactly that in one region; callers
that need fields decode on demand in a few nanoseconds.

**Keyless operations return no metadata; they return what was selected.**
Digest, xof and random have no key and therefore no `key_version` and no
nonce; their requests carry the selection inputs (`provider_id`,
`provider_configuration`, `provider_requirements`, `template_id` where a
template applies, and a required `policy_name`) and their responses report
the `api_version`, the `provider_id` and `template_id` that served the call,
and the `policy_version` that selected them. These operations deliberately
differ from the current proto: they support policy-governed provider and
template selection and filtering by construction. *Why:* the information a
keyed operation recovers from its key name and version has to travel in the
response when there is no key to recover it from.

**Metadata consumed by an operation is passed as encoded bytes.** Decrypt and
verify requests take an `agc_slice` whose byte 0 names the encoding. *Why:*
the bytes the caller stored are the bytes the caller passes back; no decode
step on the common path.

**Two encodings coexist, selected per request.** `AGC_ENCODING_PROTOBUF` is
the `OperationMetadata` message of `github.com/agile-crypto/api`, required
for anything the Go service must read. `AGC_ENCODING_WIRE_V1` is the fixed
layout of `representing_metadata.md` §6: unique, offset-addressable, O(1) to
parse, canonical without a canonicalisation step. Byte 0 of every encoded
metadata is the `agc_encoding` value. *Why:* compatibility keeps protobuf;
the security argument for parsing untrusted bytes before any key is selected
favours the fixed layout; neither can replace the other yet.

**The protobuf decoder is strict canonical.** Ascending field numbers, no
duplicates, minimal varints, in-range values. Anything else is
`AGC_ERR_INVALID_ARGUMENT`. There is no maximum encoded length. This is a
declared divergence from Go's lenient decoder, recorded in
`conformance/DIVERGENCES.yaml`. *Why:* a lenient peek of `key_version` is
either wrong or proportional to attacker-controlled input; strict rejection
is fail-closed and accepts every blob Go's own encoder produces.

**Decoding takes the encoding as an argument and cross-checks byte 0.**
`agc_metadata_decode` fails if the stored byte disagrees. *Why:* the byte is
authoritative in storage; the argument catches a caller that lost track of
what it stored.

**An output kind the header does not name is rejected on decode.** The
projection has no arm to receive it, and the wire format forbids unknown
kinds by design. *Why:* fail-closed; an older library could not have used
the algorithm anyway.

**Verification is fail-closed twice.** `resp->valid` is zeroed before any
work; an invalid signature or MAC returns an error code and leaves it zero.
Either check alone suffices (D9, DV-01).

**Responses hold no library-owned strings.** A string output is either a
`char *` that points at the request's own string when the caller supplied
the value (`provider_id`, `template_id`), and into the response's `storage`
region when the library selected it; or a fixed NUL-terminated array where
the value has a fixed bound (`api_version`, the seed-random `message`).
*Why:* the "everything the caller sees is caller-allocated" rule without an
exception for strings, and no copy when the caller already holds the value.

**Bounds live in `agc_abi.h`.** `AGC_API_VERSION_MAX_LEN`,
`AGC_OUTPUT_ENCODING_MAX_LEN`, `AGC_PROVIDER_ID_MAX`, `AGC_TEMPLATE_ID_MAX`.
There are no bounds on nonce, IV, salt or counter lengths beyond the width of
their length fields on the wire, and no static bound on an encoded metadata
or on a storage region. *Why:* every variable-length value lives in caller
storage, so a header constant would only freeze a limit into the ABI that
the representation does not need.

**Request slices are borrowed for the duration of the call.** The library
never retains a pointer into a request after returning. *Why:* the existing
`agc_slice` contract of `agc_abi.h`, unchanged.

**Variable-length values follow one shape.** Proto `bytes` becomes
`agc_slice`, proto `string` becomes a NUL-terminated `const char *`, a
repeated field becomes a `const` pointer plus a `_count`, and a map becomes
`agc_kv_list`, `agc_kb_list`, or an array of entry structs. Every one of
them points into the enclosing record's `storage`, and the field's comment
says so. Field names carry no pointer prefix. *Why:* one spelling per proto
shape, so a reader recognises the lifetime rule from the type rather than
from a naming convention, and `agc_slice` already carries exactly the
borrowed-bytes contract these fields need.

## The decoded metadata struct

`agc_metadata` is caller-allocated and filled by `agc_metadata_decode` into
an `agc_decode_metadata_result`, which owns the storage. Its scalars are
inline. Its `agc_provider_output` holds the algorithm output as a **union of
slices**: `nonce`, `iv`, `counter_block`, `block_counter`, `salt`, each an
`agc_slice` pointing into that result's storage, a region the caller owns. The vendor arm is an `agc_kb_list`, the decoded
`VendorOutput.parameters` map, whose items, keys and value bytes also live in
`storage`; the vendor provider supplies its decoder for both encodings.
`user_context` is an `agc_kv_list` whose items and strings live there too.
Decode copies every variable-length value there and never references the
encoded bytes afterwards; the struct is valid for as long as `storage` is.

**Slice arms are the v1 choice and may change.** The alternative studied in
`considerations.md` is fixed inline arrays sized by header constants. Fixed
arrays make a standard-arm metadata self-contained with no storage region,
but any change to an arm's bound or layout that leaves `sizeof` unchanged is
undetectable by `struct_size`, and every application pays the largest arm.
Slice arms keep `sizeof` independent of algorithm output lengths and make
capacity a runtime check on `storage`, at the price of a storage region on
every decode. This is the choice for this version; it will be re-evaluated
once the needs of real providers and constrained targets are known.

## Storage sizing

A caller sizes a response's `storage` region one of two ways: pass
`{NULL, 0}` and read `storage_used` from the `AGC_ERR_BUFFER_TOO_SMALL`
return; or, for metadata,
call `agc_metadata_storage_len`, which computes the exact requirement from
the length fields without decoding. Metadata of kind `NO_OUTPUT` with no
user context requires no storage.

## Encoded-size bounds

`agc_metadata_max_encoded_len` gives a per-key upper bound on the encoded
metadata an operation will produce, including user context and vendor
output, for callers that pre-size and never size-query. There is no
compile-time bound.

## Envelope

`encoding byte ‖ metadata_len u16 BE ‖ metadata body ‖ ciphertext` is the
single-blob stored form (`representing_metadata.md` §7). `agc_envelope_split`
slices it without parsing; `agc_metadata_decode_body` consumes the pair it
returns. Neither header nor metadata is authenticated by the AEAD in this
version, for compatibility with the Go service.

