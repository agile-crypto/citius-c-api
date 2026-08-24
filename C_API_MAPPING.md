# Abstract Cryptographic API — C Binding Design and Proto Mapping

**Status:** draft for review
**Covers:** `agile-crypto/api` spec v0.1.0, protobuf package `caas.crypto.v1`
**Scope:** all 98 RPCs across 7 services, plus the complete type system
**Companion artifacts:** `include/agc/*.h`

---

## 0. Why a C API at all

The immediate motivation is that gRPC has no first-class C code generation. That is true but it is the weaker half of the argument, and if it were the whole argument the right answer would be to bolt on `protobuf-c` or `nanopb` and move on.

The real argument has two parts.

**First: serialisation is the wrong shape for in-process consumption.** `protobuf-c`, `nanopb` and `upb` all exist and all generate *serialisation* types. Using them for a local AEAD call means marshalling the plaintext into an arena, unmarshalling it on the other side, and copying the result back — for an operation that should be a pointer and a length. Beyond the cycles, every copy is another region of key-adjacent memory that has to be tracked and zeroized, which cuts directly against the memory-security requirement. A local API must be able to hand a provider a `const uint8_t*` and have that be the end of it.

**Second, and more important: C is not one more language to support. C is the ABI.** A well-designed C library is the substrate that Rust, Python, Java (Panama/JNI), Go (cgo), Node and Ruby can all bind to *without any RPC at all*. The polyglot requirement and the "no RPC in the cryptographic hot path" constraint are the same requirement, and a C library satisfies both at once. gRPC then becomes a front-end over this core rather than a parallel implementation — one implementation, two transports, no drift.

A third consideration shaped the design more than expected: **PKCS#11 alignment**. The proto is already modelled on PKCS#11 v3.x — Init/Update/Final, message-based AEAD, `C_DigestKey`, dual-function operations, `CKF_END_OF_MESSAGE`. Those constructs are *native* to C and awkward over gRPC. The C binding is in several places a cleaner expression of the specification than the wire API is.

### 0.1 What is normative where

| Artifact | Normative for |
|---|---|
| `proto/**/*.proto` | Vocabulary, semantics, matching rules, wire format, cross-implementation interop |
| `include/agc/agc_types.h` | Numeric values of the C vocabulary — **generated**, never hand-edited |
| `include/agc/agc_*.h` (rest) | The local ABI: calling conventions, ownership, lifetime, threading |
| `C_API_MAPPING.md` (this file) | The derivation, and the reasons for every deliberate divergence |

**CI invariant:** a job loads the `FileDescriptorSet`, walks every enum, and asserts that a correspondingly-named C enumerator exists with the identical numeric value. Adding a proto enum value without regenerating fails the build. This is the mechanism that stops the two specifications from drifting, and it is not optional.

---

## 1. The nine conventions

Everything below is an application of these. They are stated once here rather than repeated at every function.

### C1. One result type

Every function returns `agc_rc`. `AGC_OK == 0`; every other value is a failure.

**Encoding.** Hand-written conditions (`AGC_ERR_INVALID_ARGUMENT`, `AGC_ERR_BUFFER_TOO_SMALL`, …) occupy `-1 .. -99`. Generated codes are a mechanical transform of `CryptoErrorCode`:

```
agc_rc = -(1000 + wire_value)      wire_value = -agc_rc - 1000
```

The offset keeps the ranges disjoint; the transform is arithmetic and reversible, so a gRPC front-end recovers the wire value without a lookup table, and a new `CryptoErrorCode` requires no hand edit anywhere.

**Why not an out-parameter for errors?** Because a caller who ignores the return value should get a compiler warning, and `warn_unused_result` on a returned code is the only reliable way to get one.

**Why a thread-local detail record as well?** `agc_rc` is sufficient to branch on; it is not sufficient to *debug*. The detail record carries the provider that failed, its native code (`CKR_*`, an OpenSSL reason, a KMS error), and for policy denials which check failed. Putting that in the return type would mean allocating on every error, including in the paths where the caller only wants to branch.

### C2. Two-call sizing for byte outputs

```c
size_t n = 0;
rc = agc_encrypt(ctx, &req, (agc_buf){0}, &n, NULL);   /* n <- required */
uint8_t *ct = malloc(n);
rc = agc_encrypt(ctx, &req, (agc_buf){ct, n}, &n, &md); /* n <- actual */
```

The library **never** allocates a buffer that the caller frees with `free()`. Three reasons, in order of importance:

1. **Allocator symmetry.** On Windows, and under any sanitizer or arena allocator, freeing across a DLL boundary with a mismatched allocator is a crash or a silent heap corruption.
2. **Zeroization ownership.** The caller decides whether the buffer is `mlock`ed, whether it lives in a secure enclave, and when it is erased. The library cannot know when the caller is finished with a plaintext, so it must not own it.
3. **Reuse.** A TLS record encryptor sizes once with `agc_encrypt_max_len()` and then loops with zero allocations. The size-query path exists for correctness; the `max_len` path exists so the hot loop never takes it.

`AGC_ERR_BUFFER_TOO_SMALL` sets `*out_len` to the required size, so an undersized buffer degrades into a size query rather than a truncation.

### C3. Handles for rich messages

Byte outputs are buffers. *Message* outputs — `KeyMetadata`, `TemplateInfo`, `ProviderInfo`, `OperationMetadata` — are opaque handles with typed accessors.

This is the single most consequential decision in the binding, and it is entirely about ABI stability. `KeyMetadata` transitively contains `TemplateInfo`, which contains `AlgorithmDetails`, which contains a **40-arm oneof** over algorithm parameter messages. Projecting that as C structs would freeze the entire algorithm catalog into the ABI. Adding a parameter set — a *data* change in the proto's own model, explicitly designed to require no schema change — would become a soname bump.

Handles make catalog growth ABI-neutral. `agc_template_info_cdx_parameter_set()` returns `"1024"` for a newly added ML-KEM-1024 without any header changing.

The escape hatch for callers that genuinely need parameter-level detail is `agc_template_info_to_json()`, which emits the canonical catalog entry. Tooling parses JSON; the ABI stays flat.

### C4. Versioned parameter structs

Every struct passed by pointer begins with `size_t struct_size`, set via `AGC_INIT()`. The library dispatches on it to decide which trailing fields are present.

This is the C substitute for protobuf's free forward compatibility. Protobuf lets you add a field and ignore it on the other side; C has no equivalent, so the mechanism has to be explicit. **It must be present from day one** — retrofitting it after v1.0 ships is not possible without breaking every caller, and this is the single item most likely to make the C spec age worse than the proto.

The accompanying discipline:

- New fields go at the **end** of a struct, never in the middle, never reordered.
- New behaviour that cannot be expressed as an appended field gets a **new symbol** (`agc_encrypt_v2`), with the old one kept as a shim.
- Enums grow only by **adding** values; existing values are never renumbered, mirroring proto field-number discipline.
- `soname` bumps on any layout change to an existing field. Symbol versioning (`AGC_1.0`, `AGC_1.1`) lets both live in one library.

### C5. Three-valued booleans

proto3 `optional bool` is three-valued: absent / false / true, and absence is **load-bearing** throughout this API. In a request, an absent `fips_approved` means "don't care"; `false` means "must NOT be FIPS-approved". Collapsing to C `bool` would turn every "don't care" into a hard negative filter and make discovery unusable.

```c
typedef enum agc_tribool { AGC_UNSET = 0, AGC_FALSE = 1, AGC_TRUE = 2 } agc_tribool;
```

`AGC_UNSET == 0` so that a zeroed struct means "no filters", which is the correct default.

Plain `bool` fields in the proto (`ScopedCapabilities` operations, `remove_metadata`, `retain_key_bytes`, `end_of_message`, `disabled`) map to `int`, since they are genuinely two-valued. `int` rather than `_Bool` for ABI stability across compilers and for clean FFI from languages without a native 1-byte bool.

### C6. Tagged unions for `oneof`

```c
typedef struct agc_scope_spec {
    size_t         struct_size;
    agc_scope_kind kind;
    union { ... } u;
} agc_scope_spec;
```

Where a `oneof` is stable across every message that contains it, **the tag values are the proto field numbers**. `AGC_SCOPE_KIND_AEAD == 2` because `AeadScopeSpec aead = 2`. A wire encoder uses the tag directly, and reordering the proto arms is caught by the CI invariant.

Where the same conceptual arm carries *different* field numbers in different messages — `aead_params` is field 4 in `EncryptRequest` but field 3 in `EncryptInitRequest` — field numbers cannot serve as a stable discriminant, so those unions (`agc_encrypt_params_kind`, `agc_sign_params_kind`, `agc_mac_params_kind`, `agc_wrap_params_kind`, `agc_kdf_params_kind`) use an independent enum and the marshalling layer maps per message. This is stated explicitly in the header so nobody later "fixes" it.

`NoParams` becomes a *tag value* rather than an empty struct: `AGC_ENCRYPT_PARAMS_NO_PARAMS`. This preserves the proto's key property — "intentionally no parameters" is distinguishable from "forgot to set the oneof" — because the required-oneof tag `0` is `NONE` and is always rejected.

### C7. Sessions, not identifiers

`StreamingCryptoService` names sessions with a server-generated `operation_id` string because gRPC is stateless between calls. A local library has no such constraint, so sessions are opaque `agc_session*`:

- **Cheaper**: no string hash on every `Update` in a hot loop.
- **Safer**: a freed handle is a use-after-free the sanitizer catches; a stale string is a silent lookup miss.
- **Leak-proof**: `agc_session_free()` cancels an open session, so an early `return` cannot strand provider state or leave key material resident.

Interconvertibility is preserved: `agc_session_id()` recovers the string for audit correlation or relaying to a remote front-end, and `agc_session_attach()` adopts a session created elsewhere.

### C8. Iterators, not page tokens

The proto exposes `(page_size, page_token)` on requests and `next_page_token` on responses. Reproducing that pushes cursor bookkeeping onto every caller. The iterator holds the token internally and fetches lazily; `page_size` becomes a tuning knob on the open call. `AGC_ERR_ITERATOR_EXHAUSTED` is the normal terminator and is deliberately distinct from every genuine error.

`ListScopes` is the exception: no request fields, a bounded result set of about a dozen entries. It returns an array. Pagination machinery there would be cost with no benefit.

### C9. Fail closed, twice

For every verification-shaped operation:

1. `*out_valid` is set to `0` **before any work is attempted**, so an early error return can never leave it holding a stale or uninitialised true.
2. A cryptographically invalid result returns `AGC_ERR_CRYPTO_SIGNATURE_INVALID` / `AGC_ERR_CRYPTO_AUTHENTICATION_FAILED` **and** sets `*out_valid = 0`.

Both `if (rc != AGC_OK)` and `if (!valid)` are individually sufficient. This is a deliberate divergence from the proto, which returns `VerifyResponse{valid: false}` as a *successful* response — correct for a wire protocol where transport and application failures must be distinguishable, wrong for C where the classic bug is:

```c
agc_verify(ctx, &req, &valid);   /* rc ignored */
if (valid) accept();             /* valid uninitialised on the error path */
```

A gRPC front-end maps `AGC_ERR_CRYPTO_SIGNATURE_INVALID` back to `VerifyResponse{valid:false}`, so wire behaviour is unchanged.

---

## 2. Type system mapping

### 2.1 Scalars

| Proto | C | Notes |
|---|---|---|
| `string` (in) | `const char *` | NUL-terminated UTF-8. `NULL` == absent where the field is optional; `""` and `NULL` are equivalent since the proto has no `optional string` on these fields. |
| `string` (out, borrowed) | `const char *` | Owned by the parent handle; invalid once that handle is freed. |
| `bytes` (in) | `agc_slice` | `{const uint8_t*, size_t}`. Borrowed, never freed, never retained past the call. |
| `optional bytes` (in) | `agc_optional_slice` | Adds `present`. Required where absent ≠ empty — see §2.2. |
| `bytes` (out) | `agc_buf` + `size_t *out_len` | Two-call. |
| `bool` | `int` | ABI stability, clean FFI. |
| `optional bool` | `agc_tribool` | §C5. |
| `uint32`, `uint64`, `int32`, `int64` | `uint32_t`, `uint64_t`, `int32_t`, `int64_t` | |
| `optional uint32/uint64` | scalar + `int has_*` | Except where a sentinel is unambiguous — see §2.3. |
| `enum` | `typedef enum` with `= 0x7fffffff` sentinel | Forces int32 width regardless of `-fshort-enums`, matching the wire type. |
| `map<string,string>` | `agc_kv_list` | Flat array. Order not significant; duplicate keys rejected with `AGC_ERR_INVALID_ARGUMENT`. |
| `map<string,bytes>` | `agc_kb_list` / indexed accessors | `VendorOutput.parameters` only. |
| `repeated T` | `const T*` + `size_t count`, or indexed accessors on a handle | Value types get arrays; message types get accessors (§C3). |
| `google.protobuf.Timestamp` | `agc_timestamp {int64 seconds; int32 nanos; int present;}` | Explicit presence because `activation_time`/`expiration_time` are `optional`. `time_t` deliberately avoided: 32-bit on some targets. |
| `google.protobuf.Struct` | `const char *` canonical JSON | §2.4. |
| `google.protobuf.Any` | `const char *type_url` + `agc_slice value` | §2.4. |

### 2.2 The `optional bytes` cases, and why they matter

Three fields make absence semantically distinct from emptiness, and getting this wrong is a real cryptographic bug rather than an ergonomic wart:

- `HkdfOperationParams.salt` — **absent** → server generates a random salt per RFC 5869; **empty** → HashLen zero bytes per RFC 5869 §2.2.
- `Pbkdf2OperationParams.salt` — **absent** → server generates; **empty** → intentionally empty (NOT RECOMMENDED).
- `Argon2OperationParams.salt` — same shape, RFC 9106 §3.1.

A single `agc_slice` with `{NULL, 0}` cannot distinguish these. `agc_optional_slice` carries a `present` flag, and derivation determinism depends on it: a caller intending reproducible derivation must set an explicit salt, and a caller intending fresh randomness must leave it absent. Collapsing the two turns a deterministic derivation into a random one, or vice versa, silently.

### 2.3 Sentinels where they are unambiguous

Two `optional uint32` fields are represented by a sentinel instead of a presence flag, because a natural out-of-band value exists:

- `ReadKeyRequest.version` → `uint32_t version`, where `0` means "latest". Key versions start at 1, so `0` is unambiguous.
- `TemplateInfo` page sizes → `uint32_t page_size`, where `0` means "implementation default", matching the proto's own documented meaning.

Everywhere else the presence flag is explicit. The rule: use a sentinel only where the proto *itself* documents an out-of-band meaning for the zero value.

### 2.4 `Struct` and `Any` — the vendor escape hatch

`CustomOperationParams` carries `google.protobuf.Struct` or `google.protobuf.Any`. Neither has a natural C representation, and inventing a C dynamic-value type would be a large, permanent ABI liability in service of the least-used corner of the API.

They are carried in their canonical serialised forms instead:

```c
typedef struct agc_custom_params {
    size_t                 struct_size;
    agc_str                vendor;
    agc_str                algorithm_name;
    agc_custom_params_kind kind;
    agc_str                generic_params_json;    /* Struct, canonical JSON */
    agc_str                typed_params_type_url;  /* Any.type_url */
    agc_slice              typed_params_value;     /* Any.value */
    agc_slice              raw_params;             /* additive, always forwarded */
} agc_custom_params;
```

The canonical JSON encoding of `Struct` is defined by the protobuf JSON mapping and round-trips losslessly, so a gRPC front-end re-parses it into a real `Struct` with no information loss. `Any` decomposes into exactly its two wire fields. A local provider that understands the vendor format consumes them directly and never involves protobuf at all.

`raw_params` is additive in both directions, and the proto's precedence rule (`typed_params` > `generic_params`, with `raw_params` always forwarded alongside) is preserved verbatim.

### 2.5 Fixed-length `bytes` become arrays

Where `buf.validate` pins an exact length, the C type is a fixed array and the constraint becomes structural rather than a runtime check:

| Proto field | Constraint | C |
|---|---|---|
| `XtsEncryptParams.tweak` | `bytes.len = 16` | `uint8_t tweak[16]` |
| `Tls12KdfOperationParams.client_random` | `bytes.len = 32` | `uint8_t client_random[32]` |
| `Tls12KdfOperationParams.server_random` | `bytes.len = 32` | `uint8_t server_random[32]` |
| `SignatureDomainContext.context` | `bytes.max_len = 255` | `uint8_t context[255]` + `uint8_t context_len` |

This removes an allocation from the hot path (an XTS tweak is set per sector), makes the bound a compile-time property, and — for the domain context — bounds the struct so it can live on the stack in a signing loop.

`string` length bounds (`min_len: 1, max_len: 256` on key names) stay runtime checks: fixing a 256-byte array into every request struct would bloat them for no benefit, and the check is one comparison.

### 2.6 Enums: the complete inventory

All of the following are generated into `agc_types.h` with identical numeric values. Scope enums: `SignatureScope`, `AeadScope`, `MacScope`, `KemScope`, `KeyAgreementScope`, `KdfScope`, `HashScope`, `KeyWrappingScope`, `SymmetricCipherScope`, `DiskEncryptionScope`, `GenericSecretScope`, `AsymmetricEncryptionScope`. Lifecycle and format: `KeyLifecycleState`, `KeyOrigin`, `KeyFormat`, `WrapFormat`, `MigrationStrategy`. Security: `NistSecurityLevel`, `NistStatus`. Operations: `CryptoOperation`. Templates: `TemplateStatus`, `HybridAlgorithmParams.CombinerStrategy`. Algorithm vocabulary: `HashAlgorithm`, `EllipticCurve`, `PaddingScheme`, `SignatureFormat`, `MaskGenerationFunction`, `Argon2Variant`, `Ed25519Variant`, `Ed448Variant`, `KeyType`, `CryptoPrimitive`, `MlDsaParameterSet`, `MlKemParameterSet`, `SlhDsaHashType`, `SlhDsaParameterSet`, `EcdhKdfType`, `HkdfSaltType`, `Sp800108DataType`. Providers: `ProviderType`, `Fips140Level`. Policy: `PolicyDenialReason`. Errors: `CryptoErrorCode` (transformed per §C1).

Deprecated values (`HASH_ALGORITHM_SHA1`, `HASH_ALGORITHM_MD5`, the `[deprecated = true]` algorithm arms) are **retained** at their proto values. Omitting them would break round-tripping of artifacts produced by a legacy deployment, and long-term data continuity is one of the requirements the whole framework exists to serve. They are marked in comments and can be gated with a build flag.

### 2.7 `ScopeSpecification`: the central type

Twelve scope-spec messages, each carrying its scope enum, `UniversalSecurityProperties`, zero or more primitive-specific `optional bool`s, and `additional_properties` at field 15.

The C union preserves the proto's **dual interpretation** exactly: the same `agc_scope_spec` is a *requirement filter* in a request and a *capability declaration* in a template. This is not an accident of convenience — it is what makes the matching semantics ("scope must match exactly; booleans must match if specified; security properties are minima") expressible with one type rather than two that must be kept in sync.

`additional_properties` is at field 15 in every scope spec by convention — the last single-byte varint field number, reserved for the least-frequently-accessed field. That layout reasoning is wire-specific and has no C analogue, but the field is carried through so the extensibility escape hatch survives the round trip.

### 2.8 `SecurityGuarantees`: informational, and kept that way

`FormalSecurityNotions`, `PracticalSecurityOutcomes` and `OperationalBounds` are exposed as accessors on an opaque handle, never as filter inputs. The proto is emphatic that these are **not** used for template matching, and the C API enforces that by construction: there is no request struct anywhere with a `SecurityGuarantees` field. Callers filter with `agc_scope_spec.security`; they *audit* with `agc_security_guarantees`.

`OperationalBounds.attack_success_probability` stays a `const char *`. The proto keeps it a string to preserve `"2^-32"` notation and full precision; converting to `double` in C would lose both, and CBOM export needs the original text.

Two-level resolution is preserved: `agc_template_info_capability_guarantees(ti, i)` returns the per-scope override when present and falls back to `agc_template_info_guarantees(ti)` otherwise, so hybrid templates can declare `forward_secrecy` for their key-agreement scope but not their KEM scope.

---

## 3. `OperationMetadata` — the load-bearing type

Every operation producing a durable artifact also produces metadata that **must** be stored with it. This is the type most likely to be mishandled and it gets the most deliberate treatment.

### 3.1 Handle plus canonical bytes

`agc_metadata` is opaque, with two faces:

```c
agc_rc agc_metadata_encode(const agc_metadata *md, agc_buf out, size_t *out_len);
agc_rc agc_metadata_decode(agc_ctx *ctx, agc_slice encoded, agc_metadata **out_md);
```

**The canonical encoding is the protobuf wire encoding of `OperationMetadata`.** This is the single most important interop decision in the binding. An artifact encrypted by the C library must be decryptable by the Go service and vice versa, and the wire format is the only encoding both already agree on. Inventing a C-specific metadata serialisation would create two incompatible artifact populations and quietly destroy the long-term data continuity requirement.

Callers treat the bytes as opaque. They must be stored, they must not be modified, and they do not need to be authenticated — the proto's threat model applies unchanged and is worth restating because C callers will ask: the algorithm parameters are authenticated by the AEAD tag, a wrong `key_version` produces garbage or a verification failure, and `template_id` is deliberately absent because it is unsigned and therefore tamperable. Signing the metadata would add nothing.

### 3.2 Typed accessors

`ProviderOutput.algorithm_output` is a 7-arm `oneof` taxonomised by *output structure* rather than algorithm family. That taxonomy survives:

| Proto arm | Field | C accessors |
|---|---|---|
| `no_output` | 10 | kind == `AGC_ALGORITHM_OUTPUT_NO_OUTPUT` |
| `aead_output` | 11 | `agc_metadata_aead_nonce`, `agc_metadata_aead_tag_len` |
| `block_cipher_output` | 12 | `agc_metadata_block_iv` |
| `counter_mode_output` | 13 | `agc_metadata_counter_block`, `agc_metadata_counter_bits` |
| `stream_cipher_output` | 14 | `agc_metadata_stream_nonce`, `agc_metadata_stream_block_counter` |
| `kdf_output` | 15 | `agc_metadata_kdf_salt`, `agc_metadata_kdf_iv` |
| `vendor_output` | 16 | `agc_metadata_vendor_param_count` / `_at` |

Tag values are the proto field numbers.

### 3.3 The unset-oneof contract

The proto states that an unset `algorithm_output` is a **provider bug** and the core must reject the response — this is what distinguishes "no system-generated parameters" (intentional, `no_output`) from "the provider forgot to return the IV".

In C this is enforced at the provider boundary: a response with an unset oneof produces `AGC_ERR_PROVIDER_CONTRACT_VIOLATION` and no `agc_metadata` handle is created. `agc_metadata_output_kind()` therefore **never** returns `AGC_ALGORITHM_OUTPUT_NONE` on a handle a caller can hold. The enumerator exists only so the failure is nameable.

### 3.4 Where metadata is required as *input*

This is easy to get wrong, so it is enumerated rather than left implicit. Metadata from a prior operation is a required input to: `Decrypt`, `DecryptInit`, `DecryptMessage` (per-message), `DecryptMessageBegin` (per-message, from `EncryptMessageBegin`), `Verify`, `VerifyInit`, `VerifyMessage`, `DigestVerify`, `VerifyMAC`, `VerifyMACInit`, `UnwrapKey`, `DecapsulateKey`.

The recurring subtlety is message-based AEAD: **each message has its own nonce**, so the session-level metadata is not a substitute for the per-message metadata from `EncryptMessageBegin`. The C signatures make this structural — `agc_decrypt_message_begin()` takes a `partial_md` parameter and there is nowhere else to put it.

---

## 4. Service-by-service mapping

### 4.1 KeyManagementService — 12 RPCs

| RPC | C function |
|---|---|
| `CreateKey` | `agc_create_key` |
| `ReadKey` | `agc_read_key` |
| `ListKeys` | `agc_list_keys` → iterator |
| `DeleteKey` | `agc_delete_key` |
| `RotateKey` | `agc_rotate_key` |
| `TransformKey` | `agc_transform_key` |
| `UpdateKeyState` | `agc_update_key_state` |
| `UpdateKeyPolicy` | `agc_update_key_policy` |
| `MigrateKey` | `agc_migrate_key` |
| `ValidateKeyOperation` | `agc_validate_key_operation` |
| `ExportKey` | `agc_export_key` |
| `ImportKey` | `agc_import_key` |

**Both selection modes in one struct.** `agc_create_key_params` carries both `scope_spec` and `template_id`, with the proto's precedence rule (`template_id` must agree with `scope_spec` when both are set). Splitting into `agc_create_key_by_scope` and `agc_create_key_by_template` was rejected: an operator pinning a template in policy should not require a code change at the call site, and that is exactly the property the intent-based design is protecting.

**`CreateKeyResponse` has four fields; the C call returns two handles.** `success`/`message` collapse into `agc_rc` plus the error detail record. `key_metadata` and `implementation_properties` become out-handles. `security_guarantees` is *not* a third out-parameter — it is reachable via `agc_key_info_template()` → `agc_template_info_guarantees()`, so duplicating it would create two paths to the same value that could disagree.

This collapse of `bool success` + `string message` into `agc_rc` + `agc_last_error()` is applied uniformly across every response message that has them. Carrying both a boolean and a result code is two ways of saying the same thing, and in C the two inevitably diverge.

**`DeleteKey.remove_metadata`** stays an explicit `int` parameter rather than a separate `agc_purge_key()` function. The proto's default (retain metadata in `DESTROYED` state for audit, per NIST SP 800-57 §8.3) is `0`, so a zeroed call site gets the safe behaviour.

**`UpdateKeyState`** enforces the proto's conditional requirement: `reason` is mandatory for transitions to `COMPROMISED` (breach documentation) and `NULL` there returns `AGC_ERR_INVALID_ARGUMENT`. Destruction is not reachable through this call; it goes through `agc_delete_key`, which performs zeroization.

**`MigrateKey.target`** is an unconstrained-in-shape but `required` oneof over `{target_instance_id, ProviderTarget}`. Represented as `agc_migrate_target`, a tagged union, so "neither set" is *unrepresentable* rather than merely invalid. Tags are the proto field numbers (2, 3).

**`ValidateKeyOperation`** is the most awkward message in the specification and the C binding does not hide that. `ValidateKeyOperationResponse.options` is `MigrationStrategy`-typed but is also used for `TRANSFORM` intents, where the proto documents that `strategy` is `UNSPECIFIED` and feasibility rides on `feasible`/`infeasibility_reason`. The C accessors expose exactly that, with the convention documented on the function rather than papered over — inventing a synthetic transform-strategy enum would be a C-only concept that the wire API could not represent.

`ValidateMigrateIntent.target` is a oneof *without* `required`, so "neither" is legal on the wire and means "assess all targets". The C enum makes that a named tag, `AGC_VALIDATE_MIGRATE_TARGET_ANY`, turning an implicit case into an explicit one.

**`ExportKey`** is the only place in the API where raw key material crosses into caller memory. Two-call convention, caller-owned buffer, and an explicit contract note that the caller **must** `agc_secure_zero()` it. The buffer is caller-owned *precisely because* the library cannot know when the caller is done with it. `key_check_value` is a second optional two-call output; passing a zero `agc_buf` and `NULL` length skips it.

### 4.2 CryptoService — 12 RPCs

| RPC | C function |
|---|---|
| `Encrypt` / `Decrypt` | `agc_encrypt` / `agc_decrypt` |
| `Sign` / `Verify` | `agc_sign` / `agc_verify` |
| `DigestSign` / `DigestVerify` | `agc_digest_sign` / `agc_digest_verify` |
| `GenerateMAC` / `VerifyMAC` | `agc_generate_mac` / `agc_verify_mac` |
| `Digest` | `agc_digest` |
| `Xof` | `agc_xof` |
| `GenerateRandom` | `agc_generate_random` (+ `agc_random_bytes` convenience) |
| `SeedRandom` | `agc_seed_random` |

**Request messages become request structs, not long parameter lists.** `EncryptRequest` has five fields including a required oneof; as positional parameters that is six arguments with two pointers of the same type adjacent to each other. The struct also gets `struct_size` (§C4), which a parameter list cannot have.

**`DigestSign.hash_algorithm` is required and is a security control, not metadata.** It exists so the service can validate `len(digest)` against the declared algorithm's output length — which is what stops a SHA-1 digest being presented as SHA-256 to bypass a policy that forbids SHA-1. `agc_hash_algorithm_output_len()` is exported so callers can perform the same check locally before the call.

**`Xof` output bound.** The proto caps `output_length_bytes` at 1 MiB (`buf.validate`, resource-exhaustion defence). The C API enforces the same ceiling and returns `AGC_ERR_INVALID_ARGUMENT` rather than truncating. Larger outputs stream via `agc_xof_init`.

**`GenerateRandom` breaks the two-call convention deliberately.** The output length is `num_bytes`, known before the call, so a size query would be pure ceremony. `out.cap` must be `>= num_bytes`. `agc_random_bytes()` wraps the common case in three arguments.

**`SeedRandom` distinguishes declined from failed.** The proto notes that providers may reject or ignore user entropy. `agc_seed_random` returns `AGC_OK` with `*out_accepted = 0` and an explanatory message in that case, which a bare boolean or a bare result code could not express. The security warning is carried into the header: seed material is *mixed* into the DRBG per NIST SP 800-90A §8.7.2, never used as its sole source.

### 4.3 StreamingCryptoService — 50 RPCs

This is where the C API is genuinely cleaner than the wire API, and it is worth noticing why. Fifty RPCs exist because each Init/Update/Final step needs its own request and response message over gRPC. In C they collapse into a handful of session-shaped families:

| Family | RPCs | C functions |
|---|---|---|
| Multi-part encrypt | 3 | `agc_encrypt_init/update/final` |
| Multi-part decrypt | 3 | `agc_decrypt_init/update/final` |
| Message-based encrypt | 5 | `agc_encrypt_message_init/`, `_message`, `_begin`, `_next`, `_final` |
| Message-based decrypt | 5 | mirror |
| Multi-part sign | 3 | `agc_sign_init/update/final` |
| Multi-part verify | 3 | `agc_verify_init/update/final` |
| Message-based sign | 5 | mirror of encrypt family |
| Message-based verify | 5 | mirror |
| Multi-part MAC gen | 3 | `agc_generate_mac_init/update/final` |
| Multi-part MAC verify | 3 | `agc_verify_mac_init/update/final` |
| Multi-part digest | 4 | `agc_digest_init/update/key/final` |
| Multi-part XOF | 3 | `agc_xof_init/update/final` |
| Dual-function | 4 | `agc_digest_encrypt_update` etc. |
| Session management | 1 | `agc_session_cancel` |

Function count is 1:1 with RPC count — conformance is checkable — but the *parameter* surface shrinks dramatically because the session handle replaces `operation_id` plus, in several messages, the key name and the scope params that the session already remembers.

**A structural observation worth feeding back to the proto.** `SignUpdate`, `VerifyUpdate`, `GenerateMACUpdate`, `VerifyMACUpdate`, `DigestUpdate` and `XofUpdate` all have identical shapes — `(operation_id, data_chunk) → bool success` — and six distinct message pairs exist only so they can evolve independently. The C binding keeps six functions for 1:1 conformance, but the fact that they could be one `agc_session_absorb(s, chunk)` suggests the wire surface is larger than it needs to be. That is a spec question, not a binding question, and it is raised rather than unilaterally resolved.

**`bool success` responses vanish.** `SignUpdateResponse{bool success}` and its many siblings collapse into `agc_rc`. `EncryptInitResponse{success, operation_id}` becomes `agc_rc` plus the session handle.

**Message-based AEAD, the subtle family.** The lifecycle from the proto is preserved exactly:

```
EncryptMessageInit → ( EncryptMessage | EncryptMessageBegin → EncryptMessageNext* ) * → EncryptMessageFinal
```

Two details that are easy to lose and are called out in the header:

- `EncryptMessageFinal` carries **no ciphertext**. It tears down the session. Per-message output completed at the `end_of_message` `Next`, or at the single-shot `Message`. `agc_encrypt_message_final()` therefore takes only the session and returns only `agc_rc` — a caller cannot even ask for output that does not exist.
- Each message gets its own nonce, returned by `EncryptMessageBegin` in `partial_metadata`. `agc_decrypt_message_begin()` requires that per-message metadata as a parameter, because the session alone cannot supply it.

**`end_of_message` outputs.** `SignMessageNext` returns a signature only on the `end_of_message` call. `agc_sign_message_next()` accepts `NULL` for `out_signature` and `out_md` on non-final chunks, and on final chunks writes both. Splitting into `_next` and `_next_final` was considered and rejected: it would double the function count and diverge from the wire API's own shape for no safety gain, since the flag is already the discriminant on both sides.

**Unauthenticated plaintext.** The proto states in a comment that plaintext released by `DecryptMessageNext` before `end_of_message` is unauthenticated and must be buffered. That warning is repeated on **every** decrypt-shaped streaming function in the C header, including the dual-function ones, because a C caller writing directly to a `write(2)` in a loop is precisely the caller who will miss a comment in a `.proto` file. Authentication failure returns `AGC_ERR_CRYPTO_AUTHENTICATION_FAILED` and releases nothing.

**`DigestKey`** takes a key *name*, not bytes — the point of the operation (PKCS#11 `C_DigestKey`) is to fold a stored key's value into a digest without the caller ever seeing it. That property is preserved and is the reason the signature looks the way it does.

**Dual-function operations take two session handles.** The proto passes two `operation_id` strings, which may name sessions that do not exist, are the wrong kind, or belong to different services. Two typed handles let the library validate both handles and both `agc_session_operation()` values before touching either, turning four classes of runtime error into an immediate `AGC_ERR_INVALID_HANDLE`.

**Session TTL.** The proto makes the idle TTL mandatory. In C it is `agc_ctx_config.session_idle_ttl_seconds`, and the reason it belongs at context scope is that a local library's "server-side state" is the caller's own address space — an abandoned session is a leak of the caller's memory and possibly of locked pages, so the TTL is a self-defence mechanism rather than a service-protection one. `agc_session_free()` cancelling an open session is the other half of that defence.

### 4.4 KeyEstablishmentService — 6 RPCs

| RPC | C function |
|---|---|
| `WrapKey` / `UnwrapKey` | `agc_wrap_key` / `agc_unwrap_key` |
| `DeriveKey` | `agc_derive_key` |
| `KeyAgreement` | `agc_key_agreement` |
| `EncapsulateKey` / `DecapsulateKey` | `agc_encapsulate_key` / `agc_decapsulate_key` |

**The invariant that makes this surface safe from C:** every function produces a *new named key in the key store*; none return key material. There is no buffer for a caller to leak, forget to zeroize, or accidentally log. The only byte outputs are the wrapped blob (ciphertext, must be transportable) and the KEM ciphertext (must be sent to the peer).

**`WrapFormat` vs `KeyFormat`** are kept as two distinct enums, as in the proto, and the header restates why: `KeyFormat` is transport encoding for import/export; `WrapFormat` is the encoding of the inner key material *before* wrapping. The same key can be `KEY_FORMAT_PKCS8` on export and `WRAP_FORMAT_RAW` when wrapped. Merging them would be a plausible-looking simplification that silently breaks unwrap.

**`DeriveKey` has no `scope_spec` or `template_id`**, matching the proto. The base key's template fixes both the KDF algorithm and the output key type, which is what avoids the "KDF outputs 256 bits but the template wants 128" conflict. The provider is *always* the base key's provider — not configurable in C any more than on the wire, because that is what keeps material inside one security domain. The header states both, since a C API author's instinct would be to add the missing parameters.

**`agc_key_agreement` shares `agc_kdf_params` with `agc_derive_key`.** The proto's `agreement_params` oneof (`EcdhOperationParams`, `X942DhOperationParams`, `X3dhOperationParams`, `VendorKdfParams`) is a strict subset of the `kdf_params` oneof. Rather than define a near-identical second union — which would be two types to keep in sync forever — the wider union is reused and the library rejects out-of-subset tags with `AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS`. This is a considered trade: type-level enforcement was given up for a single source of truth. If it proves error-prone in practice, the fix is a separate narrow union, and the CI conformance test would catch the divergence.

**`EncapsulateKey` deliberately does not carry the KEM algorithm.** The proto is explicit: metadata is unauthenticated, so the decapsulator resolves the algorithm from its own private key's template. The C API cannot be more helpful here without being less safe, so it isn't.

### 4.5 CryptoPolicyService — 7 RPCs

| RPC | C function |
|---|---|
| `CreateCryptoPolicy` | `agc_create_policy` |
| `ReadCryptoPolicy` | `agc_read_policy` |
| `UpdateCryptoPolicy` | `agc_update_policy` |
| `DeleteCryptoPolicy` | `agc_delete_policy` |
| `ListCryptoPolicies` | `agc_list_policies` → iterator |
| `EvaluatePolicy` | `agc_evaluate_policy` |
| `BatchEvaluatePolicy` | `agc_batch_evaluate_policy` |

**The policy document stays an opaque string.** This is the proto's central governance decision — the API treats policy as an abstract object so deployments can adopt JSON, Rego, Cedar or a vendor language without a schema change — and projecting any policy schema into C would freeze one language into the ABI and destroy exactly that property. `format` names the language; the server validates against it.

**A denied decision is a successful call.** `agc_evaluate_policy` returns `AGC_OK` with `agc_policy_decision_allowed() == 0`. Mapping denial onto `AGC_ERR_CRYPTO_POLICY_VIOLATION` would make "policy says no" indistinguishable from "policy engine is broken", and the primary use case — UI enablement, pre-flight checks — needs precisely that distinction. `AGC_ERR_CRYPTO_POLICY_VIOLATION` is reserved for policy *enforcement* on a real operation, where a denial genuinely is a failure.

**The CEL context requirement is enforced.** The proto's `evaluation_context_required` rule demands at least one of `key_name`, `template_id`, `scope_spec`, `provider_id` or `properties`. The C API checks the same condition and returns `AGC_ERR_INVALID_ARGUMENT`, so the local path does not accept requests the wire path would reject.

**Batch bound.** The 100-item cap from `buf.validate` is enforced; `out_decisions` is a caller-provided array of `count` pointers, each freed individually.

**`PolicySummary` is a value struct, not a handle.** Six scalar/string fields, no nesting, no growth pressure — the §C3 reasoning does not apply. The strings are owned by the iterator and invalidated on the next `next()`, which is documented and matches how callers use a listing.

### 4.6 AlgorithmDiscoveryService — 3 RPCs

| RPC | C function |
|---|---|
| `ListTemplates` | `agc_list_templates` → iterator |
| `GetTemplate` | `agc_get_template` |
| `ListScopes` | `agc_list_scopes` → array |

`ListTemplatesRequest` has three orthogonal filters (scope spec, allowed statuses, required standards) plus pagination, so it gets a params struct. The proto's four documented discovery patterns all translate directly; the post-quantum one is:

```c
agc_scope_spec scope; AGC_INIT(&scope);
scope.kind = AGC_SCOPE_KIND_SIGNATURE;
scope.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;
scope.u.signature.security.quantum_safe = AGC_TRUE;

agc_list_templates_params p; AGC_INIT(&p);
p.scope_spec = &scope;
agc_template_iter *it;
agc_list_templates(ctx, &p, &it);
```

Note the `AGC_TRUE` rather than `1` — this is the tribool doing its job. `AGC_UNSET` would mean "any", and a plain `bool` API could not express the difference.

`ListScopes` returns an array (§C8).

### 4.7 ProviderService — 8 RPCs

| RPC | C function |
|---|---|
| `ListProviders` | `agc_list_providers` → iterator |
| `GetProvider` | `agc_get_provider` |
| `RegisterProviderInstance` | `agc_register_provider_instance` |
| `ListProviderInstances` | `agc_list_provider_instances` → iterator |
| `GetProviderInstance` | `agc_get_provider_instance` |
| `UpdateProviderInstance` | `agc_update_provider_instance` |
| `DeleteProviderInstance` | `agc_delete_provider_instance` |
| `MatchProviders` | `agc_match_providers` |

**Two distinct concepts, kept distinct.** `ProviderInfo` (a provider *type*, static catalog) is `agc_provider_info`; `ProviderInstance` (a *configured* provider) is `agc_provider_instance`. Collapsing them would lose the property that one PKCS#11 provider type backs many HSM slot instances with different certification levels.

**Full-replacement update, with a helper.** The proto documents `UpdateProviderInstance` as full replacement with no field masking, and read-modify-write as the intended pattern. `agc_provider_instance_to_spec()` populates a writable spec from an existing instance so the read half does not force a caller to reconstruct every field by hand — which is where fields get silently dropped.

**Credential indirection is preserved in the header text.** The proto's convention is `{"pin_env": "HSM_PAYMENTS_PIN"}` rather than the PIN itself. A C API is the one most likely to be handed a literal secret in a config map, so the convention is restated on the `configuration` field.

**`MatchProviders` returns an array**, not an iterator: results are ranked by `match_score` and the caller almost always wants the whole ranked list to choose from. `resolved_implementation` — the merge of provider defaults with instance overrides — is exposed, since that is what actually applies and it is not derivable by the caller from the two inputs.

---

## 5. Cross-cutting concerns

### 5.1 Deployment mode is a context property

`agc_ctx_config.mode` selects `EMBEDDED` (direct calls), `LOCAL` (out-of-process, same host) or `REMOTE` (gRPC). **All 98 functions behave identically in all three.**

This is the design's answer to the constraint that RPC in the cryptographic hot path is a non-starter. `AGC_MODE_EMBEDDED` is the default and involves no serialisation and no IPC. A deployment that needs a central service changes one field in a config struct; no call site moves. `agc_ctx_mode()` lets a caller with a hard latency budget assert `EMBEDDED` at startup rather than discovering a socket in a profiler.

### 5.2 Threading

`agc_ctx` is thread-safe: any number of threads may operate on one context concurrently. `agc_session` is **not**, and must be confined to one thread at a time — deliberately mirroring a PKCS#11 session without `CKF_OS_LOCKING_OK`, because a streaming context is inherently sequential and internal locking would add cost to the single-threaded case that is overwhelmingly the common one.

Handles derived from a context become invalid when the context is closed.

### 5.3 Fork

This has no analogue in the proto — a gRPC client does not inherit DRBG state — and it is a genuine hazard for an in-process library. After `fork(2)` the child must not use an inherited handle. The library installs a `pthread_atfork` handler that **poisons** inherited contexts; operations on them return `AGC_ERR_INVALID_HANDLE` rather than silently reusing a DRBG state the parent also holds. `agc_ctx_reinit_after_fork()` yields a usable context with reseeded DRBG state and reopened provider connections.

Poisoning rather than auto-reinitialising is deliberate: silent reinitialisation would hide a fork the caller may not have known about, and in a crypto library a surprising fork is worth surfacing.

### 5.4 Memory hygiene

Exported because the caller owns every output buffer and is therefore the only party that can erase it:

- `agc_secure_zero()` — guaranteed not elided.
- `agc_ct_equal()` — so callers comparing a MAC out-of-band never reach for `memcmp`.
- `agc_secure_alloc()` / `agc_secure_free()` — page-locked, zeroized on release. Optional; ordinary buffers work everywhere.

`agc_ctx_config.require_locked_memory` makes `mlock` failure a context-open failure rather than a silent degradation, which is the behaviour a high-assurance deployment needs.

### 5.5 Synchronous only

No async, no callbacks, no completion queues.

An embedded provider call is a function call and completes in microseconds; an async wrapper would add a state machine to the fastest path in the system. Callers who need concurrency use threads, which the context already supports. Callers in `REMOTE` mode who need async should be using the gRPC stubs for their language directly — that is what those stubs are for, and duplicating an event loop in C would be a large, permanent surface for a case the wire API already serves well.

If this proves wrong, the addition is a new symbol (`agc_encrypt_async` plus a completion type) under §C4's evolution rules, not a change to any existing signature.

### 5.6 Reentrancy and callbacks

The API has no callbacks. Policy resolution, provider selection and template matching are all synchronous and internal. This is a deliberate constraint: a callback into caller code during policy evaluation would create a reentrancy hazard on a lock held across a cryptographic operation, and would give a caller a hook to influence a decision the policy engine is supposed to own.

---

## 6. ABI evolution

The hidden cost of the whole exercise, and the thing most likely to make the C spec age worse than the proto.

### 6.1 What protobuf gives free and C does not

Protobuf: add a field, old readers ignore it, nothing breaks, no coordination. C has no equivalent. Every one of the mechanisms below exists to substitute for that one property.

### 6.2 The mechanisms

**Sized structs.** `struct_size` first, `AGC_INIT()` to set it, new fields appended only. A caller compiled against 1.0 passes a smaller struct to a 1.1 library, which sees the smaller size and uses defaults for the tail. A caller compiled against 1.1 passing a larger struct to a 1.0 library gets `AGC_ERR_ABI_MISMATCH` rather than a misread field.

**Symbol versioning.** `AGC_1.0`, `AGC_1.1`, … via a version script. Where a function's *semantics* change, both versions ship in one shared object and old binaries keep the old behaviour. Where the change is additive, a new symbol appears in a new version node.

**Enum growth only.** New enumerators are appended; existing values are never renumbered — the same discipline as proto field numbers, enforced by the same CI job.

**Never in a struct.** Function pointers, `bool`, `enum` without a width sentinel, bitfields, anything whose size or layout is compiler-dependent.

**Soname policy.** `libagilecrypto.so.1` for the whole 1.x line. A bump means an incompatible layout change to an existing field and is treated as a serious event requiring a written rationale.

### 6.3 What is *not* in the ABI, on purpose

The algorithm catalog. `AlgorithmDetails`' 40-arm oneof, every `*Params` message in `algorithm_params.proto`, `StandardAlgorithmCatalog` and `AlgorithmFamilySpec` are reachable only through `agc_template_info_*` accessors and `agc_template_info_to_json()`.

This is what lets the catalog remain what the proto designed it to be — **data, not schema**. Adding a template is a JSON change with no header regeneration, no recompilation and no soname implications. Freezing it into the ABI would defeat the specification's own extensibility argument, which is that new algorithms should be addable without touching the API.

---

## 7. Conformance

Two implementations, one specification, and no mechanism to keep them aligned is how a project ends up with two specifications and an argument about which is right. The proposed mechanism:

**Tier 1 — vocabulary.** CI loads the `FileDescriptorSet` and asserts that every proto enum value has a C enumerator of the same numeric value, and that no C enumerator lacks a proto counterpart. Fails the build on drift. Fully automated, no judgement required.

**Tier 2 — behaviour.** A test-vector corpus expressed as protobuf messages, executed through both front-ends:
- the Go gRPC service, and
- the C library via a thin harness.

Vectors cover the round-trips (encrypt→decrypt, sign→verify, wrap→unwrap, encapsulate→decapsulate), every metadata `algorithm_output` arm, every scope, and the negative cases — expired keys, forbidden templates, invalid state transitions, authentication failures, the unset-oneof provider-contract violation. Both front-ends must agree on outputs *and* on error codes.

**Tier 3 — artifact interop.** The one that matters most for long-term data continuity: encrypt with the C library, decrypt with the Go service, and vice versa, across every template. This is what proves that `agc_metadata_encode()` really is the protobuf wire format and stays that way.

**Tier 4 — ABI.** `abidiff` against the previous release on every build. Any change to an exported symbol's signature or to a struct's existing layout fails unless accompanied by a version-script entry and a rationale.

---

## 8. Open questions

Recorded rather than silently resolved.

1. **PKCS#11 module as a separate deliverable.** The intent-based header is primary. A PKCS#11 v3 module layered on top would let existing PKCS#11-aware software consume the framework unmodified. Worth doing — but as a distinct artifact, not by reshaping this header toward `CK_` conventions. The risk to guard against is drifting into "PKCS#11 with better names", which would lose the intent abstraction that is the entire point.

2. **Rust core with a C ABI.** Writing the implementation in Rust and exporting `cdylib` gets memory safety for the plumbing with the same universal binding surface. The counterargument is the FIPS validation boundary and what the providers are already validated as, which probably decides it — but it deserves a paragraph in the design record rather than remaining an unstated assumption.

3. **Whether `agc_key_agreement` should have its own narrow params union.** §4.4. Reusing `agc_kdf_params` gives one source of truth at the cost of runtime rather than compile-time enforcement. Revisit if it causes real errors.

4. **Whether the six identical streaming `Update` RPCs should collapse.** §4.3. A spec question. If the wire API unifies them, the C API follows; the reverse would create a divergence not worth having.

5. **Async.** §5.5. Deferred, with the addition path defined so that deferring is reversible.

6. **`user_context` cost in the hot path.** Every operation carries an optional `map<string,string>` for audit enrichment. In `EMBEDDED` mode with an empty map this is one pointer and one count — free. But it is worth measuring whether callers that populate it on every AEAD call pay more than they expect, and whether a session-scoped variant (set once at `Init`, inherited by every `Update`) is warranted.
