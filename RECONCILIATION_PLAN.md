# Reconciliation Plan — one C API from `citius_*` and `agc_*`

**Branch:** `feat/reconciled-c-api` (base: `preserve/agc-draft`, which captures both source trees)
**Target:** `libagilecrypto.so.1` — a complete, correct, ergonomic C binding for `caas.crypto.v1`
**Companion:** [`C_API_COMPARISON.md`](C_API_COMPARISON.md) — the accuracy audit this plan acts on

---

## Table of contents

- [0. Scope and deliverables](#0-scope-and-deliverables)
- [1. Foundational decisions](#1-foundational-decisions)
- [2. Type transition map](#2-type-transition-map)
  - [2.1 Scalars and presence](#21-scalars-and-presence)
  - [2.2 Vocabulary enums (generated)](#22-vocabulary-enums-generated)
  - [2.3 Value structs (by value, versioned)](#23-value-structs-by-value-versioned)
  - [2.4 Opaque handles (accessor-only)](#24-opaque-handles-accessor-only)
  - [2.5 Tagged unions](#25-tagged-unions)
  - [2.6 The algorithm catalog — deliberately not in the ABI](#26-the-algorithm-catalog--deliberately-not-in-the-abi)
- [3. RPC transition map — all 90](#3-rpc-transition-map--all-90)
  - [3.1 KeyManagementService (11)](#31-keymanagementservice-11)
  - [3.2 CryptoService (12)](#32-cryptoservice-12)
  - [3.3 StreamingCryptoService (43)](#33-streamingcryptoservice-43)
  - [3.4 KeyEstablishmentService (6)](#34-keyestablishmentservice-6)
  - [3.5 CryptoPolicyService (7)](#35-cryptopolicyservice-7)
  - [3.6 AlgorithmDiscoveryService (3)](#36-algorithmdiscoveryservice-3)
  - [3.7 ProviderService (8)](#37-providerservice-8)
- [4. The divergence register](#4-the-divergence-register)
- [5. Proto RFCs](#5-proto-rfcs)
- [6. Work plan](#6-work-plan)
- [7. Conformance](#7-conformance)
- [8. Risks](#8-risks)
- [9. Plan review](#9-plan-review)
- [10. The major design decisions](#10-the-major-design-decisions)

---

## 0. Scope and deliverables

### 0.1 What "done" means

1. **Complete** — all 90 RPCs, every request and response field reachable, every proto type
   representable.
2. **Correct** — every C construct traceable to a proto line, or listed in the divergence
   register with a reason. No third category.
3. **Functional** — compiles, links, and passes a test suite against the stub provider;
   artifacts round-trip against the Go service.
4. **Usable** — the AEAD hot path is two calls and zero allocations; the discovery path
   reads like the intent it expresses.

### 0.2 Target tree

```
include/agc/
  agc_types.h        GENERATED  vocabulary: enums, error codes, scalar/presence types
  agc_core.h         hand       ctx, rc, error detail, handles, metadata, iterators, hygiene
  agc_key.h          hand       KeyManagementService                     11 fns
  agc_crypto.h       hand       CryptoService                            12 fns
  agc_stream.h       hand       StreamingCryptoService                   43 fns
  agc_establish.h    hand       KeyEstablishmentService                   6 fns
  agc_policy.h       hand       CryptoPolicyService                       7 fns
  agc_discovery.h    hand       AlgorithmDiscoveryService                 3 fns
  agc_provider.h     hand       ProviderService                           8 fns
  agc_ext.h          hand       PROPOSED extensions, not in the proto     8 fns  [opt-in]
  agc_spi.h          hand       provider backend contract                 (v1.1)
  agilecrypto.h      hand       aggregate include
src/
  core/              ctx, rc, error, session registry, iterators, buffers
  wire/              OperationMetadata encoder/decoder (hand-written, no protobuf dep)
  stub/              zero-filling provider              [from Version A]
tools/
  protoc-gen-agc-c   enum + error-code + conformance-manifest generator
conformance/
  DIVERGENCES.yaml   machine-readable register of every deliberate deviation
  tier1_vocabulary   enum value equality
  tier1_surface      RPC↔function bijection
  tier1_fields       message field↔C field bijection, modulo DIVERGENCES.yaml
  tier2_behaviour    shared test-vector corpus, C and Go
  tier3_interop      encrypt-in-C / decrypt-in-Go and back
  tier4_abi          abidiff
tests/               [from Version A, retargeted]
examples/            [from Version A, rewritten]
docs/
  C_API_MAPPING.md   rationale — every claim traceable
  PROTO_RFCS.md      the 10 proposed specification changes
```

### 0.3 Provenance summary

| Source | What survives |
|---|---|
| **Version B (`agc_*`)** | The architecture: context, handles, rc, two-call buffers, sessions, iterators, presence types, ABI versioning, memory hygiene, fork handling, fail-closed verification, metadata encode/decode. |
| **Version A (`citius_*`)** | Field-by-field derivation discipline, the RPC↔function↔HTTP mapping comments, the proto-exact `CryptoErrorCode`, CMake + CTest + `.pc`, the stub provider, 8 tests, 3 examples. |
| **Neither** | The divergence register, the generator, the wire codec, the SPI, `agc_ext.h`. |

---

## 1. Foundational decisions

Each is applied uniformly; §2 and §3 are applications of these, not new rules.

| # | Decision | From | Rationale |
|---|---|---|---|
| **D1** | Prefix `agc_` / `AGC_`; one header per proto service file, under `include/agc/`. | B layout, A discipline | The C ABI is the substrate for Rust/Python/Java/Go bindings; it should carry the specification's identity (`agile-crypto/api`), not a server product's. One-header-per-service keeps the RPC↔function bijection checkable by file. |
| **D2** | Every function returns `agc_rc` (`int32_t`, `AGC_OK == 0`). Local conditions `-1..-99`; wire codes `-(1000 + CryptoErrorCode)`. | B | Reversible arithmetic transform — a gateway recovers the wire value with `-rc - 1000`, no lookup table, no drift when the enum grows. |
| **D3** | Failure detail lives in a thread-local `agc_error_detail` (`provider_id`, native `provider_code`, `failed_check`, message). | B | `agc_rc` is enough to *branch* on, not enough to *debug*. Allocating a detail object per error would tax the branch-only path. |
| **D4** | `bool success` + `string message` in a response are **never** projected. They collapse into `agc_rc` + `agc_last_error()`. | B | Two representations of one outcome inevitably disagree in C. Applies to 14 response messages. |
| **D5** | Byte outputs use two-call sizing: `agc_buf{data,cap}` + `size_t *out_len`. The library never allocates a buffer the caller frees. `agc_*_max_len()` exists so hot loops skip the size query. | B | Allocator symmetry across DLL boundaries; the caller owns zeroization; a TLS-record loop must not allocate. `out_len` separate from `agc_buf` lets optional outputs be skipped with `NULL`. |
| **D6** | Message outputs are **opaque handles with typed accessors**, never projected structs. | B | `KeyMetadata` → `TemplateInfo` → `AlgorithmDetails` → a **41-arm** oneof. Projecting it freezes the algorithm catalog into the ABI, so adding ML-KEM-1024 — a *data* change by the proto's own design — becomes a soname bump. |
| **D7** | Every by-pointer struct begins with `size_t struct_size`, set by `AGC_INIT()`. Fields append only; enums grow only; symbol versioning from 1.0. | B | The only substitute for protobuf's free forward compatibility. **Cannot be retrofitted after 1.0.** |
| **D8** | `optional bool` → `agc_tribool{UNSET=0, FALSE=1, TRUE=2}`. `optional bytes` → `agc_optional_slice`. `optional` scalars → value + `int has_*`. `Timestamp` → `agc_timestamp{seconds,nanos,present}`. Sentinels only where the proto documents an out-of-band zero. | B | `UNSET == 0` means a zeroed struct is "no filters" — the safe default. Version A's `-1 = unset` is unreachable through `memset(0)`, which is how every one of its own examples builds a request. |
| **D9** | Verification is fail-closed twice: `*out_valid = 0` before any work, **and** an invalid result returns `AGC_ERR_CRYPTO_SIGNATURE_INVALID` / `_AUTHENTICATION_FAILED`. `out_valid` may be `NULL`. | B | Declared divergence [DV-01]; gateway maps the code back to `{valid:false}`. |
| **D10** | Streaming state is an opaque `agc_session*`. `operation_id` is **caller-supplied at Init** (matching the proto) or generated when `NULL`; `agc_session_id()` recovers it, `agc_session_attach()` adopts one. | proto-corrected B | Version B's premise that the id is server-generated is wrong — it is a request field. The handle is still right (no string hash per Update, sanitizer-visible use-after-free, `agc_session_free()` cancels), but the API must let a caller *supply* the id, which is how audit correlation actually works here. |
| **D11** | `OperationMetadata` is an opaque handle whose canonical byte form **is the protobuf wire encoding**, produced by a hand-written codec with no protobuf dependency. | B + new | The one decision that makes C-encrypted / Go-decrypted work. `OperationMetadata` is 4 fields, one 7-arm oneof and two maps — a ~300-line codec, versus taking a libprotobuf-c dependency into a FIPS boundary. |
| **D12** | Paged lists become lazy iterators holding the page token internally; `page_size` is a tuning knob at open. `ListScopes` and `MatchProviders` return arrays. | B | 5 paged RPCs. `ListScopesRequest` is empty and `MatchProvidersResponse` is a ranked list the caller wants whole. |
| **D13** | Deployment mode is an `agc_ctx` property: `EMBEDDED` (default, direct calls) / `LOCAL` / `REMOTE`. All 90 functions behave identically in all three. | B | This is the answer to "no RPC in the cryptographic hot path". Switching deployment is one config field; no call site moves. |
| **D14** | **Boolean polarity always follows the proto.** `ProviderInstance.enabled`, `ProviderTemplateSupport.enabled`, `ListProviderInstancesRequest.enabled_only`, `MatchProvidersRequest.enabled_only`. | A discipline | Version B inverted all four to `disabled` / `include_disabled`, so a zeroed struct meant "enabled" in C and "disabled" on the wire. Polarity inversion across a marshalling boundary is a security-relevant defect, not a naming preference. |
| **D15** | Every deviation from the proto is entered in `conformance/DIVERGENCES.yaml` with a reason, a gateway mapping, and an RFC id where applicable. CI asserts the C↔proto diff equals that file **exactly**. | new | This is the structural fix for Version B's failure mode. Divergences become *declared*, not discovered. |
| **D16** | Constructs not in the proto live in `agc_ext.h` behind `AGC_ENABLE_PROPOSED_EXTENSIONS`, and are excluded from core conformance. | new | Keeps "the core is exactly 90 RPCs" a machine-checkable statement while not losing the 10 genuinely good ideas Version B found. |
| **D17** | Synchronous only. No callbacks — policy, template matching and provider selection are internal and must not be re-entered by caller code. | B | An embedded provider call completes in microseconds; async would add a state machine to the fastest path. Addition path pre-defined under D7. |
| **D18** | `agc_ctx` is thread-safe; `agc_session` is not and is confined to one thread. `pthread_atfork` poisons inherited contexts; `agc_ctx_reinit_after_fork()` recovers. | B | Mirrors PKCS#11 without `CKF_OS_LOCKING_OK`. Fork has no proto analogue and is a real in-process hazard. |
| **D19** | Memory hygiene is exported: `agc_secure_zero`, `agc_ct_equal`, `agc_secure_alloc/free`, `ctx.require_locked_memory`. | B | `ExportKey` puts raw key material in caller memory; the caller is the only party that can erase it, so it must be given the tools. |
| **D20** | Enum ↔ string helpers are generated, not hand-maintained. | B, generated | Logs, CBOM exporters and policy tooling otherwise grow parallel tables that rot. |

---

## 2. Type transition map

### 2.1 Scalars and presence

| Proto | C | Notes |
|---|---|---|
| `string` (in) | `const char *` | NUL-terminated UTF-8; `NULL` ≡ `""` where the field is not `optional`. |
| `string` (out, borrowed) | `const char *` | Owned by the parent handle; invalid once freed. Lifetime stated on every accessor. |
| `bytes` (in) | `agc_slice{const uint8_t*, size_t}` | Borrowed, never retained past the call. |
| `optional bytes` (in) | `agc_optional_slice{slice, int present}` | **3 fields**: `HkdfOperationParams.salt`, `Pbkdf2OperationParams.salt`, `Argon2OperationParams.salt`. Absent ⇒ server generates; empty ⇒ RFC 5869 §2.2 zero salt. Collapsing them silently converts a deterministic derivation into a random one. |
| `bytes` (out) | `agc_buf` + `size_t *out_len` | Two-call (D5). |
| `bytes` fixed length | `uint8_t x[N]` | Only where `buf.validate` pins it: `XtsEncryptParams.tweak[16]`, `Tls12KdfOperationParams.client_random[32]`, `server_random[32]`. |
| `bytes` bounded | `uint8_t x[N]; uint8_t x_len;` | `SignatureDomainContext.context` (`max_len 255`). Stack-allocatable in a signing loop. |
| `bool` | `int` | ABI-stable width, clean FFI. Polarity per D14. |
| `optional bool` | `agc_tribool` | **31 fields**: 2 in `UniversalSecurityProperties`, 5 across scope specs, 14 in `FormalSecurityNotions`, 8 in `ImplementationProperties`, 9 in `ProviderRequirements` (overlapping counts by message). |
| `uint32/int32/uint64/int64` | exact-width `stdint.h` | `page_size` is `int32` in the proto; the C iterator takes `uint32_t` and rejects `> INT32_MAX` [DV-07]. |
| `optional uint32` | value + `int has_*`, or documented sentinel | Sentinel only for `ReadKeyRequest.version` (`0` = latest; versions start at 1). |
| `optional string` | `const char *`, `NULL` = absent | **7 fields**: `template_id` on Create/Transform/Migrate/Digest/DigestInit/Xof/XofInit, `DeriveKeyRequest.policy`. Unambiguous because `""` is not meaningful for an id. |
| `optional <Message>` | `const T *`, `NULL` = absent | `MigrateKeyRequest.scope_spec`, `KeyMetadata.public_key_bytes/format`. |
| `enum` | `typedef enum` + `= 0x7fffffff` sentinel | Forces int32 width regardless of `-fshort-enums`, matching the wire type. |
| `map<string,string>` | `agc_kv_list{const agc_kv*, size_t}` in; indexed accessors out | Duplicate keys rejected with `AGC_ERR_INVALID_ARGUMENT`. |
| `map<string,bytes>` | `agc_kb_list` in; indexed accessors out | `VendorOutput.parameters`, `NoAlgorithmOutput.parameters`. |
| `map<string,ConfigurationParameter>` | indexed accessor returning the 5 scalars | `ProviderInfo.configuration_schema`. |
| `repeated <scalar>` | `agc_str_list` / `const T* + count` | |
| `repeated <message>` | indexed accessors on the parent handle | Per D6. |
| `google.protobuf.Timestamp` | `agc_timestamp{int64 seconds; int32 nanos; int present;}` | `time_t` avoided (32-bit on some targets). **7 fields.** |
| `google.protobuf.Struct` | `const char *` canonical JSON | `CustomOperationParams.generic_params`. Round-trips losslessly under the protobuf JSON mapping. |
| `google.protobuf.Any` | `const char *type_url` + `agc_slice value` | `CustomOperationParams.typed_params`. Exactly its two wire fields. |

> **Correction carried from the audit:** `AuditReport.report_date` is a proto **`string`**, not a
> `Timestamp`. It maps to `const char *`. Version B converted it to `agc_timestamp` — a lossy,
> non-round-tripping change.

### 2.2 Vocabulary enums (generated)

All **41 top-level enums** are emitted by `tools/protoc-gen-agc-c` from the `FileDescriptorSet`
with identical numeric values. **No enum is hand-written.**

| Group | Count | Enums |
|---|--:|---|
| Scopes | 12 | `SignatureScope`, `AeadScope`, `MacScope`, `KemScope`, `KeyAgreementScope`, `KdfScope`, `HashScope`, `KeyWrappingScope`, `SymmetricCipherScope`, `DiskEncryptionScope`, `GenericSecretScope`, `AsymmetricEncryptionScope` |
| Lifecycle / format | 4 | `KeyLifecycleState`, `KeyFormat`, `WrapFormat`, `MigrationStrategy` |
| Security | 3 | `NistSecurityLevel`, `NistStatus`, `Fips140Level` |
| Operations | 1 | `CryptoOperation` (31 values) |
| Templates | 1 | `TemplateStatus` |
| Algorithm vocabulary | 14 | `HashAlgorithm`, `EllipticCurve`, `PaddingScheme`, `SignatureFormat`, `MaskGenerationFunction`, `Argon2Variant`, `Ed25519Variant`, `Ed448Variant`, `KeyType`, `CryptoPrimitive`, `MlDsaParameterSet`, `MlKemParameterSet`, `SlhDsaHashType`, `SlhDsaParameterSet` |
| Operation params | 3 | `EcdhKdfType`, `HkdfSaltType`, `Sp800108DataType` |
| Providers | 1 | `ProviderType` |
| Policy | 1 | `PolicyDenialReason` |
| Errors | 1 | `CryptoErrorCode` → `agc_rc` via D2 |
| **Total** | **41** | |

There are also **17 nested enums**. Sixteen live inside `algorithm_params.proto` messages
(`RsaPssParams.SaltLengthMode`, `TripleDesParams.KeyingOption`, four different `Mode`s,
`Gost28147Params.BlockCipher`, `X3dhParams.Role`/`X3dhKdfType`, and so on) and are therefore
**catalog-internal and not projected** (§2.6). The seventeenth,
`HybridAlgorithmParams.CombinerStrategy`, is generated as `agc_combiner_strategy` because CBOM
reporting needs to name the combiner even though `HybridAlgorithmParams` itself is not
projected. Tier 1 asserts equality over the 41 + 1; the remaining 16 are explicitly listed as
out of scope so their absence is not mistaken for drift.

**`CryptoErrorCode` is exactly 31 values** (`UNSPECIFIED`, 1–5, 10–13, 20–23, 30–31, 40–44,
50–51, 60–62, 70–71). The two codes Version B added by hand — `INVALID_KEY_STATE_TRANSITION`
and `POLICY_VERSION_CONFLICT` — **do not exist** and must not appear until the proto adds
them (RFC-08). Version A's proto-exact `citius_crypto_error_code_t` is the correct content;
its `CITIUS_RV` numbering is discarded entirely.

Deprecated values (`HASH_ALGORITHM_SHA1=100`, `MD5=101`, and the `[deprecated=true]` algorithm
arms `TripleDes`, `Blowfish`, `Twofish`, `Dsa`) are **retained** at their proto values, marked
in comments, gateable by a build flag. Omitting them breaks round-tripping of artifacts from
legacy deployments, which is one of the requirements the framework exists to serve.

### 2.3 Value structs (by value, versioned)

Small, stable, no nested growth pressure. Each gets `struct_size` unless embedded in another
versioned struct.

| Proto | C |
|---|---|
| `UniversalSecurityProperties` | `agc_security_properties` |
| 12 × `*ScopeSpec` | 12 × `agc_*_scope_spec` (union arms, no `struct_size`) |
| `ScopeSpecification` | `agc_scope_spec` — tagged union, `struct_size` |
| `ProviderRequirements` | `agc_provider_requirements` |
| `ProviderInstance` (as input) | `agc_provider_instance_spec` |
| `ProviderTarget` | `agc_provider_target` |
| `NoParams` | **tag value only** — the message is genuinely `{}` |
| `AeadEncryptParams` | `agc_aead_encrypt_params{agc_slice aad; uint64_t plaintext_length; int has_plaintext_length;}` |
| `XtsEncryptParams` | `agc_xts_encrypt_params{uint8_t tweak[16];}` |
| `AsymmetricEncryptParams` | `agc_asymmetric_encrypt_params{agc_slice label;}` |
| `SignatureDomainContext` | `agc_signature_domain_context{uint8_t context[255]; uint8_t context_len;}` |
| `CustomizableMacParams` | `agc_customizable_mac_params{agc_slice customization;}` |
| 10 × `*OperationParams` (KDF) | 10 × `agc_*_operation_params` |
| `Sp800108DataParam` | `agc_sp800108_data_param` |
| `KeyAgreementWrapParams`, `GostWrapOperationParams` | `agc_key_agreement_wrap_params`, `agc_gost_wrap_params` |
| `CustomOperationParams` | `agc_custom_params` — one type serving all 5 `Vendor*Params` wrappers |
| `PolicySummary` | `agc_policy_summary{name, created_at, updated_at}` — **3 fields, per the proto** |
| `MatchedProvider` | `agc_provider_match{instance, resolved_implementation, match_score}` |
| `StrategyOption` | flattened into `agc_feasibility_option_at()` |

> **Correction:** `PolicySummary` has exactly `{name, created_at, updated_at}`. Version B added
> `version` and `format`. The proto has **no policy format field and no policy version field
> anywhere** except the read-only audit string `PolicyDecisionDetails.policy_version`. See §3.5.

### 2.4 Opaque handles (accessor-only)

| Proto | Handle | Why opaque |
|---|---|---|
| `OperationMetadata` | `agc_metadata` | Must be serialisable (D11); contains a 7-arm oneof. |
| `KeyMetadata` | `agc_key_info` | Transitively contains `AlgorithmDetails`. |
| `TemplateInfo` | `agc_template_info` | Contains the 41-arm algorithm oneof. |
| `ScopeInfo` | `agc_scope_info` | Repeated sub-messages. |
| `ProviderInfo` | `agc_provider_info` | Two maps + repeated `ProviderTemplateSupport`. |
| `ProviderInstance` (as output) | `agc_provider_instance` | Owns strings and a map. |
| `ImplementationProperties` | `agc_impl_props` | Repeated audits + CVEs + map. |
| `SecurityGuarantees` | `agc_security_guarantees` | 14 tribools + bounds + map; borrowed from parent. |
| `EvaluatePolicyResponse` | `agc_policy_decision` | Repeated allowed templates/ops/scopes. |
| `ValidateKeyOperationResponse` | `agc_feasibility_report` | `KeyState` + repeated `StrategyOption`. |
| `MigrationResult` + `ArchivedKeyInfo` | `agc_migration_report` | Two messages, one lifetime. |
| — | `agc_ctx`, `agc_session`, 5 × `agc_*_iter` | Runtime objects with no proto analogue. |

Ownership rule, stated once and repeated on every accessor: **a handle returned through an
out-parameter is owned by the caller and freed with its `agc_*_free`; a handle returned by
value from an accessor is borrowed from its parent and must not be freed.**

### 2.5 Tagged unions

| Proto oneof | C type | Tag = field number? |
|---|---|---|
| `ScopeSpecification.scope_spec` (12) | `agc_scope_spec` | **Yes** — 1–12, stable everywhere |
| `ProviderOutput.algorithm_output` (7) | `agc_algorithm_output_kind` | **Yes** — 10–16 |
| `MigrateKeyRequest.target` (2) | `agc_migrate_target` | **Yes** — 2, 3 |
| `ValidateKeyOperationRequest.intent` (2) | `agc_validate_intent_kind` | **Yes** — 2, 3 |
| `ValidateMigrateIntent.target` (2) | `agc_validate_migrate_target_kind` | **Yes** — 1, 2; tag `0` = "assess all", which the proto permits (oneof is *not* `required`) |
| `AlgorithmDetails.algorithm` (41) | **not projected** | §2.6 |
| `CustomOperationParams.params` (3) | `agc_custom_params_kind` | **Yes** — 10, 11; `raw_params`(20) is additive and always forwarded |
| `EncryptRequest.scope_params` (5) | `agc_encrypt_params_kind` | **No** — independent enum |
| `SignRequest.scope_params` (3) | `agc_sign_params_kind` | **No** |
| `GenerateMACRequest.scope_params` (3) | `agc_mac_params_kind` | **No** |
| `WrapKeyRequest.scope_params` (4) | `agc_wrap_params_kind` | **No** |
| `DeriveKeyRequest.kdf_params` (11) | `agc_kdf_params_kind` | **No** |

The five "No" rows are the important nuance and Version A misses it entirely: the *same*
conceptual arm carries a *different* field number per enclosing message — `aead_params` is
field 4 in `EncryptRequest` but 5 in `DecryptRequest` and 4 in `EncryptInitRequest`;
`no_context` is 3 in `SignRequest` and 5 in `VerifyRequest`. A field number therefore cannot
be a stable discriminant, so those unions use an independent enum and the marshalling layer
maps per message. **This must be stated in the header** so nobody later "fixes" it.

`NoParams` becomes a tag value (`AGC_ENCRYPT_PARAMS_NO_PARAMS = 1`), never an empty struct,
preserving the proto's property that "intentionally no parameters" is distinguishable from
"forgot to set the required oneof" (tag `0` = `NONE`, always rejected).

> **Correction:** `NoAlgorithmOutput` is **not empty** — it is
> `{map<string,bytes> parameters = 1}`. `AGC_ALGORITHM_OUTPUT_NO_OUTPUT` therefore needs
> `agc_metadata_no_output_param_count()/_at()`, which Version B omitted by treating it as a
> bare tag.

### 2.6 The algorithm catalog — deliberately not in the ABI

`AlgorithmDetails` (41-arm oneof), all 44 messages and 16 nested enums in
`algorithm_params.proto`, `HybridAlgorithmParams`, `HybridComponent`,
`StandardAlgorithmCatalog` and `AlgorithmFamilySpec` are reachable **only** through:

- flattened scalars: `agc_template_info_oid/primitive/key_type/key_size_bits()`
- the CycloneDX projection: 14 accessors mirroring `CycloneDXAlgorithmProperties` exactly
- `agc_template_info_to_json()` — the canonical catalog entry, for tooling that needs
  parameter-level detail

This is what keeps the catalog **data, not schema**: adding a template is a JSON change with
no header regeneration, no recompilation, no soname implication. It is also the single largest
behavioural difference from Version A, which embeds `citius_template_info_t` by value inside
`citius_key_metadata_t` and thereby freezes all 44 parameter messages into the ABI.

---

## 3. RPC transition map — all 90

Legend for the **Δ** column: **=** faithful · **⊕** collapse (`success`/`message` → `rc`, D4) ·
**⇢** shape change (handle/iterator/two-call) · **⚠** declared divergence, see §4.

### 3.1 KeyManagementService (11)

| RPC | Reconciled C | Δ |
|---|---|---|
| `CreateKey` | `agc_create_key(ctx, const agc_create_key_params*, agc_key_info **out_key, agc_impl_props **out_impl)` | ⊕⇢ |
| `ReadKey` | `agc_read_key(ctx, const char *name, uint32_t version, agc_key_info**)` | ⇢ |
| `ListKeys` | `agc_list_keys(ctx, const agc_list_keys_params*, agc_key_iter**)` | ⇢ |
| `DeleteKey` | `agc_delete_key(ctx, const char *name)` | ⊕ |
| `RotateKey` | `agc_rotate_key(ctx, const char *name, agc_key_info **out_new_key)` | ⊕⇢ |
| `TransformKey` | `agc_transform_key(ctx, const agc_transform_key_params*, agc_key_info**)` | ⊕⇢ |
| `UpdateKeyPolicy` | `agc_update_key_policy(ctx, const char *name, const char *new_policy, agc_key_info**)` | ⊕⇢ |
| `MigrateKey` | `agc_migrate_key(ctx, const agc_migrate_key_params*, agc_key_info**, agc_migration_report**)` | ⊕⇢ |
| `ValidateKeyOperation` | `agc_validate_key_operation(ctx, const agc_validate_key_op_params*, agc_feasibility_report**)` | ⇢ |
| `ExportKey` | `agc_export_key(ctx, const agc_export_key_params*, agc_buf out_material, size_t *out_len, agc_key_format *out_format, agc_key_info**)` | ⇢ |
| `ImportKey` | `agc_import_key(ctx, const agc_import_key_params*, agc_key_info**)` | ⊕⇢ |

**Changes from Version B — all removals of invented fields:**

- `agc_create_key_params`: drop `activation_time`, `expiration_time`. `CreateKeyRequest` has
  exactly `{name, policy, provider_id, provider_configuration, scope_spec, template_id,
  provider_requirements}`.
- `agc_delete_key`: drop `remove_metadata`. `DeleteKeyRequest` is `{name}`. A *destructive*
  parameter with no wire representation is the worst kind to invent. → RFC-05, `agc_ext.h`.
- `agc_rotate_key`: drop `reason`. → RFC-06.
- `agc_export_key`: drop `out_kcv`/`out_kcv_len`. → RFC-09.
- `agc_import_key_params`: drop `key_attestation`. → RFC-10.
- `agc_update_key_state`: **removed from core**, moved to `agc_ext.h`. → RFC-01.

**Retained from Version B:** both selection modes in one params struct (an operator pinning a
template in policy must not force a code change at the call site); `CreateKeyResponse.success/
message` → `rc`; `security_guarantees` **not** a third out-parameter, reachable via
`agc_key_info_template()` → `agc_template_info_guarantees()` so there is one path to one value;
`ExportKey`'s caller-owned buffer with an explicit `agc_secure_zero()` obligation;
`MigrateKeyRequest.target` as a tagged union so "neither set" is unrepresentable;
`ValidateKeyOperationResponse.options` exposed as-is, including the documented oddity that for
`TRANSFORM` intents `strategy` is `UNSPECIFIED` and feasibility rides on
`feasible`/`infeasibility_reason`.

### 3.2 CryptoService (12)

| RPC | Reconciled C | Δ |
|---|---|---|
| `Encrypt` | `agc_encrypt(ctx, const agc_encrypt_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `Decrypt` | `agc_decrypt(ctx, const agc_decrypt_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `Sign` | `agc_sign(ctx, const agc_sign_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `Verify` | `agc_verify(ctx, const agc_verify_request*, int *out_valid, agc_metadata**)` | ⚠ DV-01 |
| `DigestSign` | `agc_digest_sign(ctx, const agc_digest_sign_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `DigestVerify` | `agc_digest_verify(ctx, const agc_digest_verify_request*, int*, agc_metadata**)` | ⚠ DV-01 |
| `GenerateMAC` | `agc_generate_mac(ctx, const agc_mac_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `VerifyMAC` | `agc_verify_mac(ctx, const agc_verify_mac_request*, int*, agc_metadata**)` | ⚠ DV-01 |
| `Digest` | `agc_digest(ctx, const agc_digest_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `Xof` | `agc_xof(ctx, const agc_xof_request*, agc_buf, size_t*, agc_metadata**)` | ⇢ |
| `GenerateRandom` | `agc_generate_random(ctx, const agc_random_request*, agc_buf, const char **out_provider_id, agc_metadata**)` | ⚠ DV-02 |
| `SeedRandom` | `agc_seed_random(ctx, const agc_seed_random_request*, int *out_accepted, const char **out_message)` | ⚠ DV-03 |

**Changes from Version B:**

- `agc_digest` / `agc_xof`: **drop `out_selected_template`**. `DigestResponse` and `XofResponse`
  are `{output, metadata}` only. `selected_template_id` exists solely on `DigestInitResponse`
  and `XofInitResponse` — i.e. on the *streaming* path, where it is correctly surfaced as
  `agc_session_selected_template()`.
- `agc_xof`: drop the invented 1 MiB ceiling. `output_length_bytes` is an unconstrained
  `uint32`. The library may impose a *configurable* ceiling via `agc_ctx_config`, which is a
  local resource-exhaustion defence and not a claim about the proto. → RFC-07.
- Drop "REQUIRED, 1..256 bytes" from every `key_name` comment — no such constraint exists.

**Retained:** `DigestSign.hash_algorithm` treated as a **security control** — the service
validates `digest.len` against the declared algorithm, which is what stops a SHA-1 digest being
presented as SHA-256 to bypass a policy forbidding SHA-1; `agc_hash_algorithm_output_len()` is
exported so callers can pre-check. `GenerateRandom` deliberately breaks two-call sizing (the
length is `num_bytes`, known before the call). `SeedRandom` distinguishes *declined* from
*failed* — the proto notes providers may reject user entropy, and `AGC_OK` with
`*out_accepted = 0` expresses that where a bare bool or a bare code could not; the header
carries the NIST SP 800-90A §8.7.2 warning that seed material is *mixed*, never the sole source.

### 3.3 StreamingCryptoService (43)

All Init calls take an optional caller-supplied `operation_id` (D10). All `*Update` responses
are `{bool success}` and collapse to `agc_rc` (D4).

**Multi-part encrypt/decrypt (6)**

| RPC | C |
|---|---|
| `EncryptInit` | `agc_encrypt_init(ctx, const agc_encrypt_init_params*, agc_session**)` |
| `EncryptUpdate` | `agc_encrypt_update(s, agc_slice, agc_buf, size_t*)` |
| `EncryptFinal` | `agc_encrypt_final(s, agc_buf, size_t*, agc_metadata**)` |
| `DecryptInit` | `agc_decrypt_init(ctx, const agc_decrypt_init_params*, agc_session**)` |
| `DecryptUpdate` | `agc_decrypt_update(s, agc_slice, agc_buf, size_t*)` ⚠ unauthenticated output |
| `DecryptFinal` | `agc_decrypt_final(s, agc_buf, size_t*, agc_metadata**)` |

> `DecryptInitRequest` has **no `metadata` field**. Version B added one, correctly reasoning
> that a decryptor cannot recover the IV without it. This is a genuine proto hole → RFC-04,
> declared as **DV-04**, and the parameter stays because the function is otherwise unusable.

**Message-based encrypt/decrypt (10)**

| RPC | C | Note |
|---|---|---|
| `EncryptMessageInit` | `agc_encrypt_message_init(ctx, const agc_encrypt_init_params*, agc_session**)` | |
| `EncryptMessage` | `agc_encrypt_message(ctx, const agc_encrypt_message_request*, agc_buf, size_t*, agc_metadata**)` | **ctx call, not session** — the proto message takes `key_name`, no `operation_id` |
| `EncryptMessageBegin` | `agc_encrypt_message_begin(s, agc_slice ad, agc_metadata **out_partial_md)` | |
| `EncryptMessageNext` | `agc_encrypt_message_next(s, agc_slice chunk, agc_buf, size_t*)` | **no `end_of_message`** |
| `EncryptMessageFinal` | `agc_encrypt_message_final(s, agc_buf, size_t*, agc_metadata**)` | **returns `ciphertext_final` + metadata** |
| `DecryptMessageInit` | `agc_decrypt_message_init(ctx, const agc_decrypt_init_params*, agc_session**)` | |
| `DecryptMessage` | `agc_decrypt_message(ctx, const agc_decrypt_message_request*, agc_buf, size_t*, agc_metadata**)` | ctx call ⚠ DV-04 |
| `DecryptMessageBegin` | `agc_decrypt_message_begin(s, agc_slice ad, const agc_metadata *partial_md)` | ⚠ DV-04 |
| `DecryptMessageNext` | `agc_decrypt_message_next(s, agc_slice chunk, agc_buf, size_t*)` | ⚠ unauthenticated output |
| `DecryptMessageFinal` | `agc_decrypt_message_final(s, agc_buf, size_t*, agc_metadata**)` | returns `plaintext_final` + metadata |

**This is the largest single correction to Version B.** Its message-based family invented
`end_of_message`, discarded four `*MessageFinal` outputs, and made the single-shot `*Message`
calls session-scoped. The reconciled family mirrors the proto exactly. The consequence is
uncomfortable and must be stated: **as specified, the proto supports one message per session**,
because there is no per-message terminator and `Final` carries the artifact. That is a real
specification defect (RFC-03), not something a binding may fix unilaterally — a C API that
silently emits a different byte stream than the wire API is worse than one that exposes an
awkward truth. The `end_of_message` variants live in `agc_ext.h` pending RFC-03.

**Multi-part sign/verify (6)**

| RPC | C |
|---|---|
| `SignInit` / `SignUpdate` / `SignFinal` | `agc_sign_init(ctx, p, &s)` · `agc_sign_update(s, chunk)` · `agc_sign_final(s, agc_buf, size_t*, agc_metadata**)` |
| `VerifyInit` / `VerifyUpdate` / `VerifyFinal` | `agc_verify_init(ctx, p, &s)` · `agc_verify_update(s, chunk)` · `agc_verify_final(s, agc_slice sig, int *out_valid, agc_metadata**)` ⚠ DV-01 |

**Message-based sign/verify (10)**

| RPC | C | Note |
|---|---|---|
| `SignMessageInit` | `agc_sign_message_init(ctx, p, &s)` | |
| `SignMessage` | `agc_sign_message(ctx, const agc_sign_message_request*, agc_buf, size_t*, agc_metadata**)` | ctx call — proto takes `key_name` |
| `SignMessageBegin` | `agc_sign_message_begin(s)` | |
| `SignMessageNext` | `agc_sign_message_next(s, agc_slice chunk)` | response is `{bool success}` → no output |
| `SignMessageFinal` | `agc_sign_message_final(s, agc_buf, size_t*, agc_metadata**)` | returns the signature |
| `VerifyMessageInit` | `agc_verify_message_init(ctx, p, &s)` | |
| `VerifyMessage` | `agc_verify_message(ctx, const agc_verify_message_request*, int*, agc_metadata**)` | ctx call ⚠ DV-01 |
| `VerifyMessageBegin` | `agc_verify_message_begin(s)` | |
| `VerifyMessageNext` | `agc_verify_message_next(s, agc_slice chunk)` | |
| `VerifyMessageFinal` | `agc_verify_message_final(s, agc_slice sig, int*, agc_metadata**)` | ⚠ DV-01 |

**Digest (4) and XOF (3)**

| RPC | C |
|---|---|
| `DigestInit` | `agc_digest_init(ctx, const agc_digest_init_params*, agc_session**)` — template via `agc_session_selected_template()` |
| `DigestUpdate` | `agc_digest_update(s, agc_slice)` |
| `DigestKey` | `agc_digest_key(s, const char *key_name)` — takes a **name**, not bytes: folding a stored key into a digest without the caller seeing it is the entire point (PKCS#11 `C_DigestKey`) |
| `DigestFinal` | `agc_digest_final(s, agc_buf, size_t*, agc_metadata**)` |
| `XofInit` / `XofUpdate` / `XofFinal` | `agc_xof_init(ctx, p, &s)` · `agc_xof_update(s, chunk)` · `agc_xof_final(s, agc_buf, size_t*, agc_metadata**)` |

**Dual-function (4)**

| RPC | C |
|---|---|
| `DigestEncryptUpdate` | `agc_digest_encrypt_update(agc_session *digest_s, agc_session *encrypt_s, agc_slice pt, agc_buf, size_t*)` |
| `DecryptDigestUpdate` | `agc_decrypt_digest_update(agc_session *decrypt_s, agc_session *digest_s, agc_slice ct, agc_buf, size_t*)` ⚠ unauthenticated |
| `SignEncryptUpdate` | `agc_sign_encrypt_update(agc_session *sign_s, agc_session *encrypt_s, agc_slice pt, agc_buf, size_t*)` |
| `DecryptVerifyUpdate` | `agc_decrypt_verify_update(agc_session *decrypt_s, agc_session *verify_s, agc_slice ct, agc_buf, size_t*)` ⚠ unauthenticated |

Two typed handles instead of two `operation_id` strings: the library validates both handles and
both `agc_session_operation()` values before touching either, turning four classes of runtime
error (nonexistent, wrong kind, wrong context, already finalised) into an immediate
`AGC_ERR_INVALID_HANDLE`.

**The unauthenticated-plaintext rule** is repeated on **every** decrypt-shaped streaming
function, including the dual-function ones: plaintext released before the closing call is not
authenticated, must be buffered, and must not be acted on. The proto states this in a comment;
a C caller writing straight into `write(2)` in a loop is exactly the caller who will not read
a `.proto` file.

### 3.4 KeyEstablishmentService (6)

| RPC | Reconciled C | Δ |
|---|---|---|
| `WrapKey` | `agc_wrap_key(ctx, const agc_wrap_key_params*, agc_buf out_wrapped, size_t*, agc_metadata**)` | ⇢ |
| `UnwrapKey` | `agc_unwrap_key(ctx, const agc_unwrap_key_params*, agc_key_info**, agc_metadata**)` | ⊕⇢ |
| `DeriveKey` | `agc_derive_key(ctx, const agc_derive_key_params*, agc_key_info**, agc_metadata**)` | ⊕⇢ |
| `KeyAgreement` | `agc_key_agreement(ctx, const agc_key_agreement_params*, agc_key_info**, agc_metadata**)` | ⊕⇢ |
| `EncapsulateKey` | `agc_encapsulate_key(ctx, const agc_encapsulate_params*, agc_buf out_ct, size_t*, agc_key_info**, agc_metadata**)` | ⇢ |
| `DecapsulateKey` | `agc_decapsulate_key(ctx, const agc_decapsulate_params*, agc_key_info**, agc_metadata**)` | ⊕⇢ |

**Change from Version B:** `agc_wrap_key` drops `out_actual_format`. `WrapKeyResponse` is
`{wrapped_key, metadata}` — no format echo. → RFC-11 (minor).

**Retained, and worth restating in the header because they are counter-intuitive:**

- **No function here returns key material.** Every one produces a new *named* key in the store.
  The only byte outputs are the wrapped blob (ciphertext, must be transportable) and the KEM
  ciphertext (must be sent to the peer). That invariant is what makes this surface safe to
  expose from C at all.
- `WrapFormat` and `KeyFormat` stay two enums. `KeyFormat` is transport encoding for
  import/export; `WrapFormat` is the encoding of the inner key material *before* wrapping. The
  same key is `KEY_FORMAT_PKCS8` on export and `WRAP_FORMAT_RAW` when wrapped. Merging them is
  a plausible-looking simplification that silently breaks unwrap.
- `DeriveKey` has **no** `scope_spec` or `template_id` — the base key's template fixes both the
  KDF and the output key type, which is what avoids the "KDF outputs 256 bits, template wants
  128" conflict. The derived key is **always** in the base key's provider. Both are stated
  explicitly, because a C API author's instinct is to add the missing parameters.
- `agc_key_agreement` reuses `agc_kdf_params`: `agreement_params` (`Ecdh`, `X942Dh`, `X3dh`,
  `VendorKdf`) is a strict subset of `kdf_params` (11 arms). One source of truth, with
  out-of-subset tags rejected at runtime as `AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS`. Trade
  recorded as an open question — type-level enforcement traded for no duplicated union.
- `EncapsulateKey` deliberately carries **no** KEM algorithm: metadata is unauthenticated, so
  the decapsulator resolves the algorithm from its own private key's template. The C API cannot
  be more helpful without being less safe.

### 3.5 CryptoPolicyService (7)

| RPC | Reconciled C |
|---|---|
| `CreateCryptoPolicy` | `agc_create_policy(ctx, const char *name, const char *policy_document)` |
| `ReadCryptoPolicy` | `agc_read_policy(ctx, const char *name, agc_policy_document *out)` + `agc_policy_document_release()` |
| `UpdateCryptoPolicy` | `agc_update_policy(ctx, const char *name, const char *policy_document)` |
| `DeleteCryptoPolicy` | `agc_delete_policy(ctx, const char *name)` |
| `ListCryptoPolicies` | `agc_list_policies(ctx, const char *name_prefix, uint32_t page_size, agc_policy_iter**)` |
| `EvaluatePolicy` | `agc_evaluate_policy(ctx, const agc_evaluate_policy_request*, agc_policy_decision**)` |
| `BatchEvaluatePolicy` | `agc_batch_evaluate_policy(ctx, const agc_evaluate_policy_request*, size_t count, agc_policy_decision **out, int32_t *allowed, int32_t *denied)` |

**This service shrinks substantially versus Version B, which invented an entire versioning and
format story:**

| Version B | Proto reality |
|---|---|
| `agc_create_policy(..., format, int64_t *out_version)` | `CreateCryptoPolicyRequest{name, policy_document}` → `{success, message}` |
| `agc_policy_document{format, version, created_at, updated_at}` | `ReadCryptoPolicyResponse{name, policy_document}` |
| `agc_update_policy(..., format, expected_version, out_new_version)` | `UpdateCryptoPolicyRequest{name, policy_document}` |
| `agc_policy_summary{version, format}` | `PolicySummary{name, created_at, updated_at}` |
| `AGC_ERR_CRYPTO_POLICY_VERSION_CONFLICT` | no such `CryptoErrorCode` |

Optimistic concurrency on a shared governance artifact is a good idea and policy-language
tagging is arguably necessary — but both are **proto changes** (RFC-02), not C inventions. Ship
the thin version; move the rest to `agc_ext.h` and `PROTO_RFCS.md`.

**Retained:** the policy document stays an **opaque string** — projecting any policy schema into
C would freeze one language (JSON / Rego / Cedar) into the ABI and destroy the governance
abstraction that is the point. A **denied decision is a successful call**: `AGC_OK` with
`agc_policy_decision_allowed() == 0`. Mapping denial onto `AGC_ERR_CRYPTO_POLICY_VIOLATION`
would make "policy says no" indistinguishable from "policy engine is broken", and pre-flight
UI enablement needs exactly that distinction; the error code is reserved for enforcement on a
real operation. Drop the invented 100-item batch cap — the library may impose a configurable
limit as local defence, not as a proto claim.

`EvaluatePolicyRequest` requires at least one of `key_name`, `template_id`, `scope_spec`,
`provider_id`, `properties` (CEL rule `evaluation_context_required`). The C API applies the same
check and returns `AGC_ERR_INVALID_ARGUMENT`, so the local path never accepts what the wire path
would reject.

### 3.6 AlgorithmDiscoveryService (3)

| RPC | Reconciled C |
|---|---|
| `ListTemplates` | `agc_list_templates(ctx, const agc_list_templates_params*, agc_template_iter**)` |
| `GetTemplate` | `agc_get_template(ctx, const char *template_id, agc_template_info**)` |
| `ListScopes` | `agc_list_scopes(ctx, agc_scope_info ***out, size_t *out_count)` + `agc_scope_info_list_free()` |

`ListTemplatesRequest` has three orthogonal filters (`scope_spec`, `allowed_statuses`,
`required_standards`) plus pagination — hence a params struct. `ListScopesRequest` is `{}` and
the result set is ~12 entries, so an array; pagination machinery there would be cost with no
benefit.

This is the surface where the tribool earns its keep, and the reconciled form should be in the
header as the worked example:

```c
agc_scope_spec scope; AGC_INIT(&scope);
scope.kind = AGC_SCOPE_KIND_SIGNATURE;
scope.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;
scope.u.signature.security.quantum_safe = AGC_TRUE;   /* not 1 — AGC_UNSET means "any" */

agc_list_templates_params p; AGC_INIT(&p);
p.scope_spec = &scope;
agc_template_iter *it;
agc_list_templates(ctx, &p, &it);
```

Under Version A's encoding the same struct zero-initialised would have requested templates that
are explicitly **not** quantum-safe.

### 3.7 ProviderService (8)

| RPC | Reconciled C |
|---|---|
| `ListProviders` | `agc_list_providers(ctx, const agc_list_providers_params*, agc_provider_iter**)` |
| `GetProvider` | `agc_get_provider(ctx, const char *provider_id, agc_provider_info**)` |
| `RegisterProviderInstance` | `agc_register_provider_instance(ctx, const agc_provider_instance_spec*, agc_provider_instance**)` |
| `ListProviderInstances` | `agc_list_provider_instances(ctx, const agc_list_provider_instances_params*, agc_provider_instance_iter**)` |
| `GetProviderInstance` | `agc_get_provider_instance(ctx, const char *instance_id, agc_provider_instance**)` |
| `UpdateProviderInstance` | `agc_update_provider_instance(ctx, const agc_provider_instance_spec*, agc_provider_instance**)` |
| `DeleteProviderInstance` | `agc_delete_provider_instance(ctx, const char *instance_id)` |
| `MatchProviders` | `agc_match_providers(ctx, const agc_match_providers_params*, agc_provider_match **out, size_t *out_count)` |

**Polarity corrections (D14) — four fields Version B inverted:**

| Proto | Version B | Reconciled |
|---|---|---|
| `ProviderInstance.enabled` | `int disabled` | `int enabled` |
| `ProviderTemplateSupport.enabled` | `int *out_disabled` | `int *out_enabled` |
| `ListProviderInstancesRequest.enabled_only` | `int enabled_only` ✓ | `int enabled_only` |
| `MatchProvidersRequest.enabled_only` | `int include_disabled` | `int enabled_only` |

Two of the four inverted the zero value, so `AGC_INIT()` would have produced the opposite of
the proto's default across the marshalling boundary.

**Retained:** `ProviderInfo` (a provider *type*) and `ProviderInstance` (a *configured*
provider) stay distinct — collapsing them loses the property that one PKCS#11 provider type
backs many HSM slots at different certification levels. `UpdateProviderInstance` is documented
full-replacement with no field masking, so `agc_provider_instance_to_spec()` exists to make
read-modify-write safe rather than letting callers reconstruct every field by hand (which is
where fields get silently dropped). The credential-indirection convention
(`{"pin_env": "HSM_PAYMENTS_PIN"}`, never the PIN) is restated on `configuration` — a C API is
the one most likely to be handed a literal secret. `MatchProviders` returns a ranked array and
exposes `resolved_implementation`, the merge of provider defaults with instance overrides,
because that is what actually applies and the caller cannot derive it from the two inputs.

---

## 4. The divergence register

`conformance/DIVERGENCES.yaml` is the contract that makes the whole thing checkable. CI computes
the C↔proto difference and asserts it equals this file **exactly** — no undeclared divergence,
and no stale entry.

| id | Divergence | Reason | Gateway mapping | RFC |
|---|---|---|---|---|
| **DV-01** | Verification returns `AGC_ERR_CRYPTO_SIGNATURE_INVALID` / `_AUTHENTICATION_FAILED` instead of `AGC_OK` + `valid:false`. 8 functions. | The classic C bug is `rc` ignored and `valid` uninitialised. Fail-closed twice makes either check individually sufficient. | error code → `{valid:false}`, not a transport error | — |
| **DV-02** | `GenerateRandom` does not use two-call sizing. | Output length is `num_bytes`, known before the call; a size query is pure ceremony. | none | — |
| **DV-03** | `SeedRandom` returns `AGC_OK` + `*out_accepted = 0` for "provider declined". | The proto notes providers may reject user entropy; a bare bool cannot distinguish declined from failed. | → `{success:false, message}` | — |
| **DV-04** | `metadata` added to `DecryptInit`, `DecryptMessage`, `DecryptMessageBegin`. | Without the nonce the provider cannot initialise. **These functions are unimplementable without it.** | drop until RFC-04 lands; C-only sessions unaffected | RFC-04 |
| **DV-05** | `success`/`message` response fields not projected (14 messages). | Two representations of one outcome (D4). | `rc == AGC_OK` → `{success:true}` | RFC-12 |
| **DV-06** | `operation_id` replaced by `agc_session*` in 37 streaming functions. | Cost and safety in a hot loop; `agc_session_id()`/`_attach()` keep them interconvertible. | id ↔ handle via the session registry | — |
| **DV-07** | `page_size`/`page_token` replaced by iterators (5 RPCs); `int32` → `uint32_t` with a range check. | Cursor bookkeeping does not belong in every caller. | iterator drives the same request fields | — |
| **DV-08** | `SecurityGuarantees` reachable only via `agc_key_info_template()`, not as a `CreateKey` out-parameter. | One path to one value; two would eventually disagree. | populate from the template | — |
| **DV-09** | `MigrationResult` + `ArchivedKeyInfo` merged into one `agc_migration_report`. | One lifetime, one free. | split on marshalling | — |
| **DV-10** | Configurable local ceilings on `Xof.output_length_bytes` and batch size. | Local resource-exhaustion defence; **not** a proto constraint. Off by default. | none | RFC-07 |
| **DV-11** | `AlgorithmDetails`, the 44 `algorithm_params.proto` messages and their 16 nested enums not projected; reachable via flattened accessors, the CycloneDX projection, and `_to_json()`. | Keeps the catalog data, not schema (D6). | full fidelity retained in the JSON form | — |

Any construct not in the proto and not in this table is a **bug**, by definition. That is the
whole point.

---

## 5. Proto RFCs

Filed as `docs/PROTO_RFCS.md`; the corresponding C functions live in `agc_ext.h` until accepted.

| RFC | Change | Origin |
|---|---|---|
| **RFC-01** | Add `UpdateKeyState` to `KeyManagementService`. `KeyLifecycleState` has 8 values and no RPC moves between them; NIST SP 800-57 §7 is unimplementable. `reason` mandatory for `→ COMPROMISED`. | B's `agc_update_key_state` |
| **RFC-02** | Add `format` and optimistic-concurrency `version` to the policy messages. | B's policy design |
| **RFC-03** | Add a per-message terminator to the message-based families (`bool end_of_message` on the four `*MessageNext`, or split `*MessageNextFinal`). **Without this the family supports one message per session**, defeating its purpose. | B's `end_of_message` |
| **RFC-04** | Add `OperationMetadata metadata` to `DecryptInitRequest`, `DecryptMessageRequest`, `DecryptMessageBeginRequest`. Currently unimplementable. | B, DV-04 |
| **RFC-05** | Add `bool remove_metadata` to `DeleteKeyRequest` (default `false` = retain in `DESTROYED` for audit, NIST SP 800-57 §8.3). | B |
| **RFC-06** | Add `string reason` to `RotateKeyRequest` for the audit trail. | B |
| **RFC-07** | Add `buf.validate` bounds to `output_length_bytes` and `BatchEvaluatePolicyRequest.evaluations`. | B |
| **RFC-08** | Add `CRYPTO_ERROR_INVALID_KEY_STATE_TRANSITION` and `CRYPTO_ERROR_POLICY_VERSION_CONFLICT` — **only if** RFC-01 and RFC-02 land. | B, hand-added to `agc_types.h` |
| **RFC-09** | Add `bytes key_check_value` to `ExportKeyResponse` (KMIP/PKCS#11 practice). | B |
| **RFC-10** | Add `bytes key_attestation` to `ImportKeyRequest` for BYOK evidence. | B |
| **RFC-11** | Add `WrapFormat format` echo to `WrapKeyResponse`. | B |
| **RFC-12** | Deprecate `bool success` + `string message`, redundant with gRPC status. | A + B |
| **RFC-13** | Add MAC streaming (`GenerateMACInit/Update/Final`, `VerifyMACInit/Update/Final`). `MAC_SCOPE_STREAMING` exists with no RPCs to use it; every other primitive has the family. | B |
| **RFC-14** | Add `CancelOperation`. A session neither finalised nor cancelled strands provider state and key material until TTL. | B |
| **RFC-15** | Consider unifying the six identical `(operation_id, data_chunk) → bool` `*Update` RPCs. Raised, not resolved — if the wire unifies, C follows; the reverse would create drift. | B |

**Sequencing note:** RFC-03 and RFC-04 block a *usable* message-based AEAD family. They should
be filed and resolved before Phase 4, or the C API ships a family that structurally conforms and
functionally cannot be used.

---

## 6. Work plan

Fourteen commits. Every one builds and passes what exists at that point.

| # | Commit | Contents | Gate |
|---:|---|---|---|
| 1 | scaffold | CMake ≥ 3.20 (not 3.25 — 3.22 is current Ubuntu LTS), `.pc.in`, `include/agc/` skeleton, `agilecrypto.h`, CI | configure + build empty lib |
| 2 | generator | `tools/protoc-gen-agc-c`: emits `agc_types.h` (41 top-level enums + `CombinerStrategy`, `agc_rc` codes, enum↔string tables) + `conformance/manifest.json` | Tier 1 vocabulary green |
| 3 | scalars & presence | `agc_slice`, `agc_optional_slice`, `agc_buf`, `agc_tribool`, `agc_timestamp`, `agc_kv_list`, `agc_kb_list`, `agc_str_list`, `AGC_INIT`, `AGC_ENUM32`, `AGC_API` | header parses `-Wall -Wextra -Wpedantic -std=c11` |
| 4 | scope specs & params | 12 scope specs, `agc_scope_spec`, the 5 operation-params unions, `agc_custom_params`, `agc_provider_requirements` | Tier 1 fields (types only) |
| 5 | core runtime | `agc_ctx` + config + modes, `agc_rc` plumbing, `agc_error_detail`, memory hygiene, fork handling, handle lifecycle, iterators | unit tests |
| 6 | **wire codec** | hand-written `OperationMetadata` encoder/decoder; `agc_metadata_*` accessors incl. `no_output` params map | round-trip fuzz + golden vectors from Go |
| 7 | key management | `agc_key.h` — 11 fns, `agc_key_info`, `agc_migration_report`, `agc_feasibility_report` | Version A's `test_key_management` retargeted |
| 8 | crypto | `agc_crypto.h` — 12 fns, `*_max_len` helpers | `test_encrypt_decrypt`, `test_sign_verify`, `test_mac_digest` |
| 9 | streaming | `agc_stream.h` — 43 fns, `agc_session` registry, TTL, dual-function validation | `test_streaming` |
| 10 | establishment | `agc_establish.h` — 6 fns | `test_key_establishment` |
| 11 | policy + discovery + provider | `agc_policy.h` (7), `agc_discovery.h` (3), `agc_provider.h` (8), `agc_impl_props`, `agc_template_info` + CycloneDX, `_to_json()` | `test_policy`, `test_discovery` |
| 12 | conformance | `DIVERGENCES.yaml`, Tier 1/1b/1c jobs, Tier 4 `abidiff` baseline | **the whole surface is machine-checked** |
| 13 | extensions | `agc_ext.h` behind `AGC_ENABLE_PROPOSED_EXTENSIONS`; `docs/PROTO_RFCS.md` | core conformance unaffected when off |
| 14 | docs & examples | `C_API_MAPPING.md` rewritten with per-claim proto citations; 3 examples rewritten; README replaced | every claim has a file:line |

**Deferred to 1.1:** `agc_spi.h` (provider backend contract), Tier 2 corpus, Tier 3 interop
harness. These need the Go side to move in step and should not gate the header freeze.

**Ordering rationale.** The generator comes second because everything downstream depends on the
vocabulary and it is the one artefact that must never be hand-edited. The wire codec comes
before any operation because `agc_metadata` is an out-parameter of 30+ functions and its
ownership model shapes their signatures. Conformance lands before extensions so the core count
is pinned before anything optional can blur it.

---

## 7. Conformance

| Tier | Job | Asserts | Catches (from the audit) |
|---|---|---|---|
| **1** | vocabulary | every proto enum value ↔ C enumerator, identical numeric value, both directions | B's two invented error codes |
| **1b** | surface | RPC count == 90; bijection between RPCs and core functions; `agc_ext.h` symbols excluded | B's 8 phantom RPCs, "98 RPCs" |
| **1c** | fields | every request/response field has a C counterpart and vice versa, modulo `DIVERGENCES.yaml` | B's ~15 invented/dropped fields; A's inconsistent presence |
| **1d** | polarity & presence | boolean field names and zero-values match the proto; every `optional` field has explicit presence | D14's four inversions; A's `-1 = unset` trap |
| **2** | behaviour | shared vector corpus through the Go service and the C library; agree on outputs **and** error codes | A's error-code collision |
| **3** | artifact interop | encrypt in C → decrypt in Go, and back, every template | proves `agc_metadata_encode()` is the wire format |
| **4** | ABI | `abidiff` vs previous release; layout change to an existing field fails without a version-script entry and rationale | A's absent evolution mechanism |

Tiers 1, 1b, 1c and 1d are roughly two days' work and would have caught almost everything in the
audit. **They are commit 12, not a follow-up.**

---

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| RFC-03/RFC-04 stall; message-based AEAD ships unusable. | High | File both before Phase 4. If unresolved, ship the family with DV-04 and a prominent header note; do **not** invent a wire-invisible parameter. |
| Hand-written protobuf codec has a bug. | High — silent artifact corruption | ~300 lines for one message. Golden vectors generated by the Go side, plus round-trip fuzzing, in commit 6. Tier 3 is the backstop. |
| Handle-and-accessor surface (≈250 accessors) becomes a maintenance burden. | Medium | Generate the accessors from the descriptor alongside the enums. Hand-writing 250 getters is how they drift. |
| `struct_size` discipline erodes; someone inserts a field mid-struct. | High — silent ABI break | Tier 4 `abidiff` from commit 12; `AGC_INIT` in every example so the idiom is visible. |
| Version A's tests encode Version A's semantics (e.g. `memset(0)` tribools). | Medium | Retarget rather than port: each test is rewritten against the new presence rules as part of its phase commit, not bulk-converted. |
| `agc_ext.h` quietly becomes the real API. | Medium | Off by default; excluded from Tier 1b; every symbol carries its RFC id; a symbol whose RFC is rejected is deleted, not kept. |
| Proto moves under us (`github.com/agile-crypto/api` vs the local copy). | Medium | Pin the `FileDescriptorSet` by digest in `conformance/`; the generator consumes the pinned set; bumping it is an explicit commit. |

---

## 9. Plan review

Reading the plan back critically, four things deserve challenge.

**9.1 Is 1:1 RPC conformance the right goal for a local library?**
Partly. It is right for *checkability* — the bijection is what makes drift detectable, and it is
the discipline Version A had and Version B lost. It is wrong as a *usability* goal: 43 streaming
functions exist because gRPC needs a message pair per step, and six of them are byte-identical
`(session, chunk) → rc`. The plan keeps all 43 for conformance and should additionally ship
`agc_session_absorb(s, chunk)` as a documented alias dispatching on
`agc_session_operation()` — one symbol, zero divergence, and it removes the most common
papercut. Added to commit 9. RFC-15 remains the real fix.

**9.2 Is the hand-written protobuf codec justified?**
It is the plan's biggest build-versus-buy call and the one most likely to be second-guessed.
The alternative — `protobuf-c` or `nanopb` for one message — costs a dependency inside a
prospective FIPS boundary, plus generated code that must itself be reviewed. `OperationMetadata`
is 4 fields, one 7-arm oneof over 7 small messages, and two maps; the encoder is varints,
length-delimited fields and one recursion level. The decision holds, **provided** the golden
vectors come from the Go implementation rather than from our own encoder — otherwise the test
proves only self-consistency. That condition is now explicit in commit 6.

**9.3 Is DV-04 acceptable?**
Uncomfortably, yes. Three functions get a parameter with no wire field, which is exactly the
sin Version B committed with `end_of_message`. The difference is material and worth being
precise about: `end_of_message` **changes the byte stream** a conforming peer produces, so an
artifact written by the C library could not be read by the Go service. DV-04's `metadata` is an
*input* the local provider needs and that the wire path obtains out-of-band; no artifact
differs. Still, it must be declared, RFC'd, and revisited — not normalised. If RFC-04 is
rejected, the message-based decrypt family should be **removed from core** rather than shipped
with a parameter the specification refuses.

**9.4 What is under-specified?**
Three things, honestly:
- **Session TTL enforcement in `EMBEDDED` mode.** The "server-side state" is the caller's own
  address space, so the TTL is self-defence against leaked sessions rather than service
  protection. Who runs the timer in a library with no thread? Probably lazy expiry checked on
  each session touch, plus expiry at `agc_ctx_close()`. Needs deciding in commit 9.
- **`user_context` in the hot path.** Carried on every operation as `map<string,string>`. Empty
  is one pointer and one count, but callers who populate it per-AEAD-call may pay more than they
  expect. Measure in commit 8; a session-scoped variant set once at `Init` is the likely answer.
- **Audit sink in `EMBEDDED` mode.** `user_context` is collected and has nowhere to go with no
  server present. Either the SPI grows an audit callback (which reintroduces the reentrancy
  hazard D17 exists to avoid — so it must be *after* the crypto completes, never during policy
  evaluation) or `EMBEDDED` documents that audit is the caller's responsibility. Decide with
  `agc_spi.h` in 1.1.

**9.5 What the plan gets right.** The divergence register is load-bearing and is the one
structural idea neither source tree had: it converts "is this binding accurate?" from a review
question into a build failure. Everything else in the plan is recoverable; if that mechanism is
dropped, the reconciled API will drift exactly the way Version B did, and nobody will notice
until an artifact fails to decrypt in production.

---

## 10. The major design decisions

Six decisions carry the design. The rest follow from them.

### ① The divergence register is the deliverable
Every difference between C and proto is declared in `DIVERGENCES.yaml`, with a reason and a
gateway mapping, and CI asserts the actual difference equals that file exactly. **A construct
not in the proto and not in the register is a build failure, not a discussion.** This is the
direct structural answer to how Version B accumulated ~15 undetected inventions while carrying
an excellent 610-line design document — good prose is not a conformance mechanism.

### ② Deployment mode is a context property, not an API
`agc_ctx_config.mode ∈ {EMBEDDED, LOCAL, REMOTE}`, and all 90 functions behave identically in
all three. `EMBEDDED` is the default and involves no serialisation and no IPC. This is what
makes "C is the ABI" real: one implementation, three transports, and gRPC becomes a front end
over this core rather than a parallel implementation that drifts. A deployment that later needs
a central service changes one config field; no call site moves.

### ③ Handles for messages, buffers for bytes
Byte outputs are caller-owned buffers with two-call sizing. Message outputs are opaque handles
with typed accessors. This is the ABI decision: `KeyMetadata` transitively contains a 41-arm
oneof over the entire algorithm catalog, and projecting it — as Version A does — would make
adding ML-KEM-1024 a soname bump, defeating the specification's own "catalog is data, not
schema" argument. The cost is real and should be stated plainly: ~250 accessors, a 3.5× larger
symbol table than Version A. That is why they are generated.

### ④ Metadata's canonical form is the protobuf wire encoding
`agc_metadata_encode()` emits exactly what the Go service writes, via a hand-written ~300-line
codec with no protobuf dependency. Without this there is no durable ciphertext and no
cross-implementation interop — the two requirements the framework exists to serve. Version A
has no serialisation at all and its own example demonstrates the failure: a shallow copy of
borrowed pointers, annotated "MUST be stored", with no way to store it.

### ⑤ Presence is load-bearing, and `UNSET` must be zero
`agc_tribool{UNSET=0, FALSE=1, TRUE=2}`, `agc_optional_slice`, explicit `has_*`, `agc_timestamp`
with a presence flag. A zeroed request struct must mean "no filters". Version A's `-1 = unset`
is unreachable through `memset(0)` — the construction idiom every one of its own examples uses
— so its shipped `encrypt_decrypt` example requests a key that must **not** be FIPS-approved.
The same principle drives the polarity rule (D14): `enabled`, never `disabled`, because the
zero value must mean the same thing on both sides of the marshalling boundary.

### ⑥ Fidelity first, ergonomics second — and never silently
Where the proto is awkward, the C API is awkward too, and the awkwardness is documented and
RFC'd rather than fixed locally. The message-based AEAD family is the test case: Version B made
it pleasant to use by inventing `end_of_message` and discarding four `*MessageFinal` outputs,
producing a C library that emits a different byte stream than a conforming peer. The reconciled
version mirrors the proto, states plainly that the family currently supports one message per
session, and files RFC-03. A binding may improve *ergonomics* freely — sessions instead of
strings, iterators instead of page tokens, `rc` instead of `bool success` — because those are
invisible on the wire. It may not improve *semantics* alone.

---

*Plan targets `caas.crypto.v1` as of `citius-server@feat/openssl-provider`: 90 RPCs across 7
services, 41 top-level enums (+17 nested, 16 of them catalog-internal), 304 messages. Sources
preserved on `preserve/agc-draft` (`6968c67`).*
