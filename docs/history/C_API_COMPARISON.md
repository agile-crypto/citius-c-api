# C API Design Comparison — `citius_*` vs `agc_*`

**Purpose:** decide how to reconcile the two candidate C bindings for the intent-based
cryptographic API into one design that is *accurate*, *complete*, *clean* and *easy to use*.

**Ground truth:** `citius-server/proto/api/**/*.proto`, protobuf package `caas.crypto.v1`
(the local copy of `github.com/agile-crypto/api`).

**Status:** every numeric claim in this document was verified mechanically against the
proto and by compiling the code. See [Appendix A](#appendix-a--verification-method).

---

## Table of contents

- [0. Which two versions?](#0-which-two-versions)
- [1. Executive summary](#1-executive-summary)
- [2. Ground truth: the proto surface](#2-ground-truth-the-proto-surface)
- [3. Accuracy audit](#3-accuracy-audit)
  - [3.1 RPC coverage](#31-rpc-coverage)
  - [3.2 Version A defects (`citius_*`)](#32-version-a-defects-citius_)
  - [3.3 Version B defects (`agc_*`)](#33-version-b-defects-agc_)
- [4. Design comparison, axis by axis](#4-design-comparison-axis-by-axis)
- [5. Gaps neither version closes](#5-gaps-neither-version-closes)
- [6. Gaps in the proto that the C work exposed](#6-gaps-in-the-proto-that-the-c-work-exposed)
- [7. Reconciliation: the recommended synthesis](#7-reconciliation-the-recommended-synthesis)
- [8. Conformance harness](#8-conformance-harness)
- [Appendix A — verification method](#appendix-a--verification-method)

---

## 0. Which two versions?

The repository state is confusing and worth stating plainly before anything else:

| | Version A | Version B |
|---|---|---|
| **Prefix** | `citius_*` / `CITIUS_*` | `agc_*` / `AGC_*` |
| **Location** | `include/citius/{types,messages,services}/` | flat `agc_*.h` at repo root |
| **Git state** | committed (`1f0d742`) | **untracked working-tree files** |
| **Branches** | `main` and `alternate` both point at `1f0d742` | — |
| **Size** | 37 headers + 8 tests + 3 examples + stub provider (~230 KB) | 10 headers + 1 design doc (~130 KB) |
| **Buildable** | yes — CMake + CTest, 8/8 tests pass | headers parse; no build system, no impl |
| **Design doc** | `README.md` (stale) | `C_API_MAPPING.md` (610 lines, excellent) |

> `git branch` shows `main` and `alternate`, but `git rev-parse main alternate` returns the
> same SHA. The "alternate version" is not a branch — it is the uncommitted `agc_*` tree
> sitting on top of a deleted `citius_*` checkout. **Commit version B to a real branch
> before doing anything else**, or it is one `git checkout .` away from being lost.

---

## 1. Executive summary

The two versions are almost perfectly complementary, and the complementarity is not an
accident — they optimise for opposite things.

**Version A optimises for structural fidelity.** It is a mechanical transliteration of the
proto: every message becomes a struct, every `oneof` becomes a tagged union, every RPC
becomes a function taking `(request*, response*)`. It covers **90 of 90 RPCs exactly**, it
compiles, and it has a passing test suite. Its per-message fidelity is genuinely high.

**Version B optimises for being a good C library.** It asks what a C caller actually needs
— buffer ownership, ABI stability, fork safety, session handles, iterators, fail-closed
verification, metadata that can be *persisted* — and answers all of it well. Its
`C_API_MAPPING.md` is the best design artefact in either tree.

**The problem is that each one fails badly at what the other does well, and both fail in
ways that are currently invisible:**

- **Version A has no story for the single most important type in the API.**
  `OperationMetadata` — the nonce/IV/salt without which no ciphertext is decryptable — is a
  transparent struct of borrowed pointers with no ownership rules and **no serialisation**.
  The shipped example does `dec_req.metadata = enc_resp.metadata;` and comments "MUST be
  stored + passed back" — but there is no way to store it. This breaks durable artifacts
  and cross-implementation interop, which are the framework's reason to exist.

- **Version B's fidelity claims do not survive contact with the proto.** Its headline
  ("all 98 RPCs across 7 services") is wrong — there are 90. It specifies functions for
  8 RPCs that do not exist, invents a `end_of_message` parameter that appears nowhere in
  the proto, drops the outputs of four `*MessageFinal` responses that the proto does
  return, and inverts the ownership of `operation_id`. Its `agc_types.h` is labelled
  "GENERATED … DO NOT EDIT" with a "hard invariant, enforced in CI" — and contains two
  error codes that do not exist in `CryptoErrorCode`, so the invariant is already violated
  and the file cannot have been generated.

**Verdict**

| Dimension | Winner | Margin |
|---|---|---|
| RPC coverage | tie (both 90/90) | — |
| Per-message field fidelity | **A** | large |
| Type-system fidelity (presence, timestamps, errors) | **B** | large |
| Memory & ownership model | **B** | decisive |
| ABI stability / evolution | **B** | decisive |
| Security ergonomics (fail-closed, zeroization, const-time) | **B** | decisive |
| Ease of use in a hot loop | **B** | large |
| Executable / validated today | **A** | decisive |
| Design rationale quality | **B** | decisive |
| Documentation accuracy | **A** | moderate |

**Recommendation: adopt Version B's architecture, re-derive its content from the proto
under Version A's discipline, and keep Version A's build, stub provider and test harness.**
Neither is close to shippable alone. Details in [§7](#7-reconciliation-the-recommended-synthesis).

---

## 2. Ground truth: the proto surface

```
$ grep -o 'rpc [A-Za-z]*' proto/api/services/*.proto | wc -l
90
```

| Service | RPCs | Notes |
|---|---:|---|
| `CryptoService` | 12 | Encrypt/Decrypt, Sign/Verify, DigestSign/DigestVerify, GenerateMAC/VerifyMAC, Digest, Xof, GenerateRandom, SeedRandom |
| `KeyManagementService` | **11** | CreateKey, ReadKey, ListKeys, DeleteKey, RotateKey, TransformKey, UpdateKeyPolicy, MigrateKey, ValidateKeyOperation, ExportKey, ImportKey |
| `StreamingCryptoService` | **43** | 6 multi-part encrypt/decrypt · 10 message-based encrypt/decrypt · 6 multi-part sign/verify · 10 message-based sign/verify · 4 digest · 3 XOF · 4 dual-function |
| `KeyEstablishmentService` | 6 | WrapKey/UnwrapKey, DeriveKey, KeyAgreement, EncapsulateKey/DecapsulateKey |
| `ProviderService` | 8 | provider catalog + instance CRUD + MatchProviders |
| `CryptoPolicyService` | 7 | policy CRUD + Evaluate + BatchEvaluate |
| `AlgorithmDiscoveryService` | 3 | ListTemplates, GetTemplate, ListScopes |
| **Total** | **90** | |

Three absences matter and are referenced repeatedly below:

- **No `UpdateKeyState` RPC.** `KeyLifecycleState` has 8 values and no RPC can move a key
  between them.
- **No MAC streaming.** `MacScope` has a `MAC_SCOPE_STREAMING = 2` value and there is no
  `GenerateMACInit/Update/Final` to use it.
- **No `CancelOperation`.** Sessions can be created and finalised but never abandoned.

---

## 3. Accuracy audit

### 3.1 RPC coverage

Both versions cover all 90 RPCs. The difference is what else they contain.

| | Version A | Version B |
|---|---|---|
| Functions mapping a real RPC | 90 | 90 |
| Functions for RPCs that **do not exist** | 0 | **8** |
| Local-only additions (honest) | 9 — `citius_init`, `citius_finalize`, `citius_op_ctx_free`, `citius_rv_to_string`, 5 provider-backend registration fns | ~250 — accessors on the opaque handles, iterators, `agc_ctx_*`, `agc_secure_*`, `agc_*_max_len`, enum↔string helpers |
| Total exported functions | 99 | 348 |

Version B's 3.5× larger surface is the direct cost of [§4](#4-design-comparison-axis-by-axis)'s
handle-plus-accessor decision: `agc_core.h` alone declares 154 functions, ~120 of which are
getters that Version A gets for free by exposing structs. That is the trade — a much larger
API in exchange for an ABI that survives catalog growth. It is the right trade, but it is
not free, and it is the main argument for generating the accessors rather than hand-writing
them.

Version B's 8 phantom RPCs: `agc_update_key_state`, `agc_generate_mac_init/update/final`,
`agc_verify_mac_init/update/final`, `agc_session_cancel`.

These are all *good ideas* — they close the three proto gaps listed above. The defect is
not that they exist; it is that `C_API_MAPPING.md` §4.1 and §4.3 present them in
**"RPC → C function" mapping tables** as if they were derived from the proto, which
disguises real specification proposals as documentation.

### 3.2 Version A defects (`citius_*`)

Severity: **C**ritical (breaks a core requirement) / **H**igh / **M**edium / **L**ow.

| # | Sev | Defect | Evidence |
|---|:--:|---|---|
| A1 | **C** | **Two incompatible error vocabularies.** `CITIUS_RV` codes are invented *and collide numerically with `CryptoErrorCode` at the same values with different meanings*: RV `2` = `KEY_ALREADY_EXISTS` vs proto `2` = `KEY_EXPIRED`; RV `3` = `KEY_INACTIVE` vs proto `3` = `KEY_VERSION_MISMATCH`; RV `30` = `POLICY_VIOLATION` vs proto `30` = `POLICY_NOT_FOUND`. Meanwhile `citius_crypto_error_code_t` **is** a byte-perfect mirror of `CryptoErrorCode` — and is referenced by exactly zero functions or structs. A gateway cannot translate a `CITIUS_RV` to a wire error, and a passthrough would be actively wrong. | [`citius_types.h:91-156`](include/citius/types/citius_types.h) vs [`citius_common.h:430-459`](include/citius/types/citius_common.h); `grep` finds no use of `citius_crypto_error_code_t` outside its definition |
| A2 | **C** | **`OperationMetadata` cannot be persisted.** `citius_operation_metadata_t` is a transparent struct of borrowed `citius_byte_buffer_t` with no ownership rule, no lifetime rule, and no encode/decode. The example performs a shallow struct copy of pointers into provider memory and calls it storage. Durable ciphertext and Go↔C interop are both impossible as specified. | `citius_metadata.h:159-186`; `examples/encrypt_decrypt.c:107` |
| A3 | **H** | **`CITIUS_AUTHENTICATION_FAILED` is documented but never defined.** The header names it as *the* AEAD-failure code in the IND-CCA2 note; it does not exist. The nearest defined codes are `CITIUS_VERIFICATION_FAILED`, `CITIUS_DECRYPTION_FAILED`, `CITIUS_TAG_MISMATCH` — three codes for one condition, with no rule for which applies. | `citius_encryption.h:330`; absent from `citius_types.h` |
| A4 | **H** | **Zero-initialisation produces the wrong security filter.** Triboolean fields are `int8_t` with `-1 = unset`, but every example and test constructs requests with `memset(&req, 0, sizeof req)` and no initialiser macro exists. A zeroed `UniversalSecurityProperties` therefore means `quantum_safe = FALSE, fips_approved = FALSE` — *"must NOT be FIPS-approved"* — rather than "don't care". The shipped `encrypt_decrypt` example creates its key with exactly this bug. | `citius_common.h:139,141`; `examples/encrypt_decrypt.c:49` |
| A5 | **H** | **No ABI-evolution mechanism.** No `struct_size`, no reserved tail, no symbol versioning. Every request/response struct is frozen at v1.0; appending a field to `citius_encrypt_request_t` breaks every compiled caller. Protobuf's free forward-compatibility has no substitute here. | `grep struct_size include/` → 0 hits |
| A6 | **H** | **The algorithm catalog is frozen into the ABI.** `citius_key_metadata_t` embeds `citius_template_info_t` **by value**, which embeds `AlgorithmDetails`. Adding a parameter set to the catalog — explicitly a *data* change in the proto's model — becomes a soname bump. This defeats the extensibility argument the specification is built on. | `citius_key_management.h:85` |
| A7 | **H** | **No context object.** `citius_init()` is process-global. Deployment mode, policy binding, provider configuration, caller identity and session TTL have nowhere to live; there is no threading statement and no fork story. Two libraries in one process cannot have different policies. | `citius_types.h:241-246` |
| A8 | **H** | **Exported key material has no ownership or zeroization contract.** `citius_export_key_response_t.key_material` is a library-owned `const uint8_t *`. The caller cannot erase it and is not told who does. No `secure_zero` or constant-time-compare helper exists anywhere in the API. | `citius_key_management.h:193` |
| A9 | **H** | **No fail-closed verification contract.** `valid` lives inside a response struct. The MAC header states `CITIUS_VERIFICATION_FAILED` accompanies `valid == 0` (good), but nothing states that `valid` is cleared *before* work begins, and the signing headers make no such statement at all. The classic `rv`-ignored / `valid`-uninitialised bug is fully available. | `citius_mac.h:105-114`, `citius_signing.h` |
| A10 | **M** | **`google.protobuf.Timestamp` → `const char *` ISO-8601.** Lossy, no explicit presence, forces every caller to parse and format strings, and does not round-trip. | `citius_key_management.h:81-82` vs `KeyMetadata.created_time` (Timestamp) |
| A11 | **M** | **`bool success` + `string message` retained alongside `CITIUS_RV`.** Two representations of one outcome in every response struct. In C these inevitably disagree. | `citius_create_key_response_t:113-119` |
| A12 | **M** | **Sessions have two identities.** Streaming functions take a `citius_op_ctx_t` handle *and* the request structs still carry `operation_id` strings. `citius_message_encrypt()` takes a ctx while its request struct carries `key_name` and no operation id. Which one addresses the operation is undefined. | `citius_streaming_crypto_service.h:270-295` vs `citius_encryption.h:224-229` |
| A13 | **M** | **Pagination is raw.** `page_size`/`page_token`/`next_page_token` are pushed onto every caller, with `const citius_key_metadata_t *keys` arrays of unstated ownership. | `citius_key_management.h:139-153` |
| A14 | **L** | **`README.md` describes a different library.** Its "Header Layout" lists six files that do not exist and documents `citius_session_open()`/`citius_session_close()`, which are in no header. | `README.md:12-32` |
| A15 | **L** | **Inconsistent optional-message presence.** `MigrateKeyRequest` gets `has_scope_spec`; `TransformKeyRequest` embeds `scope_spec` by value with no presence flag, though both are `optional ScopeSpecification` in the proto. | `citius_key_management.h:228,292` |

### 3.3 Version B defects (`agc_*`)

| # | Sev | Defect | Evidence |
|---|:--:|---|---|
| B1 | **C** | **The "generated, do not edit" file is hand-edited and violates its own invariant.** `agc_types.h` declares numeric equality with `CryptoErrorCode` a "hard invariant, enforced in CI", then defines `AGC_ERR_CRYPTO_INVALID_KEY_STATE_TRANSITION (-1006)` and `AGC_ERR_CRYPTO_POLICY_VERSION_CONFLICT (-1032)`. `CryptoErrorCode` has no value `6` and no value `32`. The proposed Tier-1 CI job would fail on the file it is meant to protect. `CRYPTO_ERROR_UNSPECIFIED = 0` (→ `-1000`) is also missing. | `agc_types.h:6-9,190-218` vs `types/common.proto:CryptoErrorCode` |
| B2 | **C** | **Four `*MessageFinal` outputs are silently dropped.** `C_API_MAPPING.md` §4.3 asserts "`EncryptMessageFinal` carries **no ciphertext**". The proto: `EncryptMessageFinalResponse{bytes ciphertext_final = 1; OperationMetadata metadata = 2}`. Same for `SignMessageFinalResponse{signature, metadata}`, `VerifyMessageFinalResponse{valid, metadata}`, `DecryptMessageFinalResponse{plaintext_final, metadata}`. `agc_encrypt_message_final(s)` returns only `agc_rc` — a caller "cannot even ask for output that does not exist", except it does exist. The message-based family is not round-trippable to the wire. | `C_API_MAPPING.md:403`; `agc_stream.h:133,220,239`; `messages/encryption.proto`, `messages/signing.proto` |
| B3 | **H** | **`end_of_message` is invented.** It is a parameter on `agc_encrypt_message_next`, `agc_decrypt_message_next`, `agc_sign_message_next`, `agc_verify_message_next`, and is justified in §4.3 and §C6 as a mapping of PKCS#11 `CKF_END_OF_MESSAGE`. `grep -rn end_of_message proto/api` returns nothing. `EncryptMessageNextRequest` is `{operation_id, plaintext_chunk}`. | `agc_stream.h:127,152,215,235` vs `messages/encryption.proto` |
| B4 | **H** | **`operation_id` ownership is inverted.** §C7 and §4.3 rest on "the proto names sessions with a *server-generated* `operation_id` because gRPC is stateless", and cite `EncryptInitResponse{success, operation_id}`. In fact `operation_id` is a **client-supplied request field** (`EncryptInitRequest.operation_id = 2`) and `EncryptInitResponse` is `{bool success = 1}`. The entire `agc_session_id()` / `agc_session_attach()` rationale is built on a false premise — the handle design is still right, but for different reasons. | `C_API_MAPPING.md:125,393`; `agc_core.h:60-64` vs `messages/encryption.proto` |
| B5 | **H** | **Headline scope is wrong: "all 98 RPCs across 7 services".** There are 90. The number appears in `agilecrypto.h:16`, `C_API_MAPPING.md` line 5, and §5.1 ("All 98 functions behave identically"). | `agilecrypto.h:16`; `C_API_MAPPING.md:5,510` |
| B6 | **H** | **8 phantom RPCs presented as mappings.** §4.1's table lists 12 KeyManagementService RPCs including `UpdateKeyState`; there are 11 and no such RPC. §4.3's family table claims 3 multi-part MAC-gen + 3 MAC-verify + 1 session-management RPC; none exist. See [§3.1](#31-rpc-coverage). | `C_API_MAPPING.md:310-343,368-390` |
| B7 | **M** | **Invented request fields presented as proto fidelity.** None of the following exist in the proto: `DeleteKeyRequest.remove_metadata` (`DeleteKeyRequest{string name = 1}`), `RotateKeyRequest.reason`, `CreateKeyRequest.activation_time`/`expiration_time`, `ExportKeyResponse.key_check_value`, `ImportKeyRequest.key_attestation`. Each is documented with a proto-derived justification (e.g. "the proto's default … is 0"). | `agc_key.h:109,118,62-63,318,332` vs `messages/key_management.proto` |
| B8 | **M** | **Invented `buf.validate` constraints, cited as enforcement of the proto.** §4.2 "The proto caps `output_length_bytes` at 1 MiB (`buf.validate`)" — the field is `uint32 output_length_bytes = 4;`, unconstrained. §4.5 "The 100-item cap from `buf.validate`" — `BatchEvaluatePolicyRequest.evaluations` is unconstrained. §2.5 "`min_len: 1, max_len: 256` on key names" — no key `name` field carries a constraint. | `C_API_MAPPING.md:235,362,453`; `agc_crypto.h:49,218` |
| B9 | **L** | **Real constraints that *are* honoured**, for balance: `XtsEncryptParams.tweak` `bytes.len = 16`, `Tls12KdfOperationParams.client_random`/`server_random` `bytes.len = 32`, `SignatureDomainContext.context` `bytes.max_len = 255` — all correct, and the fixed-array mapping is the right call. | `types/operation_params.proto:116` and `XtsEncryptParams` |
| B10 | **L** | **Dangling reference:** `agc_core.h` cites "the MANDATORY server-enforced TTL in `messages/session.proto`". No such file exists in the API proto (only `proto/server/store/session.proto`, an internal storage type outside the public contract). | `agc_core.h:153` |
| B11 | **L** | **Layout mismatch.** `C_API_MAPPING.md` refers to `include/agc/*.h`; the files are flat at repo root and `#include "agc_types.h"`. No CMake, no `.pc`, no build. | repo root |
| B12 | **L** | **Single-shot message ops re-shaped.** `agc_encrypt_message(s, ad, pt, …)` is session-scoped; the proto's `EncryptMessageRequest` is `{key_name, associated_data, plaintext, user_context}` with no `operation_id`. Defensible, but undocumented as a change. | `agc_stream.h:111` vs `messages/encryption.proto` |

**Pattern.** Version B's defects are almost all of one kind: *good design decisions
attributed to the proto instead of argued on their own merits.* Roughly a dozen genuine
improvements are wearing a fidelity costume. That is easy to fix — restate them as
proposals — but it must be fixed, because right now the document cannot be used to check
anything.

---

## 4. Design comparison, axis by axis

| Axis | Version A (`citius_*`) | Version B (`agc_*`) | Take |
|---|---|---|---|
| **Call shape** | `rv = fn(const req_t*, resp_t*)` — uniform, one struct pair per RPC | `rc = fn(ctx, const params*, out…)` — request struct only where fields ≥ 4 | **B.** A's uniformity is elegant but forces empty structs (`{uint8_t _reserved;}`) and 3-line call sites for `DeleteKey(name)`. B's `agc_read_key(ctx, name, version, &ki)` is what a caller wants. |
| **Result** | `uint32_t CITIUS_RV`, 0 = OK | `int32_t agc_rc`, 0 = OK, errors negative, `-(1000 + wire)` for generated | **B.** Reversible transform means a gateway needs no lookup table. A's collision with proto values (A1) is disqualifying. |
| **Error detail** | `citius_rv_to_string()` only | thread-local `agc_error_detail{provider_id, provider_code, failed_check, …}` | **B.** Which HSM failed with which `CKR_*`, and which policy check denied, are exactly what an operator needs. |
| **Byte output** | `citius_mutable_buffer_t{data, length, capacity}` in the response struct; `data == NULL` ⇒ size query | `agc_buf{data, cap}` + `size_t *out_len`; `+ agc_*_max_len()` fast path | **Tie on mechanism, B on ergonomics.** A's single struct carrying both in and out is arguably tidier; B's `max_len` escape hatch removes the double call from hot loops, which matters for TLS records. |
| **Rich message output** | deep aggregate structs by value | opaque handles + typed accessors | **B, decisively.** This is the ABI question (A6). Handles make catalog growth free. |
| **`optional bool`** | `int8_t`, `-1` = unset — *unreachable by `memset(0)`* | `agc_tribool{UNSET=0, FALSE=1, TRUE=2}` | **B.** `UNSET == 0` makes the zeroed struct mean "no filters", which is the only safe default (A4). |
| **`optional bytes`** | plain buffer; absent ≡ empty | `agc_optional_slice{slice, present}` | **B.** HKDF/PBKDF2/Argon2 `salt` genuinely distinguish absent (generate random) from empty (RFC 5869 §2.2 zero salt). Collapsing them turns a deterministic derivation into a random one, silently. |
| **Timestamps** | `const char *` ISO-8601 | `agc_timestamp{seconds, nanos, present}` | **B.** Lossless, explicit presence, avoids 32-bit `time_t`. |
| **`oneof`** | tagged union, independent tag enum | tagged union, tag = **proto field number** where stable | **B, with A's caveat honoured.** B correctly notes that `aead_params` is field 4 in `EncryptRequest` and 3 in `EncryptInitRequest`, so operation-params unions must use an independent discriminant. That nuance is right and A misses it entirely. |
| **Sessions** | `citius_op_ctx_t` handle **and** `operation_id` strings in the structs | opaque `agc_session*` + `agc_session_id()` / `agc_session_attach()` | **B.** A's dual identity (A12) is ambiguous. But note: since `operation_id` is client-supplied ([B4](#33-version-b-defects-agc_)), the reconciled design should let the caller *supply* one at `Init`, not just recover a generated one. |
| **Pagination** | raw `page_size`/`page_token` | lazy iterators, token held internally | **B.** `ListScopes` correctly excepted as an array. |
| **Library lifecycle** | global `citius_init()`/`citius_finalize()` | `agc_ctx` with `mode`, `catalog_path`, `default_policy`, `session_idle_ttl`, `require_locked_memory`, `fips_mode`, `caller_identity` | **B, decisively.** Deployment mode as a *context property* — with all functions behaving identically in EMBEDDED/LOCAL/REMOTE — is the single best idea in either design and is the direct answer to "no RPC in the crypto hot path". |
| **Metadata persistence** | none (A2) | `agc_metadata_encode/decode`, canonical form = **protobuf wire encoding of `OperationMetadata`** | **B, decisively.** This is what makes C-encrypted / Go-decrypted work, and it is the requirement the whole framework exists to serve. |
| **Verification** | `valid` in response struct; partial rc contract | fail-closed twice: `*out_valid = 0` before any work **and** `AGC_ERR_CRYPTO_SIGNATURE_INVALID` on failure | **B.** Both `if (rc)` and `if (!valid)` individually sufficient. |
| **Memory hygiene** | none | `agc_secure_zero`, `agc_ct_equal`, `agc_secure_alloc/free`, `require_locked_memory` | **B.** Non-negotiable for an API whose `ExportKey` puts raw key material in caller memory. |
| **ABI evolution** | none (A5) | `struct_size` + `AGC_INIT()`, appended fields only, symbol versioning, `AGC_ENUM32` width sentinel, `abidiff` in CI | **B, decisively.** And it must be present from day one — it cannot be retrofitted after 1.0. |
| **Fork** | unaddressed | `pthread_atfork` poisons inherited contexts; `agc_ctx_reinit_after_fork()` | **B.** A real hazard with no proto analogue; poisoning rather than silent reinit is the right call. |
| **Threading** | unstated | `agc_ctx` thread-safe, `agc_session` not — mirrors PKCS#11 without `CKF_OS_LOCKING_OK` | **B.** |
| **Per-message field fidelity** | high — `CreateKeyRequest` etc. match the proto field for field | ~15 invented/dropped fields ([§3.3](#33-version-b-defects-agc_)) | **A, decisively.** |
| **Executable today** | CMake + CTest, stub provider, 8/8 pass, 3 examples | headers only; parse cleanly under `-Wall -Wextra -std=c11` | **A, decisively.** |
| **Design rationale** | `README.md`, stale and partly fictional | `C_API_MAPPING.md` — nine stated conventions, every divergence argued, open questions recorded | **B, decisively** — *once its factual claims are repaired.* |

---

## 5. Gaps neither version closes

These are unaddressed in both and need to be decided, not inherited.

1. **`ProviderRequirements` on operation calls.** Both put provider selection only on
   `CreateKey`/`ImportKey`. Neither exposes it on `Digest`/`Xof`/`GenerateRandom`, which
   are keyless and therefore have no template to inherit a provider from. B has
   `agc_random_request.provider_id`, which is closer, but there is no requirements-based
   selection for keyless operations anywhere.
2. **`user_context` cost in the hot path.** Both carry an optional `map<string,string>` on
   every operation. B raises this as open question 6 but neither measures it or offers a
   session-scoped variant set once at `Init`.
3. **Audit/telemetry hook.** In `EMBEDDED` mode there is no server to write the audit
   trail. `user_context` is collected and then has nowhere to go. Neither design specifies
   a sink.
4. **Provider SPI.** A has a stub provider and a registration API
   (`citius_provider_register/unregister/select/list/describe`) but no documented vtable
   contract. B has no provider-facing surface at all — yet `AGC_ERR_PROVIDER_CONTRACT_VIOLATION`
   implies one exists. **The C API needs a second header defining the backend contract**,
   analogous to `proto/server/provider/*.proto`.
5. **Concurrency limits and backpressure.** `CRYPTO_ERROR_RATE_LIMITED` and
   `CRYPTO_ERROR_CONCURRENT_ACCESS` are in the vocabulary; neither design says when a local
   library would produce them.
6. **`google.protobuf.Struct`/`Any` round-trip proof.** B carries them as canonical JSON +
   `type_url`/`value` (a good choice) but there is no test proving losslessness. A does not
   address `CustomOperationParams` at all.
7. **CBOM export path.** Both surface CycloneDX fields (B far more completely, ~14
   accessors); neither defines how a caller assembles a document from them.

---

## 6. Gaps in the proto that the C work exposed

Version B found real specification holes while looking in the wrong place for authority.
Extracted and stated honestly, they are the most valuable output of that exercise:

| # | Gap | Why it matters | Proposed |
|---|---|---|---|
| P1 | **No `UpdateKeyState` RPC.** | `KeyLifecycleState` has 8 values and no transition mechanism. NIST SP 800-57 §7 lifecycle management is unimplementable. `reason` should be mandatory for `→ COMPROMISED`. | Add to `KeyManagementService`. |
| P2 | **No MAC streaming.** | `MAC_SCOPE_STREAMING = 2` exists in the vocabulary with no RPCs to use it. Every other primitive has an Init/Update/Final family. | Add `GenerateMACInit/Update/Final`, `VerifyMACInit/Update/Final`. |
| P3 | **No `CancelOperation`.** | A session that is neither finalised nor cancelled strands provider state and key material until TTL. | Add to `StreamingCryptoService`. |
| P4 | **`DecryptMessageRequest` carries no metadata.** | Message-based AEAD gives each message its own nonce, returned by `EncryptMessageBegin` in `partial_metadata`. The decrypting side has no field to put it in — **message-based AEAD decryption is not expressible as specified.** B's `agc_decrypt_message(s, ad, ct, metadata, …)` is a genuine fix. | Add `OperationMetadata metadata` to `DecryptMessageRequest` and `DecryptMessageBeginRequest`. |
| P5 | **No per-message termination signal.** | `EncryptMessageBegin → Next* → ?` — nothing marks the last chunk of a message, so the tag can never be emitted, and `MessageFinal` returning `ciphertext_final` implies one message per session, contradicting the family's purpose. This is the hole B papered over with `end_of_message`. | Add `bool end_of_message` to the four `*MessageNext` requests, or split into `*MessageNext` / `*MessageNextFinal`. **Decide this in the proto first**; the C API must follow, not lead. |
| P6 | **Six identical `Update` RPCs.** | `SignUpdate`, `VerifyUpdate`, `GenerateMACUpdate`, `VerifyMACUpdate`, `DigestUpdate`, `XofUpdate` are all `(operation_id, data_chunk) → bool success`. B raises this (§4.3, open question 4) and correctly declines to resolve it unilaterally. | Spec question. Keep 1:1 until the proto decides. |
| P7 | **`bool success` + `string message` in every response.** | Redundant with gRPC status, and in C it becomes two sources of truth (A11). | Consider deprecating; C should collapse them into the return code regardless. |
| P8 | **Missing error codes.** | No code for an invalid lifecycle transition (P1) or a policy version conflict — the two B invented (B1). If P1 and optimistic policy concurrency are adopted, add `CRYPTO_ERROR_INVALID_KEY_STATE_TRANSITION` and `CRYPTO_ERROR_POLICY_VERSION_CONFLICT` **to the proto**, then regenerate. | Proto change → codegen, not a hand edit. |
| P9 | **`ExportKey` has no key check value.** | Standard KMIP/PKCS#11 practice for verifying an exported key without exposing it. B invented `out_kcv` (B7); the idea is sound. | Consider `bytes key_check_value` on `ExportKeyResponse`. |

---

## 7. Reconciliation: the recommended synthesis

**Take Version B's architecture. Re-derive its content mechanically from the proto. Keep
Version A's build and test harness. Move every invention into a proto RFC.**

### 7.1 What to take from Version B (unchanged)

These are correct, well-argued and should be adopted as-is:

- `agc_ctx` with `mode ∈ {EMBEDDED, LOCAL, REMOTE}` — one API, three transports, no call
  site changes. This is the design's answer to the whole problem statement.
- `agc_rc` with the `-(1000 + wire)` reversible transform; thread-local `agc_error_detail`.
- Two-call buffer sizing, caller-owned buffers, never freeing across the DLL boundary,
  plus `agc_*_max_len()` for hot loops.
- Opaque handles + typed accessors for `KeyMetadata`, `TemplateInfo`, `ProviderInfo`,
  `ImplementationProperties`, `SecurityGuarantees` — keeping the catalog out of the ABI.
- `struct_size` + `AGC_INIT()` on every by-pointer struct, appended fields only, symbol
  versioning, `AGC_ENUM32` width sentinel. **Day one, not later.**
- `agc_tribool` with `UNSET == 0`; `agc_optional_slice`; `agc_timestamp`.
- `agc_metadata_encode/decode` with the protobuf wire encoding as canonical form.
- Fail-closed verification (clear `*out_valid` first *and* return an error code).
- `agc_secure_zero` / `agc_ct_equal` / `agc_secure_alloc`; `require_locked_memory`.
- `pthread_atfork` poisoning + `agc_ctx_reinit_after_fork()`.
- Lazy iterators for paged lists; arrays for `ListScopes` and `MatchProviders`.
- Two session handles for dual-function operations.
- Synchronous-only, with the async addition path pre-defined.

### 7.2 What to take from Version A

- **The build.** CMake + CTest + `citius.pc.in` + zero-filling stub provider + 8 tests +
  3 examples. This is the only executable artefact in the repo and it should survive the
  merge verbatim, retargeted at the new headers.
- **The discipline of per-message field derivation.** A's `CreateKeyRequest`,
  `MigrateKeyRequest`, `ImportKeyRequest` etc. match the proto field for field. That is
  the property B needs and lacks.
- **The proto-faithful `CryptoErrorCode` enum** in `citius_common.h` — as the *generator
  output*, not as a second dead vocabulary.
- **The RPC→function→HTTP-path mapping comments** in the service headers. Verbose, but
  they make the 1:1 correspondence checkable by eye, and they caught nothing wrong in A
  precisely because they were maintained.
- **Structural completeness as an explicit goal.** A hit 90/90 with no phantoms. Keep the
  count as a CI assertion.

### 7.3 What to fix before either can ship

Ordered by risk.

1. **Regenerate `agc_types.h` for real.** Write `protoc-gen-agc-c-enums`, run it against
   the `FileDescriptorSet`, and delete the two hand-added error codes (B1). If P1/P8 are
   wanted, land them in the proto first. Until the generator exists, the "DO NOT EDIT"
   banner is a claim the repo cannot back.
2. **Reconcile the message-based AEAD family with the proto** (B2, B3, P4, P5). This is
   the largest single divergence and the one that breaks artifact interop. Decide
   `end_of_message` in the proto, then make the C API follow. Restore the `*MessageFinal`
   outputs, or change the proto so they genuinely are empty — but the two must agree.
3. **Correct the `operation_id` model** (B4). It is client-supplied. `agc_session` should
   accept an optional caller-provided id at `Init` (for audit correlation and for
   relaying), with the library generating one when omitted. The handle design survives;
   only the justification changes.
4. **Fix the counts and remove the phantom mappings** (B5, B6). 90 RPCs. Move
   `UpdateKeyState`, the six MAC-streaming functions and `CancelOperation` into a clearly
   marked *"Proposed extensions — not yet in the proto"* section of both the header and
   the mapping doc, cross-referenced to [§6](#6-gaps-in-the-proto-that-the-c-work-exposed).
5. **Delete or justify every invented field and constraint** (B7, B8). Each one either
   becomes a proto RFC or comes out of the header. `agc_delete_key(ctx, name, remove_metadata)`
   in particular is a *destructive* parameter that the wire API has no way to express.
6. **Adopt A's field-by-field derivation** for the ~15 messages where B diverged, and add a
   CI check that walks `FileDescriptorSet` and asserts every request field has a C
   counterpart (and vice versa).
7. **Retarget A's test suite and stub provider** at the reconciled headers. The 8 existing
   tests are the seed of the Tier-2 corpus.
8. **Write the provider SPI header** ([§5.4](#5-gaps-neither-version-closes)). Without it,
   `AGC_ERR_PROVIDER_CONTRACT_VIOLATION` names a contract nobody has written down.

### 7.4 Naming

Pick one prefix and one layout. Recommendation: **`agc_`**, matching the upstream project
name (`agile-crypto/api`) rather than a product name — a C ABI meant to be the substrate
for Rust/Python/Java/Go bindings should carry the specification's identity, not a server
implementation's. Keep A's directory layout mirroring the proto (`types/`, `messages/`,
`services/`) so file-level correspondence stays checkable, but under `include/agc/`.

### 7.5 Target shape

```
include/agc/
  agc_types.h        ← GENERATED from FileDescriptorSet (enums, error codes, scalars)
  agc_core.h         ← ctx, rc, error detail, handles, metadata, iterators, memory hygiene
  agc_key.h          ← KeyManagementService            (11 + 1 proposed)
  agc_crypto.h       ← CryptoService                   (12)
  agc_stream.h       ← StreamingCryptoService          (43 + 7 proposed)
  agc_establish.h    ← KeyEstablishmentService         (6)
  agc_policy.h       ← CryptoPolicyService             (7)
  agc_discovery.h    ← AlgorithmDiscoveryService       (3)
  agc_provider.h     ← ProviderService                 (8)
  agc_spi.h          ← NEW: provider backend contract
  agilecrypto.h      ← aggregate
docs/
  C_API_MAPPING.md   ← rationale, with every claim traceable to a proto line
  PROTO_RFCS.md      ← the 9 proposed spec changes from §6
src/stub/            ← from Version A
tests/               ← from Version A, extended to the Tier-2 corpus
examples/            ← from Version A, rewritten against the new headers
```

---

## 8. Conformance harness

Version B proposes four tiers; all four are right and none exists. Concretely:

| Tier | What | Catches |
|---|---|---|
| **1 — Vocabulary** | Load `FileDescriptorSet`; assert every proto enum value has a C enumerator with the identical numeric value, and no C enumerator lacks a counterpart. | B1 — would have failed on day one |
| **1b — Surface** | Assert the RPC count and that every RPC has exactly one C function, and that functions outside that set live in the "proposed" section. | B5, B6 |
| **1c — Fields** | Walk every request/response message; assert each field has a C counterpart and each C struct field maps back. | B2, B3, B7, A15 |
| **2 — Behaviour** | A test-vector corpus expressed as protobuf messages, run through both the Go gRPC service and the C library. Round-trips, every `algorithm_output` arm, every scope, and the negative cases — expired keys, forbidden templates, auth failures, unset-oneof provider-contract violations. Both must agree on outputs **and** on error codes. | A1 — the error-code collision |
| **3 — Artifact interop** | Encrypt with C, decrypt with Go, and vice versa, across every template. | A2 — proves `agc_metadata_encode()` really is the wire format |
| **4 — ABI** | `abidiff` against the previous release; fail on any layout change to an existing field without a version-script entry and a written rationale. | A5, A6 |

Tier 1 and 1b are a day's work and would have caught most of what this document reports.
**Build them before writing another header.**

---

## Appendix A — verification method

Every count and quotation above was produced mechanically, not read off the design docs.

```sh
# RPC inventory (ground truth = 90)
grep -o 'rpc [A-Za-z]*' proto/api/services/*.proto | wc -l
for f in proto/api/services/*.proto; do echo "$f: $(grep -c '  rpc ' $f)"; done

# Phantom RPCs
grep -rn 'UpdateKeyState\|GenerateMACInit\|VerifyMACInit\|CancelOperation\|end_of_message' proto/api
#   → no matches

# Error-code equality
grep -A45 'enum CryptoErrorCode' proto/api/types/common.proto     # 31 values, none at 6 or 32
grep 'AGC_ERR_CRYPTO_' agc_types.h                                # includes -1006 and -1032

# Message shapes
sed -n '/^message EncryptInitRequest/,/^}/p'      proto/api/messages/encryption.proto
sed -n '/^message EncryptMessageFinalResponse/,/^}/p' proto/api/messages/encryption.proto
sed -n '/^message SignMessageFinalResponse/,/^}/p'    proto/api/messages/signing.proto
sed -n '/^message DeleteKeyRequest/,/^}/p'        proto/api/messages/key_management.proto

# buf.validate constraints actually present
grep -rn 'len:\|max_len\|min_len' proto/api/types proto/api/messages

# Dead vocabulary in Version A
grep -rn 'citius_crypto_error_code_t\|CRYPTO_ERROR_' . | grep -v citius_common.h   # → none
grep -rn 'CITIUS_AUTHENTICATION_FAILED' .    # → 1 hit, a comment; never defined

# Version A function counts per service header
for f in include/citius/services/*.h; do echo "$f $(grep -c '^CITIUS_RV citius_' $f)"; done

# Version A builds and passes
cmake -S . -B build && cmake --build build && ctest --test-dir build
#   → 100% tests passed, 0 tests failed out of 8
#   (only local change: cmake_minimum_required 3.25 → 3.20 for the host toolchain)

# Version B headers parse
printf '#include "agilecrypto.h"\nint main(void){agc_ctx_config c;AGC_INIT(&c);return 0;}\n' > /tmp/t.c
gcc -std=c11 -Wall -Wextra -I. -fsyntax-only /tmp/t.c
#   → clean
```

---

*Generated against `citius-server` proto at branch `feat/openssl-provider`, and
`citius-c-api` at `1f0d742` plus the uncommitted `agc_*` working tree.*
