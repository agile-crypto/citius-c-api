# C API Mapping

> **Note (2026-11):** this repository is header-only. The implementation is
> [citius-rust](https://github.ibm.com/citius/citius-rust). D6 and D11 were revised before 1.0:
> records and metadata are caller-allocated structs, not opaque handles.

How `include/agc/*.h` derives from `caas.crypto.v1` (`citius/api` v0.3.0), and why each
foundational decision (D1-D20, `docs/history/RECONCILIATION_PLAN.md` §1) is shaped the way it is. Every claim
below cites a real location: the proto side as `citius/api@2eb364a:<path>:<line>` (the exact
commit `conformance/api_descriptor.binpb` is pinned to — see `conformance/DESCRIPTOR_PROVENANCE.md`;
not a link, since it is a different repository, but a real, checked citation, not a paraphrase),
the C side as a normal path into this repository.

This document explains *why* the mapping is shaped this way. For the exhaustive field-by-field
transition tables, see `docs/history/RECONCILIATION_PLAN.md` §2-§3. For every place the two sides are
*deliberately* different, see `conformance/DIVERGENCES.yaml` — that file, not this one, is what CI
checks the real header text against (`conformance/tier1c_fields.py`).

## How to read the citations

A claim like "D8: `optional bool` becomes `agc_tribool`" is falsifiable two ways: does the cited
proto field actually say `optional bool`, and does the cited C field actually have type
`agc_tribool`? Both are checked below by direct citation, not by description.

## D1 — Naming and file layout

One header per proto service file, `agc_`/`AGC_` prefixed throughout.

| Proto service file | C header |
|---|---|
| `citius/api@2eb364a:proto/services/key_management_service.proto` | [`include/agc/agc_key.h`](../include/agc/agc_key.h) |
| `citius/api@2eb364a:proto/services/crypto_service.proto` | [`include/agc/agc_crypto.h`](../include/agc/agc_crypto.h) |
| `citius/api@2eb364a:proto/services/streaming_crypto_service.proto` | [`include/agc/agc_stream.h`](../include/agc/agc_stream.h) |
| `citius/api@2eb364a:proto/services/key_establishment_service.proto` | [`include/agc/agc_establish.h`](../include/agc/agc_establish.h) |
| `citius/api@2eb364a:proto/services/crypto_policy_service.proto` | [`include/agc/agc_policy.h`](../include/agc/agc_policy.h) |
| `citius/api@2eb364a:proto/services/discovery_service.proto` | [`include/agc/agc_discovery.h`](../include/agc/agc_discovery.h) |
| `citius/api@2eb364a:proto/services/provider_service.proto` | [`include/agc/agc_provider.h`](../include/agc/agc_provider.h) |

This one-to-one mapping is what makes `conformance/tier1b_surface.py`'s RPC-count-per-service check
possible without a lookup table: the service name in `conformance/rpc_manifest.yaml` names the
header directly.

## D2 — `agc_rc` encoding

Every function returns `agc_rc`, `AGC_OK == 0`. Wire error codes are `-(1000 + CryptoErrorCode)`.

- Proto: `citius/api@2eb364a:proto/types/common.proto:784`, `enum CryptoErrorCode { ... }`.
- C: [`include/agc/agc_types.h`](../include/agc/agc_types.h), e.g.
  `#define AGC_ERR_CRYPTO_KEY_NOT_FOUND ((agc_rc)-1001) /* wire value 1 */` — the arithmetic
  transform (`-rc - 1000` recovers the wire value) means a gateway needs no lookup table, and the
  generator (`tools/gen_agc_types.py`) can never drift the mapping since it computes it, not states it.

## D5 — Two-call buffer sizing

Every byte output is an `agc_buf` the caller places in the response, paired with a length field.
The library never hands back an allocation for the caller to free.

- Proto: `citius/api@2eb364a:proto/messages/encryption.proto:38-39`, `EncryptResponse.ciphertext`
  (`bytes`) — the wire message has no size-query concept; it is a pure RPC response.
- C: [`include/agc/agc_crypto.h`](../include/agc/agc_crypto.h),
  `agc_rc agc_encrypt(agc_ctx *ctx, const agc_encrypt_request *req, agc_encrypt_response *resp);`
  with `agc_encrypt_response` ([`include/agc/agc_crypto_types.h`](../include/agc/agc_crypto_types.h))
  holding `agc_buf ciphertext` + `size_t ciphertext_len` and `agc_buf metadata` + `size_t metadata_len`.
  If any output region is NULL or too small, the call returns `AGC_ERR_BUFFER_TOO_SMALL` with every
  `*_len` set, having done no provider work and drawn no randomness (SIZE QUERIES, top of
  `agc_crypto_types.h`). Rules for every response: [`docs/agc_crypto.md`](agc_crypto.md).

## D6 — Caller-allocated records, handles only for secrets and lifecycles (revised)

`KeyMetadata` (and `TemplateInfo`, `MigrationResult`, `ImplementationProperties`, ...) become
caller-allocated C structs. Their variable-length fields point into a `storage` region the caller
supplies in the enclosing response (the STORAGE CONTRACT). Only what holds secret state or a
lifecycle is an opaque, library-owned handle: `agc_ctx`, `agc_session` and the iterators.

- Proto: `citius/api@2eb364a:proto/messages/key_management.proto:160`, `message KeyMetadata { ... }`.
- C: [`include/agc/agc_key_types.h`](../include/agc/agc_key_types.h), `agc_key_info` (descriptive
  only: fields and pointers) inside `agc_key_info_response`, which owns `agc_buf storage` and
  `size_t storage_used`.

*Revision.* The first version of D6 made these records opaque handles with typed accessors
(`agc_key_info_name()`, ...). It was replaced before 1.0, for the reasons in
[`docs/agc_crypto.md`](agc_crypto.md): a caller-owned record cannot fail to materialise after the
work is done, can be placed in stack, pooled or locked memory, and needs no free function. The
PKCS#11 analogue is `C_GetAttributeValue` writing into caller memory while the key stays a handle.

*The price.* The opaque handle kept the 44-arm `AlgorithmDetails.algorithm` oneof
(`citius/api@2eb364a:proto/types/templates.proto:45`, `oneof algorithm` at :63) out of the ABI. Projected as
`agc_algorithm_params` ([`include/agc/agc_algorithm_params.h`](../include/agc/agc_algorithm_params.h)),
embedded by value in `agc_template_info`, its layout is now part of the ABI: an arm that would grow
the union, or a change to an existing arm, needs a new major version under the embedded-struct rule
in [`include/agc/agc_abi.h`](../include/agc/agc_abi.h).

## D8 — Presence types

`optional bool` → `agc_tribool{UNSET=0, FALSE=1, TRUE=2}`.

- Proto: `citius/api@2eb364a:proto/types/implementation.proto:54`,
  `optional bool formally_verified = 4;` (inside `ImplementationProperties`, line 35).
- C: [`include/agc/agc_key_types.h`](../include/agc/agc_key_types.h),
  `agc_impl_props.formally_verified` of type `agc_tribool` (defined in
  [`include/agc/agc_abi.h`](../include/agc/agc_abi.h)).

`UNSET == 0` is the point: `memset(0)` — which `AGC_INIT()` does — produces "no opinion", the safe
default for every tribool-typed filter field in the API.

## D9 — Fail-closed verification (DV-01)

Verification never returns success-shaped output for a failed check.

- Proto: `citius/api@2eb364a:proto/messages/signing.proto:62`, `bool valid = 1;` inside
  `VerifyResponse`; likewise `DigestVerifyResponse` (:131), `VerifyFinalResponse` (:216),
  `VerifyMessageResponse` (:341), `VerifyMessageNextResponse` (:368) and
  `citius/api@2eb364a:proto/messages/mac.proto:63`.
- C: [`include/agc/agc_crypto.h`](../include/agc/agc_crypto.h),
  `agc_rc agc_verify(agc_ctx *ctx, const agc_verify_request *req, agc_verify_response *resp);`
  — `resp->valid` is 0 until proven otherwise, and a failed check also returns
  `AGC_ERR_CRYPTO_SIGNATURE_INVALID`, so either check alone is sufficient (the classic "rc
  ignored, valid left uninitialised" C bug cannot silently pass).

## D10 — Sessions with a caller-suppliable `operation_id`

- Proto: `citius/api@2eb364a:proto/messages/encryption.proto:93`, `string operation_id = 2;`
  inside `EncryptInitRequest` (line 73) — a REQUEST field, settable by the caller, not
  server-generated.
- C: [`include/agc/agc_stream_types.h`](../include/agc/agc_stream_types.h), `operation_id`
  (`const char *`, `NULL` => generated) in the init requests, plus
  [`include/agc/agc_core.h`](../include/agc/agc_core.h)'s `agc_session_id()` /
  `agc_session_attach()` to recover the string form or a handle from the other.

## D11 — `OperationMetadata` as encoded bytes plus a caller-allocated decode (revised)

- Proto: `citius/api@2eb364a:proto/messages/metadata.proto:308`, `message OperationMetadata { ... }`.
- C: every operation returns the metadata ENCODED, encoding byte first, into a caller `agc_buf`.
  `agc_metadata_decode()` ([`include/agc/agc_metadata.h`](../include/agc/agc_metadata.h)) fills a
  caller-allocated `agc_metadata` inside an `agc_decode_metadata_result`, whose `storage` holds
  every variable-length value. Two encodings: `AGC_ENCODING_PROTOBUF` (the proto message itself)
  and `AGC_ENCODING_WIRE_V1` (fixed layout; [`docs/representing_metadata.md`](representing_metadata.md)).
- Checked against the real protobuf library: `conformance/golden/gen_metadata_vectors.py`
  generates `operation_metadata_vectors.json` with `google.protobuf`, and an implementation
  must decode and re-encode every vector byte for byte (citius-rust does).

*Revision.* The first version made `agc_metadata` an opaque, library-allocated handle with
accessors; it became caller-allocated with the rest of the data path (D6).

## D12 — Iterators for paged lists

- Proto: `citius/api@2eb364a:proto/messages/key_management.proto:220-221`,
  `int32 page_size = 10; string page_token = 11;` inside `ListKeysRequest` (line 212).
- C: [`include/agc/agc_key.h`](../include/agc/agc_key.h),
  `agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params, agc_key_iter **out_iter);`
  — the iterator is a library-owned handle that holds the page-token bookkeeping; the records it
  yields through `agc_key_iter_next()` are caller-allocated. See `conformance/DIVERGENCES.yaml`
  DV-07 for the `int32` → `uint32_t` narrowing this also covers.

## D14 — Boolean polarity always follows the proto

- Proto: `citius/api@2eb364a:proto/types/implementation.proto:183`, `bool disabled = 4;`
  inside `ProviderTemplateSupport` (line 164); line 310, `bool disabled = 6;` inside
  `ProviderInstance` (line 280); and `citius/api@2eb364a:proto/services/provider_service.proto:170`,
  `bool enabled_only = 3;` (`ListProviderInstancesRequest`) and :227, `bool include_disabled = 3;`
  (`MatchProvidersRequest`).
- C: [`include/agc/agc_provider_types.h`](../include/agc/agc_provider_types.h),
  `agc_provider_template_support.disabled`, `agc_provider_instance.disabled`,
  `agc_list_provider_instances_request.enabled_only` and
  `agc_match_providers_request.include_disabled` — the same names and the same polarity, each
  marked "matches the proto" in the header. The proto names its flags so that the proto3 default
  (false) is the safe one, and C keeps that: a zeroed struct means the same as an empty wire
  message. Inverting a flag at the C boundary would make a zeroed struct mean the opposite of the
  wire default.

## D18 — Thread safety and fork handling

- C only (no proto analogue — fork is a process-level hazard, not a wire concept):
  the THREADING and FORK sections of [`include/agc/agc_core.h`](../include/agc/agc_core.h) and
  `agc_ctx_reinit_after_fork()`. A context inherited across fork is poisoned (every call returns
  `AGC_ERR_INVALID_HANDLE`) until the child reinitialises it. How the fork is detected is
  unspecified; citius-rust compares process IDs and tests the poison-and-recover cycle.

## D20 — Generated enum tables

- [`include/agc/agc_types.h`](../include/agc/agc_types.h) is produced by
  [`tools/gen_agc_types.py`](../tools/gen_agc_types.py) from `conformance/api_descriptor.binpb` —
  never hand-edited. The name and message functions it declares (`agc_rc_name()`, ...) are
  provided by the implementation. `conformance/tier1_vocabulary.py` checks every proto enum value
  against its generated C enumerator, both directions, as a `ctest` test.

## Divergences (where C and proto deliberately differ)

Every deliberate deviation is in [`conformance/DIVERGENCES.yaml`](../conformance/DIVERGENCES.yaml)
(DV-01 through DV-16; DV-04, DV-11 and DV-13 are withdrawn), not scattered across comments — that file is what
`conformance/tier1c_fields.py` actually loads and checks the header text against. A construct in
the C headers with no wire counterpart, and not listed there, is a bug by definition.

## RPC surface

`conformance/rpc_manifest.yaml` is the machine-checked map of all 98 RPCs to their C entry point;
`conformance/tier1b_surface.py` verifies it in both directions (every RPC is mapped and declared;
every plausible entry-point function is mapped to some RPC) as a `ctest` test. See that file
directly for the full 98-row mapping rather than a second, driftable copy of it here.

## Proposed extensions

Constructs with no RPC at all — `include/agc/agc_ext.h`, behind `AGC_ENABLE_PROPOSED_EXTENSIONS`
— are tracked in [`docs/PROTO_RFCS.md`](PROTO_RFCS.md), not here: this document maps the C API to
the proto that exists today, and extensions by definition are not that.
