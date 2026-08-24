# C API Mapping

How `include/agc/*.h` derives from `caas.crypto.v1` (`github.com/agile-crypto/api`), and why each
foundational decision (D1-D20, `RECONCILIATION_PLAN.md` §1) is shaped the way it is. Every claim
below cites a real location: the proto side as `citius-server@476f9dd:<path>:<line>` (the exact
commit `conformance/api_descriptor.binpb` is pinned to — see `conformance/DESCRIPTOR_PROVENANCE.md`;
not a link, since it is a different repository, but a real, checked citation, not a paraphrase),
the C side as a normal path into this repository.

This document explains *why* the mapping is shaped this way. For the exhaustive field-by-field
transition tables, see `RECONCILIATION_PLAN.md` §2-§3. For every place the two sides are
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
| `citius-server@476f9dd:proto/api/services/key_management_service.proto` | [`include/agc/agc_key.h`](../include/agc/agc_key.h) |
| `citius-server@476f9dd:proto/api/services/crypto_service.proto` | [`include/agc/agc_crypto.h`](../include/agc/agc_crypto.h) |
| `citius-server@476f9dd:proto/api/services/streaming_crypto_service.proto` | [`include/agc/agc_stream.h`](../include/agc/agc_stream.h) |
| `citius-server@476f9dd:proto/api/services/key_establishment_service.proto` | [`include/agc/agc_establish.h`](../include/agc/agc_establish.h) |
| `citius-server@476f9dd:proto/api/services/crypto_policy_service.proto` | [`include/agc/agc_policy.h`](../include/agc/agc_policy.h) |
| `citius-server@476f9dd:proto/api/services/discovery_service.proto` | [`include/agc/agc_discovery.h`](../include/agc/agc_discovery.h) |
| `citius-server@476f9dd:proto/api/services/provider_service.proto` | [`include/agc/agc_provider.h`](../include/agc/agc_provider.h) |

This one-to-one mapping is what makes `conformance/tier1b_surface.py`'s RPC-count-per-service check
possible without a lookup table: the service name in `conformance/rpc_manifest.yaml` names the
header directly.

## D2 — `agc_rc` encoding

Every function returns `agc_rc`, `AGC_OK == 0`. Wire error codes are `-(1000 + CryptoErrorCode)`.

- Proto: `citius-server@476f9dd:proto/api/types/common.proto:740`, `enum CryptoErrorCode { ... }`.
- C: [`include/agc/agc_types.h`](../include/agc/agc_types.h), e.g.
  `#define AGC_ERR_CRYPTO_KEY_NOT_FOUND ((agc_rc)-1001) /* wire value 1 */` — the arithmetic
  transform (`-rc - 1000` recovers the wire value) means a gateway needs no lookup table, and the
  generator (`tools/gen_agc_types.py`) can never drift the mapping since it computes it, not states it.

## D5 — Two-call buffer sizing

Every byte OUTPUT is `agc_buf out, size_t *out_len`, never an allocation the library hands back for
the caller to free.

- Proto: `citius-server@476f9dd:proto/api/messages/encryption.proto`, `EncryptResponse.ciphertext`
  (`bytes`) — the wire message has no size-query concept; it is a pure RPC response.
- C: [`include/agc/agc_crypto.h`](../include/agc/agc_crypto.h),
  `agc_rc agc_encrypt(agc_ctx *ctx, const agc_encrypt_request *req, agc_buf out, size_t *out_len, agc_metadata **out_md)`
  — calling with `out.data == NULL` returns the required size in `*out_len` without doing the
  encryption; see `AGC_ERR_BUFFER_TOO_SMALL` handling in `src/services/crypto.c`.

## D6 — Opaque handles instead of projected structs

`KeyMetadata` (and `TemplateInfo`, `MigrationResult`, `ImplementationProperties`, ...) become
opaque handles with typed accessors, never a plain C struct mirroring the message.

- Proto: `citius-server@476f9dd:proto/api/messages/key_management.proto:150`, `message KeyMetadata { ... }`.
- C: [`include/agc/agc_key.h`](../include/agc/agc_key.h), `typedef struct agc_key_info agc_key_info;`
  (forward-declared opaque in [`include/agc/agc_core.h`](../include/agc/agc_core.h)) plus its
  accessor set (`agc_key_info_name`, `agc_key_info_template_id`, ...).

Why this matters concretely: `AlgorithmDetails` is a 41-arm `oneof` (D6's stated reason). Projecting
it into a C struct freezes the entire algorithm catalog into the ABI — adding one new algorithm
becomes a soname bump. The opaque-handle indirection is what `conformance/tier1c_fields.py`'s
"one-hop" check (see its module docstring) verifies actually has a real accessor behind it, not
just a type declaration nothing populates.

## D8 — Presence types

`optional bool` → `agc_tribool{UNSET=0, FALSE=1, TRUE=2}`.

- Proto: `citius-server@476f9dd:proto/api/types/implementation.proto:50`,
  `optional bool formally_verified = 4;` (inside `ImplementationProperties`, line 31).
- C: [`include/agc/agc_provider.h`](../include/agc/agc_provider.h),
  `AGC_API agc_tribool agc_impl_props_formally_verified(const agc_impl_props *ip);`

`UNSET == 0` is the point: `memset(0)` — which `AGC_INIT()` does — produces "no opinion", the safe
default for every tribool-typed filter field in the API.

## D9 — Fail-closed verification (DV-01)

Verification never returns success-shaped output for a failed check.

- Proto: `citius-server@476f9dd:proto/api/messages/signing.proto:59`, `bool valid = 1;` inside
  `VerifyResponse`. Also lines 142, 220, 314, 341 (the other four `*valid` fields DV-01 covers) and
  `citius-server@476f9dd:proto/api/messages/mac.proto:57`.
- C: [`include/agc/agc_crypto.h`](../include/agc/agc_crypto.h),
  `agc_rc agc_verify(agc_ctx *ctx, const agc_verify_request *req, int *out_valid, agc_metadata **out_md);`
  — `src/services/crypto.c`'s `agc_verify()` sets `*out_valid = 0` before any work, and a failed
  check returns `AGC_ERR_CRYPTO_SIGNATURE_INVALID` on top of that, so either check alone is
  sufficient (the classic "rc ignored, valid left uninitialised" C bug cannot silently pass).

## D10 — Sessions with a caller-suppliable `operation_id`

- Proto: `citius-server@476f9dd:proto/api/messages/encryption.proto:70`, `string operation_id = 2;`
  inside `EncryptInitRequest` — a REQUEST field, settable by the caller, not server-generated.
- C: [`include/agc/agc_stream.h`](../include/agc/agc_stream.h),
  `agc_encrypt_init_params.operation_id` (`const char *`, `NULL` => generated) plus
  [`include/agc/agc_core.h`](../include/agc/agc_core.h)'s `agc_session_id()` /
  `agc_session_attach()` to recover the string form or a handle from the other.

## D11 — `OperationMetadata` as an opaque handle over real wire bytes

- Proto: `citius-server@476f9dd:proto/api/messages/metadata.proto:391`, `message OperationMetadata { ... }`.
- C: `agc_metadata` (opaque, [`include/agc/agc_core.h`](../include/agc/agc_core.h)), encoded/decoded
  by a hand-written codec with no protobuf dependency:
  [`src/wire/metadata_codec.c`](../src/wire/metadata_codec.c). Verified against the REAL protobuf
  library in both directions: `tests/golden/verify_c_encoded.py` decodes C-encoded bytes with
  `google.protobuf`, and `tests/golden/gen_metadata_vectors.py` generates golden vectors the C
  decoder must reproduce.

## D12 — Iterators for paged lists

- Proto: `citius-server@476f9dd:proto/api/messages/key_management.proto:193-194`,
  `int32 page_size = 10; string page_token = 11;` inside `ListKeysRequest`.
- C: [`include/agc/agc_key.h`](../include/agc/agc_key.h),
  `agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params, agc_key_iter **out_iter);`
  — the iterator holds the page-token bookkeeping internally; see `conformance/DIVERGENCES.yaml`
  DV-07 for the `int32` → `uint32_t` narrowing this also covers.

## D14 — Boolean polarity always follows the proto

- Proto: `citius-server@476f9dd:proto/api/types/implementation.proto:178`, `bool enabled = 4;`
  inside `ProviderTemplateSupport` (line 160); and line 303, `bool enabled = 6;` inside
  `ProviderInstance` (line 275); and `citius-server@476f9dd:proto/api/services/provider_service.proto:167`
  and `:220`, `bool enabled_only = 3;` in two request messages.
- C: [`include/agc/agc_provider.h`](../include/agc/agc_provider.h),
  `agc_provider_instance_spec.enabled` and `agc_list_provider_instances_params.enabled_only` —
  matching field names AND polarity, called out explicitly in the header's own comments as
  "matches the proto field name and polarity" at both call sites, specifically because the
  reconciled draft this tree replaced inverted all four of these to `disabled`/`include_disabled`
  (a zeroed struct silently meant "enabled" in C and "disabled" on the wire — a marshalling-boundary
  polarity inversion, not a naming preference).

## D18 — Thread safety and fork handling

- C only (no proto analogue — fork is a process-level hazard, not a wire concept):
  [`src/core/ctx.c`](../src/core/ctx.c)'s `pthread_atfork` registration and
  `agc_ctx_reinit_after_fork()` ([`include/agc/agc_core.h`](../include/agc/agc_core.h)).
  `tests/test_fork.c` exercises the poison-and-recover cycle.

## D20 — Generated enum/string tables

- [`include/agc/agc_types.h`](../include/agc/agc_types.h) and
  [`src/core/agc_types.c`](../src/core/agc_types.c) are produced by
  [`tools/gen_agc_types.py`](../tools/gen_agc_types.py) from `conformance/api_descriptor.binpb` —
  never hand-edited. `conformance/tier1_vocabulary.py` checks every proto enum value against its
  generated C enumerator, both directions, on every `ctest` run.

## Divergences (where C and proto deliberately differ)

Every deliberate deviation is in [`conformance/DIVERGENCES.yaml`](../conformance/DIVERGENCES.yaml)
(DV-01 through DV-14), not scattered across comments — that file is what
`conformance/tier1c_fields.py` actually loads and checks the header text against. A construct in
the C headers with no wire counterpart, and not listed there, is a bug by definition.

## RPC surface

`conformance/rpc_manifest.yaml` is the machine-checked map of all 90 RPCs to their C entry point;
`conformance/tier1b_surface.py` verifies it in both directions (every RPC is mapped and declared;
every plausible entry-point function is mapped to some RPC) on every `ctest` run. See that file
directly for the full 90-row mapping rather than a second, driftable copy of it here.

## Proposed extensions

Constructs with no RPC at all — `include/agc/agc_ext.h`, behind `AGC_ENABLE_PROPOSED_EXTENSIONS`
— are tracked in [`docs/PROTO_RFCS.md`](PROTO_RFCS.md), not here: this document maps the C API to
the proto that exists today, and extensions by definition are not that.
