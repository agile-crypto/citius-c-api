# agilecrypto — C binding for the Citius intent-based cryptographic API

A local, in-process C library that mirrors `caas.crypto.v1` (the protobuf/gRPC specification in
`github.com/agile-crypto/api`) closely enough to be checked against it mechanically, while
behaving like a proper C library rather than a transliterated wire format.

**Status:** reconciliation complete. All 90 RPCs across all 7 services are implemented against a
deterministic (**not cryptographically secure** — see `src/stub/stub_crypto.h`) stub backend, with
a machine-checked conformance harness gating every deliberate divergence from the wire spec. See
[`RECONCILIATION_PLAN.md`](RECONCILIATION_PLAN.md) for the plan this tree was built from and its
commit-by-commit sequencing, [`docs/C_API_MAPPING.md`](docs/C_API_MAPPING.md) for the design
rationale with real proto citations, [`C_API_COMPARISON.md`](C_API_COMPARISON.md) for the audit of
the two earlier drafts this tree reconciles, and
[`STRENGTHS_AND_WEAKNESSES.md`](STRENGTHS_AND_WEAKNESSES.md) for a plain-language summary of that
audit.

## Layout

```
include/agc/     public headers — one per proto service, plus core/types
                 agc_ext.h is separate: proposed, not-yet-standard extensions (opt-in)
src/core/        ctx, error handling, memory hygiene, iterators, sessions
src/wire/        hand-written OperationMetadata protobuf codec
src/store/       in-memory key/policy/provider stores (stub backend)
src/services/    the 90 RPCs, implemented against the stub backend, plus ext.c (opt-in)
src/stub/        deterministic (NOT cryptographically secure) stub primitives
tools/           the enum/error-code generator, driven by the pinned proto
conformance/     DIVERGENCES.yaml, rpc_manifest.yaml, and the Tier 1/4 conformance checks
tests/           CTest suite (24 tests; 25 with AGC_ENABLE_PROPOSED_EXTENSIONS on)
examples/        example programs
docs/            C_API_MAPPING.md (design rationale) and PROTO_RFCS.md
```

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

`ctest` includes the Tier 1/4 conformance checks (`conformance/tier1*.py`,
`conformance/tier4_abi_baseline.sh`), which run against the pinned proto descriptor on every
build — no separate step to remember. The Python checks need `pip install protobuf pyyaml`.

To build the proposed extensions in `agc_ext.h` (RFC-01 UpdateKeyState, RFC-13 MAC streaming,
RFC-14 CancelOperation — see `docs/PROTO_RFCS.md`):

```sh
cmake -S . -B build-ext -DAGC_ENABLE_PROPOSED_EXTENSIONS=ON
cmake --build build-ext
```

This surface is excluded from Tier 1b/1c conformance by construction (D16): "the core is exactly
90 RPCs" stays true regardless of which extensions a build opts into.

## Regenerating the vocabulary

`include/agc/agc_types.h` and `src/core/agc_types.c` are generated:

```sh
python3 tools/gen_agc_types.py
```

They are a deterministic function of `conformance/api_descriptor.binpb` (the pinned proto
snapshot — see `conformance/DESCRIPTOR_PROVENANCE.md`) plus the small hand-maintained
`LOCAL_ERROR_CODES` table inside the generator itself. **Never hand-edit
`agc_types.h`/`.c` directly** — that is exactly the failure mode `C_API_COMPARISON.md` finding B1
documents in one of the two earlier drafts this tree reconciles.

## Conformance

Every deliberate divergence between this C API and the wire proto is declared in
[`conformance/DIVERGENCES.yaml`](conformance/DIVERGENCES.yaml) — a construct that exists on one
side and not the other, and is not listed there, is a bug by definition. Four tiers run today:

| Tier | Script | Checks |
|---|---|---|
| 1 (vocabulary) | `tier1_vocabulary.py` | every proto enum value ↔ C enumerator, both directions |
| 1c (oneof tags) | `tier1c_oneof_tags.py` | tagged-union field-number tags match the proto's oneof |
| 1b (surface) | `tier1b_surface.py` | RPC count == 90; every RPC ↔ C function, both directions |
| 1c (fields) | `tier1c_fields.py` | every request/response field has a C counterpart, modulo `DIVERGENCES.yaml` |
| 4 (ABI) | `tier4_abi_baseline.sh` | `abidiff` against a stored baseline (skips cleanly pre-1.0 or without `libabigail` installed) |

## What this is not (yet)

The stub backend (`src/stub/stub_crypto.h`) proves the API's shapes, ownership rules, and
round-trips structurally; it does **not** perform real cryptography — no key schedule, no
diffusion, no resistance to related-key or chosen-plaintext attacks. Wiring a real provider
(OpenSSL, PKCS#11) behind the same `src/services/*.c` entry points is out of scope for this
reconciliation; the provider SPI that would make that swap possible is deferred to 1.1 (see
`RECONCILIATION_PLAN.md` §6, "Deferred to 1.1").
