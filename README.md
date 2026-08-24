# agilecrypto — C binding for the Citius intent-based cryptographic API

A local, in-process C library that mirrors `caas.crypto.v1` (the protobuf/gRPC
specification in `github.com/agile-crypto/api`) closely enough to be checked
against it mechanically, while behaving like a proper C library rather than a
transliterated wire format.

**Status:** under active reconciliation. See
[`RECONCILIATION_PLAN.md`](RECONCILIATION_PLAN.md) for the full plan and its
commit-by-commit sequencing, [`C_API_COMPARISON.md`](C_API_COMPARISON.md) for
the audit of the two earlier drafts this tree reconciles, and
[`STRENGTHS_AND_WEAKNESSES.md`](STRENGTHS_AND_WEAKNESSES.md) for a plain-language
summary of that audit.

## Layout

```
include/agc/     public headers — one per proto service, plus core/types
src/core/        ctx, error handling, memory hygiene, iterators, sessions
src/wire/        hand-written OperationMetadata protobuf codec
src/store/       in-memory key/template/policy/provider stores (stub backend)
src/services/    the 90 RPCs, implemented against the stub backend
src/stub/        deterministic (NOT cryptographically secure) stub primitives
tools/           the enum/error-code generator, driven by the pinned proto
conformance/     DIVERGENCES.yaml + the Tier 1 vocabulary/surface/field checks
tests/           CTest suite
examples/        example programs
docs/            C_API_MAPPING.md (design rationale) and PROTO_RFCS.md
```

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

`ctest` includes the Tier 1 conformance checks (`conformance/tier1_*.py`),
which run against the pinned proto descriptor on every build — no separate
step to remember. They need `python3 -m pip install protobuf`.

## Regenerating the vocabulary

`include/agc/agc_types.h` and `src/core/agc_types.c` are generated:

```sh
python3 tools/gen_agc_types.py
```

They are a deterministic function of `conformance/api_descriptor.binpb` (the
pinned proto snapshot — see `conformance/DESCRIPTOR_PROVENANCE.md`) plus the
small hand-maintained `LOCAL_ERROR_CODES` table inside the generator itself.
**Never hand-edit `agc_types.h`/`.c` directly** — that is exactly the failure
mode `C_API_COMPARISON.md` finding B1 documents in the earlier draft.

## What this is not (yet)

The stub backend proves the API's shapes, ownership rules, and round-trips
structurally; it does **not** perform real cryptography (see
`src/stub/README.md` once commit 8 lands). Wiring a real provider (OpenSSL,
PKCS#11) is out of scope for the reconciliation itself — see
`RECONCILIATION_PLAN.md` §5's provider SPI item.
