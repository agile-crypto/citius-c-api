# citius-c-api — the C contract for the Citius intent-based cryptographic API

The `agc_*` C headers: a local, in-process C API that mirrors `caas.crypto.v1` (the
protobuf/gRPC specification, pinned here as `conformance/api_descriptor.binpb`) closely enough to
be checked against it mechanically, while behaving like a proper C library rather than a
transliterated wire format.

**This repository is header-only.** It holds the contract, its generator and its conformance
checks; it builds no library. The implementation is
[citius-rust](https://github.ibm.com/citius/citius-rust), which ships `libagilecrypto` and
installs these headers with it. (Until 2026-11 this repository also contained a C stub backend;
it is in the git history before the commit "Make citius-c-api header-only".)

**API version:** 2.0 (`AGC_API_VERSION_*` in `agc_abi.h`, the single version source), a mirror of
citius/api v0.3.0.

## Layout

```
include/agc/        the public headers: one per proto service (agc_key.h, agc_crypto.h, ...)
                    and its *_types.h, plus core, ABI and generated vocabulary (agc_types.h).
                    agilecrypto.h includes them all. agc_ext.h is separate and opt-in:
                    proposed, not-yet-standard extensions (docs/PROTO_RFCS.md).
tools/              gen_agc_types.py (generates agc_types.h from the pinned descriptor),
                    refresh_descriptor.sh
conformance/        the pinned descriptor, DIVERGENCES.yaml, rpc_manifest.yaml, the Tier 1/4
                    checks, and golden/ (OperationMetadata vectors encoded by real protobuf)
tests/              header checks: every header compiles on its own as C99, C11 and C++11;
                    layout and idiom tests that need only the headers
docs/               C_API_MAPPING.md (design rationale), PROTO_RFCS.md, and history/ (the
                    reconciliation plan and audits this tree was built from)
```

## Checking the headers

```sh
cmake -S . -B build
cmake --build build                      # fails if any header does not compile standalone
ctest --test-dir build --output-on-failure
```

The build compiles every header on its own, as C99 and C11 (and C++11 if a C++ compiler is
found), with `-Wall -Wextra -Wpedantic -Werror`. `ctest` runs the header-only layout tests and the
conformance checks. The conformance checks need Python 3 with `pip install protobuf pyyaml`;
without them, CMake says so and leaves them out.

To install the headers and a cflags-only `agc-headers.pc`:

```sh
cmake --install build --prefix /usr/local
```

An application normally gets the headers from its implementation's install instead (citius-rust:
`cargo xtask install`, which installs `agilecrypto.pc` and a CMake package).

## Regenerating the vocabulary

`include/agc/agc_types.h` is generated:

```sh
python3 tools/gen_agc_types.py
```

It is a deterministic function of `conformance/api_descriptor.binpb` (see
`conformance/DESCRIPTOR_PROVENANCE.md`) plus the small hand-maintained `LOCAL_ERROR_CODES` table
inside the generator. **Never hand-edit `agc_types.h`.** It declares an `agc_<enum>_name` /
`agc_<enum>_from_name` pair per enum; implementations define them.

## Conformance

Every deliberate divergence between this C API and the wire proto is declared in
[`conformance/DIVERGENCES.yaml`](conformance/DIVERGENCES.yaml). A construct that exists on one
side and not the other, and is not listed there, is a bug by definition.

| Tier | Script | Checks |
|---|---|---|
| 1 (vocabulary) | `tier1_vocabulary.py` | every proto enum value ↔ C enumerator, both directions |
| 1b (surface) | `tier1b_surface.py` | 98 RPCs across 7 services; every RPC ↔ C function, both directions |
| 1c (fields) | `tier1c_fields.py` | every request/response field has a C counterpart in the service's headers, modulo `DIVERGENCES.yaml` |
| 1c (oneof tags) | `tier1c_oneof_tags.py` | tagged-union tags match the proto's oneof field numbers |
| 4 (ABI) | `tier4_abi_baseline.sh` | `abidiff` of an implementation's library against a stored baseline; configure with `-DAGC_ABI_LIB=/path/to/libagilecrypto.so` (skips without it, without a baseline, or without libabigail) |

Behaviour behind the headers is tested by the implementation: citius-rust runs its C test suite
(`tests/c`) against `libagilecrypto`, plain, under ASan/UBSan and under TSan.

`conformance/golden/operation_metadata_vectors.json` holds OperationMetadata messages encoded by
real protobuf, for implementations to check their metadata codec against
(`conformance/golden/gen_metadata_vectors.py` documents how they are made).
