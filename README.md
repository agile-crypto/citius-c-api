# Citius C API

A pure-C (C11) cryptographic API that mirrors the [Citius ProtoBuf API](../api/proto/) as
closely as the C type system allows, while drawing session and handle semantics from
PKCS#11.

## Design Principles

- **Structural parity**: every proto message → C `struct`; every `oneof` → tagged union.
- **Scope-driven algorithm selection**: callers pass a `citius_scope_spec_t` expressing
  intent; the provider/policy engine selects the concrete algorithm at runtime.
- **PKCS#11-style sessions**: `citius_session_open()` / `citius_session_close()`; all
  operations carry a `CITIUS_SESSION_HANDLE`.
- **Single return type**: every function returns `CITIUS_RV` (`uint32_t`); `CITIUS_OK = 0`.
- **Buffer size-query pattern**: pass `NULL` (or `capacity = 0`) for an output buffer to
  receive the required size without performing the operation.

## Header Layout

```
include/citius/
├── citius_types.h           # Handles, CITIUS_RV, error codes, byte buffers
├── citius_algorithm_params.h# Algorithm enums + 30+ param structs + tagged union
├── citius_scope.h           # 12 scope enums, scope_spec_t, security properties
├── citius_operation_params.h# Per-call params (AAD, KDF salts, domain context)
├── citius_provider.h        # Session API, provider vtable, provider info
├── citius_key_management.h  # 11 key lifecycle functions
├── citius_crypto.h          # 18 single-shot operations
├── citius_streaming.h       # Init/Update/Final streaming + opaque ctx
├── citius_policy.h          # Template discovery + policy CRUD/eval
└── citius.h                 # Aggregate top-level include
```

## Prerequisites

- CMake ≥ 3.25
- A C11-capable compiler (GCC ≥ 7, Clang ≥ 5, Apple Clang ≥ 11)

## Build & Test

```sh
cmake -S citius-c-api -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

All tests use the zero-filling stub provider; no external crypto library is required.

## Project Status

This repository contains the public header specification and a CMake/CTest test harness
that validates the API contract. A real provider implementation backed by a crypto library
is out of scope for this scaffold.
