#!/usr/bin/env python3
"""Tier 1 -- vocabulary conformance (docs/history/RECONCILIATION_PLAN.md §7).

Loads the pinned FileDescriptorSet directly (not conformance/manifest.json,
which is generator OUTPUT and could in principle drift from agc_types.h the
same way agc_types.h could drift from the proto) and re-parses agc_types.h
with a small, deliberately dumb regex extractor. Asserts:

  1. Every proto enum value has a C enumerator (AGC_<value name>) with the
     identical numeric value.
  2. No C enumerator in a generated enum type lacks a proto counterpart.
  3. Every CryptoErrorCode value has an AGC_ERR_CRYPTO_* code satisfying
     agc_rc == -(1000 + wire_value).

This is the check that docs/history/C_API_COMPARISON.md finding B1 says should have
existed from day one: the previous draft's agc_types.h carried a "hard
invariant, enforced in CI" banner with no enforcement mechanism behind it,
and defined two error codes that do not exist on the wire. Run this on every
build; it is wired into `ctest` as a test, not left as a standalone script
someone has to remember to run.
"""
import re
import sys
from pathlib import Path

from google.protobuf import descriptor_pb2

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"
HEADER = ROOT / "include" / "agc" / "agc_types.h"

sys.path.insert(0, str(ROOT / "tools"))
from gen_agc_types import pascal_to_c, PROMOTED_NESTED_ENUMS, CRYPTO_ERROR_CODE_ENUM  # noqa: E402


def load_proto_enums():
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())
    by_name = {f.name: f for f in fds.file}
    enums = {}
    for f in fds.file:
        if not f.name.startswith("api/"):
            continue
        for e in f.enum_type:
            enums[e.name] = {v.name: v.number for v in e.value}
    for file_name, msg_name, enum_name in PROMOTED_NESTED_ENUMS:
        f = by_name[file_name]
        msg = next(m for m in f.message_type if m.name == msg_name)
        e = next(x for x in msg.enum_type if x.name == enum_name)
        enums[e.name] = {v.name: v.number for v in e.value}
    return enums


def load_header_defines():
    """Extract every `AGC_<NAME> = <number>` enumerator and every
    `#define AGC_ERR_CRYPTO_<SUFFIX> ((agc_rc)<value>)` from agc_types.h."""
    text = HEADER.read_text()
    enum_values = {}  # AGC_<name> -> number, scoped by enclosing enum
    for block in re.finditer(r"typedef enum (agc_\w+) \{(.*?)\}\s*\1;", text, re.S):
        c_type, body = block.group(1), block.group(2)
        vals = {}
        for m in re.finditer(r"AGC_(\w+)\s*=\s*(-?\d+)", body):
            vals[m.group(1)] = int(m.group(2))
        enum_values[c_type] = vals

    error_defines = {}
    for m in re.finditer(r"#define AGC_ERR_CRYPTO_(\w+) \(\(agc_rc\)(-?\d+)\)", text):
        error_defines[m.group(1)] = int(m.group(2))

    return enum_values, error_defines


def main():
    proto_enums = load_proto_enums()
    header_enums, header_error_defines = load_header_defines()

    failures = []

    for proto_name, values in proto_enums.items():
        if proto_name == CRYPTO_ERROR_CODE_ENUM:
            continue
        c_type = "agc_" + pascal_to_c(proto_name)
        if c_type not in header_enums:
            failures.append(f"enum {proto_name} ({c_type}) missing from agc_types.h entirely")
            continue
        c_values = header_enums[c_type]
        for value_name, number in values.items():
            if value_name not in c_values:
                failures.append(f"{proto_name}.{value_name} = {number}: no AGC_{value_name} in {c_type}")
            elif c_values[value_name] != number:
                failures.append(
                    f"{proto_name}.{value_name}: proto={number} but AGC_{value_name}={c_values[value_name]}"
                )
        for c_name, c_number in c_values.items():
            if c_name not in values:
                failures.append(f"{c_type} has AGC_{c_name}={c_number} with no {proto_name} counterpart")

    crypto_error = proto_enums[CRYPTO_ERROR_CODE_ENUM]
    for value_name, number in crypto_error.items():
        suffix = value_name[len("CRYPTO_ERROR_"):] if value_name.startswith("CRYPTO_ERROR_") else value_name
        expected = -(1000 + number)
        if suffix not in header_error_defines:
            failures.append(f"CryptoErrorCode.{value_name} (wire {number}): no AGC_ERR_CRYPTO_{suffix} defined")
        elif header_error_defines[suffix] != expected:
            failures.append(
                f"AGC_ERR_CRYPTO_{suffix} = {header_error_defines[suffix]}, expected {expected} "
                f"(wire value {number})"
            )
    for suffix, rc in header_error_defines.items():
        expected_wire = -rc - 1000
        if expected_wire not in crypto_error.values():
            failures.append(
                f"AGC_ERR_CRYPTO_{suffix} = {rc} implies wire value {expected_wire}, "
                f"which does not exist in CryptoErrorCode"
            )

    if failures:
        print(f"TIER 1 VOCABULARY: FAIL ({len(failures)} issue(s))", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"TIER 1 VOCABULARY: PASS ({len(proto_enums) - 1} enums + CryptoErrorCode, "
          f"{sum(len(v) for k, v in proto_enums.items() if k != CRYPTO_ERROR_CODE_ENUM)} values checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
