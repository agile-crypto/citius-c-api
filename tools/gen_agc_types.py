#!/usr/bin/env python3
"""gen_agc_types.py — generates include/agc/agc_types.h (and
conformance/manifest.json) from the pinned FileDescriptorSet at
conformance/api_descriptor.binpb.

The header declares an agc_<enum>_name / agc_<enum>_from_name pair per enum;
implementations define them (citius-rust generates its own from the header).

This is the mechanism referenced throughout docs/history/RECONCILIATION_PLAN.md: agc_types.h
carries numeric equality with the wire enums as a hard, checkable invariant
(see conformance/tier1_vocabulary.py), which only holds if the file is never
hand-edited. docs/history/C_API_COMPARISON.md finding B1 was exactly this promise being
broken by a hand edit with no generator behind it at all.

"Generated" here means: the output is a deterministic function of (a)
the pinned descriptor and (b) the small LOCAL_ERROR_CODES table below. Fix a
bug or add a local error code by editing LOCAL_ERROR_CODES and re-running this
script — never by editing agc_types.h directly.

Usage:
    python3 tools/gen_agc_types.py
    (regenerates include/agc/agc_types.h and conformance/manifest.json in place; run from the repo root or anywhere,
     paths are resolved relative to this script)
"""
import json
import re
import sys
from pathlib import Path

from google.protobuf import descriptor_pb2

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"
OUT_HEADER = ROOT / "include" / "agc" / "agc_types.h"
OUT_MANIFEST = ROOT / "conformance" / "manifest.json"

# ---------------------------------------------------------------------------
# Hand-authored input #1: local conditions that exist only in a local library
# and have no wire representation. Edit HERE, never in agc_types.h.
# Layout: AGC_OK = 0; local codes -1..-99; CryptoErrorCode-derived codes are
# generated separately at -(1000 + wire_value) (see D2 / C1 in the plan).
# ---------------------------------------------------------------------------
LOCAL_ERROR_CODES = [
    ("UNSPECIFIED", -1, "no more specific code applies"),
    ("INVALID_ARGUMENT", -2, "NULL where required, bad length, bad enum"),
    ("BUFFER_TOO_SMALL", -3, "out_len holds the required size"),
    ("OUT_OF_MEMORY", -4, "allocation failure"),
    ("NOT_IMPLEMENTED", -5, "optional RPC not offered by this build"),
    ("INVALID_HANDLE", -6, "stale/foreign/freed handle"),
    ("ABI_MISMATCH", -7, "struct_size not recognised"),
    ("UNAVAILABLE", -8, "remote deployment mode: transport failure"),
    ("PERMISSION_DENIED", -9, "caller identity lacks the IAM scope"),
    ("ALREADY_EXISTS", -10, "duplicate name where uniqueness is required"),
    ("CANCELLED", -11, "operation cancelled by the caller"),
    ("DEADLINE_EXCEEDED", -12, "remote deployment mode: timed out"),
    ("INTERNAL", -13, "unexpected internal condition"),
    ("PROVIDER_CONTRACT_VIOLATION", -14, "e.g. unset ProviderOutput.algorithm_output"),
    ("ITERATOR_EXHAUSTED", -15, "normal end of a list iteration"),
]

# ---------------------------------------------------------------------------
# Hand-authored input #2: the one nested enum promoted out of the
# catalog-internal algorithm_params.proto tree. See docs/history/RECONCILIATION_PLAN.md
# §2.2 — CombinerStrategy is generated because CBOM reporting needs to name
# the hybrid combiner even though HybridAlgorithmParams itself is not
# projected (§2.6). No other nested enum is included; the other 16 stay
# catalog-internal by omission, which is the default, not an exception list.
# ---------------------------------------------------------------------------
PROMOTED_NESTED_ENUMS = [
    # (proto file, message name, nested enum name)
    ("api/types/templates.proto", "HybridAlgorithmParams", "CombinerStrategy"),
]

CRYPTO_ERROR_CODE_ENUM = "CryptoErrorCode"


def pascal_to_c(name: str) -> str:
    """PascalCase -> snake_case. Verified against every enum name in the
    pinned descriptor to match the naming already established in prior art
    (e.g. Sp800108DataType -> sp800108_data_type, Ed25519Variant ->
    ed25519_variant, Fips140Level -> fips140_level)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def load_descriptor() -> descriptor_pb2.FileDescriptorSet:
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())
    return fds


def collect_enums(fds):
    """Returns [(file_name, enum_descriptor_proto), ...] for every top-level
    enum in api/*.proto, plus the promoted nested enums, in file order."""
    result = []
    by_name = {f.name: f for f in fds.file}
    for f in fds.file:
        if not f.name.startswith("api/"):
            continue
        for e in f.enum_type:
            result.append((f.name, e))
    for file_name, msg_name, enum_name in PROMOTED_NESTED_ENUMS:
        f = by_name[file_name]
        msg = next(m for m in f.message_type if m.name == msg_name)
        e = next(x for x in msg.enum_type if x.name == enum_name)
        result.append((file_name, e))
    return result


def emit_enum(e, out):
    c_type = "agc_" + pascal_to_c(e.name)
    out.append(f"typedef enum {c_type} {{")
    lines = []
    for v in e.value:
        dep = " /* deprecated */" if v.options.deprecated else ""
        lines.append(f"    AGC_{v.name} = {v.number}{dep}")
    out.append(",\n".join(lines))
    out.append(f"    AGC_ENUM32({c_type})")
    out.append(f"}} {c_type};")
    out.append("")
    return c_type


def emit_name_fn_decl(c_type):
    return f"AGC_API const char *{c_type}_name({c_type} v);"


def emit_from_name_fn_decl(c_type):
    return f"AGC_API agc_rc {c_type}_from_name(const char *name, {c_type} *out);"


def main():
    fds = load_descriptor()
    enums = collect_enums(fds)

    crypto_error_enum = None
    normal_enums = []
    for file_name, e in enums:
        if e.name == CRYPTO_ERROR_CODE_ENUM:
            crypto_error_enum = e
        else:
            normal_enums.append((file_name, e))
    assert crypto_error_enum is not None, "CryptoErrorCode not found in pinned descriptor"

    header = []
    header.append("/* SPDX-License-Identifier: Apache-2.0")
    header.append(" *")
    header.append(" * agc_types.h -- Abstract Cryptographic API, C binding: generated vocabulary.")
    header.append(" *")
    header.append(" * ============================================================================")
    header.append(" * GENERATED by tools/gen_agc_types.py from the pinned descriptor at")
    header.append(" * conformance/api_descriptor.binpb (see conformance/DESCRIPTOR_PROVENANCE.md).")
    header.append(" * DO NOT EDIT BY HAND. To change a local error code, edit LOCAL_ERROR_CODES in")
    header.append(" * the generator and re-run it. To pick up a proto change, bump the pinned")
    header.append(" * descriptor (tools/refresh_descriptor.sh) and re-run the generator.")
    header.append(" *")
    header.append(" * Every enumerator below carries the SAME NUMERIC VALUE as the corresponding")
    header.append(" * protobuf enum value. conformance/tier1_vocabulary.py checks this against the")
    header.append(" * same pinned descriptor on every run and fails the build on drift.")
    header.append(" *")
    header.append(" * Enum storage: every enum carries an explicit `= 0x7fffffff` sentinel (via")
    header.append(" * AGC_ENUM32) so it has int32 width on every conforming compiler, matching the")
    header.append(" * protobuf wire type and making the ABI independent of -fshort-enums.")
    header.append(" * ============================================================================")
    header.append(" */")
    header.append("")
    header.append("#ifndef AGC_TYPES_H")
    header.append("#define AGC_TYPES_H")
    header.append("")
    header.append('#include "agc_abi.h"')
    header.append("#include <stdint.h>")
    header.append("")
    header.append("#ifdef __cplusplus")
    header.append('extern "C" {')
    header.append("#endif")
    header.append("")
    header.append("/* AGC_ENUM32 is hand-written infrastructure from agc_abi.h, used below on")
    header.append(" * every generated enum. Not redefined here. */")
    header.append("")
    header.append("/* --------------------------------------------------------------------------")
    header.append(" * Result codes")
    header.append(" *")
    header.append(" * Layout:")
    header.append(" *   AGC_OK                = 0")
    header.append(" *   AGC_ERR_* (local)      = -1 .. -99")
    header.append(" *   AGC_ERR_CRYPTO_*       = -(1000 + CryptoErrorCode)")
    header.append(" *")
    header.append(" * The second range is a mechanical, reversible transform of CryptoErrorCode")
    header.append(" * (api/types/common.proto): agc_rc = -(1000 + wire_value). A gRPC front-end")
    header.append(" * recovers the wire value arithmetically: wire = -rc - 1000.")
    header.append(" * -------------------------------------------------------------------------- */")
    header.append("")
    header.append("typedef int32_t agc_rc;")
    header.append("")
    header.append("#define AGC_OK ((agc_rc)0)")
    header.append("")
    header.append("/* --- Local codes: conditions that exist only in a local library. Edit")
    header.append(" * LOCAL_ERROR_CODES in tools/gen_agc_types.py, not here. --- */")
    for suffix, value, comment in LOCAL_ERROR_CODES:
        header.append(f"#define AGC_ERR_{suffix} ((agc_rc){value})  /* {comment} */")
    header.append("")
    header.append(f"/* --- Generated from {CRYPTO_ERROR_CODE_ENUM} (api/types/common.proto) --- */")
    for v in crypto_error_enum.value:
        suffix = v.name
        if suffix.startswith("CRYPTO_ERROR_"):
            suffix = suffix[len("CRYPTO_ERROR_"):]
        wire_rc = -(1000 + v.number)
        header.append(f"#define AGC_ERR_CRYPTO_{suffix} ((agc_rc){wire_rc})  /* wire value {v.number} */")
    header.append("")

    manifest = {
        "descriptor_sha256": None,  # filled below
        "local_error_codes": [{"name": s, "value": v} for s, v, _ in LOCAL_ERROR_CODES],
        "crypto_error_code": {
            v.name: v.number for v in crypto_error_enum.value
        },
        "enums": {},
    }

    header.append("/* ==========================================================================")
    header.append(" * VOCABULARY ENUMS")
    header.append(" * ========================================================================== */")
    header.append("")

    for file_name, e in normal_enums:
        header.append(f"/* {e.name} ({file_name}) */")
        c_type = emit_enum(e, header)
        header.append(emit_name_fn_decl(c_type))
        header.append(emit_from_name_fn_decl(c_type))
        header.append("")
        manifest["enums"][e.name] = {
            "c_type": c_type,
            "file": file_name,
            "values": {v.name: v.number for v in e.value},
        }

    header.append("/* --- agc_rc helpers --- */")
    header.append("AGC_API const char *agc_rc_name(agc_rc rc);")
    header.append("AGC_API const char *agc_rc_message(agc_rc rc);")
    header.append("")
    header.append("#ifdef __cplusplus")
    header.append("}")
    header.append("#endif")
    header.append("#endif /* AGC_TYPES_H */")
    header.append("")

    OUT_HEADER.write_text("\n".join(header))

    import hashlib
    manifest["descriptor_sha256"] = hashlib.sha256(DESCRIPTOR.read_bytes()).hexdigest()
    manifest["enum_count"] = len(manifest["enums"])
    manifest["local_error_code_count"] = len(LOCAL_ERROR_CODES)
    manifest["crypto_error_code_count"] = len(crypto_error_enum.value)
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(f"wrote {OUT_HEADER.relative_to(ROOT)} ({len(normal_enums)} enums)")
    print(f"wrote {OUT_MANIFEST.relative_to(ROOT)}")


if __name__ == "__main__":
    sys.exit(main())
