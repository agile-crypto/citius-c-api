#!/usr/bin/env python3
"""Tier 1b -- RPC <-> C entry-point surface bijection (RECONCILIATION_PLAN.md §7).

Loads the pinned FileDescriptorSet and conformance/rpc_manifest.yaml, and
checks, in both directions:

  forward:  every RPC method in the descriptor's 7 core services has an
            entry in rpc_manifest.yaml, naming a function that is a real
            AGC_API declaration in the header the manifest says it lives in.
  reverse:  every `agc_ctx *ctx`-taking AGC_API function declared in those
            7 headers is either the mapped function of some RPC, or listed
            in rpc_manifest.yaml's non_rpc_ctx_helpers with a reason.

Also asserts the descriptor carries exactly 90 RPCs across exactly the 7
service names the reconciliation targets -- no more, no fewer.

This is the check that would have caught C_API_COMPARISON.md findings B1/B2
("Version B invents 8 phantom RPCs", "claims 98 RPCs"): a function with no
RPC behind it, or an RPC with no function, both fail loudly instead of
surviving as an unnoticed drift between the header and the spec.

agc_ext.h (commit 13, AGC_ENABLE_PROPOSED_EXTENSIONS) is out of scope by
construction: it is not one of the 7 headers scanned here, and its symbols
are never expected to satisfy the reverse check.
"""
import re
import sys
from pathlib import Path

import yaml
from google.protobuf import descriptor_pb2

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"
MANIFEST = ROOT / "conformance" / "rpc_manifest.yaml"
INCLUDE_DIR = ROOT / "include" / "agc"

EXPECTED_TOTAL_RPCS = 90
EXPECTED_SERVICE_COUNTS = {
    "CryptoService": 12,
    "StreamingCryptoService": 43,
    "KeyManagementService": 11,
    "KeyEstablishmentService": 6,
    "CryptoPolicyService": 7,
    "ProviderService": 8,
    "AlgorithmDiscoveryService": 3,
}

# Matches a top-level "AGC_API <ret> <name>(" declaration, tolerating a
# return type that wraps to a following line is NOT supported -- all real
# declarations in this tree keep the name on the AGC_API line, verified by
# inspection; a future declaration that breaks this convention will show up
# as a spurious "declared nowhere" failure rather than silently passing.
DECL_RE = re.compile(r"^AGC_API\b.*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
CTX_FIRST_ARG_RE = re.compile(r"\(\s*agc_ctx\s*\*\s*ctx\b")


def load_descriptor_rpcs():
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())

    services = {}
    for fd in fds.file:
        if fd.package != "caas.crypto.v1":
            continue
        for svc in fd.service:
            if svc.name in EXPECTED_SERVICE_COUNTS:
                services[svc.name] = [m.name for m in svc.method]
    return services


def load_header_declarations(header_name):
    """Returns {function_name: is_ctx_taking} for every AGC_API declaration
    in the given header under include/agc/."""
    text = (INCLUDE_DIR / header_name).read_text()
    decls = {}
    for match in DECL_RE.finditer(text):
        name = match.group(1)
        # Slice from the declaration start to the matching '(' to check the
        # first argument without a full C parser.
        start = match.start()
        paren = text.index("(", match.end() - 1)
        call_open = text[start:paren + 200]  # enough to see the first arg
        decls[name] = bool(CTX_FIRST_ARG_RE.search(text[start:paren + 1] + text[paren + 1:paren + 40]))
    return decls


def main():
    errors = []

    descriptor_services = load_descriptor_rpcs()

    if set(descriptor_services) != set(EXPECTED_SERVICE_COUNTS):
        errors.append(
            f"service set mismatch: descriptor has {sorted(descriptor_services)}, "
            f"expected {sorted(EXPECTED_SERVICE_COUNTS)}"
        )

    total = 0
    for svc, methods in descriptor_services.items():
        expected = EXPECTED_SERVICE_COUNTS[svc]
        total += len(methods)
        if len(methods) != expected:
            errors.append(f"{svc}: descriptor has {len(methods)} RPCs, expected {expected}")

    if total != EXPECTED_TOTAL_RPCS:
        errors.append(f"total RPC count is {total}, expected {EXPECTED_TOTAL_RPCS}")

    manifest = yaml.safe_load(MANIFEST.read_text())
    manifest_services = manifest.get("services", {})
    non_rpc_helpers = {h["function"]: h for h in manifest.get("non_rpc_ctx_helpers", [])}

    if set(manifest_services) != set(EXPECTED_SERVICE_COUNTS):
        errors.append(
            f"manifest service set mismatch: {sorted(manifest_services)} "
            f"vs expected {sorted(EXPECTED_SERVICE_COUNTS)}"
        )

    # ---- forward direction: every descriptor RPC has a manifest entry
    # naming a real declared function. ----
    header_decls_cache = {}
    manifest_functions_by_header = {}

    for svc, methods in descriptor_services.items():
        entry = manifest_services.get(svc)
        if entry is None:
            errors.append(f"{svc}: no manifest entry at all")
            continue

        header_name = entry["header"]
        rpc_map = entry.get("rpcs", {})
        manifest_functions_by_header.setdefault(header_name, set())

        if header_name not in header_decls_cache:
            header_decls_cache[header_name] = load_header_declarations(header_name)
        decls = header_decls_cache[header_name]

        for rpc_name in methods:
            func = rpc_map.get(rpc_name)
            if func is None:
                errors.append(f"{svc}.{rpc_name}: no C function mapped in rpc_manifest.yaml")
                continue
            manifest_functions_by_header[header_name].add(func)
            if func not in decls:
                errors.append(
                    f"{svc}.{rpc_name}: mapped function '{func}' is not declared "
                    f"AGC_API in {header_name}"
                )
            # No ctx-taking requirement here: DV-06 replaces operation_id
            # with agc_session* for the 29 Update/Final/Begin/Next-shaped
            # streaming RPCs, so a real mapped function may legitimately
            # take a session instead of a context. The ctx-arg signal is
            # used only in the reverse (phantom-detection) direction below,
            # where it identifies the set of "could plausibly be an RPC
            # entry point" functions worth checking for a missing mapping.

        # Extra RPCs in the manifest that the descriptor does not have.
        for rpc_name in rpc_map:
            if rpc_name not in methods:
                errors.append(f"{svc}.{rpc_name}: manifest lists this RPC, but it is not in the descriptor")

    # ---- reverse direction: every ctx-taking AGC_API function in a scanned
    # header is either an RPC entry point or a documented helper. ----
    for header_name, mapped_functions in manifest_functions_by_header.items():
        decls = header_decls_cache[header_name]
        for func, is_ctx_taking in decls.items():
            if not is_ctx_taking:
                continue
            if func in mapped_functions:
                continue
            helper = non_rpc_helpers.get(func)
            if helper is None:
                errors.append(
                    f"{header_name}: '{func}' takes agc_ctx* but maps to no RPC "
                    f"and is not in non_rpc_ctx_helpers (phantom entry point?)"
                )
            elif helper.get("header") != header_name:
                errors.append(
                    f"{header_name}: non_rpc_ctx_helpers entry for '{func}' names "
                    f"header '{helper.get('header')}', which does not match"
                )

    if errors:
        print(f"Tier 1b (surface) FAILED with {len(errors)} error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"Tier 1b (surface): OK -- {total} RPCs across {len(descriptor_services)} services, "
          f"all mapped and declared; no phantom entry points.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
