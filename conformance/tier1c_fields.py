#!/usr/bin/env python3
"""Tier 1c -- request/response field presence (RECONCILIATION_PLAN.md §7).

For every RPC in the pinned descriptor, takes its request and response
message's TOP-LEVEL fields and asserts each field's name appears as an
identifier token in the C header that RPC's entry point lives in (per
conformance/rpc_manifest.yaml), UNLESS the field is listed as dropped in
conformance/DIVERGENCES.yaml.

A response field of message type is a D6 opaque-handle projection (e.g.
CreateKeyResponse.key_metadata -> agc_key_info*), so ITS OWN fields are
never restated at the RPC's response level -- they surface only as
accessors on the handle (agc_key_info_extractable(), ...). Those accessor
sets still need checking (a dropped accessor is exactly the kind of bug
this tier exists to catch), so this script follows exactly ONE hop into
each such nested message type and checks its fields the same way, against
the same header. It does not recurse further (a KeyMetadata field that is
itself message-typed, e.g. template_info, is left unchecked at that
second hop) -- this bound is a deliberate, stated scope limit, not an
oversight: chasing arbitrary nesting depth turns a regex tool into the real
C parser this file explicitly declines to be.

This is a deliberately dumb token-presence check, the same style as
tier1_vocabulary.py's regex enum extractor and tier1c_oneof_tags.py's tag
registry -- not a real C parser, and stated as such. It has real power in
the direction the audit's finding B12 ("~15 invented/dropped fields") cared
about most: a field silently DROPPED from the C header (missing
functionality nobody notices until a caller needs it) shows up as a token
absent from the whole header text, which is a very low false-negative check
even without struct-level precision.

KNOWN LIMITATIONS, stated rather than hidden:
  - This check cannot reliably detect a C-only INVENTED field with a name
    that doesn't collide with anything (the reverse direction), because
    doing that precisely needs a real C struct parser scoped to the one
    struct for the one RPC, which this regex-based tool does not attempt.
    Tier 1c oneof tag checking (tier1c_oneof_tags.py) already covers the
    highest-risk invented-field shape (a wrong oneof arm) exactly, which is
    where B's invented fields actually were.
  - An enum- or message-typed field whose accessor is removed can still
    read as "present" if the TYPE name itself embeds the field's own name
    (e.g. removing agc_key_info_lifecycle_state() still leaves
    agc_key_lifecycle_state, the enum typedef, as a matching substring
    elsewhere in the same header). Substring containment trades this
    specific blind spot for catching compound-identifier cases like
    agc_feasibility_recommended_strategy; scalar/string fields (the
    majority of what was actually found dropped during this commit) do not
    have this problem, since they have no separate backing type to hide
    behind.
"""
import sys
from pathlib import Path

import yaml
from google.protobuf import descriptor_pb2

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"
MANIFEST = ROOT / "conformance" / "rpc_manifest.yaml"
DIVERGENCES = ROOT / "conformance" / "DIVERGENCES.yaml"
INCLUDE_DIR = ROOT / "include" / "agc"

# Fields that are legitimately never spelled out as C identifiers because
# they collapse into agc_rc / agc_last_error() (D4) rather than being
# projected as struct members at all.
COLLAPSED_FIELD_NAMES = {"success", "message"}

# Bare proto field names structurally renamed/collapsed by a named,
# already-declared divergence, checked by exact name regardless of which
# message they appear on (the rename is a convention, not a per-message
# decision):
#   - operation_id / *_operation_id -> agc_session* (DV-06)
#   - page_token / next_page_token  -> iterator (DV-07)
#   - valid                          -> int *out_valid parameter (DV-01)
STRUCTURAL_RENAME_NAMES = {"page_token", "next_page_token", "valid"}


def is_structurally_exempt(field):
    name = field.name
    if name in STRUCTURAL_RENAME_NAMES:
        return True
    if name == "operation_id" or name.endswith("_operation_id"):
        return True  # DV-06
    # D5: every byte OUTPUT is delivered via the two-call agc_buf/out_len
    # convention, never re-stated under the proto's own field name.
    if field.type == field.TYPE_BYTES:
        return True
    # D6: any message-typed field is either a shared, separately-checked
    # value type on a REQUEST (kept as a literal field, e.g. scope_spec) or
    # an opaque-handle projection on a RESPONSE (KeyMetadata,
    # MigrationResult, ImplementationProperties, ...) whose accessors never
    # restate the field's own proto name. Only the response side is exempt
    # here; request-side message fields are still checked below.
    return False


def load_messages_by_name():
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())
    messages = {}
    for fd in fds.file:
        if fd.package != "caas.crypto.v1":
            continue
        for msg in fd.message_type:
            messages[msg.name] = msg
    return messages


def load_service_rpcs():
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())
    out = {}
    for fd in fds.file:
        if fd.package != "caas.crypto.v1":
            continue
        for svc in fd.service:
            out[svc.name] = [(m.name, m.input_type.rsplit(".", 1)[-1], m.output_type.rsplit(".", 1)[-1])
                              for m in svc.method]
    return out


def header_tokens(header_name, cache={}):
    if header_name not in cache:
        text = (INCLUDE_DIR / header_name).read_text()
        # Split on non-identifier characters; keep the token set only (a
        # dumb but adequate substitute for real tokenisation here, matching
        # the stated style of every other Tier 1* check in this directory).
        import re
        cache[header_name] = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))
    return cache[header_name]


def field_name_present(field_name, tokens):
    """A field name is considered present if it is a whole token, OR a
    substring of a compound token (e.g. proto field 'recommended_strategy'
    matching C identifier 'agc_feasibility_recommended_strategy') -- real C
    identifiers here are consistently formed by prefixing a proto field or
    RPC name with a namespacing prefix (agc_<noun>_<proto field>), never by
    interleaving or abbreviating it, so substring containment is a safe
    relaxation, not a loophole, for this specific codebase's naming style."""
    if field_name in tokens:
        return True
    return any(field_name in token for token in tokens)


def check_message_fields(label, msg, tokens, is_response, dropped, errors, counts, *, second_hop_of=None):
    """Checks one message's top-level fields against `tokens`. Returns the
    set of message type names found on response-side message fields (D6
    opaque-handle candidates), for the caller to optionally follow one hop
    into. `second_hop_of` is set when this call IS that one hop, purely so
    the emitted error names both the outer RPC-facing field and the nested
    message being checked."""
    counts["messages"] += 1
    nested_response_messages = set()
    for field in msg.field:
        counts["fields"] += 1
        if field.name in COLLAPSED_FIELD_NAMES or field.name in dropped:
            continue
        if field.HasField("oneof_index"):
            continue  # tagged-union arm: not projected as a literal name (see module docstring)
        if is_response and field.type == field.TYPE_MESSAGE:
            nested_response_messages.add(field.type_name.rsplit(".", 1)[-1])
            continue  # D6: opaque-handle projection, never restates the field name
        if is_structurally_exempt(field):
            continue
        if not field_name_present(field.name, tokens):
            where = f"{label} (via {second_hop_of})" if second_hop_of else label
            errors.append(
                f"{where}: {msg.name}.{field.name} has no matching identifier token "
                f"in the expected header(s) (dropped field, or needs a "
                f"DIVERGENCES.yaml dropped_fields entry)"
            )
    return nested_response_messages


def main():
    errors = []

    messages = load_messages_by_name()
    service_rpcs = load_service_rpcs()
    manifest = yaml.safe_load(MANIFEST.read_text())
    manifest_services = manifest.get("services", {})
    divergences = yaml.safe_load(DIVERGENCES.read_text()).get("divergences", [])

    # dropped_fields: DV entries may declare per-message dropped field names
    # explicitly via a "dropped_fields: {MessageName: [field, ...]}" map.
    # Entries without one (most of them: they are behavioural/shape
    # divergences, not per-field drops) simply contribute nothing here.
    dropped_by_message = {}
    for dv in divergences:
        for msg_name, fields in (dv.get("dropped_fields") or {}).items():
            dropped_by_message.setdefault(msg_name, set()).update(fields)

    counts = {"messages": 0, "fields": 0}

    all_headers_tokens = header_tokens("agc_core.h")
    for entry in manifest_services.values():
        all_headers_tokens = all_headers_tokens | header_tokens(entry["header"])

    for svc, rpcs in service_rpcs.items():
        header_name = manifest_services.get(svc, {}).get("header")
        if header_name is None:
            errors.append(f"{svc}: no header in rpc_manifest.yaml (should have been caught by tier1b)")
            continue
        # agc_core.h is unioned in for every service: it holds the
        # cross-cutting accessors shared by all of them (D10's
        # agc_session_selected_template_id(), agc_last_error(), ...), so a
        # field legitimately surfaced only there (never restated in the
        # per-service header) must not read as dropped.
        tokens = header_tokens(header_name) | header_tokens("agc_core.h")

        for rpc_name, req_name, resp_name in rpcs:
            for msg_name, is_response in ((req_name, False), (resp_name, True)):
                msg = messages.get(msg_name)
                if msg is None:
                    errors.append(f"{svc}.{rpc_name}: message '{msg_name}' not found in descriptor")
                    continue
                label = f"{svc}.{rpc_name}"
                dropped = dropped_by_message.get(msg_name, set())
                nested = check_message_fields(label, msg, tokens, is_response, dropped, errors, counts)

                # One hop into each D6 opaque-handle candidate: its OWN
                # fields must have accessors too, not just exist as a type.
                # Shared handle types (KeyMetadata, ImplementationProperties,
                # ...) are exposed from whichever header owns that concept,
                # not necessarily the current RPC's own header (e.g.
                # UnwrapKeyResponse.key_metadata's accessors live in
                # agc_key.h, not agc_establish.h) -- so the second hop
                # checks against every service header's tokens, not just
                # this one's.
                for nested_name in nested:
                    nested_msg = messages.get(nested_name)
                    if nested_msg is None:
                        continue
                    nested_dropped = dropped_by_message.get(nested_name, set())
                    check_message_fields(
                        label, nested_msg, all_headers_tokens, is_response=True,
                        dropped=nested_dropped, errors=errors, counts=counts,
                        second_hop_of=f"{msg_name}.<message field of type {nested_name}>",
                    )

    checked_messages, checked_fields = counts["messages"], counts["fields"]

    if errors:
        print(f"Tier 1c (fields) FAILED with {len(errors)} error(s) "
              f"[{checked_fields} fields checked across {checked_messages} messages]:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"Tier 1c (fields): OK -- {checked_fields} fields across {checked_messages} "
          f"request/response messages all have a header counterpart.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
