#!/usr/bin/env python3
"""Tier 1c -- oneof tag conformance (RECONCILIATION_PLAN.md §2.5, §4).

Some C tagged unions use the proto FIELD NUMBER of each oneof arm as the tag
value (agc_scope_kind, agc_custom_params_kind, and more added in later
commits). That mapping is hand-transcribed into the C headers because oneofs
have no EnumDescriptorProto of their own -- there is nothing for
tools/gen_agc_types.py to generate it from. This script is the check that
transcription is still correct, by reading the real field numbers out of the
pinned descriptor and comparing them against a REGISTRY of (C enumerator ->
proto field name) pairs maintained alongside each header that needs one.

Extend TAG_REGISTRY every time a new field-number-derived union is added.
Unions that use an INDEPENDENT (non-field-number) tag, such as
agc_encrypt_params_kind, are explicitly NOT registered here -- see the header
comment in agc_params.h for why those five are different in kind.
"""
import re
import sys
from pathlib import Path

from google.protobuf import descriptor_pb2

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"

# Each entry: (header file, proto file, message name, {C enumerator suffix: proto field name})
# AGC_<PREFIX>_NONE / _UNSPECIFIED-style sentinels with no field-name mapping
# are omitted; they are required-oneof-unset markers, not field numbers.
TAG_REGISTRY = [
    (
        "agc_scope.h",
        "api/types/common.proto",
        "ScopeSpecification",
        {
            "AGC_SCOPE_KIND_SIGNATURE": "signature",
            "AGC_SCOPE_KIND_AEAD": "aead",
            "AGC_SCOPE_KIND_MAC": "mac",
            "AGC_SCOPE_KIND_KEM": "kem",
            "AGC_SCOPE_KIND_KEY_AGREEMENT": "key_agreement",
            "AGC_SCOPE_KIND_KDF": "kdf",
            "AGC_SCOPE_KIND_HASH": "hash",
            "AGC_SCOPE_KIND_KEY_WRAPPING": "key_wrapping",
            "AGC_SCOPE_KIND_SYMMETRIC_CIPHER": "symmetric_cipher",
            "AGC_SCOPE_KIND_GENERIC_SECRET": "generic_secret",
            "AGC_SCOPE_KIND_DISK_ENCRYPTION": "disk_encryption",
            "AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION": "asymmetric_encryption",
        },
    ),
    (
        "agc_params.h",
        "api/types/operation_params.proto",
        "CustomOperationParams",
        {
            "AGC_CUSTOM_PARAMS_GENERIC": "generic_params",
            "AGC_CUSTOM_PARAMS_TYPED": "typed_params",
        },
    ),
    (
        "agc_core.h",
        "api/messages/metadata.proto",
        "ProviderOutput",
        {
            "AGC_ALGORITHM_OUTPUT_NO_OUTPUT": "no_output",
            "AGC_ALGORITHM_OUTPUT_AEAD": "aead_output",
            "AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER": "block_cipher_output",
            "AGC_ALGORITHM_OUTPUT_COUNTER_MODE": "counter_mode_output",
            "AGC_ALGORITHM_OUTPUT_STREAM_CIPHER": "stream_cipher_output",
            "AGC_ALGORITHM_OUTPUT_KDF": "kdf_output",
            "AGC_ALGORITHM_OUTPUT_VENDOR": "vendor_output",
        },
    ),
    (
        "agc_key_types.h",
        "api/messages/key_management.proto",
        "MigrateKeyRequest",
        {
            "AGC_MIGRATE_TARGET_INSTANCE": "target_instance_id",
            "AGC_MIGRATE_TARGET_PROVIDER": "provider_target",
        },
    ),
    (
        "agc_key_types.h",
        "api/messages/key_management.proto",
        "ValidateKeyOperationRequest",
        {
            "AGC_VALIDATE_INTENT_TRANSFORM": "transform",
            "AGC_VALIDATE_INTENT_MIGRATE": "migrate",
        },
    ),
    (
        "agc_key_types.h",
        "api/messages/key_management.proto",
        "ValidateMigrateIntent",
        {
            "AGC_VALIDATE_MIGRATE_TARGET_INSTANCE": "target_instance_id",
            "AGC_VALIDATE_MIGRATE_TARGET_PROVIDER": "target_provider_id",
        },
    ),
]


def load_message(fds, file_name, message_name):
    f = next(x for x in fds.file if x.name == file_name)
    return next(m for m in f.message_type if m.name == message_name)


def field_numbers_by_name(msg):
    return {f.name: f.number for f in msg.field}


def extract_c_enum_values(header_path):
    text = header_path.read_text()
    values = {}
    for m in re.finditer(r"AGC_(\w+)\s*=\s*(-?\d+)", text):
        values["AGC_" + m.group(1)] = int(m.group(2))
    return values


def main():
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())

    failures = []
    checked = 0

    for header_file, proto_file, message_name, mapping in TAG_REGISTRY:
        msg = load_message(fds, proto_file, message_name)
        field_numbers = field_numbers_by_name(msg)
        c_values = extract_c_enum_values(ROOT / "include" / "agc" / header_file)

        for c_name, proto_field in mapping.items():
            checked += 1
            if proto_field not in field_numbers:
                failures.append(
                    f"{header_file}: {c_name} claims proto field '{proto_field}' on "
                    f"{message_name}, which does not exist"
                )
                continue
            if c_name not in c_values:
                failures.append(f"{header_file}: {c_name} not found as a C enumerator")
                continue
            expected = field_numbers[proto_field]
            actual = c_values[c_name]
            if actual != expected:
                failures.append(
                    f"{header_file}: {c_name} = {actual}, but {message_name}.{proto_field} "
                    f"is field {expected}"
                )

    if failures:
        print(f"TIER 1C ONEOF TAGS: FAIL ({len(failures)} issue(s))", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"TIER 1C ONEOF TAGS: PASS ({checked} tag(s) across {len(TAG_REGISTRY)} oneof(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
