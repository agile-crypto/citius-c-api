#!/usr/bin/env python3
"""Reads c_encoded_vectors/*.bin, written by test_metadata_codec.c's
encode_and_export_vectors(), and decodes them with the REAL protobuf library
against the pinned descriptor. This is the other half of commit 6's
cross-implementation check: gen_metadata_vectors.py proves our DECODER
understands real protobuf bytes; this proves our ENCODER produces bytes a
real protobuf implementation understands.

Must run in the same working directory the C test wrote c_encoded_vectors/
into -- CTest gives every test registered from the same CMakeLists.txt the
same default working directory, so this just needs to run after
test_metadata_codec (enforced by set_tests_properties DEPENDS in
tests/CMakeLists.txt).
"""
import sys
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

ROOT = Path(__file__).resolve().parent.parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"
VECTORS_DIR = Path("c_encoded_vectors")


def build_operation_metadata_class():
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(DESCRIPTOR.read_bytes())
    pool = descriptor_pool.DescriptorPool()
    added = set()

    def add_file(fd):
        if fd.name in added:
            return
        for dep in fd.dependency:
            dep_fd = next((f for f in fds.file if f.name == dep), None)
            if dep_fd is not None:
                add_file(dep_fd)
        pool.Add(fd)
        added.add(fd.name)

    for f in fds.file:
        add_file(f)

    md = pool.FindMessageTypeByName("caas.crypto.v1.OperationMetadata")
    return message_factory.GetMessageClass(md)


def main():
    OperationMetadata = build_operation_metadata_class()
    failures = []

    def check_file(name, checker):
        path = VECTORS_DIR / f"{name}.bin"
        if not path.exists():
            failures.append(f"{path} does not exist -- did test_metadata_codec run first?")
            return
        m = OperationMetadata()
        try:
            m.ParseFromString(path.read_bytes())
        except Exception as e:  # noqa: BLE001
            failures.append(f"{path}: real protobuf failed to parse C-encoded bytes: {e}")
            return
        checker(m)

    def check_aead(m):
        if m.key_version != 9:
            failures.append(f"c_aead: key_version = {m.key_version}, expected 9")
        if m.provider_output.WhichOneof("algorithm_output") != "aead_output":
            failures.append("c_aead: algorithm_output oneof is not aead_output")
        expected_nonce = bytes([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0xFF, 0xEE])
        if m.provider_output.aead_output.nonce != expected_nonce:
            failures.append(f"c_aead: nonce = {m.provider_output.aead_output.nonce.hex()}, "
                             f"expected {expected_nonce.hex()}")
        if m.provider_output.aead_output.tag_length_bytes != 16:
            failures.append("c_aead: tag_length_bytes != 16")
        if m.provider_output.encoding != "raw":
            failures.append(f"c_aead: encoding = {m.provider_output.encoding!r}, expected 'raw'")
        if m.api_version != "1.0":
            failures.append(f"c_aead: api_version = {m.api_version!r}, expected '1.0'")
        if dict(m.user_context) != {"purpose": "test"}:
            failures.append(f"c_aead: user_context = {dict(m.user_context)}, expected purpose=test")

    def check_no_output(m):
        if m.provider_output.WhichOneof("algorithm_output") != "no_output":
            failures.append("c_no_output: algorithm_output oneof is not no_output")
        if m.api_version != "1.0":
            failures.append(f"c_no_output: api_version = {m.api_version!r}, expected '1.0'")

    def check_vendor(m):
        if m.key_version != 5:
            failures.append(f"c_vendor: key_version = {m.key_version}, expected 5")
        if m.provider_output.WhichOneof("algorithm_output") != "vendor_output":
            failures.append("c_vendor: algorithm_output oneof is not vendor_output")
        params = dict(m.provider_output.vendor_output.parameters)
        if params != {"note": b"hi"}:
            failures.append(f"c_vendor: parameters = {params}, expected note=b'hi'")

    check_file("c_aead", check_aead)
    check_file("c_no_output", check_no_output)
    check_file("c_vendor", check_vendor)

    if failures:
        print(f"VERIFY C-ENCODED METADATA: FAIL ({len(failures)} issue(s))", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("VERIFY C-ENCODED METADATA: PASS (3 vectors, decoded by real protobuf, match expected values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
