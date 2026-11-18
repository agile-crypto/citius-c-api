#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generates OperationMetadata golden vectors using the REAL protobuf
library against the pinned descriptor (conformance/api_descriptor.binpb),
never a hand-written codec.

Implementations check their metadata codec against these: decode each
vector's bytes, compare the fields, and re-encode byte for byte. citius-rust
does so in src/domain/crypto/metadata.rs
(golden_protobuf_vectors_decode_and_re_encode_byte_for_byte).

Run manually to regenerate:
    python3 conformance/golden/gen_metadata_vectors.py

Protobuf leaves the order of map entries open, and protobuf releases differ
in it: regenerating can reorder the "vendor" vector's map, which is equally
valid but no longer byte-identical to what implementations re-encode. Commit
regenerated vectors only together with the implementations' matching update.
"""
import json
import sys
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

ROOT = Path(__file__).resolve().parent.parent.parent
DESCRIPTOR = ROOT / "conformance" / "api_descriptor.binpb"
OUT_DIR = Path(__file__).resolve().parent


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
    vectors = {}

    # 1. AEAD output, the common case.
    m = OperationMetadata()
    m.key_version = 3
    m.provider_output.aead_output.nonce = bytes(range(1, 13))
    m.provider_output.aead_output.tag_length_bytes = 16
    m.provider_output.encoding = "raw"
    m.api_version = "1.0"
    m.user_context["tenant"] = "acme"
    vectors["aead"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 3,
        "output_kind": "AEAD",
        "aead_nonce_hex": bytes(range(1, 13)).hex(),
        "aead_tag_length_bytes": 16,
        "encoding": "raw",
        "api_version": "1.0",
        "user_context": {"tenant": "acme"},
    }

    # 2. NoAlgorithmOutput -- genuinely empty submessage, still a present arm.
    m = OperationMetadata()
    m.key_version = 1
    m.provider_output.no_output.SetInParent()
    m.api_version = "1.0"
    vectors["no_output"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 1,
        "output_kind": "NO_OUTPUT",
        "api_version": "1.0",
        "user_context": {},
    }

    # 3. BlockCipherOutput.
    m = OperationMetadata()
    m.key_version = 7
    m.provider_output.block_cipher_output.iv = bytes(range(16))
    vectors["block_cipher"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 7,
        "output_kind": "BLOCK_CIPHER",
        "block_iv_hex": bytes(range(16)).hex(),
        "api_version": "",
        "user_context": {},
    }

    # 4. CounterModeOutput.
    m = OperationMetadata()
    m.provider_output.counter_mode_output.counter_block = bytes(range(16))
    m.provider_output.counter_mode_output.counter_bits = 64
    vectors["counter_mode"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 0,
        "output_kind": "COUNTER_MODE",
        "counter_block_hex": bytes(range(16)).hex(),
        "counter_bits": 64,
        "api_version": "",
        "user_context": {},
    }

    # 5. StreamCipherOutput.
    m = OperationMetadata()
    m.provider_output.stream_cipher_output.nonce = b"\xAA" * 8
    m.provider_output.stream_cipher_output.block_counter = b"\x00\x00\x00\x01"
    vectors["stream_cipher"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 0,
        "output_kind": "STREAM_CIPHER",
        "stream_nonce_hex": (b"\xAA" * 8).hex(),
        "stream_block_counter_hex": b"\x00\x00\x00\x01".hex(),
        "api_version": "",
        "user_context": {},
    }

    # 6. KdfOutput.
    m = OperationMetadata()
    m.provider_output.kdf_output.salt = b"\x01" * 16
    m.provider_output.kdf_output.iv = b"\x02" * 4
    vectors["kdf"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 0,
        "output_kind": "KDF",
        "kdf_salt_hex": (b"\x01" * 16).hex(),
        "kdf_iv_hex": (b"\x02" * 4).hex(),
        "api_version": "",
        "user_context": {},
    }

    # 7. VendorOutput with a multi-entry map.
    m = OperationMetadata()
    m.provider_output.vendor_output.parameters["attestation"] = b"\xDE\xAD\xBE\xEF"
    m.provider_output.vendor_output.parameters["slot"] = b"\x00\x01"
    vectors["vendor"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 0,
        "output_kind": "VENDOR",
        "vendor_params": {"attestation": "deadbeef", "slot": "0001"},
        "api_version": "",
        "user_context": {},
    }

    # 8. Multiple user_context entries plus a non-AEAD arm, to exercise the
    #    repeated-map-entry path with more than one item.
    m = OperationMetadata()
    m.key_version = 42
    m.provider_output.no_output.SetInParent()
    m.provider_output.encoding = "der"
    m.api_version = "1.0"
    m.user_context["tenant"] = "acme"
    m.user_context["request_id"] = "abc-123"
    vectors["multi_user_context"] = {
        "bytes": m.SerializeToString().hex(),
        "key_version": 42,
        "output_kind": "NO_OUTPUT",
        "encoding": "der",
        "api_version": "1.0",
        "user_context": {"tenant": "acme", "request_id": "abc-123"},
    }

    (OUT_DIR / "operation_metadata_vectors.json").write_text(json.dumps(vectors, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(vectors)} golden vectors to {OUT_DIR / 'operation_metadata_vectors.json'}")


if __name__ == "__main__":
    sys.exit(main())
