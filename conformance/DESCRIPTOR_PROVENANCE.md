# Pinned proto descriptor

`api_descriptor.binpb` is a compiled `FileDescriptorSet` (protobuf binary
form) covering the 35 files that make up the public `caas.crypto.v1` surface:
`api/types/*`, `api/messages/*`, `api/services/*`, `api/api.proto`, and their
`google.protobuf`, `google.api` and `buf.validate` dependencies.

It is the **pinned source of truth** for `tools/gen_agc_types.py` and for the
Tier 1 conformance checks in this directory. `citius-c-api` does not depend on
a sibling checkout of `citius-server` at build time or generate time — this
file is the whole dependency, vendored in binary form so it cannot silently
drift.

## Current pin

| | |
|---|---|
| Source repo | `citius-server` |
| Source commit | `476f9dd1ef20dedbbe7483474cc71acf41637445` |
| Source path | `proto/api/**` |
| `sha256sum api_descriptor.binpb` | `36480188a689a306992477334e6494efd7242b390efdab70a2c6156d9b309133` |
| Files | 35 (see `tools/refresh_descriptor.sh` for the exact `buf build` invocation) |
| Pinned on | 2026-08-24 |

## Bumping the pin

Regenerating this file is a **deliberate, explicit commit**, never a build-time
side effect:

```sh
tools/refresh_descriptor.sh /path/to/citius-server/proto
git diff --stat conformance/api_descriptor.binpb
# review what changed (new enum values, new RPCs, ...) before committing
```

Then re-run `tools/gen_agc_types.py` and the Tier 1 conformance suite, and
update the table above.
