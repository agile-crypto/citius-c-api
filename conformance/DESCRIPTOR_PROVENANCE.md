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
| Source repo | `agile-crypto/api` |
| Source tag | `v0.3.0` (the release citius-api-go v0.3.0, used by citius-core and citius-server) |
| Source commit | `2eb364a69b5a7ba41d3770af35248f452930a787` |
| Source path | `proto/` (files at its top level; recorded under `api/`, see below) |
| `shasum -a 256 api_descriptor.binpb` | `fd3978a909eafaa86e2e99d6ea1b32cd0addfb139eb8451cab6a54076df1c27c` |
| Pinned on | 2026-11-04 |

`agile-crypto/api` keeps its files at the top of `proto/`, while citius-server
kept them under `api/`. The descriptor names them `api/...` either way, as
`tools/gen_agc_types.py` and the conformance checks expect:
`tools/refresh_descriptor.sh` copies the files under `api/` and rewrites
their imports of each other. The messages are those of the tag, unchanged.

The previous pin was citius-server `476f9dd` (2026-08-24), one release
behind: v0.3.0 adds the digest-hash fields, and v0.2.0 before it about 218
other breaking changes.

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
