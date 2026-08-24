#!/usr/bin/env bash
# Regenerates conformance/api_descriptor.binpb from a citius-server checkout.
#
# This is intentionally NOT run by the build. Bumping the pinned descriptor is
# a deliberate commit (see conformance/DESCRIPTOR_PROVENANCE.md) — running it
# silently as part of `cmake --build` would let the C API drift out from under
# a proto change without anyone noticing until conformance broke.
#
# Usage: tools/refresh_descriptor.sh /path/to/citius-server/proto
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/citius-server/proto" >&2
    exit 1
fi

PROTO_DIR="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${HERE}/conformance/api_descriptor.binpb"

if [[ ! -f "${PROTO_DIR}/buf.yaml" ]]; then
    echo "error: ${PROTO_DIR} does not look like the citius-server proto/ directory (no buf.yaml)" >&2
    exit 1
fi

command -v buf >/dev/null || { echo "error: buf is required (https://buf.build)" >&2; exit 1; }

( cd "${PROTO_DIR}" && buf build --path api -o "${OUT}" )

echo "wrote ${OUT}"
sha256sum "${OUT}"
echo
echo "Source commit: $(cd "${PROTO_DIR}" && git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "Update conformance/DESCRIPTOR_PROVENANCE.md with the values above before committing."
