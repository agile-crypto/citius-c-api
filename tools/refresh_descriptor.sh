#!/usr/bin/env bash
# Regenerates conformance/api_descriptor.binpb from a proto checkout.
#
# This is intentionally NOT run by the build. Bumping the pinned descriptor is
# a deliberate commit (see conformance/DESCRIPTOR_PROVENANCE.md) — running it
# silently as part of `cmake --build` would let the C API drift out from under
# a proto change without anyone noticing until conformance broke.
#
# Usage: tools/refresh_descriptor.sh /path/to/proto
#
# The proto directory is either
#   - the `proto/` directory of a `citius/api` checkout, whose files sit at its
#     top level (messages/, services/, types/, api.proto), or
#   - the `proto/` directory of a citius-server checkout, whose files sit
#     under api/.
# The descriptor always names the files api/...: tools/gen_agc_types.py and
# the conformance checks select the public surface by that prefix. For the
# citius/api layout the files are copied under api/ and their imports of each
# other rewritten to match; nothing else changes.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/proto" >&2
    exit 1
fi

PROTO_DIR="$(cd "$1" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${HERE}/conformance/api_descriptor.binpb"

if [[ ! -f "${PROTO_DIR}/buf.yaml" ]]; then
    echo "error: ${PROTO_DIR} has no buf.yaml; pass the proto/ directory" >&2
    exit 1
fi

command -v buf >/dev/null || { echo "error: buf is required (https://buf.build)" >&2; exit 1; }

if [[ -d "${PROTO_DIR}/api" ]]; then
    ( cd "${PROTO_DIR}" && buf build --path api -o "${OUT}" )
elif [[ -f "${PROTO_DIR}/api.proto" ]]; then
    WORK="$(mktemp -d)"
    trap 'rm -rf "${WORK}"' EXIT
    mkdir -p "${WORK}/api"
    cp "${PROTO_DIR}/buf.yaml" "${PROTO_DIR}/buf.lock" "${WORK}/"
    cp -R "${PROTO_DIR}/api.proto" "${PROTO_DIR}/messages" "${PROTO_DIR}/services" "${PROTO_DIR}/types" "${WORK}/api/"
    find "${WORK}/api" -name '*.proto' -exec sed -i.bak -E \
        -e 's#^import "(messages|types|services)/#import "api/\1/#' \
        -e 's#^import "api\.proto"#import "api/api.proto"#' {} +
    find "${WORK}/api" -name '*.bak' -delete
    ( cd "${WORK}" && buf build --path api -o "${OUT}" )
else
    echo "error: ${PROTO_DIR} has neither api/ nor api.proto" >&2
    exit 1
fi

echo "wrote ${OUT}"
shasum -a 256 "${OUT}"
echo
echo "Source commit: $(cd "${PROTO_DIR}" && git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "Source tag:    $(cd "${PROTO_DIR}" && git describe --tags --exact-match 2>/dev/null || echo none)"
echo "Update conformance/DESCRIPTOR_PROVENANCE.md with the values above before committing."
