#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tier 4 -- ABI stability (docs/history/RECONCILIATION_PLAN.md §7): a layout change to an
# EXISTING field must fail this check unless it comes with a version-script
# entry and a rationale. Uses libabigail's abidw/abidiff, the same tool
# real C library releases (glibc, systemd, ...) gate on.
#
# Usage:
# The headers define the ABI, but only a built library has one: point
# AGC_ABI_LIB at an implementation's shared library (citius-rust:
# target/release/libagilecrypto.so). Without it the check skips.
#
#   tier4_abi_baseline.sh baseline   -- (re)generate conformance/abi-baseline.xml
#                                        from the library at $AGC_ABI_LIB.
#                                        Run this deliberately, once per accepted
#                                        ABI change, never automatically.
#   tier4_abi_baseline.sh check      -- abidiff the current build against the
#                                        stored baseline. Exit 0 if identical
#                                        (or no baseline exists yet -- see NOTE),
#                                        exit 1 on any difference.
#
# NOTE: this reconciliation has not shipped a 1.0 release yet, so there is
# no prior ABI to diff against -- D7's struct_size/AGC_INIT/append-only-enum
# discipline is what keeps 1.0 itself extendable later. `check` with no
# baseline present exits 0 with a message, not a failure: there is nothing
# to have diverged from yet. Once 1.0 ships, `baseline` must be run once and
# the result committed, and CI's `check` becomes a real gate from then on.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${AGC_ABI_LIB:-}"
BASELINE="$ROOT/conformance/abi-baseline.xml"
MODE="${1:-check}"

if ! command -v abidw >/dev/null 2>&1; then
    echo "tier4_abi: abidw (libabigail) not installed -- skipping (not a failure)." >&2
    echo "Install libabigail to make this a real gate: https://sourceware.org/libabigail/" >&2
    exit 0
fi

if [ -z "$LIB" ]; then
    echo "tier4_abi: AGC_ABI_LIB not set (path to an implementation's libagilecrypto) -- skipping." >&2
    exit 0
fi
if [ ! -f "$LIB" ]; then
    echo "tier4_abi: $LIB not found." >&2
    exit 1
fi

case "$MODE" in
    baseline)
        abidw --headers-dir "$ROOT/include/agc" "$LIB" > "$BASELINE"
        echo "tier4_abi: wrote $BASELINE from $LIB"
        ;;
    check)
        if [ ! -f "$BASELINE" ]; then
            echo "tier4_abi: no baseline yet (pre-1.0, see script header) -- skipping." >&2
            exit 0
        fi
        abidw --headers-dir "$ROOT/include/agc" "$LIB" > /tmp/agc-abi-current.xml
        if abidiff "$BASELINE" /tmp/agc-abi-current.xml; then
            echo "tier4_abi: OK -- no ABI change since baseline."
        else
            echo "tier4_abi: ABI CHANGED. If this is deliberate: add a version-script" >&2
            echo "entry, a rationale in the commit message, then re-run with 'baseline'." >&2
            exit 1
        fi
        ;;
    *)
        echo "usage: $0 {baseline|check}" >&2
        exit 2
        ;;
esac
