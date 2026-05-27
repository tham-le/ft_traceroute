#!/usr/bin/env bash

# Run ft_traceroute and traceroute with the same args and compare structural output.
# RTT values are masked (they always differ); hop IPs and star patterns are compared.
#
# Usage: sudo ./compare.sh [traceroute options] HOST
#
# Exit codes:
#   0  outputs match
#   1  outputs differ
#   2  usage error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FT="$SCRIPT_DIR/ft_traceroute"

if [[ $# -eq 0 ]]; then
    echo "usage: sudo $0 [traceroute options] HOST" >&2
    exit 2
fi

if [[ ! -x "$FT" ]]; then
    echo "error: $FT not found or not executable, run 'make' first" >&2
    exit 2
fi

# Normalise a traceroute output line for structural comparison.
#
# Rules:
#   - RTT values (e.g. "1.234 ms") replaced with "X ms"
#   - Consecutive whitespace collapsed to single space
#   - Trailing whitespace stripped
normalise_rtts() {
    sed -E 's/[0-9]+\.[0-9]+ ms/X ms/g' \
    | sed -E 's/[[:space:]]+/ /g' \
    | sed -E 's/[[:space:]]+$//'
}

# Strip hostnames from hop lines, keeping only IPs and structure.
# " 1  hostname (1.2.3.4)  X ms ..."  ->  " 1  (1.2.3.4)  X ms ..."
# " 1  1.2.3.4  X ms ..."             ->  " 1  1.2.3.4  X ms ..."  (unchanged)
# " 1  * * *"                         ->  " 1  * * *"              (unchanged)
strip_hostnames() {
    sed -E 's/^( *[0-9]+ +)[^ (]+ \(([^)]+)\)/\1(\2)/'
}

run_and_normalise() {
    local out
    out=$("$@" 2>&1) || true
    # strip_hostnames must run before normalise_rtts collapses the double space
    echo "$out" | strip_hostnames | normalise_rtts
}

echo "=== ft_traceroute $* ==="
FT_OUT=$(run_and_normalise "$FT" "$@")
echo "$FT_OUT"

echo ""
echo "=== traceroute -I $* ==="
SYS_OUT=$(run_and_normalise traceroute -I "$@")
echo "$SYS_OUT"

echo ""
echo "=== diff (ft_traceroute vs traceroute -I) ==="

DIFF=$(diff \
    <(echo "$FT_OUT") \
    <(echo "$SYS_OUT") \
    --label "ft_traceroute" \
    --label "traceroute -I" \
    -u) || true

if [[ -z "$DIFF" ]]; then
    echo "outputs match"
    exit 0
else
    echo "$DIFF"
    exit 1
fi
