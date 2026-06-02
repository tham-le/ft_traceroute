#!/usr/bin/env bash

# Test runner for ft_traceroute.
# Run with sudo to include all network tests.
# Without sudo, only help and argument-error tests run.
#
# Exit 0 if all executed tests pass, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FT="$SCRIPT_DIR/ft_traceroute"

PASS=0
FAIL=0
SKIP=0

# Set true when the system 'traceroute' is available for output comparison.
# When false, expect_match tests are skipped so the suite runs standalone.
HAVE_SYS_TR=false

# -----------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------
pass() { echo "[PASS] $1"; ((PASS++)); }
skip() { echo "[SKIP] $1"; ((SKIP++)); }

fail() {
    echo "[FAIL] $1"
    ((FAIL++))
}

# -----------------------------------------------------------------------
# Normalise a traceroute output stream for structural comparison.
#   1. Strip hostnames from hop lines, keeping only the IP.
#   2. Mask all RTT values ("1.234 ms" -> "X ms").
#   3. Mask the packet size in the header ("48 byte packets" -> "N byte packets").
#      This lets us compare structure without caring about default size differences.
#   4. Collapse runs of whitespace and strip trailing whitespace.
# -----------------------------------------------------------------------
normalise() {
    sed -E 's/^( *[0-9]+ +)[^ (]+ \(([^)]+)\)/\1(\2)/' \
    | sed -E 's/[0-9]+\.[0-9]+ ms/X ms/g' \
    | sed -E 's/, [0-9]+ byte packets/, N byte packets/' \
    | sed -E 's/[[:space:]]+/ /g' \
    | sed -E 's/[[:space:]]+$//'
}

# -----------------------------------------------------------------------
# Assertion helpers
# -----------------------------------------------------------------------

# ft_traceroute must exit 0.
expect_ok() {
    local desc="$1"; shift
    if "$FT" "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc (expected exit 0)"
    fi
}

# ft_traceroute must exit non-zero.
expect_err() {
    local desc="$1"; shift
    if ! "$FT" "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc (expected non-zero exit)"
    fi
}

# ft_traceroute stdout+stderr must match a grep -E pattern.
expect_output() {
    local desc="$1"; local pattern="$2"; shift 2
    local out
    out=$("$FT" "$@" 2>&1) || true
    if echo "$out" | grep -qE "$pattern"; then
        pass "$desc"
    else
        fail "$desc"
        echo "    pattern : $pattern"
        echo "    actual  : $(echo "$out" | head -3)"
    fi
}

# ft_traceroute stdout+stderr must NOT match a grep -E pattern.
expect_no_output() {
    local desc="$1"; local pattern="$2"; shift 2
    local out
    out=$("$FT" "$@" 2>&1) || true
    if ! echo "$out" | grep -qE "$pattern"; then
        pass "$desc"
    else
        fail "$desc"
        echo "    pattern : $pattern"
        echo "    actual  : $(echo "$out" | head -3)"
    fi
}

# The first output line of ft_traceroute must match a grep -E pattern.
expect_header() {
    local desc="$1"; local pattern="$2"; shift 2
    local line
    line=$("$FT" "$@" 2>&1 | head -1) || true
    if echo "$line" | grep -qE "$pattern"; then
        pass "$desc"
    else
        fail "$desc"
        echo "    pattern : $pattern"
        echo "    actual  : $line"
    fi
}

# Normalised output of ft_traceroute must equal that of real traceroute -I (ICMP mode).
# Both tools use ICMP ECHO probes; this is the only fair apples-to-apples comparison.
# System traceroute defaults to UDP, which triggers different router behaviour than ICMP.
expect_match() {
    local desc="$1"; shift
    local ft_out sys_out attempt
    # Standalone mode: no reference tool, nothing to compare against.
    if [[ $HAVE_SYS_TR != true ]]; then
        skip "$desc (no system traceroute)"
        return
    fi
    # Retry: probes are occasionally dropped on loopback, so a single run of
    # either tool can show a stray "*" where the other shows an RTT. A real
    # mismatch persists across retries; a transient drop does not.
    for attempt in 1 2 3; do
        ft_out=$(  "$FT"          "$@" 2>&1 | normalise) || true
        sys_out=$(traceroute -I   "$@" 2>&1 | normalise) || true
        [[ "$ft_out" == "$sys_out" ]] && break
    done
    if [[ "$ft_out" == "$sys_out" ]]; then
        pass "$desc"
    else
        fail "$desc"
        diff \
            <(echo "$ft_out") \
            <(echo "$sys_out") \
            --label ft_traceroute --label "traceroute -I" -u \
            | head -40 || true
    fi
}

# -----------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------
if [[ ! -x "$FT" ]]; then
    echo "error: $FT not found or not executable, run 'make' first" >&2
    exit 2
fi

command -v traceroute >/dev/null 2>&1 && HAVE_SYS_TR=true

IS_ROOT=false
[[ $EUID -eq 0 ]] && IS_ROOT=true

echo "========================================="
echo " ft_traceroute test suite"
[[ $IS_ROOT == true ]] && echo " mode: full (root)" || echo " mode: no-root only"
if [[ $HAVE_SYS_TR == true ]]; then
    echo " compare: system traceroute found"
else
    echo " compare: no system traceroute (standalone, match tests skipped)"
fi
echo "========================================="
echo ""

# -----------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------
echo "--- Help ---"
expect_ok     "help: --help exits 0"          --help
expect_ok     "help: -? exits 0"              -?
expect_output "help: -p flag listed"          '\-p'    --help
expect_output "help: -l flag listed"          '\-l'    --help
expect_output "help: -f flag listed"          '\-f'    --help
expect_output "help: -m flag listed"          '\-m'    --help
expect_output "help: -q flag listed"          '\-q'    --help
expect_output "help: -N flag listed"          '\-N'    --help
expect_output "help: -n flag listed"          '\-n'    --help
expect_output "help: -t flag listed"          '\-t'    --help
expect_output "help: -s flag listed"          '\-s'    --help
expect_output "help: -i flag listed"          '\-i'    --help
expect_output "help: -w flag listed"          '\-w'    --help
echo ""

# -----------------------------------------------------------------------
# Argument errors (no root needed)
# -----------------------------------------------------------------------
echo "--- Argument errors ---"
expect_err "no host"                           # no args at all
expect_err "unknown flag -z"                   -z localhost
expect_err "-m missing argument"               -m
expect_err "-m 0 (below min 1)"                -m 0    localhost
expect_err "-m 256 (above max 255)"            -m 256  localhost
expect_err "-m abc (non-numeric)"              -m abc  localhost
expect_err "-f 0 (below min 1)"                -f 0    localhost
expect_err "-f 256 (above max 255)"            -f 256  localhost
expect_err "-q 0 (below min 1)"                -q 0    localhost
expect_err "-q 11 (above max 10)"              -q 11   localhost
expect_err "-N 0 (below min 1)"                -N 0    localhost
expect_err "-N 129 (above max 128)"            -N 129  localhost
expect_err "-t -1 (below min 0)"               -t -1   localhost
expect_err "-t 256 (above max 255)"            -t 256  localhost
expect_err "-w 0 (below min 1)"                -w 0    localhost
expect_err "-w 61 (above max 60)"              -w 61   localhost
expect_err "-p -1 (below min 0)"               -p -1   localhost
expect_err "-p 65536 (above max 65535)"        -p 65536 localhost
expect_err "-l 7 (below min 8)"                -l 7    localhost
expect_err "-l 4097 (above max 4096)"          -l 4097 localhost
expect_err "-s invalid IP"                     -s 999.999.999.999 localhost
expect_err "unresolvable host"                 -n nonexistent.invalid
echo ""

# -----------------------------------------------------------------------
# Network tests require root
# -----------------------------------------------------------------------
if ! $IS_ROOT; then
    echo "Skipping network tests (not root). Re-run with sudo to run all tests."
    echo ""
    echo "========================================="
    echo " Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP (+network)"
    echo "========================================="
    [[ $FAIL -eq 0 ]]
    exit
fi

# -----------------------------------------------------------------------
# Basic
# -----------------------------------------------------------------------
echo "--- Basic ---"
expect_header "basic: header line format"  \
    'traceroute to localhost \(127\.0\.0\.1\), 30 hops max, 48 byte packets' \
    localhost
expect_output "basic: hop 1 shows 127.0.0.1"  '^ *1 ' -n -m 1 localhost
expect_match  "basic: matches real traceroute" -n -m 3 localhost
echo ""

# -----------------------------------------------------------------------
# -n: disable DNS
# -----------------------------------------------------------------------
echo "--- -n: disable DNS ---"
expect_output    "-n absent: hostname appears"    '^ *1 +localhost '  -m 1 localhost
expect_no_output "-n set: no hostname on hop 1"  '^ *1 +localhost '  -n -m 1 localhost
expect_output    "-n set: bare IP on hop 1"       '^ *1 +127\.0\.0\.1 ' -n -m 1 localhost
echo ""

# -----------------------------------------------------------------------
# -m: max hops
# -----------------------------------------------------------------------
echo "--- -m: max hops ---"
expect_header "-m 1: header says 1 hops max"   '1 hops max'   -m 1 localhost
expect_header "-m 3: header says 3 hops max"   '3 hops max'   -m 3 localhost
expect_match  "-m 3 localhost"                  -n -m 3 localhost
expect_match  "-m 3 8.8.8.8"                   -n -m 3 8.8.8.8
echo ""

# -----------------------------------------------------------------------
# -f: first TTL
# -----------------------------------------------------------------------
echo "--- -f: first TTL ---"
expect_no_output "-f 2: hop 1 absent"       '^ *1 ' -f 2 -m 4 -n 8.8.8.8
expect_output    "-f 2: hop 2 present"      '^ *2 ' -f 2 -m 4 -n 8.8.8.8
expect_match     "-f 2 -m 5 8.8.8.8"               -f 2 -m 5 -n 8.8.8.8
echo ""

# -----------------------------------------------------------------------
# -q: probes per hop
# -----------------------------------------------------------------------
echo "--- -q: probes per hop ---"
expect_match "-q 1 localhost"  -q 1 -n localhost
expect_match "-q 5 localhost"  -q 5 -n localhost
echo ""

# -----------------------------------------------------------------------
# -N: simultaneous probes
# -----------------------------------------------------------------------
echo "--- -N: simultaneous probes ---"
expect_ok "-N 1 completes"    -N 1  -n -m 3 8.8.8.8
expect_ok "-N 32 completes"   -N 32 -n -m 3 8.8.8.8
echo ""

# -----------------------------------------------------------------------
# -w: timeout
# Structural checks only: comparing two timed-out runs is non-deterministic.
# 192.0.2.1 (RFC 5737) is never reachable, but the path to it crosses real
# routers that reply with TTL-exceeded. Stars only appear past the last
# responding router, so we check the unreachable TAIL, not fixed hop numbers.
# -N 16 probes all hops in parallel, keeping the 1s timeout to ~one window.
# -----------------------------------------------------------------------
echo "--- -w: timeout (~2s) ---"
_w_max=16
_w_out=$("$FT" -w 1 -m $_w_max -N 16 -n 192.0.2.1 2>&1) || true
_w_hops=$(echo "$_w_out" | grep -cE '^ *[0-9]+ ') || true
if [[ $_w_hops -eq $_w_max ]]; then
    pass "-w 1: produces $_w_max hop lines"
else
    fail "-w 1: expected $_w_max hop lines, got $_w_hops"
    echo "    actual:"
    echo "$_w_out" | head -20 | sed 's/^/    /'
fi
# The destination is unreachable, so the tail hops time out as * * *.
_w_star_hops=$(echo "$_w_out" | grep -cE '^ *[0-9]+ +\*[[:space:]]+\*[[:space:]]+\*') || true
if [[ $_w_star_hops -ge 1 ]]; then
    pass "-w 1: unreachable hops show stars ($_w_star_hops all-star hops)"
else
    fail "-w 1: expected at least one * * * hop, got none"
    echo "    actual:"
    echo "$_w_out" | head -20 | sed 's/^/    /'
fi
echo ""

# -----------------------------------------------------------------------
# -t: TOS byte
# -----------------------------------------------------------------------
echo "--- -t: TOS byte ---"
expect_match "-t 0   localhost"   -t 0   -n -m 2 localhost
expect_match "-t 16  localhost"   -t 16  -n -m 2 localhost
expect_match "-t 255 localhost"   -t 255 -n -m 2 localhost
echo ""

# -----------------------------------------------------------------------
# -s: source address
# -----------------------------------------------------------------------
echo "--- -s: source address ---"
expect_ok  "-s 127.0.0.1 localhost completes"  -s 127.0.0.1 -n -m 2 localhost
expect_err "-s non-local IP fails"              -s 10.255.255.254 localhost
echo ""

# -----------------------------------------------------------------------
# -i: bind to interface
# -----------------------------------------------------------------------
echo "--- -i: bind to interface ---"
expect_ok  "-i lo localhost completes"  -i lo -n -m 2 localhost
expect_err "-i eth999 fails"            -i eth999 -n localhost
echo ""

# -----------------------------------------------------------------------
# -p: base ICMP sequence
# -----------------------------------------------------------------------
echo "--- -p: base ICMP sequence ---"
expect_match "-p 0     localhost"  -p 0     -n -m 2 localhost
expect_match "-p 1000  localhost"  -p 1000  -n -m 2 localhost
expect_match "-p 65535 localhost"  -p 65535 -n -m 2 localhost
echo ""

# -----------------------------------------------------------------------
# -l: probe packet length
# -----------------------------------------------------------------------
echo "--- -l: probe packet length ---"
for size in 8 28 48 200 1472 4096; do
    expect_header "-l $size: header says $size byte packets"  \
        "$size byte packets"  -l $size -n localhost
    expect_match  "-l $size: matches real traceroute"  \
        -l $size -n localhost
done
echo ""

# -----------------------------------------------------------------------
# Combined flags
# -----------------------------------------------------------------------
echo "--- Combined flags ---"
expect_header "combined: header format"  \
    '5 hops max, 60 byte packets'  \
    -m 5 -q 2 -N 4 -f 1 -t 0 -p 100 -l 60 -n localhost
expect_match "combined flags"  -m 5 -q 2 -N 4 -f 1 -t 0 -p 100 -l 60 -n localhost
echo ""

# -----------------------------------------------------------------------
# Star display
# Structural checks only for the same timing reason as the -w section.
# -----------------------------------------------------------------------
echo "--- Star display (~2s) ---"
# Reach past the responding routers so the unreachable tail prints stars.
_s_out=$("$FT" -w 1 -m 16 -N 16 -n 192.0.2.1 2>&1) || true
# At least one hop must be all three stars.
# Raw output uses double-space between fields: "2    *  *  *"
if echo "$_s_out" | grep -qE '^ *[0-9]+[[:space:]]+\*[[:space:]]+\*[[:space:]]+\*$'; then
    pass "stars: at least one hop shows * * *"
else
    fail "stars: no hop showed * * *"
    echo "    actual:"
    echo "$_s_out" | sed 's/^/    /'
fi
# Stars must be space-separated, not concatenated (no "***" runs).
if ! echo "$_s_out" | grep -qE '\*\*'; then
    pass "stars: spacing correct (no run of **)"
else
    fail "stars: stars are not space-separated"
    echo "    actual:"
    echo "$_s_out" | sed 's/^/    /'
fi
echo ""

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo "========================================="
echo " Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "========================================="
[[ $FAIL -eq 0 ]]
