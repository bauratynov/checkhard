#!/usr/bin/env bash
#
# integration.sh — end-to-end audit of fixture binaries.
#
# Builds them if necessary, then asserts the JSON verdict for each.
# Gated by toolchain availability: we only run the strict-vs-minimal
# assertions when cc is present (CI always has one).

set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -x ../checkhard ]]; then
    (cd .. && make)
fi

if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "no C compiler available — skipping integration"
    exit 0
fi

if ! ls fixtures/bin_* >/dev/null 2>&1; then
    (cd fixtures && ./build.sh)
fi

CHECKHARD=../checkhard
fails=0

say_pass() { echo "  [ok]   $*"; }
say_fail() { echo "  [FAIL] $*"; fails=$((fails + 1)); }

audit() {
    local bin=$1
    "$CHECKHARD" --json "$bin" 2>/dev/null || true
}

expect_json() {
    local bin=$1
    local key=$2
    local want=$3
    local got
    got=$(audit "$bin" | tr ',' '\n' | grep -E "\"$key\"" | head -1)
    if [[ "$got" == *"\"$key\":$want"* ]] || [[ "$got" == *"\"$key\":\"$want\""* ]]; then
        say_pass "$(basename "$bin"): $key = $want"
    else
        say_fail "$(basename "$bin"): $key expected $want, got: $got"
    fi
}

echo "minimal binary (expect weak)"
expect_json fixtures/bin_minimal pie     "no"
expect_json fixtures/bin_minimal canary  false

echo
echo "strict binary (expect hardened)"
expect_json fixtures/bin_strict  pie     "yes (PIE)"
expect_json fixtures/bin_strict  canary  true
expect_json fixtures/bin_strict  relro   "full"

echo
echo "partial-RELRO binary"
expect_json fixtures/bin_partial_relro relro "partial"

echo
echo "binary with RPATH"
got=$(audit fixtures/bin_with_rpath)
if [[ "$got" == *'"runpath":"/opt/weird/libs"'* ]] || \
   [[ "$got" == *'"rpath":"/opt/weird/libs"'* ]]; then
    say_pass "bin_with_rpath: RPATH/RUNPATH recorded"
else
    say_fail "bin_with_rpath: RPATH/RUNPATH not found in JSON: $got"
fi

# Exit-code contract: strict must pass policy (0), minimal must fail (1).
if ../checkhard fixtures/bin_strict >/dev/null; then
    say_pass "bin_strict: exit 0"
else
    say_fail "bin_strict: expected exit 0, got $?"
fi

set +e
../checkhard fixtures/bin_minimal >/dev/null
rc=$?
set -e
if [[ "$rc" == "1" ]]; then
    say_pass "bin_minimal: exit 1"
else
    say_fail "bin_minimal: expected exit 1, got $rc"
fi

echo
if [[ $fails -eq 0 ]]; then
    echo "integration tests passed"
else
    echo "integration: $fails failure(s)"
    exit 1
fi
