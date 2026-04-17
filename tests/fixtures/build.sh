#!/usr/bin/env bash
#
# build.sh — compile test binaries with various hardening flag combos.
# Generates into tests/fixtures/bin_* that integration.sh then audits.

set -euo pipefail

cd "$(dirname "$0")"

CC=${CC:-cc}
SRC=hello.c

# 1. Minimum hardening: no PIE, no canary, no FORTIFY, no RELRO, exec stack.
$CC -O0 -fno-PIE -no-pie -fno-stack-protector \
    -U_FORTIFY_SOURCE \
    -Wl,-z,norelro -Wl,-z,execstack \
    "$SRC" -o bin_minimal

# 2. Strict hardening: PIE, canary, FORTIFY, full RELRO, NX.
$CC -O2 -fPIE -pie \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro -Wl,-z,now \
    "$SRC" -o bin_strict

# 3. Partial RELRO only (no -z,now).
$CC -O2 -fPIE -pie \
    -fstack-protector-strong \
    -U_FORTIFY_SOURCE \
    -Wl,-z,relro \
    "$SRC" -o bin_partial_relro

# 4. RPATH set (audit-worthy even if otherwise hardened).
$CC -O2 -fPIE -pie \
    -fstack-protector-strong \
    -Wl,-z,relro,-z,now \
    -Wl,-rpath=/opt/weird/libs \
    "$SRC" -o bin_with_rpath

echo "fixtures built:"
ls -1 bin_* 2>/dev/null
