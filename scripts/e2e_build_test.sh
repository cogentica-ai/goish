#!/usr/bin/env bash
# Test argv selection without compiling. printf stands in for Cargo.
set -euo pipefail
cd "$(dirname "$0")/.."
full=$(FILTER='' bash scripts/e2e_build.sh printf '%s\n')
[[ "$full" == $'build\n--examples' ]]
single=$(FILTER='^json_v2_smoke$' bash scripts/e2e_build.sh printf '%s\n')
[[ "$single" == $'build\n--example\njson_v2_smoke' ]]
selected=$(FILTER='^(json|base64)' bash scripts/e2e_build.sh printf '%s\n')
actual=$(printf '%s\n' "$selected" | sed '/^build$/d; /^--example$/d')
# Derive expected names exactly as the existing runner does, independently
# of the new script. This pins selection without freezing the example count.
expected=$(grep -E '^name = "[^\"]+"$' Cargo.toml \
    | grep -v 'name = "goish"' | sed 's/name = "//;s/"$//' | sort -u \
    | grep -E '^(json|base64)')
[[ "$actual" == "$expected" ]]
none=$(FILTER='^does_not_exist$' bash scripts/e2e_build.sh printf '%s\n')
[[ "$none" == 'e2e build: no declared examples match FILTER=^does_not_exist$' ]]
echo 'E2E_BUILD_SELECTION_OK full, singleton, package union, and empty filters'
