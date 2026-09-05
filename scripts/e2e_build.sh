#!/usr/bin/env bash
# Same declared-example names and Bash regex matching as e2e_runner.sh.
# An empty FILTER retains cargo build --examples (including auto-discovery).
set -euo pipefail
if [[ $# -eq 0 ]]; then set -- cargo; fi
if [[ -z "${FILTER:-}" ]]; then
    exec "$@" build --examples
fi
DECLARED=$(grep -E '^name = "[^\"]+"$' Cargo.toml \
    | grep -v 'name = "goish"' | sed 's/name = "//;s/"$//' | sort -u)
selected=()
while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if [[ "$name" =~ $FILTER ]]; then selected+=(--example "$name"); fi
done <<< "$DECLARED"
if [[ ${#selected[@]} -eq 0 ]]; then
    echo "e2e build: no declared examples match FILTER=$FILTER"
    exit 0
fi
exec "$@" build "${selected[@]}"
