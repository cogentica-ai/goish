#!/usr/bin/env bash
# e2e_runner.sh — run every declared example LOOPS times, report PASS/FAIL.
#
# Env knobs:
#   LOOPS=50         number of iterations per example
#   TIMEOUT=15       per-run timeout (seconds)
#   ARTIFACTS=...    where to save failure logs (default scripts/.e2e-artifacts)
#   FILTER=regex     only run examples whose name matches (default: all)
#   EXCLUDE=regex    skip examples matching this pattern
#                    (default: long-running / interactive — see below)
#   TARGET_DIR=...   cargo target dir (default target/x86_64-unknown-linux-gnu/debug)
#
# Exit code: 0 if every iteration of every example passes; 1 otherwise.

set -u

LOOPS="${LOOPS:-50}"
TIMEOUT="${TIMEOUT:-15}"
ARTIFACTS="${ARTIFACTS:-scripts/.e2e-artifacts}"
FILTER="${FILTER:-.*}"
# Default skips: HTTP servers that don't self-terminate, very-large
# stress workloads that take >TIMEOUT seconds, and tests whose
# success requires external drivers.
EXCLUDE="${EXCLUDE:-^(http_hello|spawn_million|spawn_density|preempt_sysmon)$}"
TARGET_DIR="${TARGET_DIR:-target/x86_64-unknown-linux-gnu/debug}"

EXAMPLES_DIR="$TARGET_DIR/examples"
mkdir -p "$ARTIFACTS"
rm -f "$ARTIFACTS"/*.log "$ARTIFACTS"/summary.txt

# Discover declared examples from Cargo.toml.
DECLARED=$(grep -E '^name = "[^"]+"$' Cargo.toml \
           | grep -v 'name = "goish"' \
           | sed 's/name = "//;s/"$//' \
           | sort -u)

# Apply FILTER + EXCLUDE.
TARGETS=()
SKIPPED=()
while IFS= read -r name; do
  [[ -z "$name" ]] && continue
  if ! [[ "$name" =~ $FILTER ]]; then continue; fi
  if [[ "$name" =~ $EXCLUDE ]]; then SKIPPED+=("$name"); continue; fi
  TARGETS+=("$name")
done <<< "$DECLARED"

NUM_TARGETS=${#TARGETS[@]}
echo "e2e suite — $NUM_TARGETS examples × $LOOPS loops (timeout=${TIMEOUT}s each)"
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
  echo "  skipped (EXCLUDE): ${SKIPPED[*]}"
fi
echo

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_TIMEOUT=0
TOTAL_PANIC=0
FAILED_EXAMPLES=()

START=$(date +%s)

for name in "${TARGETS[@]}"; do
  bin="$EXAMPLES_DIR/$name"
  if [[ ! -x "$bin" ]]; then
    printf "  %-40s MISSING (build failed?)\n" "$name"
    FAILED_EXAMPLES+=("$name:missing")
    continue
  fi

  pass=0; fail=0; tout=0; panic=0
  first_log="$ARTIFACTS/$name.first_failure.log"

  for i in $(seq 1 "$LOOPS"); do
    out=$(timeout "$TIMEOUT" "$bin" 2>&1)
    rc=$?
    if [[ $rc -eq 124 ]]; then
      tout=$((tout+1))
      if [[ ! -s "$first_log" ]]; then
        { echo "=== iter $i: TIMEOUT after ${TIMEOUT}s ==="; echo "$out"; } > "$first_log"
      fi
    elif echo "$out" | grep -q 'panic'; then
      panic=$((panic+1))
      if [[ ! -s "$first_log" ]]; then
        { echo "=== iter $i: PANIC (rc=$rc) ==="; echo "$out"; } > "$first_log"
      fi
    elif [[ $rc -ne 0 ]]; then
      fail=$((fail+1))
      if [[ ! -s "$first_log" ]]; then
        { echo "=== iter $i: FAIL (rc=$rc) ==="; echo "$out"; } > "$first_log"
      fi
    else
      pass=$((pass+1))
    fi
  done

  bad=$((fail+tout+panic))
  if [[ $bad -eq 0 ]]; then
    printf "  %-40s %d/%d\n" "$name" "$pass" "$LOOPS"
  else
    printf "  %-40s %d/%d  (panic=%d timeout=%d fail=%d) → %s\n" \
      "$name" "$pass" "$LOOPS" "$panic" "$tout" "$fail" "$first_log"
    FAILED_EXAMPLES+=("$name:p=$panic,t=$tout,f=$fail")
  fi

  TOTAL_PASS=$((TOTAL_PASS+pass))
  TOTAL_FAIL=$((TOTAL_FAIL+fail))
  TOTAL_TIMEOUT=$((TOTAL_TIMEOUT+tout))
  TOTAL_PANIC=$((TOTAL_PANIC+panic))
done

ELAPSED=$(($(date +%s) - START))

echo
echo "─── e2e summary ──────────────────────────────────────────"
printf "  examples:  %d (skipped %d)\n" "$NUM_TARGETS" "${#SKIPPED[@]}"
printf "  iterations: %d total\n" "$((NUM_TARGETS * LOOPS))"
printf "  pass:      %d\n" "$TOTAL_PASS"
printf "  panic:     %d\n" "$TOTAL_PANIC"
printf "  timeout:   %d\n" "$TOTAL_TIMEOUT"
printf "  fail:      %d\n" "$TOTAL_FAIL"
printf "  elapsed:   %ds (%dm%ds)\n" "$ELAPSED" $((ELAPSED/60)) $((ELAPSED%60))

{
  echo "e2e summary $(date -Iseconds)"
  echo "examples=$NUM_TARGETS loops=$LOOPS timeout=${TIMEOUT}s"
  echo "pass=$TOTAL_PASS panic=$TOTAL_PANIC timeout=$TOTAL_TIMEOUT fail=$TOTAL_FAIL elapsed=${ELAPSED}s"
  if [[ ${#FAILED_EXAMPLES[@]} -gt 0 ]]; then
    echo "failed:"
    for f in "${FAILED_EXAMPLES[@]}"; do echo "  $f"; done
  fi
} > "$ARTIFACTS/summary.txt"

if [[ ${#FAILED_EXAMPLES[@]} -gt 0 ]]; then
  echo
  echo "  failed examples (${#FAILED_EXAMPLES[@]}):"
  for f in "${FAILED_EXAMPLES[@]}"; do echo "    $f"; done
  echo
  echo "  artifacts: $ARTIFACTS/"
  exit 1
fi

echo "  all green ✓"
exit 0
