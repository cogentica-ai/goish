#!/usr/bin/env bash
# e2e_runner.sh — run every declared example N times, report PASS/FAIL.
#
# LOOP TIERS (default mode, LOOPS unset): each example runs at its
# tier's loop count — the loop count is a property of what the TEST
# exercises, not of the change being validated:
#   tier 1 (TIER1=1)   functional/deterministic tests — parsers, crypto,
#                      json, unicode, http parsing … : one run proves it.
#   tier 2 (TIER2=10)  memory/allocator/runtime-introspection tests —
#                      alloc_*, mheap_*, mcentral, leak_proof …
#   tier 3 (TIER3=50)  scheduling/racing/stress tests — chan/select,
#                      preempt, sched, sync, timers, stacks, server
#                      lifecycle (shutdown/keepalive/goginx), TLS conns.
#                      50 stays 50: the historical lost-wakeup bug was
#                      ~2% — at 10 loops it hides ~80% of the time.
# Setting LOOPS=N forces every example to N (the old uniform behavior;
# `make e2e-full` uses LOOPS=50 — REQUIRED for scheduler/allocator/
# runtime-core changes, where races surface in unrelated tests).
# NEW TESTS: anything goroutine/timer/socket-lifecycle-coupled MUST be
# added to the tier-3 patterns below; unmatched names default to tier 1.
#
# Env knobs:
#   LOOPS=N          force a uniform loop count (disables tiers)
#   TIER1/2/3=N      override a tier's loop count (default 1/10/50)
#   TIMEOUT=15       per-run timeout (seconds); see example_timeout
#                    for the per-example exceptions
#   ARTIFACTS=...    where to save failure logs (default scripts/.e2e-artifacts)
#   FILTER=regex     only run examples whose name matches (default: all)
#   EXCLUDE=regex    skip examples matching this pattern
#                    (default: long-running / interactive — see below)
#   TARGET_DIR=...   cargo target dir (default target/x86_64-unknown-linux-gnu/debug)
#
# Exit code: 0 if every iteration of every example passes; 1 otherwise.

set -u

LOOPS="${LOOPS:-}"
TIER1="${TIER1:-1}"
TIER2="${TIER2:-10}"
TIER3="${TIER3:-50}"
TIMEOUT="${TIMEOUT:-15}"

# Tier classification — ordered, first match wins; see the header.
loops_for() {
  if [[ -n "$LOOPS" ]]; then echo "$LOOPS"; return; fi
  case "$1" in
    # tier 3 — scheduling / racing / stress
    chan_*|select_*|preempt_*|sched_*|sync_*|spawn_*|stack_*|lockfree_*|lookpath_*|\
    time_sleep|time_timer|stopwatch|signal_smoke|signal_winch_smoke|sigaltstack_offline_proof|\
    context_*|cmd_stdout_pipe_test|syscall_fswatch_smoke|m20_smoke|\
    testing_parallel_smoke|testing_nested_parallel_smoke|\
    goginx|https_real_smoke|http_shutdown_smoke|http_keepalive_smoke|\
    http_stream_body_smoke|\
    http_panic_demo|production_http_server|tls_smoke|tls_server_smoke)
      echo "$TIER3" ;;
    # tier 2 — memory / allocator / runtime introspection
    alloc_*|mheap_*|mcentral_*|leak_proof|rt_section_smoke|\
    runtime_callers_smoke|temp_uniqueness_smoke)
      echo "$TIER2" ;;
    # tier 1 — functional/deterministic (the default)
    *)
      echo "$TIER1" ;;
  esac
}
# Per-example timeout override, in seconds. Defaults to $TIMEOUT.
#
# The global budget is tuned for a smoke that starts, asserts and
# exits. A few examples stand up real servers and drive them, and the
# expensive part is a DEBUG-build RSA handshake — https_server_smoke's
# own comment records that one of those can miss a 300ms budget on a
# loaded box. goginx does several, plus a full static/vhost/proxy
# self-test, and timed out once on CI while exiting in 2.3s on an idle
# machine here: measured across the commit it was blamed on, 2.29-2.34s
# before and 2.30-2.32s after, so the cause was contention, not a
# change.
#
# Raising the GLOBAL timeout would hide real hangs in the other ~840
# examples, so the exception is named rather than universal. A genuine
# hang in goginx still fails the suite, just later.
example_timeout() {
  case "$1" in
    goginx) echo 60 ;;
    *)      echo "$TIMEOUT" ;;
  esac
}

ARTIFACTS="${ARTIFACTS:-scripts/.e2e-artifacts}"
FILTER="${FILTER:-.*}"
# Default skips: HTTP servers that don't self-terminate, very-large
# stress workloads that take >TIMEOUT seconds, and tests whose
# success requires external drivers.
# https_real_smoke is back IN the set. It used to fail ~1 run in 4, but
# the cause was its hosts, not the port: two probes hit
# stefanprodan.github.io (a personal GitHub Pages site) and one hung on
# tls13.1d.pw. It now dials only raw.githubusercontent.com and
# Cloudflare, and the HRR probe is not run — 6/6 clean, ~11s.
EXCLUDE="${EXCLUDE:-^(hello_query|http_hello|https_serve|spawn_million|spawn_density|preempt_sysmon|lockfree_ring_bench|segv_diagnostic_smoke)$}"
# Tests that talk to the REAL internet: a timeout is network latency,
# not a runtime bug (the artifact still gets saved). Such a test fails
# the suite only on panic/fail or if NO iteration succeeded. This
# mechanizes the long-standing "199/200 with the https_real_smoke
# timing flake is green" convention instead of leaving it tribal.
NETWORK_FLAKY="^(https_real_smoke)$"
TARGET_DIR="${TARGET_DIR:-target/x86_64-unknown-linux-gnu/debug}"

# Per-example CLI args + stdin. Some demos parse argv (`sumargs N…`,
# `greet NAME…`, etc.) or read stdin (`json_pretty`); without these,
# they exit nonzero with a usage banner — a false positive in e2e.
# Map: example-name → "ARGS||STDIN". STDIN is sent on input if present.
example_inputs() {
  case "$1" in
    sumargs)      echo '1 2 3 4 5||' ;;
    stopwatch)    echo '50||' ;;
    greet)        echo 'world||' ;;
    bytestack)    echo ',||' ;;
    uniq_sort)    echo '3 1 4 1 5 9 2 6 5 3||' ;;
    json_pretty)  echo '||{"a":1,"b":[2,3],"c":{"d":true}}' ;;
    *)            echo '||' ;;
  esac
}

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
if [[ -n "$LOOPS" ]]; then
  echo "e2e suite — $NUM_TARGETS examples × $LOOPS loops (uniform; timeout=${TIMEOUT}s each, see example_timeout for exceptions)"
else
  echo "e2e suite — $NUM_TARGETS examples, tiered loops (functional=$TIER1 memory=$TIER2 stress=$TIER3; timeout=${TIMEOUT}s each, see example_timeout for exceptions)"
fi
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
  echo "  skipped (EXCLUDE): ${SKIPPED[*]}"
fi
echo

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_TIMEOUT=0
TOTAL_PANIC=0
TOTAL_ITERS=0
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
  loops=$(loops_for "$name")
  first_log="$ARTIFACTS/$name.first_failure.log"

  inp=$(example_inputs "$name")
  ex_args="${inp%%||*}"
  ex_stdin="${inp#*||}"
  ex_timeout=$(example_timeout "$name")

  for i in $(seq 1 "$loops"); do
    if [[ -n "$ex_stdin" ]]; then
      # Stdin-driven demo (e.g. json_pretty).
      # shellcheck disable=SC2086
      out=$(printf '%s' "$ex_stdin" | timeout "$ex_timeout" "$bin" $ex_args 2>&1)
    elif [[ -n "$ex_args" ]]; then
      # Argv-driven demo.
      # shellcheck disable=SC2086
      out=$(timeout "$ex_timeout" "$bin" $ex_args 2>&1)
    else
      out=$(timeout "$ex_timeout" "$bin" 2>&1)
    fi
    rc=$?
    # rc=0 wins regardless of stdout content. Tests that intentionally
    # panic + recover (e.g. panic_recovery_smoke) print "panic" to
    # stderr and exit 0; treating them as panic-fails would be wrong.
    #
    # For rc!=0 the test below is the runtime's OWN panic banner
    # (runtime/mod.rs:809), anchored, not the bare word "panic"
    # anywhere in the output. A smoke that merely PRINTS the word —
    # defer_panic_smoke's failure line reads "panics=0" — was being
    # bucketed as a panic, so the summary said "panic: 1" for a run
    # whose only problem was a failed assertion, and the diagnosis
    # started in the wrong place.
    if [[ $rc -eq 0 ]]; then
      pass=$((pass+1))
    elif [[ $rc -eq 124 ]]; then
      tout=$((tout+1))
      if [[ ! -s "$first_log" ]]; then
        { echo "=== iter $i: TIMEOUT after ${ex_timeout}s ==="; echo "$out"; } > "$first_log"
      fi
    elif echo "$out" | grep -q '^goish: panic$'; then
      panic=$((panic+1))
      if [[ ! -s "$first_log" ]]; then
        { echo "=== iter $i: PANIC (rc=$rc) ==="; echo "$out"; } > "$first_log"
      fi
    else
      fail=$((fail+1))
      if [[ ! -s "$first_log" ]]; then
        { echo "=== iter $i: FAIL (rc=$rc) ==="; echo "$out"; } > "$first_log"
      fi
    fi
  done

  bad=$((fail+tout+panic))
  if [[ $bad -eq 0 ]]; then
    printf "  %-40s %d/%d\n" "$name" "$pass" "$loops"
  elif [[ "$name" =~ $NETWORK_FLAKY && $panic -eq 0 && $fail -eq 0 && $pass -gt 0 ]]; then
    printf "  %-40s %d/%d  (timeout=%d — network-flaky, tolerated) → %s\n" \
      "$name" "$pass" "$loops" "$tout" "$first_log"
  else
    printf "  %-40s %d/%d  (panic=%d timeout=%d fail=%d) → %s\n" \
      "$name" "$pass" "$loops" "$panic" "$tout" "$fail" "$first_log"
    FAILED_EXAMPLES+=("$name:p=$panic,t=$tout,f=$fail")
  fi

  TOTAL_PASS=$((TOTAL_PASS+pass))
  TOTAL_FAIL=$((TOTAL_FAIL+fail))
  TOTAL_TIMEOUT=$((TOTAL_TIMEOUT+tout))
  TOTAL_PANIC=$((TOTAL_PANIC+panic))
  TOTAL_ITERS=$((TOTAL_ITERS+loops))
done

ELAPSED=$(($(date +%s) - START))

echo
echo "─── e2e summary ──────────────────────────────────────────"
printf "  examples:  %d (skipped %d)\n" "$NUM_TARGETS" "${#SKIPPED[@]}"
printf "  iterations: %d total\n" "$TOTAL_ITERS"
printf "  pass:      %d\n" "$TOTAL_PASS"
printf "  panic:     %d\n" "$TOTAL_PANIC"
printf "  timeout:   %d\n" "$TOTAL_TIMEOUT"
printf "  fail:      %d\n" "$TOTAL_FAIL"
printf "  elapsed:   %ds (%dm%ds)\n" "$ELAPSED" $((ELAPSED/60)) $((ELAPSED%60))

{
  echo "e2e summary $(date -Iseconds)"
  echo "examples=$NUM_TARGETS loops=${LOOPS:-tiered($TIER1/$TIER2/$TIER3)} iterations=$TOTAL_ITERS timeout=${TIMEOUT}s"
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
