#!/bin/bash
# Flag-matrix stress runner. Each row tests one flag (or combination)
# against chan_micro_select_send_only. Reports pass/fail/hang counts.
set -u
BIN=target/x86_64-unknown-linux-gnu/release/examples/chan_micro_select_send_only
RUNS="${RUNS:-100}"
TIMEOUT_S="${TIMEOUT_S:-8}"

run_with_flags() {
  local label="$1"
  local envs="$2"
  local pass=0 fail=0 hang=0
  for i in $(seq 1 "$RUNS"); do
    out=$(env $envs timeout "${TIMEOUT_S}s" "$BIN" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then pass=$((pass+1))
    elif [ $rc -eq 124 ]; then hang=$((hang+1))
    else fail=$((fail+1))
    fi
  done
  printf "%-40s pass=%3d fail=%3d hang=%3d\n" "$label" "$pass" "$fail" "$hang"
}

echo "Matrix: $RUNS runs each, ${TIMEOUT_S}s timeout"
echo "----------------------------------------------------------------"
run_with_flags "baseline (all on)"               ""
run_with_flags "RUNNEXT=0"                       "GOISH_RUNNEXT=0"
run_with_flags "STEAL_RUNNEXT=0"                 "GOISH_STEAL_RUNNEXT=0"
run_with_flags "WORK_STEALING=0"                 "GOISH_WORK_STEALING=0"
run_with_flags "COOP_PREEMPT=0"                  "GOISH_COOP_PREEMPT=0"
run_with_flags "ASYNC_PREEMPT=0"                 "GOISH_ASYNC_PREEMPT=0"
run_with_flags "RUNNEXT=0 STEAL_RUNNEXT=0"       "GOISH_RUNNEXT=0 GOISH_STEAL_RUNNEXT=0"
run_with_flags "all preempt off"                 "GOISH_COOP_PREEMPT=0 GOISH_ASYNC_PREEMPT=0"
