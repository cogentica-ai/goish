#!/bin/bash
# Stress runner forcing single CPU via taskset.
set -u
BIN="$1"
RUNS="$2"
LOG="$3"
TIMEOUT_S=10
PASS=0; FAIL=0; HANG=0
: > "$LOG"
for i in $(seq 1 "$RUNS"); do
  out=$(timeout "${TIMEOUT_S}s" taskset -c 0 "$BIN" 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then PASS=$((PASS+1))
  elif [ $rc -eq 124 ]; then HANG=$((HANG+1)); echo "RUN${i}: HANG" >> "$LOG"
  else FAIL=$((FAIL+1)); echo "RUN${i}: rc=$rc out=$out" >> "$LOG"
  fi
done
echo "DONE pass=$PASS fail=$FAIL hang=$HANG of $RUNS" >> "$LOG"
