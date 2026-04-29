#!/usr/bin/env bash
# spawn_million.sh — drive the spawn_million example and sample its
# memory from a separate process via /proc.
#
# Runs the (release-built) binary in the background, captures its PID
# from the first stdout line ("goish PID: NNN"), then polls
# /proc/<pid>/status every second emitting VmRSS / VmSize until the
# child exits.

set -euo pipefail

BIN="${1:-./target/x86_64-unknown-linux-gnu/release/examples/spawn_million}"
if [[ ! -x "$BIN" ]]; then
    echo "spawn_million.sh: binary not found at $BIN"
    echo "  build with:  cargo build --target x86_64-unknown-linux-gnu --release --example spawn_million"
    exit 2
fi

LOG="$(mktemp -t spawn_million.XXXXXX)"
trap 'rm -f "$LOG"' EXIT

# Launch in background, redirecting stdout to LOG so we can tail it
# while also reading its first line for PID extraction.
"$BIN" > "$LOG" 2>&1 &
GOISH_PID=$!
echo "[driver] launched goish (host pid=$GOISH_PID), logging to $LOG"

# Wait briefly for the program to print its first line.
for _ in {1..50}; do
    if [[ -s "$LOG" ]]; then break; fi
    sleep 0.1
done

# Pull the inner PID for completeness; we use the host pid for /proc.
INNER_PID=$(grep -m1 'goish PID' "$LOG" | awk '{print $3}' || true)
echo "[driver] inner pid (Getpid in goish): ${INNER_PID:-?}"

# Sampler loop: poll /proc/<host pid>/status while the process is alive.
SAMPLE_FILE=/proc/$GOISH_PID/status
echo "[driver] sampling memory every 1s while $GOISH_PID is alive"
echo "ts  vmsize_kb  vmrss_kb  vmpeak_kb  vmhwm_kb  threads"
START=$(date +%s)
while kill -0 "$GOISH_PID" 2>/dev/null; do
    if [[ -r "$SAMPLE_FILE" ]]; then
        ts=$(($(date +%s) - START))
        vmsize=$(grep -m1 '^VmSize:' "$SAMPLE_FILE" | awk '{print $2}' || echo 0)
        vmrss=$(grep -m1 '^VmRSS:' "$SAMPLE_FILE" | awk '{print $2}' || echo 0)
        vmpeak=$(grep -m1 '^VmPeak:' "$SAMPLE_FILE" | awk '{print $2}' || echo 0)
        vmhwm=$(grep -m1 '^VmHWM:' "$SAMPLE_FILE" | awk '{print $2}' || echo 0)
        threads=$(grep -m1 '^Threads:' "$SAMPLE_FILE" | awk '{print $2}' || echo 0)
        printf "%3ds  %10s  %10s  %10s  %10s  %4s\n" \
            "$ts" "$vmsize" "$vmrss" "$vmpeak" "$vmhwm" "$threads"
    fi
    sleep 1
done

wait "$GOISH_PID"
RC=$?
echo
echo "[driver] goish exited with code $RC"
echo "[driver] goish stdout/stderr (tail):"
tail -40 "$LOG"
exit "$RC"
