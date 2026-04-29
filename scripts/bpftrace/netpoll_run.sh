#!/usr/bin/env bash
# netpoll_run.sh — run a goish binary under netpoll_leak.bt and emit
# a single coalesced report when the binary exits.
#
# Usage: scripts/bpftrace/netpoll_run.sh <binary> [binary args...]
#
# Requires: bpftrace + sudo (for uprobe attach). Without sudo the
# uprobe attach fails silently and you see zero counts — that's the
# tell.

set -eu

if [ $# -lt 1 ]; then
        echo "usage: $0 <binary> [args...]" >&2
        exit 2
fi

BIN="$1"
shift

if [ ! -x "$BIN" ]; then
        echo "error: $BIN is not executable" >&2
        exit 1
fi

# Resolve to absolute path so bpftrace's uprobe path-match works
# regardless of cwd.
BIN="$(readlink -f "$BIN")"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Background bpftrace, give it a moment to attach uprobes, then run.
TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

sudo bpftrace "$SCRIPT_DIR/netpoll_leak.bt" "$BIN" >"$TMP_OUT" 2>&1 &
BT_PID=$!

# Give bpftrace ~300ms to finish attaching uprobes.
sleep 0.3

# Run the target. Don't kill bpftrace if the binary returns nonzero.
"$BIN" "$@" || true

# Drain — bpftrace's END runs on SIGINT.
sudo kill -INT "$BT_PID" 2>/dev/null || true
wait "$BT_PID" 2>/dev/null || true

cat "$TMP_OUT"
