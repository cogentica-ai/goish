#!/usr/bin/env python3
"""spin_park_check - a SpinLock guard must not be held across a park.

`runtime::spin::SpinLock` is the runtime's non-preemptible critical
section: taking one bumps `m.locks`, and the scheduler kills the
process with `schedule: holding locks` if the G parks or yields before
the guard drops. That tripwire is exact, but it only fires on paths a
test actually walks, and the ones that matter are contended and rare.
This finds the shape statically instead.

What is NOT a finding: allocating under a spin guard. goish's allocator
runs its whole path inside `acquirem()`/`releasem()` and never parks,
so `Vec::push` or `gomap::Set` under a guard is nested spinning, not a
park. Flagging those would bury the real thing in three dozen lazy
table initialisers. What matters is a call that can SUSPEND the G:
another goroutine then resumes it on a different M, and the guard's
eventual drop decrements that M's counter instead of this one's.

Exit status is 1 if anything is found, so this can gate.

    scripts/spin_park_check.py [path ...]
"""
import os
import re
import sys

# Calls that can suspend or yield the G. `.Lock()` is `sync::Mutex`,
# whose slow path queues on a semaphore; the capital is what tells it
# apart from `.lock()`, which is the SpinLock itself and only spins.
PARKS = [
    (re.compile(r"\.Lock\(\)"), "sync::Mutex::Lock"),
    (re.compile(r"\bGosched\(\)"), "Gosched"),
    (re.compile(r"\.Wait\(\)"), "Wait"),
    (re.compile(r"\.Send\("), "chan Send"),
    (re.compile(r"\.Recv\(\)"), "chan Recv"),
    (re.compile(r"\btime::Sleep\("), "time::Sleep"),
    (re.compile(r"netpoll::block\("), "netpoll::block"),
    (re.compile(r"\bgopark\("), "gopark"),
    (re.compile(r"\bselect!"), "select!"),
]

# A guard only exists if something BINDS it. `let x = m.lock().clone();`
# drops the guard at the end of the statement, so the tail after
# `.lock()` has to be empty for the binding to be the guard itself.
GUARD = re.compile(r"^(\s*)let\s+(?:mut\s+)?(\w+)\s*=\s*[\w:.\[\]()]+\.lock\(\)\s*;\s*$")

# How far a guard can plausibly live. A critical section longer than
# this is its own problem; the cap stops one unbalanced brace from
# reporting the rest of the file.
MAX_SCOPE = 200


def indent(line):
    return len(line) - len(line.lstrip())


def scan(path):
    out = []
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    for i, ln in enumerate(lines):
        m = GUARD.match(ln)
        if not m:
            continue
        ind, var = len(m.group(1)), m.group(2)
        dropped = re.compile(r"\bdrop\(\s*%s\s*\)" % re.escape(var))
        for j in range(i + 1, min(i + MAX_SCOPE, len(lines))):
            s = lines[j].strip()
            if not s or s.startswith("//"):
                continue
            if indent(lines[j]) < ind and s.startswith("}"):
                break
            if dropped.search(s):
                break
            for pat, why in PARKS:
                if pat.search(s):
                    out.append((path, i + 1, j + 1, var, why, s[:90]))
                    break
    return out


def main(argv):
    roots = argv[1:] or ["src"]
    found = []
    for root in roots:
        if os.path.isfile(root):
            found += scan(root)
            continue
        for dirpath, _, files in os.walk(root):
            for fn in sorted(files):
                if fn.endswith(".rs"):
                    found += scan(os.path.join(dirpath, fn))

    seen = set()
    for path, gl, cl, var, why, txt in found:
        key = (path, gl, why)
        if key in seen:
            continue
        seen.add(key)
        print(f"{path}:{gl}: SpinLock guard `{var}` is still held at line {cl} ({why})")
        print(f"    {txt}")

    n = len(seen)
    if n:
        print(f"\nspin_park_check: {n} guard(s) held across a park.")
        print("  Use sync::Mutex (or drop the guard first) — a spin guard is an")
        print("  m.locks region, and parking inside one aborts the process.")
        return 1
    print("spin_park_check: OK — no SpinLock guard held across a park.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
