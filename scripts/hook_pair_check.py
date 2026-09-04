#!/usr/bin/env python3
"""Types registered for an interface that cannot be reached through one.

goish resolves `x.(Iface)` through a registry keyed on the concrete
type. Reaching it needs the concrete impl to expose an `Any` view, and
there are TWO hooks — `__goish_as_dyn_any` for a `&dyn` carrier and
`__goish_as_dyn_any_mut` for a `&mut dyn` one. Both default to `None`,
so a missing override is not an error: the assertion just misses, and
the caller silently takes its fallback path.

That is what kept `io::Copy` from ever taking Go's `src.(WriterTo)`
fast path. `strings::Reader` implements `WriterTo` and IS registered
for it, and the assertion still missed, because its `io::Reader` impl
overrode neither hook. The tree had 162 immutable overrides and almost
no mutable ones, so every `cast!(&mut …)` in it was dead.

Two checks:

  MUT_MISSING   an impl overrides `__goish_as_dyn_any` but not
                `__goish_as_dyn_any_mut`. Cheap to fix and always
                safe — the pair should travel together.

  UNREACHABLE   a type implements a fast-path interface (WriterTo,
                ReaderFrom) but no impl block for it overrides the
                mutable hook, so `io::Copy` cannot find it.

Exit status is 0 unless --strict is given and something is reported.
"""

import argparse
import os
import re
import sys

SRC = "src"
FAST_PATH = ("WriterTo", "ReaderFrom")

IMPL = re.compile(r"^impl(?:<[^>]*>)?\s+(?:[\w:]+::)?(\w+)\s+for\s+([\w:]+)")


def blocks(path):
    """(trait, type, body) for each top-level impl block in the file."""
    lines = open(path, errors="replace").read().split("\n")
    i = 0
    while i < len(lines):
        m = IMPL.match(lines[i])
        if not m:
            i += 1
            continue
        depth = 0
        started = False
        body = []
        j = i
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            body.append(lines[j])
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield m.group(1), m.group(2).split("::")[-1], "\n".join(body), i + 1
        i = j + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="list every MUT_MISSING finding, not the first few")
    args = ap.parse_args()

    mut_missing = []
    has_mut = {}          # type -> True if any impl block overrides the mut hook
    implements_fast = {}  # type -> [trait, ...]

    for root, _, names in os.walk(SRC):
        for n in names:
            if not n.endswith(".rs"):
                continue
            p = os.path.join(root, n)
            for trait, ty, body, ln in blocks(p):
                imm = "fn __goish_as_dyn_any(" in body
                mut = "fn __goish_as_dyn_any_mut(" in body
                if mut:
                    has_mut[ty] = True
                if imm and not mut:
                    mut_missing.append((p, ln, ty, trait))
                if trait in FAST_PATH:
                    implements_fast.setdefault(ty, []).append((trait, p))

    unreachable = []
    for ty, entries in sorted(implements_fast.items()):
        if not has_mut.get(ty):
            trait, p = entries[0]
            unreachable.append((p, ty, trait))

    print("hook_pair_check: %d type(s) implement a fast-path interface" % len(implements_fast))

    if mut_missing:
        # A backlog, not a gate. These are latent rather than broken:
        # the immutable assertion works and only `cast!(&mut …)` misses,
        # which almost nothing does yet. Printing all 89 would make the
        # useful half of this script unreadable — the same reason
        # port_lint.py is a ratchet rather than a wall of text.
        print("\n  MUT_MISSING (%d) — overrides the Any hook but not its `&mut` twin." % len(mut_missing))
        print("      Latent: only `cast!(&mut x, Iface)` misses, and little does that yet.")
        print("      First few, `--all` for the rest:")
        for p, ln, ty, trait in (mut_missing if args.all else mut_missing[:5]):
            print("        %s:%d: `impl %s for %s`" % (p, ln, trait, ty))

    if unreachable:
        print("\n  UNREACHABLE (%d) — fast-path impl no `&mut` assertion can find:" % len(unreachable))
        for p, ty, trait in unreachable:
            print("    %s: %s implements %s, but no impl block for it" % (p, ty, trait))
            print("      overrides __goish_as_dyn_any_mut — io::Copy will miss it")

    if not mut_missing and not unreachable:
        print("  OK — every fast-path type is reachable through a `&mut` assertion.")

    # Only UNREACHABLE gates: it means a fast path Go takes and goish
    # cannot. MUT_MISSING is latent and reported for the record.
    return 1 if args.strict and unreachable else 0


if __name__ == "__main__":
    sys.exit(main())
