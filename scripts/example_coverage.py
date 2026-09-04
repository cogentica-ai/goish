#!/usr/bin/env python3
"""Ported packages that no example exercises.

The project's method is to diff behaviour against a running Go, and the
examples are where that lives. A package with real size and no example
is a package nobody has ever compared to Go — which is where the
defects in this tree have consistently been.

Coverage is decided by IMPORTS, not by counting how often a name
appears. An example that writes

    use goish::net::dnsmessage as dm;

mentions `net::dnsmessage` exactly once and then says `dm` five hundred
times. Counting occurrences reads that as almost-uncovered and sends
you to rewrite a smoke that already exists — which is precisely the
mistake this script is written to stop.

Also treated as coverage: an example whose FILE NAME starts with the
package's leaf (`tar_sparse_ref_smoke.rs` covers `archive/tar`), since
that is the naming convention here.
"""

import argparse
import os
import re
import sys

SRC = "src"
EXAMPLES = "examples"

# Packages with no Go counterpart to diff against.
SKIP_PREFIXES = ("runtime/sched", "runtime/symbolize", "goish", "lazy")


def package_dirs():
    for root, _, files in os.walk(SRC):
        if not any(f.endswith(".rs") for f in files):
            continue
        rel = os.path.relpath(root, SRC)
        if rel == ".":
            continue
        if any(rel.startswith(p) for p in SKIP_PREFIXES):
            continue
        loc = 0
        for f in files:
            if f.endswith(".rs"):
                with open(os.path.join(root, f), errors="replace") as fh:
                    loc += sum(1 for _ in fh)
        yield rel, loc


def example_imports():
    """{example: set(package paths it imports)}"""
    out = {}
    use_re = re.compile(r"use\s+goish::([A-Za-z0-9_:]+)")
    brace_re = re.compile(r"use\s+goish::([A-Za-z0-9_:]*?)\{([^}]*)\}")
    for name in sorted(os.listdir(EXAMPLES)):
        if not name.endswith(".rs"):
            continue
        text = open(os.path.join(EXAMPLES, name), errors="replace").read()
        pkgs = set()
        for m in use_re.finditer(text):
            parts = m.group(1).split("::")
            for i in range(1, len(parts) + 1):
                pkgs.add("/".join(parts[:i]))
        for m in brace_re.finditer(text):
            prefix = m.group(1).strip(":").replace("::", "/")
            for item in m.group(2).split(","):
                item = item.strip().split(" as ")[0].strip()
                if not item:
                    continue
                pkgs.add(("%s/%s" % (prefix, item)).strip("/"))
        out[name[:-3]] = pkgs
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-loc", type=int, default=200,
                    help="only report packages at least this large")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    imports = example_imports()
    covered = set()
    for pkgs in imports.values():
        covered |= pkgs

    uncovered = []
    for pkg, loc in sorted(package_dirs()):
        if loc < args.min_loc:
            continue
        if pkg in covered:
            continue
        leaf = pkg.split("/")[-1]
        # the naming convention: <leaf>_..._smoke.rs covers <pkg>
        if any(ex == leaf or ex.startswith(leaf + "_") for ex in imports):
            continue
        uncovered.append((loc, pkg))

    uncovered.sort(reverse=True)
    print("example_coverage: %d package(s) >= %d lines with no example import"
          % (len(uncovered), args.min_loc))
    for loc, pkg in uncovered:
        print("  %6d  %s" % (loc, pkg))
    if not uncovered:
        print("  OK — every package of that size is imported by some example.")
    return 1 if args.strict and uncovered else 0


if __name__ == "__main__":
    sys.exit(main())
