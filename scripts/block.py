#!/usr/bin/env python3
"""Review one translated block against the Go source its anchor cites.

    scripts/block.py ls   src/net/http/transfer.rs [--draft-only]
    scripts/block.py diff src/net/http/transfer.rs newTransferWriter

`ls` lists every anchored block in a goish file: its symbol, where it
lives in the Rust file, the Go range it claims, whether it is still a
goishc draft, and how many `TODO(goishc)` holes it carries. That is the
review queue.

`diff` prints one block's Go source beside the goish translation, which
is the unit of review: a draft is promoted by reading these two side by
side, fixing what the transpiler could not express, and deleting the
`// go: draft` line.

Why this is not a goishc subcommand: both operations need the extent of
a *Rust* block, and goishc has no Rust parser. anchor_check.py already
carries that machinery — and has been wrong about it three separate
ways. The most expensive was `string("{")` in server.rs, where a brace
inside a string literal left the depth counter permanently open and hid
122 declarations from coverage. Reimplementing brace matching in Go
would re-earn those bugs; importing it means both tools are wrong or
right together, and a fix lands once.

The Go side is authoritative. When an anchor's range and its symbol
disagree, run scripts/anchor_check.py — it verifies the range names
exactly the declaration it claims, and can repair the range in place.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anchor_check import (  # noqa: E402
    ANCHOR, GOROOT, go_src, strip_literals,
)

DRAFT = re.compile(r"^\s*//\s*go:\s*draft\b")
HOLE = re.compile(r"TODO\(goishc\)")


def rust_block(lines, idx):
    """(first_code_line, last_line) of the item anchored at `idx`, 0-indexed.

    Walks past the comment/attribute block the anchor heads, then brace
    matches to the item's close. Literals are stripped first: a brace
    inside a string is not a brace.
    """
    i = idx
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("//") or s.startswith("#[") or s == "":
            i += 1
            continue
        break
    if i >= len(lines):
        return idx, idx
    start, depth, seen = i, 0, False
    while i < len(lines):
        code = strip_literals(lines[i])
        depth += code.count("{") - code.count("}")
        if "{" in code:
            seen = True
        # A bodyless declaration (`pub fn f(&self) -> int;` in a trait)
        # never opens a brace and ends on its own line.
        if not seen and code.rstrip().endswith(";"):
            return start, i
        if seen and depth <= 0:
            return start, i
        i += 1
    return start, len(lines) - 1


def blocks(path):
    """Every anchored block in a goish file, in source order."""
    lines = open(path, errors="replace").read().split("\n")
    out = []
    for idx, line in enumerate(lines):
        m = ANCHOR.search(line)
        if not m:
            continue
        gofile, a, b, sym = m.group(2), int(m.group(3)), int(m.group(4)), m.group(6)
        draft = idx + 1 < len(lines) and bool(DRAFT.match(lines[idx + 1]))
        start, end = rust_block(lines, idx)
        body = "\n".join(lines[start:end + 1])
        out.append({
            "sym": sym, "gofile": gofile, "ga": a, "gb": b,
            "draft": draft, "anchor_line": idx + 1,
            "rs_start": start + 1, "rs_end": end + 1,
            "holes": len(HOLE.findall(body)),
            "body": body,
        })
    return out


def cmd_ls(path, argv):
    bs = blocks(path)
    if "--draft-only" in argv:
        bs = [b for b in bs if b["draft"]]
    if not bs:
        print(f"{path}: no anchored blocks" +
              (" still in draft" if "--draft-only" in argv else ""))
        return 0
    print(f"{'st':2} {'holes':>5} {'rust':>11}  {'go':>11}  symbol")
    for b in bs:
        st = "D" if b["draft"] else "."
        print(f"{st:2} {b['holes']:5} "
              f"{b['rs_start']:5}-{b['rs_end']:<5} "
              f"{b['ga']:5}-{b['gb']:<5}  {b['sym']}")
    nd = sum(1 for b in bs if b["draft"])
    nh = sum(b["holes"] for b in bs)
    print(f"\n{len(bs)} block(s); {nd} draft; {nh} hole(s). "
          f"Go source: {bs[0]['gofile']}")
    return 0


def cmd_diff(path, sym):
    bs = [b for b in blocks(path) if b["sym"] == sym
          or b["sym"].split(".")[-1] == sym]
    if not bs:
        print(f"block.py: no anchored block named {sym!r} in {path}",
              file=sys.stderr)
        return 2
    for b in bs:
        src = go_src(b["gofile"])
        if src is None:
            print(f"block.py: Go source not found: "
                  f"{os.path.join(GOROOT, 'src', b['gofile'])}", file=sys.stderr)
            return 2
        go = "\n".join(src[b["ga"] - 1:b["gb"]])
        head = f"{b['sym']}  —  {'DRAFT' if b['draft'] else 'verified'}"
        if b["holes"]:
            head += f", {b['holes']} hole(s)"
        print("=" * 72)
        print(head)
        print("=" * 72)
        print(f"--- Go: {b['gofile']}:{b['ga']}-{b['gb']}")
        print(go)
        print(f"\n--- goish: {path}:{b['rs_start']}-{b['rs_end']}")
        print(b["body"])
    return 0


def main():
    argv = sys.argv[1:]
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, path = argv[0], argv[1]
    if not os.path.exists(path):
        sys.exit(f"block.py: no such file: {path}")
    if cmd == "ls":
        return cmd_ls(path, argv[2:])
    if cmd == "diff":
        if len(argv) < 3:
            sys.exit("block.py: diff needs a symbol")
        return cmd_diff(path, argv[2])
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
