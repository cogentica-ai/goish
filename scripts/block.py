#!/usr/bin/env python3
"""Review one translated block against the Go source its anchor cites.

    scripts/block.py ls      src/net/http/fs.rs.draft [--draft-only]
    scripts/block.py diff    src/net/http/fs.rs.draft scanETag
    scripts/block.py promote src/net/http/fs.rs.draft scanETag [more...]

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


# A `::`-qualified reference, keeping the segment before the final name:
# `crate::strings::Contains` -> module `strings`, symbol `Contains`.
PATH = re.compile(r"((?:[A-Za-z_]\w*::)+)([A-Za-z_]\w*)")
# Paths that name Rust or the crate spine rather than a goish module.
NOT_A_MODULE = {"crate", "self", "Self", "super"}
# A path rooted at one of these is Rust's, not goish's, and its
# interior segments must not be read as goish modules:
# `alloc::sync::Arc` is valid, and judging it on the `sync`
# segment reported nine of fs.go's blocks as blocked on a symbol
# that was never missing.
RUST_ROOT = {"alloc", "core", "std"}


def missing_deps(body, idx):
    """goish modules the block calls into for names they do not export.

    Reports ONLY when the module is known and the name is absent from
    it. An unknown module, or one carrying a glob re-export, yields
    nothing — the question is "does this reference definitely not
    resolve?", and a maybe is worth less than silence here.
    """
    out = set()
    for prefix, sym in PATH.findall(body):
        segs = prefix.rstrip(":").split("::")
        if segs[0] in RUST_ROOT:
            continue
        mod = segs[-1]
        if mod in NOT_A_MODULE or mod[:1].isupper():
            continue
        e = idx.get(mod)
        if not e or e["open"]:
            continue
        # `string::from_rune` is an associated function on the type
        # `string`, not a lookup in a module called string. goish types
        # are lowercase, so only the type set can tell them apart.
        if any(mod in v["types"] for v in idx.values()):
            continue
        if sym not in e["names"]:
            out.add(f"{mod}::{sym}")
    return out


USE_LINE = re.compile(r"^\s*use\s+(?:goish|crate)::([^;]+);", re.M)


def add_imports(dst, body, draft_lines):
    """Carry the `use` lines a promoted block needs into the live file.

    A draft is a standalone crate with its own import header; the file
    it is promoted into has a different one. Every symbol the block
    names is known to exist (that is what `deps` checks) but is not
    necessarily in scope, and the gap shows up as a wall of "cannot
    find" errors that look like missing API and are not: promoting
    three of fs.go's blocks produced twelve, every one of them
    `delete`, `textproto` or `len` — all present in goish, none
    imported here.

    Only imports the block actually references are added, so the live
    file does not accumulate the draft's whole header.
    """
    draft_hdr = "\n".join(draft_lines[:60])
    want = {}
    for spec in USE_LINE.findall(draft_hdr):
        spec = spec.strip()
        if spec.startswith("{"):
            for n in re.findall(r"[A-Za-z_]\w*", spec):
                want[n] = f"use crate::{n};"
        else:
            want[spec.split("::")[-1].strip()] = f"use crate::{spec};"
    named = set(re.findall(r"[A-Za-z_]\w*", body))
    have = set(re.findall(r"[A-Za-z_]\w*", "\n".join(
        l for l in dst.split("\n") if l.strip().startswith("use "))))
    add = [line for name, line in sorted(want.items())
           if name in named and name not in have]
    if not add:
        return dst
    out = dst.split("\n")
    last = max((i for i, l in enumerate(out) if l.startswith("use ")), default=-1)
    if last < 0:
        return "\n".join(add) + "\n" + dst
    out[last + 1:last + 1] = add
    return "\n".join(out)


def cmd_deps(path, argv):
    """Per block, what it references that goish does not export."""
    from goish_api import build, index_by_leaf
    idx = index_by_leaf(build())
    bs = blocks(path)
    ready, blocked = [], []
    for b in bs:
        miss = missing_deps(b["body"], idx)
        (blocked if miss else ready).append((b, sorted(miss)))
    if "--ready" in argv:
        for b, _ in ready:
            print(b["sym"])
        print(f"\n{len(ready)} of {len(bs)} block(s) reference nothing missing.")
        return 0
    for b, miss in blocked:
        print(f"{b['sym']}")
        for m in miss:
            print(f"    needs  {m}")
    print(f"\n{len(ready)} ready, {len(blocked)} blocked, {len(bs)} total.")
    print("Promote the ready ones first: "
          f"scripts/block.py promote {path} $(scripts/block.py deps {path} --ready | head -n -2)")
    return 0


def cmd_promote(path, syms):
    """Move blocks out of `<stem>.rs.draft` and into `<stem>.rs`.

    This is the only step that changes what compiles. The block leaves
    the draft, loses its `// go: draft` line, and lands in the live file
    keeping its anchor — so the moment it builds, coverage counts it.

    Nothing here tries to make it compile. That is the reviewer's job
    and the whole point: the compiler is what proves the translation
    integrates, and it can only speak once the code is in the build.
    """
    if not path.endswith(".rs.draft"):
        sys.exit("block.py: promote takes a .rs.draft file")
    live = path[:-len(".rs.draft")] + ".rs"
    if not os.path.exists(live):
        sys.exit(f"block.py: no live file to promote into: {live}")

    lines = open(path, errors="replace").read().split("\n")
    bs = blocks(path)
    want = []
    for s in syms:
        hit = [b for b in bs if b["sym"] == s or b["sym"].split(".")[-1] == s]
        if not hit:
            sys.exit(f"block.py: no block named {s!r} in {path}")
        want.extend(hit)

    # Cut from the bottom up so earlier spans keep their indices. Each
    # block spans its anchor comment through the item's closing brace.
    moved, cut = [], sorted(want, key=lambda b: -b["anchor_line"])
    for b in cut:
        top = b["anchor_line"] - 1
        # goishc writes a draft as a standalone crate that USES goish, so
        # every runtime path reads `goish::`. Inside the goish crate the
        # same path is `crate::`. Promotion is the moment the code
        # crosses that boundary, so it is the right place to rewrite —
        # doing it in the draft would leave a file that is neither valid
        # standalone nor valid in place.
        body = [l.replace("goish::", "crate::")
                for l in lines[top:b["rs_end"]] if not DRAFT.match(l)]
        moved.append((b["sym"], "\n".join(body)))
        del lines[top:b["rs_end"]]

    dst = open(live, errors="replace").read()
    dst = add_imports(dst, "\n".join(b for _, b in moved), lines)
    dst = dst.rstrip("\n")
    for sym, body in reversed(moved):
        dst += "\n\n" + body
    open(live, "w").write(dst + "\n")
    open(path, "w").write("\n".join(lines))

    for sym, _ in reversed(moved):
        print(f"promoted {sym}  ->  {live}")
    left = len(blocks(path))
    print(f"{left} block(s) left in {path}")
    if left == 0:
        print(f"  draft is empty — delete it: git rm {path}")
    print("Now make it compile: cargo check --lib")
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
    if cmd == "deps":
        return cmd_deps(path, argv[2:])
    if cmd == "promote":
        if len(argv) < 3:
            sys.exit("block.py: promote needs at least one symbol")
        return cmd_promote(path, argv[2:])
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
