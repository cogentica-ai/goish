#!/usr/bin/env python3
"""Triage aid for the one defect class the lint tier cannot see.

GOISH018 compares signatures, arity and struct fields. It never reads
the statements inside a function, so a port that forgot to emit an
extension passes every tier-2 check. Two shipped that way:
`encryptedExtensionsMsg.marshal` dropped three extensions and
`serverHelloMsg.marshal` dropped six, both under valid anchors.

This compares the call multiset of each anchored goish function against
its Go source and reports calls Go makes more often. It depends on
anchor ranges being correct - run scripts/anchor_check.py first, or the
output is noise about the wrong function entirely.

**This is triage, not a gate.** The general mode has a high false
positive rate, all from legitimate differences:

  - goish extracts a helper Go inlines twice
    (Conn.verifyServerCertificate -> verifyChainAgainstRoots)
  - goish binds a Go func value to a local first
    (`suite.cipher(...)` -> `let cipherFn = ...; cipherFn(...)`)
  - a Rust operator replaces a Go call (bytes.Equal -> ==,
    slices.Clone -> derive(Clone))
  - a documented deviation (no weak pointers, no RWMutex, no QUIC)
  - goish merges two identical Go switch arms

  --emit  restricts the comparison to cryptobyte builder/parser calls.
          Those have no operator or helper equivalent, so a deficit is
          nearly always either a dropped field or an obvious refactor.
          This is the mode worth running routinely.
"""
import os, re, sys, collections

GOROOT = os.environ.get("GOROOT") or \
    "/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src"
ANCHOR = re.compile(r"//\s*go:\s*sdk\s+\S+\s+(\S+):(\d+)-(\d+)\s+(\S+)")
CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
EMIT = re.compile(r"^(AddUint\d+|AddBytes|AddUint\d+LengthPrefixed|addBytesWithLength|"
                  r"ReadUint\d+|ReadBytes|ReadUint\d+LengthPrefixed|readUint\d+LengthPrefixed|"
                  r"Skip|Empty|CopyBytes)$")

IGNORE = {
    "clone","unwrap","to_vec","len","Len","from_vec","__from_vec","into","new",
    "as_slice","as_bytes","is_empty","iter","collect","Some","None","Box","push",
    "extend_from_slice","from_static","from_bytes","String","Vec","format","vec",
    "map","unwrap_or","as_ref","as_mut","expect","min","max","cmp","default",
    "Default","with_capacity","resize","to_string","downcast_ref","is","filter",
    "take","and_then","unwrap_or_default","get","into_vec","__into_vec","slice",
    "copy_from_slice","enumerate","zip","rev","Clone","Equal","make","append",
    "cap","copy","string","byte","int","uint16","uint8","uint32","uint64",
    "int32","int64","bool","panic","recover","print","println","func","range",
    "delete","clear",
}

_cache = {}


def go_src(g):
    if g not in _cache:
        fp = os.path.join(GOROOT, g)
        _cache[g] = open(fp, errors="replace").read().split("\n") \
            if os.path.exists(fp) else None
    return _cache[g]


def strip_comments(text):
    out = []
    for l in text.split("\n"):
        if l.lstrip().startswith("//"):
            continue
        out.append(re.sub(r"//.*$", "", l))
    return "\n".join(out)


def calls(text, emit_only):
    c = collections.Counter()
    for m in CALL.finditer(text):
        n = m.group(1)
        if emit_only:
            if EMIT.match(n):
                c[n] += 1
        elif n not in IGNORE:
            c[n] += 1
    return c


def rs_body(lines, i):
    while i < len(lines) and not re.search(r"\bfn\s+[A-Za-z_]", lines[i]):
        i += 1
        if i > len(lines):
            return None
    if i >= len(lines):
        return None
    depth, started, buf = 0, False, []
    while i < len(lines):
        buf.append(lines[i])
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth <= 0:
            break
        i += 1
    return "\n".join(buf)


def main():
    emit_only = "--emit" in sys.argv
    roots = [a for a in sys.argv[1:] if not a.startswith("--")] or ["src/crypto"]
    found, checked = [], 0
    for root in roots:
        for dp, _, names in os.walk(root):
            for n in sorted(names):
                if not n.endswith(".rs"):
                    continue
                p = os.path.join(dp, n)
                lines = open(p, errors="replace").read().split("\n")
                for i, l in enumerate(lines):
                    m = ANCHOR.search(l)
                    if not m:
                        continue
                    g, a, b, sym = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
                    src = go_src(g)
                    if src is None:
                        continue
                    rb = rs_body(lines, i + 1)
                    if rb is None:
                        continue
                    checked += 1
                    gc = calls(strip_comments("\n".join(src[a - 1:b])), emit_only)
                    if not gc:
                        continue
                    rc = calls(strip_comments(rb), emit_only)
                    miss = {k: (v, rc.get(k, 0)) for k, v in gc.items() if rc.get(k, 0) < v}
                    if miss:
                        found.append((sum(v - h for v, h in miss.values()),
                                      sym, g, a, b, p, miss))
    found.sort(key=lambda x: -x[0])
    mode = "emit/parse calls only" if emit_only else "all calls"
    print(f"port_bodydiff ({mode}): {checked} anchored fns, {len(found)} with a deficit\n")
    for sc, sym, g, a, b, p, miss in found[:30]:
        items = ", ".join(f"{k} {h}/{v}" for k, (v, h) in
                          sorted(miss.items(), key=lambda x: -(x[1][0] - x[1][1]))[:6])
        print(f"-{sc:<3d} {sym:<46s} {g}:{a}-{b}")
        print(f"      {p}")
        print(f"      {items}")
    if found:
        print("\nTriage each by hand - see the module docstring for the "
              "legitimate differences this cannot tell from a real drop.")
    return 0


sys.exit(main())
