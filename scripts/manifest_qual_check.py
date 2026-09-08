#!/usr/bin/env python3
"""manifest_qual_check.py - a `decls:` manifest must name Go declarations
receiver-qualified when Go declares them as methods.

A file manifest is a provenance claim:

    // go: file container/list/list.go decls: List.Init, New, lazyInit, ...

`lazyInit` there is under-qualified. Go declares it `func (l *List)
lazyInit()`, so the declaration's name is `List.lazyInit`, and the bare
spelling costs two concrete things:

  * IDENTITY. Go's encoding/binary declares `Uint16` on both bigEndian
    and littleEndian. A manifest saying `Uint16` names neither of them,
    so the provenance claim - this port came from that declaration -
    cannot be checked or even read. Eleven entries in binary.rs and
    multi.rs were ambiguous in exactly this way.

  * COVERAGE. port_coverage.py --by-decl keys declarations as
    `Recv.Method` and credits a manifest entry that matches. A bare name
    matches nothing, so a ported, anchored declaration reads MISSING.
    132 did. container/list read 19/23 with all 23 ported, and io read
    85/98 with 87 ported.

The second failure has a nastier variant than a false MISSING. Matching
is case-insensitive, so Go's unexported `List.remove` was quietly
credited to goish's public `List.Remove` - a DIFFERENT declaration.
That one did not read as missing, so nothing pointed at it. A bare
lowercase name whose type also has an exported twin is the shape to
watch.

Reports, never fails on ambiguity it cannot resolve: when Go declares
the same method name on several types, this script cannot know which
one a bare entry meant, and says so rather than guessing.
"""
import os
import re
import subprocess
import sys

FILE_DECLS = re.compile(r"//\s*go:\s*file\s+(\S+\.go)\s+decls:\s*([^\n]+)")
# A receiver group is optional: `func (l *List) f` vs `func f`.
FUNC = re.compile(r"^func\s+(?:\((\w+\s+)?\*?(\w+)\)\s+)?(\w+)", re.M)


def goroot():
    r = os.environ.get("GOROOT")
    if r:
        return r
    out = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True)
    return out.stdout.strip()


def go_decls(path):
    """`name -> {receiver types}` for methods, plus the set of free funcs."""
    src = open(path, encoding="utf8", errors="replace").read()
    meth, free = {}, set()
    for _, recv, name in FUNC.findall(src):
        if recv:
            meth.setdefault(name, set()).add(recv)
        else:
            free.add(name)
    return meth, free


def main():
    root = goroot()
    scope = sys.argv[1] if len(sys.argv) > 1 else "src"
    bad, ambiguous, dup, manifests = [], [], [], 0
    for base, _, files in os.walk(scope):
        for f in sorted(files):
            if not f.endswith(".rs"):
                continue
            p = os.path.join(base, f)
            src = open(p, encoding="utf8", errors="replace").read()
            for gof, lst in FILE_DECLS.findall(src):
                manifests += 1
                gp = os.path.join(root, "src", gof)
                if not os.path.exists(gp):
                    continue
                meth, free = go_decls(gp)
                seen = []
                for raw in lst.split(","):
                    t = raw.strip()
                    if not t:
                        continue
                    if t in seen:
                        dup.append((p, gof, t))
                    seen.append(t)
                    if "." in t or "(" in t:
                        continue
                    # A name Go declares BOTH ways stays bare: the free
                    # function is a real declaration with that exact name.
                    if t in meth and t not in free:
                        rs = sorted(meth[t])
                        if len(rs) == 1:
                            bad.append((p, gof, t, f"{rs[0]}.{t}"))
                        else:
                            ambiguous.append((p, gof, t, "|".join(rs)))

    for p, gof, t, want in bad:
        print(f"UNQUALIFIED {p} [{gof}] {t} -> {want}")
    for p, gof, t, rs in ambiguous:
        print(f"AMBIGUOUS   {p} [{gof}] {t} -> one of {rs}")
    for p, gof, t in dup:
        print(f"DUPLICATE   {p} [{gof}] {t}")

    print(f"manifest_qual_check: {manifests} manifests under {scope}")
    if not bad and not ambiguous and not dup:
        print("  OK - every manifest entry names its Go declaration exactly")
        return 0
    print(f"  UNQUALIFIED {len(bad)}   AMBIGUOUS {len(ambiguous)}   "
          f"DUPLICATE {len(dup)}")
    return 1 if bad or dup else 0


if __name__ == "__main__":
    sys.exit(main())
