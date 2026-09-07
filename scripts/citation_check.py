#!/usr/bin/env python3
"""citation_check — validate the PROSE citations in goish comments.

`anchor_check.py` validates `// go: sdk <file>:<a>-<b> <Symbol>` anchors.
It does not look at the other kind of provenance this tree carries: the
prose citation inside a `// go: none` block or a doc comment, naming
where in Go a thing lives. Those rot in silence, and when one is the
STATED REASON for not anchoring, a wrong one hides real work.

Two checks, both deliberately narrow — a citation may legitimately point
INSIDE a function, so "the range does not start at a declaration" is not
an error here:

  UNRESOLVED     the cited .go file does not exist, even after
                 resolving a bare name against the .rs's own package.
  SYMBOL ABSENT  the comment names a symbol in backticks and then cites
                 a range, and the symbol does not appear in it (nor in
                 the doc comment directly above it). This is the one
                 that finds drift: Go moves, the comment does not.

Exit status is 0 unless --strict is given, because the remaining hits
need judgement — `var`, `go` and `Count` are words as well as symbols.

    scripts/citation_check.py [--strict] [src]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from port_coverage import RELOCATED  # noqa: E402  (one table, not two)

GOSRC = os.environ.get("GOROOT_SRC", "/usr/local/go/src")
# A citation is a range (`x.go:12-20`, `x.go lines 12-20`) OR a single
# line (`x.go:189`, `x.go line 189`). The single-line form was missed by
# the first version of this script, and the first thing the fix found
# was `Cmd.Process` cited to exec.go:189 — a line inside Dir's doc
# comment, three fields above the real one.
CITE = re.compile(
    r'([a-z0-9_][a-z0-9_/]*\.go)(?::|\s+lines?\s+|\s+line\s+)(\d+)(?:-(\d+))?')
TICK = re.compile(r'`([A-Za-z_][A-Za-z0-9_.]*)`')
_lines = {}


def golines(path):
    if path not in _lines:
        _lines[path] = open(path, errors="replace").read().split("\n")
    return _lines[path]


_suffix = None


def _index():
    """Every .go under GOROOT/src, indexed by path suffix. A citation
    names a file the way a reader would — `jsonwire/decode.go`,
    `builder.go` — not by import path, so the resolver has to search."""
    global _suffix
    if _suffix is not None:
        return _suffix
    _suffix = {}
    for dirpath, _, files in os.walk(GOSRC):
        for f in files:
            if not f.endswith(".go"):
                continue
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, GOSRC)
            parts = rel.split(os.sep)
            for i in range(len(parts)):
                _suffix.setdefault("/".join(parts[i:]), []).append(full)
    return _suffix


def resolve(g, rspath):
    """A citation may name an import path, a path fragment, or a bare
    file in the .rs's own package. Returns (path, note) where a note
    explains an unresolved or ambiguous result."""
    g = g[4:] if g.startswith("src/") else g   # some cite `src/time/format.go`
    p = os.path.join(GOSRC, g)
    if os.path.exists(p):
        return p, None
    d = os.path.dirname(rspath)
    d = d[4:] if d.startswith("src/") else d
    if "/" not in g:
        for cand in (os.path.join(GOSRC, d, g),
                     os.path.join(GOSRC, os.path.dirname(d), g)):
            if os.path.exists(cand):
                return cand, None
    hits = _index().get(g, [])
    if len(hits) == 1:
        return hits[0], None
    if len(hits) > 1:
        # prefer a hit in, or nearest to, the .rs's own package
        near = [h for h in hits if os.path.relpath(h, GOSRC).startswith(d + "/")]
        if len(near) == 1:
            return near[0], None
        # port_coverage's RELOCATED maps a Go package that goish files
        # elsewhere (vendored x/crypto, mostly) onto the goish path.
        # Reusing it rather than keeping a second copy: two tables of
        # the same facts drift, and this one is already maintained.
        for gopkg, goishpkg in RELOCATED.items():
            if d == goishpkg or d.startswith(goishpkg + "/"):
                cand = os.path.join(GOSRC, gopkg, os.path.basename(g))
                if os.path.exists(cand):
                    return cand, None
        return None, "ambiguous: %d files match" % len(hits)
    return None, "no such Go file"


def blocks(path):
    """Each contiguous run of // lines, with its starting line number."""
    L = open(path, errors="replace").read().split("\n")
    i = 0
    while i < len(L):
        if L[i].strip().startswith("//"):
            j = i
            while j < len(L) and L[j].strip().startswith("//"):
                j += 1
            yield i + 1, L[i:j]
            i = j
        else:
            i += 1


def main(argv):
    strict = "--strict" in argv
    roots = [a for a in argv[1:] if not a.startswith("-")] or ["src"]
    unresolved, absent, total = [], [], 0
    for root in roots:
        for dirpath, _, files in os.walk(root):
            for f in sorted(files):
                if not f.endswith(".rs"):
                    continue
                rs = os.path.join(dirpath, f)
                for start, blk in blocks(rs):
                    # real anchors belong to anchor_check.py
                    if any(l.strip().startswith("// go: sdk") for l in blk):
                        continue
                    text = " ".join(l.strip().lstrip("/").strip() for l in blk)
                    for m in CITE.finditer(text):
                        g, a = m.group(1), int(m.group(2))
                        b = int(m.group(3)) if m.group(3) else a
                        total += 1
                        p, note = resolve(g, rs)
                        if p is None:
                            unresolved.append((rs, start, g, a, b, note))
                            continue
                        L = golines(p)
                        if a < 1 or a > b or b > len(L):
                            absent.append((rs, start, g, a, b,
                                           "range outside a %d-line file" % len(L)))
                            continue
                        syms = [t.group(1) for t in TICK.finditer(text[:m.start()])]
                        if not syms:
                            continue
                        sym = syms[-1].split(".")[-1]
                        if not re.match(r'^[A-Za-z_]\w*$', sym):
                            continue
                        pat = r'\b%s\b' % re.escape(sym)
                        if re.search(pat, "\n".join(L[a - 1:b])):
                            continue
                        j, up = a - 2, []
                        while j >= 0 and L[j].strip().startswith("//"):
                            up.append(L[j])
                            j -= 1
                        if re.search(pat, "\n".join(up)):
                            continue
                        absent.append((rs, start, g, a, b,
                                       "`%s` is not in those lines" % sym))
    print("citation_check: %d prose citation(s); %d unresolved, %d symbol-absent"
          % (total, len(unresolved), len(absent)))
    for title, rows in (("UNRESOLVED", unresolved), ("SYMBOL ABSENT", absent)):
        if rows:
            print("\n=== %s (%d)" % (title, len(rows)))
            for r in rows:
                print("%s:%d  %s:%d-%d  %s" % r)
    if strict and (unresolved or absent):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
