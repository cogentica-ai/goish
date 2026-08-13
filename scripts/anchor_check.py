#!/usr/bin/env python3
"""Validate every `// go: sdk <ver> <file>:<a>-<b> <Symbol>` anchor.

goishlint resolves the anchored symbol by NAME and ignores the line
range entirely, so a range can point at a different function - or at
nothing - and every tier-2 check still passes. The range is the only
pointer from goish code to the Go source it must match, and it is what a
body-level differ has to trust, so it needs its own gate.

The invariant checked is: **the range must name exactly one Go
declaration, and that declaration must be Symbol.** That admits both
conventions in the tree - starting at the `func` line, or a few lines
earlier at its doc comment - while rejecting a range that covers two
functions or none. ClientHelloInfo.SupportsCertificate was anchored
across a span holding both it and CertificateRequestInfo's same-named
method; only this rule catches that.

Checks per anchor:
  NOT_FOUND    no declaration of Symbol anywhere in that Go file
  RANGE_WRONG  the range holds no declaration of Symbol
  RANGE_FAT    the range holds Symbol plus other declarations
  END_SHORT    the range stops more than one line before the closing
               brace. One line short is the house convention (anchor
               the body, not the brace). Bodyless decls
               (//go:linkname stubs) end on their own line.
  BARE         Symbol names a method without its receiver, so it cannot
               be told apart from same-named methods on other types
               (reported by --strict only; 80% of the tree is like this)
  UNFIXABLE    --fix computed the range the anchor already had. Happens
               for a member of a grouped `var (` / `const (` block: the
               member resolves to its own line, but the BLOCK is the
               declaration, so the tight range is rejected and rewriting
               it changes nothing. Anchor the whole block instead.

Usage:
  scripts/anchor_check.py                 # check src/, exit 1 on any error
  scripts/anchor_check.py src/crypto      # check a subtree
  scripts/anchor_check.py --fix src/...   # rewrite wrong ranges in place
  scripts/anchor_check.py --strict        # also fail on BARE
"""
import os, re, sys, collections

def _goroot():
    """The directory anchors resolve against, i.e. the one holding `crypto/`.

    Anchors cite package-relative paths (`crypto/tls/conn.go`), so this
    must be Go's `src` directory - NOT what `go env GOROOT` prints, which
    is its parent. port_coverage.py takes the other convention and appends
    "src" itself, so `GOROOT=$(go env GOROOT)` silently made every anchor
    here report MISSING_FILE while port_coverage stayed green.

    Accept either spelling: if `$GOROOT/src` exists, that is the real Go
    root and `src` is what we want.
    """
    r = os.environ.get("GOROOT")
    if not r:
        return "/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src"
    nested = os.path.join(r, "src")
    return nested if os.path.isdir(os.path.join(nested, "crypto")) else r


GOROOT = _goroot()
ANCHOR = re.compile(r"(//\s*go:\s*sdk\s+\S+\s+)(\S+):(\d+)-(\d+)(\s+)(\S+)")

_src_cache = {}
_decl_cache = {}

DECL = re.compile(r"^(func|type|var|const)\s")


def decl_starts(gofile):
    """1-indexed lines of every top-level declaration in the file."""
    if gofile not in _decl_cache:
        src = go_src(gofile)
        _decl_cache[gofile] = (
            [i + 1 for i, l in enumerate(src) if DECL.match(l)]
            if src is not None else []
        )
    return _decl_cache[gofile]


def go_src(gofile):
    if gofile not in _src_cache:
        fp = os.path.join(GOROOT, gofile)
        _src_cache[gofile] = (
            open(fp, errors="replace").read().split("\n")
            if os.path.exists(fp) else None
        )
    return _src_cache[gofile]


def decl_hits(gofile, sym, free_only=False):
    """(1-indexed decl lines, is_bare). None if the Go file is missing.

    `free_only` drops the any-receiver fallback: an anchor that sits
    outside every `impl` block names a free function, so Go's method of
    the same name is not a candidate.
    """
    src = go_src(gofile)
    if src is None:
        return None, None
    if "." in sym:
        recv, meth = sym.split(".", 1)
        pats = [re.compile(
            r"^func\s*\(\s*\w*\s*\*?" + re.escape(recv) +
            r"(\[[^]]*\])?\s*\)\s*" + re.escape(meth) + r"\b")]
        bare = False
    else:
        pats = [re.compile(r"^func\s+" + re.escape(sym) + r"\b"),
                re.compile(r"^(type|var|const)\s+" + re.escape(sym) + r"\b"),
                # A member of a grouped `const (` / `var (` block. Go
                # writes most related constants that way (slog's
                # TimeKey/LevelKey/MessageKey/SourceKey, io/fs's mode
                # bits, crypto's cipher suite IDs), and without this an
                # anchor to one can never resolve — the block itself has
                # no name and the member is not a top-level decl. The
                # indent requirement keeps this from matching an
                # assignment inside a function body.
                re.compile(r"^\s+" + re.escape(sym) +
                           r"\s*(=|\s+[\w.\[\]*]+\s*=|\s+[\w.\[\]*]+$)"),
                # An `iota` continuation line, which carries no `=` at
                # all: net/http's `protoHTTP1 = 1 << iota` is followed
                # by bare `protoHTTP2` and `protoUnencryptedHTTP2`.
                # Without this those names resolve nowhere and can never
                # be anchored, though they are as much declarations as
                # the first member of the block.
                re.compile(r"^\s+" + re.escape(sym) + r"\s*$"),
                ] + ([] if free_only else
                     [re.compile(r"^func\s*\([^)]*\)\s*" + re.escape(sym) + r"\b")])
        bare = True
    return [i + 1 for i, l in enumerate(src) if any(p.match(l) for p in pats)], bare


def decl_end(gofile, start):
    """Line of the closing brace of the decl beginning at `start`.

    A declaration with no body - `func fatal(string)` behind a
    //go:linkname, or a bare interface method - ends on its own line.
    """
    src = go_src(gofile)
    if "{" not in src[start - 1]:
        return start
    depth, seen = 0, False
    for i in range(start - 1, len(src)):
        code = strip_literals(src[i])
        depth += code.count("{") - code.count("}")
        if "{" in src[i]:
            seen = True
        if seen and depth <= 0:
            return i + 1
    return start


# Braces inside a string or char literal are not code. `server.rs` holds
# `string("{")`, and counting that brace walks the enclosing-impl search
# past the block it was looking for. port_coverage.py had the same
# defect, where it hid 12 declarations.
_LITERAL = re.compile(
    r'(?s)r#*"(?:.*?)"#*'
    r'|b?"(?:[^\"\\\\]|\\\\.)*"'
    r"|b?'(?:[^'\\\\]|\\\\.)*'"
)


def strip_literals(line):
    """Blank out string/char literal bodies so brace counting sees code."""
    return _LITERAL.sub('""', line)


IMPL = re.compile(r"^impl(?:\s*<[^>]*>)?\s+(?:(?P<tr>[\w:]+(?:<[^>]*>)?)\s+for\s+)?(?P<ty>[\w:]+)")


def enclosing_impl(lines, idx):
    """Rust type whose `impl` block encloses line `idx`, or None.

    Used to recover the receiver for a bare anchor: an anchor reading
    `Sum` inside `impl Digest` is Go's `Digest.Sum`. Go names methods by
    receiver, so a bare anchor cannot be resolved when two types in the
    same file share a method name - which is why the tree has anchors
    that no fixer can place without this.
    """
    depth = 0
    for i in range(idx, -1, -1):
        line = lines[i]
        # A closing brace in column 0 above us means we were never
        # inside that block - the anchor is on a free function.
        if line.startswith("}") and i < idx:
            return None
        code = strip_literals(line)
        depth += code.count("}") - code.count("{")
        m = IMPL.match(line)
        if m and depth <= 0:
            ty = m.group("ty")
            return ty.split("::")[-1]
    return None


def qualify(roots):
    """Rewrite bare anchors to `Recv.Method` where the receiver is
    unambiguous. Returns (rewritten, left_bare)."""
    done = left = 0
    for root in roots:
        for dp, _, names in os.walk(root):
            for n in sorted(names):
                if not n.endswith(".rs"):
                    continue
                p = os.path.join(dp, n)
                lines = open(p, errors="replace").read().split("\n")
                changed = False
                for idx, line in enumerate(lines):
                    m = ANCHOR.search(line)
                    if not m or "." in m.group(6):
                        continue
                    gofile, sym = m.group(2), m.group(6)
                    src = go_src(gofile)
                    if src is None:
                        continue
                    ty = enclosing_impl(lines, idx)
                    if not ty:
                        # Outside any impl: a free function, already
                        # unambiguous. Note this must be decided by
                        # WHERE the anchor sits, not by whether Go
                        # happens to have a same-named free function -
                        # md5 has both `Sum` and `digest.Sum`.
                        continue
                    # goish capitalises Go's unexported types (Go's
                    # `digest` is goish's `Digest`), so match the
                    # receiver case-insensitively and write back the
                    # spelling Go uses.
                    pat = re.compile(r"^func\s*\(\s*\w*\s*\*?(" + re.escape(ty) +
                                     r")(\[[^]]*\])?\s*\)\s*" + re.escape(sym) + r"\b",
                                     re.IGNORECASE)
                    hit = next((pat.match(l) for l in src if pat.match(l)), None)
                    if hit is None:
                        left += 1
                        continue
                    ty = hit.group(1)
                    lines[idx] = line[:m.start()] + m.group(1) + m.group(2) + ":" + \
                        m.group(3) + "-" + m.group(4) + m.group(5) + f"{ty}.{sym}" + \
                        line[m.end():]
                    changed = True
                    done += 1
                if changed:
                    open(p, "w").write("\n".join(lines))
    return done, left


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    fix = "--fix" in sys.argv
    if "--qualify" in sys.argv:
        d, l = qualify(args or ["src"])
        print(f"anchor_check: qualified {d} bare anchors, {l} left bare")
        return 0
    strict = "--strict" in sys.argv
    roots = args or ["src"]

    stats = collections.Counter()
    problems = []

    for root in roots:
        for dp, _, names in os.walk(root):
            for n in sorted(names):
                if not n.endswith(".rs"):
                    continue
                p = os.path.join(dp, n)
                lines = open(p, errors="replace").read().split("\n")
                changed = False
                for idx, line in enumerate(lines):
                    m = ANCHOR.search(line)
                    if not m:
                        continue
                    gofile, a, b, sym = m.group(2), int(m.group(3)), int(m.group(4)), m.group(6)
                    stats["total"] += 1
                    free = "." not in sym and enclosing_impl(lines, idx) is None
                    hits, bare = decl_hits(gofile, sym, free_only=free)
                    if hits is None:
                        stats["MISSING_FILE"] += 1
                        problems.append(("MISSING_FILE", p, idx + 1, sym, gofile, a, b, None))
                        continue
                    if bare:
                        stats["BARE"] += 1
                    if not hits:
                        stats["NOT_FOUND"] += 1
                        problems.append(("NOT_FOUND", p, idx + 1, sym, gofile, a, b, None))
                        continue
                    inside = [h for h in hits if a <= h <= b]
                    covered = [d for d in decl_starts(gofile) if a <= d <= b]
                    if not inside or len(covered) != 1:
                        kind = "RANGE_WRONG" if not inside else "RANGE_FAT"
                        stats[kind] += 1
                        problems.append((kind, p, idx + 1, sym, gofile, a, b, hits))
                        if fix and len(hits) == 1:
                            s = hits[0]
                            e = decl_end(gofile, s)
                            new = (line[:m.start()] + m.group(1) +
                                   f"{gofile}:{s}-{e}" + m.group(5) + sym +
                                   line[m.end():])
                            # A member of a grouped `var (`/`const (`
                            # block resolves to its own line, but the
                            # block is the declaration, so the rewrite
                            # lands right back on the range that was
                            # already rejected. Counting that as a fix
                            # made --fix report work it had not done and
                            # left the next run reporting the same
                            # error; say nothing rather than lie.
                            if new != line:
                                lines[idx] = new
                                changed = True
                                stats["fixed"] += 1
                            else:
                                stats["UNFIXABLE"] += 1
                        continue
                    s = inside[0]
                    e = decl_end(gofile, s)
                    if b < e - 1:
                        stats["END_SHORT"] += 1
                        problems.append(("END_SHORT", p, idx + 1, sym, gofile, a, b, [s, e]))
                        if fix:
                            lines[idx] = (line[:m.start()] + m.group(1) +
                                          f"{gofile}:{s}-{e}" + m.group(5) + sym +
                                          line[m.end():])
                            changed = True
                            stats["fixed"] += 1
                        continue
                    stats["ok"] += 1
                if changed:
                    open(p, "w").write("\n".join(lines))

    print(f"anchor_check: {stats['total']} anchors under {', '.join(roots)}")
    for k in ("ok", "RANGE_WRONG", "RANGE_FAT", "END_SHORT", "NOT_FOUND",
              "MISSING_FILE", "BARE", "fixed", "UNFIXABLE"):
        if stats[k]:
            print(f"  {k:12s} {stats[k]}")

    hard = [x for x in problems if x[0] != "END_SHORT"]
    if problems and not fix:
        print()
        byfile = collections.Counter(x[1] for x in problems)
        for f, c in byfile.most_common(15):
            print(f"  {c:4d}  {f}")
        print("\n  first 15:")
        for kind, p, ln, sym, gofile, a, b, hits in problems[:15]:
            where = f"real {hits}" if hits else ""
            print(f"    {kind:12s} {sym:<44s} claims {gofile}:{a}-{b}  {where}")
            print(f"                 {p}:{ln}")
        print("\n  re-run with --fix to rewrite ranges automatically")

    bad = len(problems) + (stats["BARE"] if strict else 0)
    if bad and not fix:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
