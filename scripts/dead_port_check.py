#!/usr/bin/env python3
"""Find ported functions that nothing calls.

Every existing tier passes a function like this. `anchor_check` sees a
well-formed anchor. `port_coverage` counts the Go declaration as
ported. `port_bodydiff` compares the body against Go's and finds it
faithful. goishlint has nothing to say. The function is a correct port
of the right Go code — and it never runs.

That is not hypothetical. `net/http/transport.rs`'s `validateHeaders`
was anchored to `transport.go:565-579`, the exact Go function, and was
called from nowhere; Go calls it twice in `Transport.roundTrip`, which
is the only thing standing between a caller's header value and request
smuggling. Six malformed header shapes went onto the wire verbatim
because a defence was ported and then not wired up.

So the check is: for each anchored `fn` under src/, count the mentions
of its name outside its own declaration. Zero mentions means nothing
reaches it.

Two categories, reported apart because they mean different things:

  PRIVATE_DEAD  a non-`pub` anchored fn with no mention outside its
                own body. Nothing outside the module can call it and
                nothing inside does. This is the validateHeaders shape
                and is almost always either a defect or dead weight.

  PUBLIC_DEAD   a `pub` anchored fn with no mention anywhere else in
                the tree. Often FINE: goish is a library, and a faithful
                port of an exported Go function is meant to be called by
                users, not by us. Worth reading only when the Go
                original is called by other stdlib code, which is the
                case this cannot see. Reported for review, not failure.

  TESTED_NOT_WIRED  an anchored fn that examples/ calls and that NOTHING
                under src/ calls. This is the one that matters, and it
                is the shape validateHeaders actually had: it was `pub`
                inside a `pub mod`, so PUBLIC_DEAD could not see it, and
                `http_transport_opts_smoke` called it directly and found
                it correct. The smoke tested the UNIT. Nothing tested
                that the unit's answer was ever consulted. A green
                example on a function the library never calls proves the
                function works and says nothing about whether it runs.

                False positives are expected here: a port meant purely
                for library users is legitimately called only by an
                example. The question to ask of each is the one that
                broke here — does Go's own stdlib call this? If Go calls
                it and goish does not, the port is decoration.

Exit status is 0 unless --strict, so this is safe in a pre-commit hook.
"""

import argparse
import os
import re
import sys

SRC = "src"

ANCHOR = re.compile(r"^\s*//\s*go:\s*sdk\b")
# `fn name(`, with any of the usual prefixes in front.
FNDECL = re.compile(
    r"^(?P<indent>\s*)(?P<pre>(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?)fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)


def rs_files(root):
    for dirpath, _, names in os.walk(root):
        for n in names:
            if n.endswith(".rs"):
                yield os.path.join(dirpath, n)


def collect(paths):
    """Every anchored fn: name -> (path, line, is_pub, body_line_span)."""
    found = []
    for path in paths:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
        anchored = False
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if ANCHOR.match(line):
                anchored = line.strip()
                continue
            if stripped.startswith("//") or stripped.startswith("///") or not stripped:
                # Comments and blanks between the anchor and the decl
                # keep the anchor live; anything else drops it.
                continue
            m = FNDECL.match(line)
            if m and anchored:
                found.append((m.group("name"), path, i + 1,
                              "pub" in m.group("pre"), body_end(lines, i),
                              anchored))
            anchored = False
    return found


def body_end(lines, start):
    """Last line index of the fn body, by brace balance from `start`."""
    depth = 0
    seen = False
    for i in range(start, len(lines)):
        # Crude, but the alternative is a Rust parser. Strings and
        # comments containing braces can skew this; the consequence is
        # only a wider or narrower self-span, which at worst hides a
        # finding rather than inventing one.
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
        if seen and depth <= 0:
            return i
    return len(lines) - 1


GOSYM = re.compile(r"//\s*go:\s*sdk\s+\S+\s+(?P<gofile>\S+\.go):(?P<span>\S+)\s+(?P<sym>[A-Za-z_][A-Za-z0-9_.]*)")


def strip_go_comments(text):
    """Blank out // and /* */ comments, keeping string literals intact."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "`" or c == "'":
            q = c
            out.append(c)
            i += 1
            while i < n:
                if q != "`" and text[i] == "\\":
                    out.append(text[i:i + 2])
                    i += 2
                    continue
                out.append(text[i])
                if text[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            # Keep the newlines. Dropping them shifts every line number
            # after the comment, which makes the caller's
            # declaration-span exclusion miss — and then the
            # DECLARATION ITSELF matches as a call, so a function with
            # no callers at all is reported as one Go calls. That is
            # how this script came to claim 88 hot findings where the
            # real number is smaller.
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def decl_lines(span):
    """The (lo, hi) line range an anchor's `NNN-MMM` (or `NNN`) names."""
    parts = span.split("-")
    try:
        lo = int(parts[0])
        hi = int(parts[1]) if len(parts) > 1 else lo
    except ValueError:
        return (0, 0)
    return (lo, hi)


def go_calls_it(goroot, anchor):
    """Does Go's own stdlib call this symbol from some OTHER file?

    This is the question that separates the one finding that mattered
    from the 258 that did not. `container/list`'s `Front` is called by
    nothing in Go's stdlib either — it is API for users, and an example
    is its only rightful caller. `validateHeaders` is called twice by
    `Transport.roundTrip`. Go's own call graph says which kind a port
    is, and it is sitting on disk.

    Returns the list of Go files that call it, excluding the file that
    declares it and any _test.go. Empty list means Go does not wire it
    up internally either, so goish not wiring it up is not a defect.
    """
    m = GOSYM.search(anchor or "")
    if not m:
        return None
    gofile, sym = m.group("gofile"), m.group("sym").split(".")[-1]
    span = m.group("span")
    pkgdir = os.path.join(goroot, "src", os.path.dirname(gofile))
    if not os.path.isdir(pkgdir):
        return None
    rx = re.compile(r"\b%s\s*\(" % re.escape(sym))
    hits = []
    for dirpath, _, names in os.walk(pkgdir):
        for n in names:
            if not n.endswith(".go") or n.endswith("_test.go"):
                continue
            fp = os.path.join(dirpath, n)
            rel = os.path.relpath(fp, os.path.join(goroot, "src"))
            try:
                text = open(fp, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            # `//go:build ignore` files are not part of the package —
            # math/bits/make_examples.go is a code GENERATOR that calls
            # every function in the package, and counting it made all
            # nineteen of math/bits look like Go wires them up.
            if re.search(r"^//go:build ignore\b", text, re.M):
                continue
            # And strip Go's own comments before looking, for the same
            # reason the Rust side strips them: fmt/doc.go NAMES Sscanf
            # in package documentation and calls nothing at all.
            text = strip_go_comments(text)
            if rel == gofile:
                # The declaring file is searched too, minus the
                # declaration's own lines. Skipping the whole file —
                # which this did — makes a symbol whose real callers
                # live beside it look uncalled, or picks up an
                # unrelated same-named method elsewhere in the package
                # and reports THAT as the call site. persistConn's
                # `cancelRequest` is called twice from transport.go and
                # was reported as "called from h2_bundle.go", which is
                # a different type's method of the same name.
                lo, hi = decl_lines(span)
                lines = text.split("\n")
                text = "\n".join(
                    l for n, l in enumerate(lines, 1) if not (lo <= n <= hi))
            if rx.search(text):
                hits.append(rel)
    return sorted(hits)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--goroot", default=os.environ.get("GOROOT", "/usr/local/go"),
                    help="Go tree used to ask whether Go itself calls a symbol")
    ap.add_argument("--also", default="examples",
                    help="extra dir whose mentions count as calls")
    args = ap.parse_args()

    src_paths = sorted(rs_files(SRC))
    fns = collect(src_paths)

    # One pass over every file, counting each name's mentions and where.
    names = {}
    for name, path, line, is_pub, end, anchor in fns:
        names.setdefault(name, []).append((path, line, is_pub, end, anchor))

    word = {n: re.compile(r"\b%s\b" % re.escape(n)) for n in names}
    # mentions[name] -> list of (path, lineno)
    mentions = {n: [] for n in names}
    scan = src_paths + (sorted(rs_files(args.also))
                        if os.path.isdir(args.also) else [])
    for path in scan:
        text = open(path, encoding="utf-8", errors="replace").read()
        for name, rx in word.items():
            if name not in text:
                continue
            for i, line in enumerate(text.split("\n"), 1):
                # A name written in prose is not a call. This tree
                # documents heavily and cross-references by name
                # constantly: `validateHeaders` is named in a GOISH
                # waiver comment in net/http/internal/httpcommon, and
                # counting that comment as a caller was enough to hide
                # the one defect this script exists to find. Full-line
                # comments are dropped; a trailing comment after real
                # code keeps its line, since the code is what counts.
                if line.lstrip().startswith("//"):
                    continue
                if rx.search(line):
                    mentions[name].append((path, i))

    private_dead, public_dead, tested_only = [], [], []
    for name, decls in names.items():
        for path, line, is_pub, end, anchor in decls:
            outside = [(p, l) for p, l in mentions[name]
                       if not (p == path and line <= l <= end + 1)]
            # A name declared twice (two impls, two modules) is
            # ambiguous: a mention could be for either. Skip it rather
            # than report a finding this check cannot substantiate.
            if len(decls) > 1:
                continue
            if outside:
                in_src = [(p, l) for p, l in outside if p.startswith(SRC + os.sep)]
                if not in_src:
                    tested_only.append((path, line, name,
                                        sorted({p for p, _ in outside}),
                                        anchor))
                continue
            (public_dead if is_pub else private_dead).append((path, line, name))

    print("dead_port_check: %d anchored fn(s) under %s/" % (len(fns), SRC))

    if private_dead:
        print("\n  PRIVATE_DEAD (%d) — anchored, non-pub, no caller anywhere:"
              % len(private_dead))
        for path, line, name in sorted(private_dead):
            print("    %s:%d: %s" % (path, line, name))

    if public_dead:
        print("\n  PUBLIC_DEAD (%d) — anchored, pub, unmentioned outside itself:"
              % len(public_dead))
        for path, line, name in sorted(public_dead):
            print("    %s:%d: %s" % (path, line, name))
        print("      (many are legitimate — an exported port is for the")
        print("       library's users. Read the ones Go's own stdlib calls.)")

    if tested_only:
        hot, cold = [], []
        for path, line, name, callers, anchor in sorted(tested_only):
            gohits = go_calls_it(args.goroot, anchor)
            (hot if gohits else cold).append(
                (path, line, name, callers, gohits))

        if hot:
            print("\n  TESTED_NOT_WIRED, AND GO CALLS IT (%d) — read every one:"
                  % len(hot))
            for path, line, name, callers, gohits in hot:
                print("    %s:%d: %s" % (path, line, name))
                print("      goish: called only from %s" % ", ".join(callers[:2]))
                print("      Go:    called from %s" % ", ".join(gohits[:3]))
        if cold:
            print("\n  TESTED_NOT_WIRED, and Go does not call it either (%d)"
                  % len(cold))
            print("      Library API whose only caller is rightly an example.")
            print("      Pass -v to list them.")
            if args.verbose:
                for path, line, name, callers, _ in cold:
                    print("    %s:%d: %s" % (path, line, name))

    if not private_dead and not public_dead and not tested_only:
        print("  OK — every anchored fn is reachable.")

    if args.strict and (private_dead or public_dead or tested_only):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
