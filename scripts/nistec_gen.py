#!/usr/bin/env python3
"""nistec_gen.py — generate p384.rs / p521.rs from p224.rs.

Go's crypto/internal/fips140/nistec generates p224.go, p384.go and p521.go
from one text/template in generate.go: the three files are the same curve
code at different parameters. This script keeps the goish port under the
same guarantee — edit `p224.rs`, re-run this, and the other two follow.

    scripts/nistec_gen.py            # rewrite p384.rs and p521.rs
    scripts/nistec_gen.py --check    # exit 1 if they are stale

What varies between the files:

  * the curve name (p224/P224 -> p384/P384),
  * pNNNElementLength,
  * three byte literals: the generator's x and y, and the curve's B,
  * pNNNSqrtCandidate, which for p = 3 mod 4 is an addchain exponentiation
    living IN the curve file, and for p224 (p = 1 mod 4) is a Tonelli-
    Shanks variant living in p224_sqrt.go.

Everything else must match, and this script proves it rather than assuming
it: before generating, it renames the target Go file's identifiers back to
p224 and diffs it against p224.go. Any difference outside the four known
varying spots aborts the run. That check is the whole point — a silent
divergence between the curve files is exactly the class of bug that no
unit test catches until a signature verifies against the wrong curve.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RSDIR = os.path.join(ROOT, "src/crypto/internal/fips140/nistec")

# (name, element length in bytes)
TARGETS = [("p384", 48), ("p521", 66)]


def goroot():
    if os.environ.get("GOROOT"):
        return os.environ["GOROOT"]
    return subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()


def godir():
    return os.path.join(goroot(), "src/crypto/internal/fips140/nistec")


# ---------------------------------------------------------------- Go parsing

# `p.x.SetBytes([]byte{0xb7, 0xe, …})`
GEN_X = re.compile(r"p\.x\.SetBytes\(\[\]byte\{([^}]*)\}\)")
GEN_Y = re.compile(r"p\.y\.SetBytes\(\[\]byte\{([^}]*)\}\)")


def curve_constants(go_src, p):
    """The three byte literals that differ per curve."""
    b = re.search(
        r"_%sB, _ = new\(fiat\.%sElement\)\.SetBytes\(\[\]byte\{([^}]*)\}\)"
        % (p, p.upper().replace("P", "P", 1)),
        go_src,
    )
    if not b:
        # The Element type is `P384Element`, i.e. the curve name upper-cased.
        b = re.search(
            r"_%sB, _ = new\(fiat\.%sElement\)\.SetBytes\(\[\]byte\{([^}]*)\}\)"
            % (p, p.capitalize()),
            go_src,
        )
    x, y = GEN_X.search(go_src), GEN_Y.search(go_src)
    for name, m in (("generator x", x), ("generator y", y), ("curve B", b)):
        if not m:
            sys.exit("nistec_gen: %s: no %s literal found" % (p, name))
    return [tok.strip() for tok in x.group(1).split(",") if tok.strip()], \
           [tok.strip() for tok in y.group(1).split(",") if tok.strip()], \
           [tok.strip() for tok in b.group(1).split(",") if tok.strip()]


FUNC = re.compile(r"^func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s*)?(\w+)\s*[\(\[]")


def go_func_ranges(go_src):
    """name -> (first line of its doc comment, line of its closing brace)."""
    lines = go_src.split("\n")
    out = {}
    for i, ln in enumerate(lines):
        m = FUNC.match(ln)
        if not m:
            continue
        top = i
        while top > 0 and lines[top - 1].startswith("//"):
            top -= 1
        end = i
        while end < len(lines) and lines[end] != "}":
            end += 1
        out[m.group(1)] = (top + 1, end + 1)
    return out


def go_span(go_src, first_re, last_re=None):
    """Line span of a non-func declaration, doc comment included."""
    lines = go_src.split("\n")
    start = next((i for i, ln in enumerate(lines) if re.match(first_re, ln)), None)
    if start is None:
        sys.exit("nistec_gen: no line matching %r" % first_re)
    top = start
    while top > 0 and lines[top - 1].startswith("//"):
        top -= 1
    if last_re is None:
        end = start
        if lines[start].rstrip().endswith("{"):
            end = start
            while end < len(lines) and lines[end] != "}":
                end += 1
    else:
        end = next(i for i in range(start, len(lines)) if re.match(last_re, lines[i]))
    return top + 1, end + 1


# ------------------------------------------------- structural equality check

def strip_varying(src, p):
    """p224-normalised source with the four varying spots blanked out."""
    s = src.replace(p.upper(), "P224").replace(p, "p224")
    s = GEN_X.sub("p.x.SetBytes(<<GEN_X>>)", s)
    s = GEN_Y.sub("p.y.SetBytes(<<GEN_Y>>)", s)
    s = re.sub(
        r"_p224B, _ = new\(fiat\.P224Element\)\.SetBytes\(\[\]byte\{[^}]*\}\)",
        "_p224B = <<B>>",
        s,
    )
    s = re.sub(r"const p224ElementLength = \d+", "const p224ElementLength = N", s)
    # Drop the trailing pNNNSqrtCandidate (p = 3 mod 4 curves only).
    s = re.sub(r"\n// p224SqrtCandidate sets z to.*", "\n", s, flags=re.S)
    return s.rstrip() + "\n"


def assert_same_shape(base_go, target_go, p):
    a = strip_varying(base_go, "p224")
    b = strip_varying(target_go, p)
    if a != b:
        import difflib

        d = "\n".join(
            difflib.unified_diff(a.split("\n"), b.split("\n"), "p224.go", p + ".go", lineterm="")
        )
        sys.exit(
            "nistec_gen: %s.go diverges from p224.go outside the known per-curve\n"
            "constants — the template assumption no longer holds, so generating\n"
            "%s.rs from p224.rs would be wrong. Diff:\n\n%s" % (p, p, d)
        )


# ------------------------------------------------- pNNNSqrtCandidate -> Rust

DECL = re.compile(r"^\tvar (t\d) = new\(fiat\.\w+Element\)$")
CALL = re.compile(r"^\t(\**\w+)\.(Square|Mul)\(([^)]*)\)$")
FOR = re.compile(r"^\tfor s := (\d+); s < (\d+); s\+\+ \{$")


def translate_sqrt_candidate(go_src, p, P):
    """Translate `func pNNNSqrtCandidate(z, x *fiat.PNNNElement)`.

    The body is a straight-line addchain: `var tN = new(…)` declarations,
    `recv.Square(a)` / `recv.Mul(a, b)` calls, and `for s := A; s < B; s++`
    loops whose body is a single squaring. Anything else raises — a silent
    mistranslation of an exponentiation chain produces a wrong-but-plausible
    square root, which no smoke test would localise.
    """
    m = re.search(
        r"^// %sSqrtCandidate sets z.*?\nfunc %sSqrtCandidate\(z, x \*fiat\.%sElement\) \{\n(.*?)\n\}$"
        % (p, p, P),
        go_src,
        re.S | re.M,
    )
    if not m:
        sys.exit("nistec_gen: %s: no pNNNSqrtCandidate to translate" % p)
    out = []

    def arg(a):
        a = a.strip()
        if a == "z":
            return "*z"
        if a == "x" or re.fullmatch(r"t\d", a):
            return a
        sys.exit("nistec_gen: %s: unhandled operand %r" % (p, a))

    depth = 0
    for ln in m.group(1).split("\n"):
        if not ln.strip():
            out.append("")
            continue
        if ln.startswith("\t//"):
            out.append("    " + ln.strip())
            continue
        d = DECL.match(ln)
        if d:
            out.append("    let mut %s = %sElement::New();" % (d.group(1), P))
            continue
        f = FOR.match(ln)
        if f:
            out.append("    let mut s: usize = %s;" % f.group(1))
            out.append("    while s < %s {" % f.group(2))
            depth += 1
            continue
        if ln == "\t}" and depth:
            out.append("        s += 1;")
            out.append("    }")
            depth -= 1
            continue
        c = CALL.match(ln.replace("\t\t", "\t", 1) if depth else ln)
        if c:
            recv, meth, args = c.group(1), c.group(2), c.group(3)
            rendered = ", ".join(arg(a) for a in args.split(","))
            indent = "        " if depth else "    "
            out.append("%s%s.%s(%s);" % (indent, recv, meth, rendered))
            continue
        sys.exit("nistec_gen: %s: unhandled line in SqrtCandidate: %r" % (p, ln))
    if depth:
        sys.exit("nistec_gen: %s: unbalanced for-loop in SqrtCandidate" % p)
    return "\n".join(out).rstrip()


# ------------------------------------------------------------------ emitting

def fmt_bytes(tokens, indent):
    """Render Go's `0xb7, 0xe, …` as an indented Rust literal list."""
    lines, cur = [], []
    for t in tokens:
        cur.append(t)
        if len(cur) == 12:
            lines.append(indent + ", ".join(cur) + ",")
            cur = []
    if cur:
        lines.append(indent + ", ".join(cur))
    return "\n".join(lines)


def generate(p, elem_len, base_rs, base_go, target_go):
    P = p.capitalize()
    assert_same_shape(base_go, target_go, p)
    gx, gy, gb = curve_constants(target_go, p)
    src = base_rs

    # p224's square-root candidate lives in its own file; p384/p521 carry
    # theirs in the curve file, so the import goes away and the function
    # is appended below.
    src = src.replace("\nuse super::p224_sqrt::p224SqrtCandidate;\n", "")

    # The three per-curve byte literals.
    def sub_bytes(anchor_re, tokens, indent):
        nonlocal src
        new = anchor_re.split("%s\n" % fmt_bytes(tokens, indent), 1)
        return new

    src = re.sub(
        r"(let _ = self\.x\.SetBytes\(slice::__from_vec\(alloc::vec!\[\n)(?:.*?)(\n\s*\]\)\);)",
        lambda m: m.group(1) + fmt_bytes(gx, " " * 12) + m.group(2),
        src,
        flags=re.S,
    )
    src = re.sub(
        r"(let _ = self\.y\.SetBytes\(slice::__from_vec\(alloc::vec!\[\n)(?:.*?)(\n\s*\]\)\);)",
        lambda m: m.group(1) + fmt_bytes(gy, " " * 12) + m.group(2),
        src,
        flags=re.S,
    )
    src = re.sub(
        r"(let _ = e\.SetBytes\(slice::__from_vec\(alloc::vec!\[\n)(?:.*?)(\n\s*\]\)\);)",
        lambda m: m.group(1) + fmt_bytes(gb, " " * 8) + m.group(2),
        src,
        flags=re.S,
    )

    # Curve name and element length.
    src = src.replace("P224", P).replace("p224", p)
    src = re.sub(
        r"pub const %sElementLength: usize = \d+;" % p,
        "pub const %sElementLength: usize = %d;" % (p, elem_len),
        src,
    )

    # Anchors: re-derive every cited line range from the target Go file.
    franges = go_func_ranges(target_go)
    def fix_anchor(m):
        name = m.group(2)
        if name not in franges:
            sys.exit("nistec_gen: %s: anchor names %r, absent from %s.go" % (p, name, p))
        a, b = franges[name]
        return "%s:%d-%d %s" % (m.group(1), a, b, name)

    src = re.sub(
        r"(crypto/internal/fips140/nistec/%s\.go):\d+-\d+ (\w+)" % p, fix_anchor, src
    )

    # The informational `// Go: pNNN.go:A-B` comments on the non-func decls.
    for pat, first, last in (
        (r"// Go: %s\.go:\d+-\d+\n//   type %sPoint struct" % (p, P),
         r"^type %sPoint struct \{" % P, None),
        (r"// Go: %s\.go:\d+-\d+ — `var _%sB" % (p, p),
         r"^var _%sB \*fiat" % p, r"^var _%sBOnce" % p),
        (r"// Go: %s\.go:\d+-\d+\n//   type %sTable" % (p, P),
         r"^type %sTable \[15\]" % p, None),
        (r"// Go: %s\.go:\d+-\d+ — `var %sGeneratorTable" % (p, p),
         r"^var %sGeneratorTable \*" % p, r"^var %sGeneratorTableOnce" % p),
    ):
        a, b = go_span(target_go, first, last)
        src = re.sub(
            pat.replace(r"\d+-\d+", r"\d+-\d+"),
            lambda m, a=a, b=b: re.sub(r":\d+-\d+", ":%d-%d" % (a, b), m.group(0)),
            src,
        )

    # Append the curve's own square-root candidate.
    a, b = franges["%sSqrtCandidate" % p]
    body = translate_sqrt_candidate(target_go, p, P)
    src = src.rstrip() + (
        "\n\n// go: sdk 1.25.5 crypto/internal/fips140/nistec/%s.go:%d-%d %sSqrtCandidate\n"
        "/// Set z to a square root candidate for x.\n"
        "fn %sSqrtCandidate(z: &mut %sElement, x: %sElement) {\n%s\n}\n"
        % (p, a, b, p, p, P, P, body)
    )

    # Header: manifest, provenance note, and the p224-only deviations.
    src = src.replace(
        " %sSqrt\n" % p, " %sSqrt, %sSqrtCandidate\n" % (p, p), 1
    )
    src = src.replace(
        "// Code generated by generate.go. DO NOT EDIT.",
        "// Code generated by generate.go (Go side) and scripts/nistec_gen.py\n"
        "// (goish side) from p224.rs. DO NOT EDIT — edit p224.rs and re-run\n"
        "//     scripts/nistec_gen.py",
    )
    return src


def main():
    check = "--check" in sys.argv
    gd = godir()
    base_rs = open(os.path.join(RSDIR, "p224.rs")).read()
    base_go = open(os.path.join(gd, "p224.go")).read()
    stale = []
    for p, n in TARGETS:
        target_go = open(os.path.join(gd, "%s.go" % p)).read()
        out = generate(p, n, base_rs, base_go, target_go)
        path = os.path.join(RSDIR, "%s.rs" % p)
        old = open(path).read() if os.path.exists(path) else None
        if check:
            if old != out:
                stale.append(p)
            continue
        with open(path, "w") as f:
            f.write(out)
        print("wrote %s.rs (%d lines)" % (p, out.count("\n")))
    if check:
        if stale:
            sys.exit("nistec_gen: stale: %s — re-run scripts/nistec_gen.py" % ", ".join(stale))
        print("nistec_gen: p384.rs and p521.rs are up to date")


if __name__ == "__main__":
    main()
