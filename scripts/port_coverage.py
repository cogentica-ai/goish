#!/usr/bin/env python3
"""port_coverage.py - measure goish's port coverage of a Go stdlib subtree.

    scripts/port_coverage.py crypto            # coverage table for crypto/
    scripts/port_coverage.py crypto --json     # machine-readable
    scripts/port_coverage.py crypto --pkg tls  # per-package detail (missing fns)
    scripts/port_coverage.py crypto --md       # markdown table (for tracking docs)

Go source root comes from $GOROOT, else `go env GOROOT`, else --goroot.

Method: for each in-scope Go package, collect every `func` ident declared in
its non-test .go files, then check whether an identically-named `fn` exists
anywhere in the matching goish package directory (case/underscore-insensitive).
This is a NAME-level proxy for coverage, not a semantic diff:

  * a Go func whose port was renamed reads as missing (that is intentional -
    a renamed port is not a verbatim port);
  * a same-named Rust helper reads as ported even if the body diverges.

The authoritative per-function check is goishlint GOISH018, which parses the
Go file cited by each `// go:` anchor. This script exists to rank the work
BEFORE anchors are in place, and to track the percentage over time.
"""
import os, re, sys, json, subprocess

# Out of scope: cgo/BoringSSL bridge, asm generators, test-only helpers.
SKIP = re.compile(r"(^|/)(boring|_asm|cryptotest|checktest|syso|fipsonly)(/|$)")

# goish is single-target x86_64-unknown-linux-gnu. Files whose build
# constraint is another GOARCH/GOOS are not part of the port surface, the
# same way crypto/x509/internal/macos is not. `_amd64.go`, `_generic.go`,
# `_noasm.go`, `_asm.go`, `_unix.go`, `_linux.go` all stay in scope.
SKIP_FILE = re.compile(
    r"_(s390x|ppc64|ppc64le|ppc64x|arm64|arm|386|riscv64|loong64|mips|mips64|"
    r"mipsle|mips64le|wasm|js|darwin|windows|openbsd|freebsd|netbsd|dragonfly|"
    r"solaris|aix|plan9|ios|android)(_gen)?\.go$"
)

# `*_asm.go` / `*_amd64.go` are Go's `//go:build !purego` assembly entry
# points. goish CAN write assembly (the runtime already does: gogo,
# mcall, swap_context, the preempt trampoline), so these are in scope and
# tracked as performance work — see CRYPTO_PORT.md "Assembly".
# `--purego` reports the subset reachable without any asm, for triage.
SKIP_ASM = re.compile(r"_(asm|amd64)\.go$")

FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\(\[]", re.M)
RSFN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_]\w*)", re.M)
ANCHOR = re.compile(r"^\s*//\s*go:", re.M)


def goroot(argv):
    for i, a in enumerate(argv):
        if a == "--goroot" and i + 1 < len(argv):
            return argv[i + 1]
    if os.environ.get("GOROOT"):
        return os.environ["GOROOT"]
    try:
        return subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
    except Exception:
        sys.exit("port_coverage: set $GOROOT or pass --goroot <dir> (no `go` on PATH)")


def norm(s):
    return s.lower().replace("_", "")


PUREGO = False


# GOOS values. A file whose //go:build line mentions ONLY these and does
# not include `linux` cannot be part of a linux build.
_GOOS = {"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos",
         "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris",
         "wasip1", "windows", "unix"}


def is_foreign_goos(path):
    """True for a file constrained to GOOS values that exclude linux —
    e.g. crypto/x509/internal/macos, which is `//go:build darwin`.

    Deliberately narrow: it fires only when EVERY identifier on the
    build line is a GOOS. A constraint mentioning GOARCH or `purego`
    (`//go:build (!amd64 && !s390x) || purego`) is left alone, because
    which side of that goish implements is a porting decision, not a
    platform fact — silently dropping those would shrink the denominator
    in our favour."""
    try:
        with open(path, errors="replace") as f:
            for line in f:
                st = line.strip()
                if st.startswith("//go:build "):
                    idents = set(re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", st[len("//go:build "):]))
                    if not idents or not idents <= _GOOS:
                        return False
                    return "linux" not in idents and "unix" not in idents
                if st.startswith("package "):
                    return False
    except Exception:
        pass
    return False


def is_build_ignored(path):
    """True for a `//go:build ignore` file. These are standalone `package
    main` programs (md5's gen.go, nistec's generate.go, tls's
    generate_cert.go) that `go build` never compiles into the package.
    Counting their funcs would inflate the denominator with code that is
    not part of the library — same reason `_asm/` is skipped."""
    try:
        with open(path, errors="replace") as f:
            for line in f:
                st = line.strip()
                if st.startswith("//go:build "):
                    return "ignore" in st.split()[1:] or st == "//go:build ignore"
                if st.startswith("package "):
                    return False
    except Exception:
        pass
    return False


def is_boringcrypto(path):
    """True for a file built only under `//go:build boringcrypto`.

    `boringcrypto` is a cgo-only build tag, and goish has no cgo — the
    BoringSSL bridge is out of scope everywhere else in this script (SKIP
    matches the `boring` path component) and in port_deps. Every such file
    comes as a pair: `boring.go` (`//go:build boringcrypto`) and
    `notboring.go` (`//go:build !boringcrypto`). Go compiles exactly one of
    the two, so counting both double-counts the package's surface — and it
    counts the side goish structurally cannot take.

    crypto/ecdsa is the worked example: `notboring.go` is ported, and
    `boring.go`'s copyPublicKey / copyPrivateKey / publicKeyEqual /
    privateKeyEqual read as four permanent gaps against a branch that never
    compiles here.

    Deliberately narrow, like is_foreign_goos: it fires only on a bare,
    un-negated `boringcrypto` constraint.
    """
    try:
        with open(path, errors="replace") as f:
            for line in f:
                st = line.strip()
                if st.startswith("//go:build "):
                    return st[len("//go:build "):].strip() == "boringcrypto"
                if st.startswith("package "):
                    return False
    except Exception:
        pass
    return False


def asm_decls(paths):
    """Names of Go funcs declared with NO body — the assembly stubs.

    Why this is worth computing: the raw gap column has produced a wrong
    leverage claim three times in this repo. `fips140deps/godebug` looked
    like a blocker on 45 functions across five packages; 44 of them were
    `*Asm` / `gcmAes*` / `blockAVX2` / `blockSHANI`, and the real leverage
    was one function. The gap number was true and the conclusion drawn
    from it was false.

    A bodyless `func` is the exact signal, and it beats filename
    heuristics: `_amd64.go` holds both the stubs and the Go dispatch code
    that chooses between them, and the dispatch code is ordinary portable
    Go. (A handful of bodyless decls are `//go:linkname` rather than
    assembly. Both are alike for ranking: neither is a function you port
    by reading Go and writing goish.)
    """
    out = set()
    for p in paths:
        lines = open(p, errors="replace").read().split("\n")
        i = 0
        while i < len(lines):
            if not lines[i].startswith("func "):
                i += 1
                continue
            # Join a signature that wraps across lines: balance parens,
            # then ask whether the declaration ended on an opening brace.
            text, depth, seen = "", 0, False
            j = i
            while j < len(lines):
                text += lines[j]
                depth += lines[j].count("(") - lines[j].count(")")
                seen = seen or "(" in lines[j]
                if seen and depth <= 0:
                    break
                j += 1
            m = FUNC.match(text)
            if m and not text.rstrip().endswith("{"):
                out.add(m.group(1))
            i = j + 1
    return out


def scan_go(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        rel = "" if rel == "." else rel
        if SKIP.search(rel):
            continue
        gofiles = sorted(f for f in files if f.endswith(".go")
                         and not f.endswith("_test.go") and not SKIP_FILE.search(f)
                         and not (PUREGO and SKIP_ASM.search(f))
                         and not is_build_ignored(os.path.join(dirpath, f))
                         and not is_boringcrypto(os.path.join(dirpath, f))
                         and not is_foreign_goos(os.path.join(dirpath, f)))
        if not gofiles:
            continue
        funcs, loc = set(), 0
        for f in gofiles:
            src = open(os.path.join(dirpath, f), errors="replace").read()
            funcs |= set(FUNC.findall(src))
            loc += src.count("\n")
        paths = [os.path.join(dirpath, f) for f in gofiles]
        out[rel or "."] = {"nfiles": len(gofiles), "loc": loc,
                           "asm": asm_decls(paths),
                           "funcs": sorted(f for f in funcs if not f.startswith("init"))}
    return out


def _facts(paths):
    idents, loc, anchors = set(), 0, 0
    for p in paths:
        src = open(p, errors="replace").read()
        idents |= set(RSFN.findall(src))
        anchors += len(ANCHOR.findall(src))
        loc += src.count("\n")
    return {"idents": {norm(i) for i in idents}, "loc": loc,
            "nfiles": len(paths), "anchors": anchors}


def scan_rs(root):
    """Map goish package dir -> facts. A package may be a directory
    (`aes/mod.rs`) or a single sibling file (`rsa.rs`); Go has both shapes
    collapsed into one package, so treat `<pkg>.rs` as package `<pkg>`."""
    out = {}
    for dirpath, _, files in os.walk(root):
        rs = sorted(f for f in files if f.endswith(".rs"))
        if not rs:
            continue
        rel = os.path.relpath(dirpath, root)
        rel = "" if rel == "." else rel
        # `foo.rs` next to `foo/` would double-count; file-form only counts
        # when no same-named directory exists.
        own, filepkgs = [], {}
        for f in rs:
            stem = f[:-3]
            cand = os.path.join(dirpath, stem)
            if stem not in ("mod", "lib") and os.path.isdir(cand):
                own.append(os.path.join(dirpath, f))
            elif stem not in ("mod", "lib") and any(
                os.path.isdir(os.path.join(dirpath, x)) for x in [stem]
            ):
                own.append(os.path.join(dirpath, f))
            else:
                filepkgs.setdefault(stem, []).append(os.path.join(dirpath, f))
        # mod.rs/lib.rs and any leftovers belong to this package itself.
        for stem, paths in list(filepkgs.items()):
            if stem in ("mod", "lib"):
                own.extend(paths)
                del filepkgs[stem]
        out[rel or "."] = _facts(own + [p for ps in filepkgs.values() for p in ps])
        # Also expose each non-mod file as its own candidate package name,
        # so Go's `crypto/rsa` finds goish's `crypto/rsa.rs`.
        for stem, paths in filepkgs.items():
            key = f"{rel}/{stem}" if rel else stem
            out.setdefault(key, _facts(paths))
    return out


def build(subtree, gr):
    gp = scan_go(os.path.join(gr, "src", subtree))
    rp = scan_rs(os.path.join("src", subtree))
    rows = []
    for pkg, g in sorted(gp.items()):
        r = rp.get(pkg)
        have = r["idents"] if r else set()
        hit = [f for f in g["funcs"] if norm(f) in have]
        want = g["funcs"]
        missing = sorted(set(want) - set(hit))
        # Split the gap: what is left to *write in goish* versus what is
        # left to write in assembly. Ranking on the raw gap has misled
        # three times — see asm_decls.
        missing_asm = sorted(m for m in missing if m in g["asm"])
        rows.append({
            "pkg": pkg, "go_files": g["nfiles"], "go_loc": g["loc"],
            "go_funcs": len(want), "ported": len(hit),
            "pct": round(100.0 * len(hit) / len(want), 1) if want else 100.0,
            "rs_files": r["nfiles"] if r else 0, "rs_loc": r["loc"] if r else 0,
            "anchors": r["anchors"] if r else 0,
            "missing": missing,
            "missing_asm": missing_asm,
            "gap_portable": len(missing) - len(missing_asm),
        })
    return rows


def main():
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        sys.exit(__doc__)
    global PUREGO
    PUREGO = "--purego" in argv
    subtree, gr = argv[0], goroot(argv)
    rows = build(subtree, gr)

    if "--pkg" in argv:
        want = argv[argv.index("--pkg") + 1]
        for r in rows:
            if r["pkg"] == want or r["pkg"].endswith("/" + want):
                print(f"{r['pkg']}: {r['ported']}/{r['go_funcs']} ported ({r['pct']}%), "
                      f"{r['go_files']} .go / {r['rs_files']} .rs, {r['anchors']} anchors")
                print(f"  gap {len(r['missing'])} = {r['gap_portable']} portable "
                      f"+ {len(r['missing_asm'])} assembly")
                asm = set(r["missing_asm"])
                for m in r["missing"]:
                    print(f"  MISSING {m}" + ("  [asm]" if m in asm else ""))
        return
    if "--json" in argv:
        print(json.dumps(rows, indent=1))
        return

    tf = sum(r["go_funcs"] for r in rows)
    tp = sum(r["ported"] for r in rows)
    ta = sum(r["anchors"] for r in rows)
    tasm = sum(len(r["missing_asm"]) for r in rows)
    tport = sum(r["gap_portable"] for r in rows)
    split = f"{tf - tp} left = {tport} portable + {tasm} assembly"
    if "--md" in argv:
        print("| package | Go .go | Go LOC | Go fns | ported | % | .rs | anchors |")
        print("|---|--:|--:|--:|--:|--:|--:|--:|")
        for r in sorted(rows, key=lambda r: -r["go_funcs"]):
            print(f"| `{r['pkg']}` | {r['go_files']} | {r['go_loc']} | {r['go_funcs']} "
                  f"| {r['ported']} | {r['pct']}% | {r['rs_files']} | {r['anchors']} |")
        print(f"\n**TOTAL: {tp}/{tf} = {100.0*tp/tf:.1f}%** across {len(rows)} in-scope "
              f"packages; {ta} provenance anchors. {split}.")
        return

    print(f"{'package':44} {'.go':>4} {'goLOC':>6} {'fns':>4} {'port':>4} {'%':>6} {'.rs':>4} {'anch':>4}")
    for r in sorted(rows, key=lambda r: -r["go_funcs"]):
        print(f"{r['pkg']:44} {r['go_files']:4} {r['go_loc']:6} {r['go_funcs']:4} "
              f"{r['ported']:4} {r['pct']:5.1f}% {r['rs_files']:4} {r['anchors']:4}")
    print(f"\nTOTAL {tp}/{tf} funcs = {100.0*tp/tf:.1f}%   "
          f"{len(rows)} packages   {sum(r['go_loc'] for r in rows)} Go LOC vs "
          f"{sum(r['rs_loc'] for r in rows)} goish LOC   {ta} anchors")
    print(f"      {split}")


if __name__ == "__main__":
    main()
