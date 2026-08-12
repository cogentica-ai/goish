#!/usr/bin/env python3
"""port_coverage.py - measure goish's port coverage of a Go stdlib subtree.

    scripts/port_coverage.py crypto            # coverage table for crypto/
    scripts/port_coverage.py crypto --json     # machine-readable
    scripts/port_coverage.py crypto --pkg tls  # per-package detail (missing fns)
    scripts/port_coverage.py crypto --md       # markdown table (for tracking docs)
    scripts/port_coverage.py crypto --by-decl  # count Recv.Method, not bare names

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
# tracked as performance work — see PROGRESS.md.
# `--purego` reports the subset reachable without any asm, for triage.
SKIP_ASM = re.compile(r"_(asm|amd64)\.go$")

FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\(\[]", re.M)

# The same match, but keeping the receiver type. `FUNC` collapses every
# method that shares a name — `marshal` on fifteen handshake-message
# types is ONE entry, and it counts as ported the moment any one of them
# is. Measured 2026-08-12: crypto/ has 1780 receiver-qualified
# declarations behind 1493 counted names, so 16% of the real surface is
# invisible, and crypto/tls is 727 behind 296.
#
# `--by-decl` reports the receiver-qualified figure. It is not the
# default because every published number, and the whole lint baseline
# workflow, is keyed to the name-level count; switching silently would
# restate them all. Use it to see the true denominator.
FUNC_RECV = re.compile(
    r"^func\s+(?:\(\s*\w+\s+\*?(\w+)\s*\)\s*)?([A-Za-z_]\w*)\s*[\(\[]", re.M)


def decl_key(recv, name):
    """`Recv.Method` when there is a receiver, else the bare name —
    the same keying `anchor_by_name.py` uses for anchors."""
    return "%s.%s" % (recv, name) if recv else name
RSFN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_]\w*)", re.M)
ANCHOR = re.compile(r"^\s*//\s*go:", re.M)
# A Go declaration that goish deliberately resolves somewhere else, so it
# will never have a same-named counterpart here. The motivating case is a
# `//go:linkname` pair: Go declares the body on one side and a bodyless
# stub on the other, and goish — which has no linkname — writes the body
# once, on whichever side can reach the field. crypto/sha3 read 26/27
# forever because of that, which is the squatter problem inverted: the
# number lies, only downward.
#
# The reason text after the em dash is REQUIRED and is what keeps this
# from becoming a way to launder a gap into 100%. Waived decls leave the
# denominator (they are not work) but are printed on their own line, so
# they can never quietly inflate a percentage.
WAIVED = re.compile(
    r"^\s*//\s*go:\s*waived\s+([A-Za-z_][\w.]*)\s*(?:—|--)\s*\S", re.M)


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
    """Fold case, but NOT underscores.

    goish keeps Go's spelling (CONTRIBUTING.md §5: `fileLogger` stays
    `fileLogger`), so the only legitimate drift is case. Folding `_`
    away as well made every invented snake_case helper collide with a
    real Go name: `crypto/tls`'s hand-written `read_record`,
    `negotiate_alpn`, `send_alert` and `select_signature_scheme` each
    counted as a port of Go's `readRecord`, `negotiateALPN`, `sendAlert`
    and `selectSignatureScheme` while sharing no code with them. That
    is the squatter problem measured from the other end — 15 of tls's
    37 "ported" names were this, and `anchor_by_name.py` confirms none
    of those files contain a single function Go declares.
    """
    return s.lower()


PUREGO = False
BY_DECL = False


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
    (`//go:build (!amd64 && !s390x) || purego`) is left alone here,
    because which side of that goish implements is a porting decision,
    not a platform fact — silently dropping those would shrink the
    denominator in our favour.

    `other_route` handles those, and only once the *anchors* say which
    side goish took. That is evidence rather than assumption, which is
    what makes it safe to shrink the denominator on."""
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


ROUTE_SUFFIX = re.compile(r"_(asm|amd64|noasm|generic|purego)+$")


def build_line(path):
    """The file's `//go:build` constraint, or '' if it has none."""
    try:
        with open(path, errors="replace") as f:
            for line in f:
                st = line.strip()
                if st.startswith("//go:build "):
                    return st[len("//go:build "):].strip()
                if st.startswith("package "):
                    return ""
    except Exception:
        pass
    return ""


def route_stem(name):
    """`p256_asm.go` -> `p256`; `fe_amd64_noasm.go` -> `fe`."""
    return ROUTE_SUFFIX.sub("", name[:-3])


def other_route(gofiles, dirpath, anchored):
    """Go files implementing an alternative route to the one goish took.

    Go ships some algorithms twice behind mutually exclusive build tags —
    `p256.go` (`(!amd64 && …) || purego`) and `p256_asm.go`. A build
    compiles exactly one. goish picks a side by *porting* it, and the
    anchors say which: nistec carries 33 anchors citing `p256.go`, the
    pure-Go side.

    The functions unique to the side goish did NOT take are not work. They
    are scaffolding for the other implementation — `bytesToLimbs`,
    `p256Add`, `uint64IsZero` exist only to serve the assembly path, and
    porting them into a tree that took the pure-Go path would be writing
    code with no caller.

    Counting them was the fourth wrong-leverage claim of the same shape in
    this repo: nistec read `16 portable + 12 assembly` when its real
    portable remainder is zero. The bodyless-func test in `asm_decls` does
    not catch these, because they are ordinary Go with ordinary bodies —
    just on the road not taken.

    Deliberately conservative: a file is dropped only when it carries a
    build constraint naming `purego`, an alternative sharing its route
    stem IS anchored, and the file itself is NOT.
    """
    out = set()
    stems = {}
    for f in gofiles:
        if "purego" in build_line(os.path.join(dirpath, f)):
            stems.setdefault(route_stem(f), []).append(f)
    for group in stems.values():
        if len(group) < 2:
            continue
        taken = [f for f in group if f in anchored]
        if not taken:
            continue
        for f in group:
            if f not in anchored:
                out.add(f)
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
        byfile = {}
        for f in gofiles:
            src = open(os.path.join(dirpath, f), errors="replace").read()
            byfile[f] = {n for n in pc_FUNC(src) if not n.startswith("init")}
        out[rel or "."] = {"nfiles": len(gofiles), "loc": loc,
                           "asm": asm_decls(paths),
                           "dir": dirpath, "gofiles": gofiles, "byfile": byfile,
                           "funcs": sorted(f for f in funcs if not f.startswith("init"))}
    return out


def pc_FUNC(src):
    if BY_DECL:
        return {decl_key(r, n) for r, n in FUNC_RECV.findall(src)}
    return set(FUNC.findall(src))


ANCHOR_GO = re.compile(r"//\s*go:[^\n]*?([A-Za-z0-9_]+\.go):")

# The receiver-qualified symbol an anchor names, in both anchor shapes:
#   // go: sdk 1.25.5 crypto/des/block.go:217-239 desCipher.generateSubkeys
#   // go: file crypto/cipher/gcm.go decls: (*gcmFallback).Seal, newGCMFallback
# goish deliberately ports some Go methods as free fns (a `&mut` receiver
# on a value type has no impl block to live in), so `rust_decl_idents`
# can never synthesize their `Recv.Method` key — 15 ported, anchored
# declarations read MISSING under --by-decl because of it. The anchors
# are the authoritative link: anchor_check.py verifies each range names
# exactly that declaration and `make lint` gates on it, so an anchored
# symbol whose fn actually exists in the same file is a port.
ANCHOR_SDK_SYM = re.compile(
    r"//\s*go:\s*sdk\s+\S+\s+\S+\.go:\d+(?:-\d+)?\s+"
    r"((?:\(\*?\w+\)|\w+)(?:\.\w+)?)")
ANCHOR_FILE_DECLS = re.compile(r"//\s*go:\s*file\s+\S+\.go\s+decls:\s*([^\n]+)")


def anchored_decl_keys(src):
    """Every `Recv.Method` (or bare name) an anchor in `src` claims,
    with Go's `(*Type).Method` pointer spelling folded to `Type.Method`."""
    syms = set(ANCHOR_SDK_SYM.findall(src))
    for lst in ANCHOR_FILE_DECLS.findall(src):
        syms |= {s.strip() for s in lst.split(",") if s.strip()}
    return {re.sub(r"^\(\*?(\w+)\)", r"\1", s) for s in syms}


def _facts(paths):
    idents, loc, anchors, cited, unanchored = set(), 0, 0, set(), set()
    waived = set()
    for p in paths:
        src = open(p, errors="replace").read()
        waived |= {norm(w) for w in WAIVED.findall(src)}
        mine = rust_decl_idents(src) if BY_DECL else set(RSFN.findall(src))
        if BY_DECL:
            # Credit anchored Recv.Method keys whose method exists in this
            # file as a fn under any receiver shape — see anchored_decl_keys.
            # The fn-exists check keeps a stray anchor from crediting a
            # declaration nobody wrote.
            fns = set(RSFN.findall(src))
            mine |= {k for k in anchored_decl_keys(src)
                     if "." in k and k.split(".", 1)[1] in fns}
        idents |= mine
        n = len(ANCHOR.findall(src))
        anchors += n
        # A goish file with NO provenance anchor at all is where invented
        # code lives. Its fn names still match Go's by string, so they
        # count as "ported" — which is exactly how src/crypto/ecdsa/mod.rs
        # read as done for four sessions while holding 915 lines of
        # hand-rolled P-256. is_squatter only catches this when the WHOLE
        # package is invented; one anchorless file inside a partly-ported
        # package slips through. So the names are tracked and reported.
        if n == 0:
            unanchored |= {norm(i) for i in mine}
        cited |= set(ANCHOR_GO.findall(src))
        loc += src.count("\n")
    return {"idents": {norm(i) for i in idents}, "loc": loc,
            "nfiles": len(paths), "anchors": anchors, "cited": cited,
            "unanchored": unanchored, "waived": waived}



# Rust-side receiver qualification, mirroring anchor_by_name.py's
# impl-block tracking. Without this, `--by-decl` would compare Go's
# `Recv.Method` keys against bare Rust fn names and match almost
# nothing — a flag that understates as badly as the default overstates.
RE_IMPL = re.compile(
    r'^\s*impl(?:\s*<[^>]*>)?\s+(?:.+\s+for\s+)?(?P<ty>[A-Za-z_]\w*)')


def rust_decl_idents(src):
    """Every Rust fn, keyed `ImplType.fn` inside an impl block and by the
    bare name outside one. Both forms are emitted for a method, because
    Go reaches a method as `Recv.Method` while a free function that a
    port turned into an inherent method is still legitimately matched by
    name."""
    out, impl_ty, impl_depth, depth = set(), None, 0, 0
    impl_open = False
    for line in src.split("\n"):
        # A comment-only line is not code. Ported bodies quote Go verbatim,
        # and Go composite literals carry braces — counting those would
        # leave `impl_ty` stuck on whichever block came first, silently
        # scoring every later method as unported. Caught on
        # crypto/tls/common.rs, where five methods vanished this way.
        if line.lstrip().startswith("//"):
            continue
        m = RE_IMPL.match(line)
        if m and impl_ty is None:
            impl_ty, impl_depth, impl_open = m.group("ty"), depth, False
        fn = RSFN.match(line)
        if fn:
            name = fn.group(1)
            out.add(name)
            if impl_ty:
                out.add("%s.%s" % (impl_ty, name))
        depth += line.count("{") - line.count("}")
        # Only close the impl block once its brace has actually opened.
        # A multi-line `impl<F> Trait for Ty<F>` + `where` header leaves
        # depth unchanged on the `impl` line, and closing eagerly there
        # dropped every method in the block. Caught on
        # crypto/tls/handshake_messages.rs's marshalingFunction.
        if impl_ty is not None and depth > impl_depth:
            impl_open = True
        if impl_ty is not None and impl_open and depth <= impl_depth:
            impl_ty, impl_open = None, False
    return out


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
        # Functions belonging to a build-tag route goish did not take are
        # not remaining work — see other_route.
        dropped = other_route(g["gofiles"], g["dir"], r["cited"] if r else set())
        want = sorted({n for f, ns in g["byfile"].items() if f not in dropped
                       for n in ns})
        # Declarations goish resolves elsewhere by design leave the
        # denominator — they are not remaining work — but are carried on
        # the row so they stay visible. See WAIVED.
        wv = r["waived"] if r else set()
        waived = sorted(f for f in want if norm(f) in wv)
        want = [f for f in want if norm(f) not in wv]
        hit = [f for f in want if norm(f) in have]
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
            "waived": waived,
            "gap_portable": len(missing) - len(missing_asm),
            "unanchored": sorted(f for f in hit
                                 if r and norm(f) in r["unanchored"]),
        })
    return rows


def main():
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        sys.exit(__doc__)
    global PUREGO, BY_DECL
    PUREGO = "--purego" in argv
    BY_DECL = "--by-decl" in argv
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
                if r["waived"]:
                    print(f"  WAIVED {len(r['waived'])} decl(s) resolved "
                          f"elsewhere by design, out of the denominator: "
                          f"{' '.join(r['waived'])}")
                if r["unanchored"]:
                    print(f"  UNVERIFIED: {len(r['unanchored'])} of the {r['ported']} "
                          f"'ported' names come from goish files with NO `// go:` "
                          f"anchor. They match Go by NAME ONLY — GOISH018 cannot "
                          f"diff them, so a rename, a dropped arg or an invented "
                          f"body is invisible. Anchor them with "
                          f"scripts/anchor_by_name.py:")
                    print(f"    {' '.join(r['unanchored'])}")
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
    tun = sum(len(r["unanchored"]) for r in rows)
    twv = sum(len(r["waived"]) for r in rows)
    split = f"{tf - tp} left = {tport} portable + {tasm} assembly"
    if twv:
        split += (f"; {twv} decl(s) WAIVED out of the denominator "
                  f"(resolved elsewhere by design)")
    if tun:
        split += (f"; {tun} counted name(s) are UNVERIFIED "
                  f"(anchorless — name match only)")
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
