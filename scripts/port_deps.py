#!/usr/bin/env python3
"""port_deps.py — pre-flight check before porting a Go package.

    scripts/port_deps.py crypto/elliptic          # go / no-go for one package
    scripts/port_deps.py crypto/elliptic -v       # + the symbols each import needs
    scripts/port_deps.py --ready crypto           # rank unported packages by readiness

Answers, in one command, the three questions that have to be settled
BEFORE writing any code:

  1. Does every package this one imports exist in goish, and how complete
     is it?
  2. Which *symbols* does the port actually reach for, and do they exist?
  3. Is the target path free, or is it already held by invented code?

This exists because these were answered from memory instead:

  * CRYPTO_PORT.md claimed crypto/elliptic was blocked on an unported
    math/big. math/big is 7053 lines of goish. `ls src/math/` disproves it.
  * ~900 lines of crypto/elliptic were written before discovering that
    big::Int has no PartialEq, so a struct holding one cannot derive it.
  * crypto/ecdsa was ranked READY for four sessions running. Its path was
    occupied by 915 lines of hand-rolled P-256 — three packages' worth of
    unrelated code — that the live TLS handshake called. Path existence
    alone reported that as `present`.

Package presence is necessary but NOT sufficient. Questions 2 and 3 are
the ones that bite. Run with -v and grep the symbols it lists before
writing.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")

# Deliberately out of scope, mirroring port_coverage.py's SKIP: the
# BoringSSL bridge and its caches (goish has no cgo), the darwin-only
# x509 verifier, and non-linux syscall shims. Reporting these as blockers
# would hide the packages that are genuinely ready.
OUT_OF_SCOPE = re.compile(
    r"(^|/)(boring|bbig|bcache|_asm|cryptotest|checktest|syso|fipsonly)(/|$)"
    r"|^crypto/x509/internal/macos$"
    r"|^internal/syscall/windows"
)

# Go stdlib packages goish maps somewhere other than src/<path>.
ALIASES = {
    "math/big": "math/big",
    "internal/byteorder": "internal/byteorder",
    "hash": "hash",
    "io": "io",
    "errors": "errors",
    "bytes": "bytes",
    "strings": "strings",
    "sync": "sync",
    "time": "time",
    "unsafe": None,        # language, not a package
    "internal/godebug": None,
    "internal/cpu": None,
    "internal/goarch": None,
    "internal/goos": None,
    "runtime": "runtime",
    "math/bits": "math/bits",
    "encoding/binary": "encoding/binary",
    "encoding/hex": "encoding/hex",
    "encoding/asn1": "encoding/asn1",
    "crypto": "crypto",
    # Vendored x/crypto modules goish keeps under src/crypto/ rather than
    # mirroring GOROOT's src/vendor/ path.
    "golang.org/x/crypto/chacha20poly1305": "crypto/chacha20poly1305",
    "golang.org/x/crypto/chacha20": "crypto/chacha20",
    "golang.org/x/crypto/cryptobyte": "crypto/cryptobyte",
    "golang.org/x/crypto/cryptobyte/asn1": "crypto/cryptobyte/asn1",
}

IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)^\)", re.S | re.M)
IMPORT_ONE = re.compile(r'^import\s+(?:\w+\s+|_\s+|\.\s+)?"([^"]+)"', re.M)
IMPORT_LINE = re.compile(r'^\s*(?:(\w+|_|\.)\s+)?"([^"]+)"', re.M)

# Symbols used from an imported package: `pkg.Symbol`.
USE = re.compile(r"\b([a-z][a-z0-9]*)\.([A-Z]\w*)\b")


def rust_sources(d):
    """Every .rs under a goish package directory (or the single file)."""
    out = []
    if d and os.path.isfile(d + ".rs"):
        out.append(d + ".rs")
    if d and os.path.isdir(d):
        for dirpath, _, names in os.walk(d):
            out.extend(os.path.join(dirpath, n) for n in names if n.endswith(".rs"))
    return out


def missing_symbols(d, syms):
    """Which of `syms` are not declared anywhere in the goish package.

    This is the check that matters. Package presence is cheap and almost
    always true; it was `encoding/asn1` having BitString and RawValue but
    no Marshal/Unmarshal, and `math/big` having Int without PartialEq,
    that actually cost time.
    """
    if not syms:
        return []
    text = ""
    for f in rust_sources(d):
        try:
            text += open(f, errors="replace").read()
        except Exception:
            pass
    if not text:
        return sorted(syms)
    gone = []
    for sym in sorted(syms):
        pat = re.compile(
            r"\b(?:pub(?:\([^)]*\))?\s+)?"
            r"(?:unsafe\s+)?(?:const\s+)?"
            r"(?:fn|struct|enum|trait|type|static|const|mod|union)\s+%s\b" % re.escape(sym))
        # `goish::var! { pub EOF: error = "EOF"; }` declares a name without
        # any of those keywords; io::ErrShortWrite was reported absent.
        varpat = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?%s\s*:" % re.escape(sym), re.M)
        if not pat.search(text) and not varpat.search(text):
            gone.append(sym)
    return gone


def goroot():
    if os.environ.get("GOROOT"):
        return os.environ["GOROOT"]
    return subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()


def go_files(pkgdir):
    out = []
    for name in sorted(os.listdir(pkgdir)):
        if not name.endswith(".go") or name.endswith("_test.go"):
            continue
        path = os.path.join(pkgdir, name)
        with open(path, errors="replace") as f:
            head = f.read(400)
        if "//go:build ignore" in head:
            continue
        out.append(path)
    return out


def strip_comments(src):
    """Blank out // and /* */ comments, preserving offsets loosely."""
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            if j < 0:
                break
            out.append("\n")
            i = j + 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


VERSION_ELEM = re.compile(r"^v[2-9]\d*$")


def default_local(import_path):
    """The identifier Go binds an unaliased import to.

    It is the *package name*, not the last path element — and for a
    versioned module those differ: `math/rand/v2` binds to `rand`. Taking
    the last element made every `pkg.Symbol` use in a /vN package invisible
    to the symbol check, which is how `rand.NewChaCha8` — genuinely absent
    from goish, and needed by crypto/ecdsa's legacy signing path — got
    reported as no gap at all.
    """
    parts = import_path.rstrip("/").split("/")
    if len(parts) >= 2 and VERSION_ELEM.match(parts[-1]):
        return parts[-2]
    return parts[-1]


def imports_of(paths):
    """import path -> {local name, files that use it}"""
    found = {}
    for p in paths:
        src = open(p, errors="replace").read()
        block = IMPORT_BLOCK.search(src)
        # Symbol harvesting must not see comments: a doc reference like
        # `[crypto/aes.NewCipher]` is not a use, and reporting it absent
        # sends the reader off to port something nothing needs.
        code = strip_comments(src)
        entries = []
        if block:
            for m in IMPORT_LINE.finditer(block.group(1)):
                entries.append((m.group(1), m.group(2)))
        for m in IMPORT_ONE.finditer(src):
            entries.append((None, m.group(1)))
        for alias, path in entries:
            local = alias or default_local(path)
            e = found.setdefault(path, {"local": local, "files": [], "syms": set()})
            e["files"].append(os.path.basename(p))
            if alias not in ("_", "."):
                for u in USE.finditer(code):
                    if u.group(1) == local:
                        e["syms"].add(u.group(2))
    return found


def is_vendored(import_path):
    """True if GOROOT vendors this module under src/vendor/.

    `golang.org/x/crypto/cryptobyte` and `.../chacha20poly1305` both live
    in the Go source tree, so they are as portable as any stdlib package —
    and crypto/ecdsa and crypto/internal/hpke cannot be ported without
    them. Calling every `golang.org/...` path external hid both."""
    try:
        return os.path.isdir(os.path.join(goroot(), "src/vendor", import_path))
    except Exception:
        return False


def goish_dir(import_path):
    """Where goish would keep this package, or None if it is not a package."""
    if import_path in ALIASES:
        mapped = ALIASES[import_path]
        if mapped is None:
            return None
        return os.path.join(SRC, mapped)
    if import_path.startswith("golang.org/") or import_path.startswith("github.com/"):
        if is_vendored(import_path):
            # goish would keep a vendored module at the same path.
            return os.path.join(SRC, "vendor", import_path)
        return ""  # outside the SDK entirely
    return os.path.join(SRC, import_path)


def present(d, import_path=None):
    if import_path and OUT_OF_SCOPE.search(import_path):
        return "skipped"
    if d is None:
        return "n/a"
    if d == "":
        return "external"
    if os.path.isdir(d) or os.path.exists(d + ".rs"):
        return "SQUATTER" if is_squatter(d, import_path) else "present"
    return "MISSING"


def split_subtree(import_path):
    """(subtree, pkg) as port_coverage.py wants them, for any import path."""
    head = import_path.split("/")[0]
    return head, import_path[len(head):].lstrip("/") or "."


_COV_CACHE = {}


def coverage(subtree, pkg):
    """Reuse port_coverage.py's numbers for one package, if it knows it.

    Returns a dict, or None when port_coverage does not measure the
    package (vendored modules, non-SDK paths).
    """
    key = (subtree, pkg)
    if key in _COV_CACHE:
        return _COV_CACHE[key]
    try:
        out = subprocess.check_output(
            [sys.executable, os.path.join(HERE, "port_coverage.py"), subtree,
             "--pkg", pkg],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        out = ""
    m = re.search(r"(\d+)/(\d+) ported \(([\d.]+)%\).*?(\d+) anchors", out, re.S)
    got = None
    if m:
        got = {
            "text": "%s/%s ported (%s%%)" % (m.group(1), m.group(2), m.group(3)),
            "ported": int(m.group(1)),
            "total": int(m.group(2)),
            "pct": float(m.group(3)),
            "anchors": int(m.group(4)),
        }
    _COV_CACHE[key] = got
    return got


def coverage_of(import_path):
    """Coverage for an import path, for any subtree — not just crypto."""
    if import_path in ALIASES and ALIASES[import_path] != import_path:
        return None            # goish keeps it somewhere port_coverage can't map
    if import_path.startswith(("golang.org/", "github.com/")):
        return None
    return coverage(*split_subtree(import_path))


def is_squatter(d, import_path):
    """Goish code holds this package's path, but none of it is a port.

    A squatter is worse than a missing package: the path is taken, live
    consumers depend on the invented API, and `present` reports it as
    ready. `src/crypto/ecdsa/mod.rs` was 915 lines of hand-rolled P-256 —
    three packages' worth of unrelated code — under the name of a package
    that had never been ported, and every pre-flight run called it
    `present`.

    The test is deliberately strict: zero provenance anchors AND zero
    name-level coverage. A package that is merely *incomplete* has one or
    the other above zero, and is not a squatter.
    """
    if not import_path:
        return False
    cov = coverage_of(import_path)
    if not cov or cov["total"] == 0:
        return False
    return cov["anchors"] == 0 and cov["ported"] == 0


def goish_module_path(d):
    """`src/crypto/ecdsa` -> `crypto::ecdsa`, the prefix consumers spell."""
    rel = os.path.relpath(d, SRC)
    return "::".join(rel.split(os.sep))


def consumers(d):
    """Files outside the package that reference it by its goish module path.

    Matching the full `crypto::ecdsa::` prefix rather than a bare `ecdsa::`
    keeps `fips140::ecdsa::` — a different, genuinely ported package — out
    of the count.
    """
    pat = re.compile(r"\b%s::" % re.escape(goish_module_path(d)))
    inside = os.path.abspath(d) + os.sep
    hits = []
    for base in (SRC, os.path.join(ROOT, "examples")):
        for dirpath, _, names in os.walk(base):
            if (os.path.abspath(dirpath) + os.sep).startswith(inside):
                continue
            for n in names:
                if not n.endswith(".rs"):
                    continue
                p = os.path.join(dirpath, n)
                try:
                    if pat.search(open(p, errors="replace").read()):
                        hits.append(os.path.relpath(p, ROOT))
                except Exception:
                    pass
    return sorted(hits)


def check(import_path, verbose):
    gr = goroot()
    pkgdir = os.path.join(gr, "src", import_path)
    if not os.path.isdir(pkgdir):
        sys.exit("port_deps: no such Go package: %s" % import_path)
    files = go_files(pkgdir)
    imps = imports_of(files)

    print("== %s (%d .go files)" % (import_path, len(files)))
    self_cov = coverage_of(import_path)
    print("   own coverage: %s" % (self_cov["text"] if self_cov else "not measured"))

    self_dir = goish_dir(import_path)
    self_squats = present(self_dir, import_path) == "SQUATTER"
    if self_squats:
        users = consumers(self_dir)
        print()
        print("   SQUATTER: goish code already holds src/%s, and none of it is"
              % os.path.relpath(self_dir, SRC))
        print("   a port — %d functions, 0 anchors, 0%% coverage." % self_cov["total"])
        print("   The path must be freed before this package can be ported.")
        if users:
            print("   %d file(s) outside the package depend on the invented API:"
                  % len(users))
            for u in users:
                print("     %s" % u)
            print("   Each one has to move or be rewritten first — that cost is")
            print("   the real size of this port, and it is not in the gap column.")
    print()

    blockers, externals, squatters, symbol_gaps = [], [], [], []
    print("   %-42s %-9s %s" % ("import", "state", "coverage"))
    print("   %s" % ("-" * 74))
    for path in sorted(imps):
        d = goish_dir(path)
        state = present(d, path)
        cov = ""
        if state in ("present", "SQUATTER"):
            c = coverage_of(path)
            cov = c["text"] if c else ""
        print("   %-42s %-9s %s" % (path, state, cov))
        if state == "MISSING":
            blockers.append(path)
        if state == "external":
            externals.append(path)
        if state == "SQUATTER":
            squatters.append(path)
        gone = []
        if state in ("present", "SQUATTER"):
            gone = missing_symbols(d, imps[path]["syms"])
        if verbose and imps[path]["syms"]:
            syms = sorted(imps[path]["syms"])
            print("       uses: %s" % ", ".join(syms))
        if gone:
            print("       ABSENT from goish: %s" % ", ".join(gone))
            symbol_gaps.append((path, gone))
    print()

    if self_squats:
        print("   NO-GO: the target path is held by invented code (see above).")
        print("   Evict it first — move each concern to the package it actually")
        print("   belongs to, keeping goish-only shims under a `// go: none`")
        print("   banner (crypto/ecdh/x25519.rs is the worked example).")
    elif blockers:
        print("   NO-GO: %d import(s) absent from goish: %s"
              % (len(blockers), ", ".join(blockers)))
    elif squatters:
        print("   NO-GO: %d import(s) are SQUATTERS — the path exists but holds"
              % len(squatters))
        print("   invented code, so anything this port calls there is unported:")
        for p in squatters:
            print("     %s" % p)
    elif symbol_gaps:
        n = sum(len(g) for _, g in symbol_gaps)
        print("   NO-GO: every import exists, but %d symbol(s) do not:" % n)
        for path, gone in symbol_gaps:
            print("     %s: %s" % (path, ", ".join(gone)))
        print("   The package being present says nothing about this — it is")
        print("   the check that actually catches the expensive cases.")
    elif externals:
        print("   PARTIAL: needs non-SDK module(s): %s" % ", ".join(externals))
        print("   Those have no Go-SDK counterpart to port verbatim.")
    else:
        print("   GO: every import exists in goish.")
    print()
    print("   Symbol presence still is not sufficient. Before writing:")
    print("     * a type alias has no methods — `type ObjectIdentifier = slice<int>`")
    print("       and `type Hash = uint` both look present and take a newtype to fix;")
    print("     * confirm Clone/Default/PartialEq/Copy on every goish type that")
    print("       will sit in a struct field — derives fail silently at design")
    print("       time and loudly 900 lines later;")
    print("     * remember inherent impls do NOT satisfy a #[goish::interface]")
    print("       trait; the `impl Trait for T` block has to be written.")
    return 1 if (self_squats or blockers or squatters or symbol_gaps) else 0


def ready(subtree):
    """Rank unported packages by whether their dependencies are all present."""
    gr = goroot()
    base = os.path.join(gr, "src", subtree)
    rows = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ("testdata", "_asm")]
        if not any(f.endswith(".go") and not f.endswith("_test.go") for f in filenames):
            continue
        rel = os.path.relpath(dirpath, os.path.join(gr, "src"))
        pkg = rel[len(subtree):].lstrip("/") or "."
        cov = coverage(subtree, pkg)
        if not cov:
            continue
        done, total, pct = cov["ported"], cov["total"], cov["pct"]
        if total == 0 or pct >= 100.0:
            continue
        imps = imports_of(go_files(dirpath))
        states = {p: present(goish_dir(p), p) for p in imps}
        missing = [p for p, s in states.items() if s == "MISSING"]
        external = [p for p, s in states.items() if s == "external"]
        squat = [p for p, s in states.items() if s == "SQUATTER"]
        self_squat = present(goish_dir(rel), rel) == "SQUATTER"
        rows.append((total - done, rel, pct, missing, external, squat, self_squat))
    rows.sort(reverse=True)
    print("%-44s %6s  %5s  %s" % ("package", "gap", "done", "blockers"))
    print("-" * 100)
    for gap, rel, pct, missing, external, squat, self_squat in rows:
        if self_squat:
            # READY would be a lie: the path is occupied by invented code
            # and has to be evicted before a line of the port can land.
            note = "SQUATTED (evict src/%s first)" % rel
        elif missing:
            note = "MISSING: " + ",".join(missing)
        elif squat:
            note = "SQUATTER dep: " + ",".join(squat)
        elif external:
            note = "external: " + ",".join(external)
        else:
            note = "READY"
        print("%-44s %6d  %4.0f%%  %s" % (rel, gap, pct, note))
    return 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "-v" in sys.argv
    if "--ready" in sys.argv:
        if not args:
            sys.exit("port_deps: --ready needs a subtree, e.g. `--ready crypto`")
        sys.exit(ready(args[0]))
    if not args:
        sys.exit(__doc__)
    sys.exit(check(args[0], verbose))


if __name__ == "__main__":
    main()
