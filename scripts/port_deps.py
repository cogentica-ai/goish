#!/usr/bin/env python3
"""port_deps.py — pre-flight check before porting a Go package.

    scripts/port_deps.py crypto/elliptic          # go / no-go for one package
    scripts/port_deps.py crypto/elliptic -v       # + the symbols each import needs
    scripts/port_deps.py --ready crypto           # rank unported packages by readiness

Answers, in one command, the two questions that have to be settled BEFORE
writing any code:

  1. Does every package this one imports exist in goish, and how complete
     is it?
  2. Which *symbols* does the port actually reach for, and do they exist?

This exists because both questions were answered from memory instead, in
the same session, twice:

  * CRYPTO_PORT.md claimed crypto/elliptic was blocked on an unported
    math/big. math/big is 7053 lines of goish. `ls src/math/` disproves it.
  * ~900 lines of crypto/elliptic were written before discovering that
    big::Int has no PartialEq, so a struct holding one cannot derive it.

Package presence is necessary but NOT sufficient — question 2 is the one
that bites. Run with -v and grep the symbols it lists before writing.
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
        if not pat.search(text):
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


def imports_of(paths):
    """import path -> {local name, files that use it}"""
    found = {}
    for p in paths:
        src = open(p, errors="replace").read()
        block = IMPORT_BLOCK.search(src)
        entries = []
        if block:
            for m in IMPORT_LINE.finditer(block.group(1)):
                entries.append((m.group(1), m.group(2)))
        for m in IMPORT_ONE.finditer(src):
            entries.append((None, m.group(1)))
        for alias, path in entries:
            local = alias or path.rsplit("/", 1)[-1]
            e = found.setdefault(path, {"local": local, "files": [], "syms": set()})
            e["files"].append(os.path.basename(p))
            if alias not in ("_", "."):
                for u in USE.finditer(src):
                    if u.group(1) == local:
                        e["syms"].add(u.group(2))
    return found


def goish_dir(import_path):
    """Where goish would keep this package, or None if it is not a package."""
    if import_path in ALIASES:
        mapped = ALIASES[import_path]
        if mapped is None:
            return None
        return os.path.join(SRC, mapped)
    if import_path.startswith("golang.org/") or import_path.startswith("github.com/"):
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
        return "present"
    return "MISSING"


def coverage(subtree, pkg):
    """Reuse port_coverage.py's numbers for one package, if it knows it."""
    try:
        out = subprocess.check_output(
            [sys.executable, os.path.join(HERE, "port_coverage.py"), subtree,
             "--pkg", pkg],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    m = re.search(r"(\d+)/(\d+) ported \(([\d.]+)%\)", out)
    return m.group(0) if m else None


def check(import_path, verbose):
    gr = goroot()
    pkgdir = os.path.join(gr, "src", import_path)
    if not os.path.isdir(pkgdir):
        sys.exit("port_deps: no such Go package: %s" % import_path)
    files = go_files(pkgdir)
    imps = imports_of(files)

    print("== %s (%d .go files)" % (import_path, len(files)))
    self_cov = None
    if import_path.startswith("crypto"):
        rel = import_path[len("crypto"):].lstrip("/") or "."
        self_cov = coverage("crypto", rel)
    print("   own coverage: %s" % (self_cov or "not measured"))
    print()

    blockers, externals, symbol_gaps = [], [], []
    print("   %-42s %-9s %s" % ("import", "state", "coverage"))
    print("   %s" % ("-" * 74))
    for path in sorted(imps):
        d = goish_dir(path)
        state = present(d, path)
        cov = ""
        if state == "present" and path.startswith("crypto"):
            rel = path[len("crypto"):].lstrip("/") or "."
            cov = coverage("crypto", rel) or ""
        print("   %-42s %-9s %s" % (path, state, cov))
        if state == "MISSING":
            blockers.append(path)
        if state == "external":
            externals.append(path)
        gone = []
        if state == "present":
            gone = missing_symbols(d, imps[path]["syms"])
        if verbose and imps[path]["syms"]:
            syms = sorted(imps[path]["syms"])
            print("       uses: %s" % ", ".join(syms))
        if gone:
            print("       ABSENT from goish: %s" % ", ".join(gone))
            symbol_gaps.append((path, gone))
    print()

    if blockers:
        print("   NO-GO: %d import(s) absent from goish: %s"
              % (len(blockers), ", ".join(blockers)))
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
    return 1 if (blockers or symbol_gaps) else 0


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
        m = re.match(r"(\d+)/(\d+) ported \(([\d.]+)%\)", cov)
        done, total, pct = int(m.group(1)), int(m.group(2)), float(m.group(3))
        if total == 0 or pct >= 100.0:
            continue
        imps = imports_of(go_files(dirpath))
        missing = [p for p in imps if present(goish_dir(p), p) == "MISSING"]
        external = [p for p in imps if present(goish_dir(p), p) == "external"]
        rows.append((total - done, rel, pct, missing, external))
    rows.sort(reverse=True)
    print("%-44s %6s  %5s  %s" % ("package", "gap", "done", "blockers"))
    print("-" * 100)
    for gap, rel, pct, missing, external in rows:
        note = ""
        if missing:
            note = "MISSING: " + ",".join(missing)
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
