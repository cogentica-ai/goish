#!/usr/bin/env python3
"""What goish actually exports, read from the tree rather than declared.

    scripts/goish_api.py                # summary
    scripts/goish_api.py strings        # one module's surface
    scripts/goish_api.py --json

goishc translates against a hand-maintained picture of goish's API
(`stdlib_registry.go`, 905 lines), and that picture drifts. It is why
drafts call `strings::FieldsFuncSeq`, `io::ReadWriteCloser`,
`net::FileListener` and a non-generic `bufio::Writer` — none of which
exist here. Every one of those became a compile error discovered only
after the translation was already in the tree.

This reads the truth off `src/` instead: for each module, the set of
names it makes public. It is deliberately syntactic — no rustc, no
macro expansion — because the question being answered is "would
`strings::Foo` resolve?", and a name that is not written anywhere in
the module's source cannot resolve no matter how it is expanded.

Known limits, stated so callers do not over-trust it: macro-generated
items are invisible, and a `pub use` of a glob (`pub use child::*;`)
re-exports names this cannot enumerate, so a module carrying one is
marked open and never reports a miss.
"""
import json
import os
import re
import sys

SRC = "src"

# `pub fn`, `pub(crate) fn`, `pub unsafe fn`, `pub extern "C" fn`, …
DECL = re.compile(
    r"^\s*pub(?:\([^)]*\))?\s+"
    r"(?:unsafe\s+|extern\s+\"[^\"]*\"\s+|const\s+|async\s+)*"
    r"(fn|struct|trait|enum|type|const|static|mod)\s+(?:r#)?([A-Za-z_]\w*)",
    re.M)
# `pub use foo::{A, B};` / `pub use foo::A;` / `pub use foo::*;`
USE = re.compile(r"^\s*pub\s+use\s+([^;]+);", re.M)
MACRO = re.compile(r"^\s*(?:#\[macro_export\]\s*)?macro_rules!\s+([A-Za-z_]\w*)", re.M)
# A `crate::var! { pub ErrNotExist: error = "..."; }` member. These are
# module-level names produced by a macro, so the `pub fn`/`pub static`
# forms above never see them — io/fs's five sentinels read as absent and
# `block.py deps` called four fs.go blocks blocked on errors that were
# right there. Struct fields match this shape too; over-reporting names
# only costs a missed warning, while under-reporting invents blockers.
VAR_MEMBER = re.compile(r"^\s*pub\s+([A-Za-z_]\w*)\s*:\s*[A-Za-z_&]", re.M)


def module_of(path):
    """`src/net/http/fs.rs` -> `net::http::fs`; `src/strings/mod.rs` -> `strings`."""
    rel = os.path.relpath(path, SRC)
    rel = rel[:-3] if rel.endswith(".rs") else rel
    parts = [p for p in rel.split(os.sep) if p not in ("mod", "lib")]
    return "::".join(parts)


def build(src=SRC):
    """{module_path: {"names": set, "open": bool}} for every .rs under src."""
    mods = {}
    for dirpath, _, files in os.walk(src):
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(dirpath, f)
            text = open(p, errors="replace").read()
            mod = module_of(p)
            e = mods.setdefault(mod, {"names": set(), "open": False,
                                      "types": set()})
            for kind, name in DECL.findall(text):
                e["names"].add(name)
                # goish spells its types in Go's lowercase (`string`,
                # `slice`, `error`), so a path segment cannot be told
                # from a module name by case. Callers need the type set
                # to know that `string::from_rune` is an associated
                # function, not a module lookup.
                if kind in ("struct", "trait", "enum", "type"):
                    e["types"].add(name)
            for name in MACRO.findall(text):
                e["names"].add(name)
            for name in VAR_MEMBER.findall(text):
                e["names"].add(name)
            for spec in USE.findall(text):
                if "*" in spec:
                    # A glob re-export forwards names this cannot see, so
                    # the module can never be said to LACK something.
                    e["open"] = True
                    continue
                for part in re.findall(r"([A-Za-z_]\w*)\s*(?:as\s+([A-Za-z_]\w*))?\s*[,}]",
                                       spec + ","):
                    e["names"].add(part[1] or part[0])
                tail = spec.rstrip().split("::")[-1].strip()
                if re.fullmatch(r"[A-Za-z_]\w*", tail):
                    e["names"].add(tail)
    return mods


def index_by_leaf(mods):
    """{leaf module name: merged entry}.

    Draft code writes `strings::Contains`, not `crate::strings::Contains`,
    so lookups key on the last path segment. Two modules sharing a leaf
    (`net::http::fs` and `io::fs`) merge, which can only turn a real miss
    into a silent pass — never the reverse.
    """
    out = {}
    for mod, e in mods.items():
        leaf = mod.split("::")[-1]
        t = out.setdefault(leaf, {"names": set(), "open": False,
                                  "types": set(), "paths": []})
        t["names"] |= e["names"]
        t["types"] |= e["types"]
        t["open"] = t["open"] or e["open"]
        t["paths"].append(mod)
    return out


def main():
    argv = sys.argv[1:]
    mods = build()
    if "--json" in argv:
        print(json.dumps(
            {m: sorted(e["names"]) for m, e in sorted(mods.items())}, indent=1))
        return 0
    named = [a for a in argv if not a.startswith("-")]
    if named:
        idx = index_by_leaf(mods)
        for want in named:
            e = idx.get(want)
            if not e:
                print(f"{want}: NO SUCH MODULE under src/")
                continue
            print(f"{want}  ({', '.join(e['paths'])})"
                  f"{'  [glob re-export — surface not fully visible]' if e['open'] else ''}")
            for n in sorted(e["names"]):
                print(f"  {n}")
        return 0
    tot = sum(len(e["names"]) for e in mods.values())
    print(f"{len(mods)} modules, {tot} public names under {SRC}/")
    for mod, e in sorted(mods.items(), key=lambda kv: -len(kv[1]["names"]))[:15]:
        print(f"  {len(e['names']):5}  {mod}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
