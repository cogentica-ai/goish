#!/usr/bin/env python3
"""anchor_port.py - add goishlint GOISH014 provenance anchors to a ported file.

    scripts/anchor_port.py src/crypto/des/block.rs

For every `fn` in the file, ensures the FIRST line of the comment block
directly above it is an anchor:

    // go: sdk 1.25.5 crypto/des/block.go:12-38 cryptBlock

The Go file+line is taken from an existing legacy `// Go: block.go:12`
marker in that comment block when present; otherwise the Go source is
searched for a `func` matching the Rust fn name and its line span used.
The Go package path is derived from the .rs path (src/crypto/des/block.rs
-> crypto/des/block.go), overridable with --gofile.

`--fill-none "<reason>"` anchors every remaining fn that has no Go
counterpart as `// go: none — <reason>` (goish-idiom scaffolding: nil
impls, trait shims, local helpers). Their names are printed so they can
be pasted into the file's `// go: file … decls:` manifest.

Idempotent: a comment block that already starts with `// go:` is left
alone. Nothing is written unless at least one anchor changes.
"""
import os, re, sys, subprocess

SDK = os.environ.get("GOISH_SDK_VER", "1.25.5")

RS_FN = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_]\w*)")
LEGACY = re.compile(r"^\s*//\s*Go:\s*([\w./]+\.go):(\d+)")


def goroot():
    if os.environ.get("GOROOT"):
        return os.environ["GOROOT"]
    return subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()


def go_funcs(path):
    """ident -> (start_line, end_line) for every top-level func in a Go file."""
    out, lines = {}, open(path, errors="replace").read().split("\n")
    cur, start = None, 0
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", ln)
        if m:
            if cur:
                out.setdefault(cur, (start, i - 1))
            cur, start = m.group(1), i
            if ln.rstrip().endswith("}"):  # one-liner
                out.setdefault(cur, (start, i))
                cur = None
        elif cur and ln == "}":
            out.setdefault(cur, (start, i))
            cur = None
    if cur:
        out.setdefault(cur, (start, len(lines)))
    return out


def norm(s):
    return s.lower().replace("_", "")


def main():
    rs = sys.argv[1]
    gofile = None
    if "--gofile" in sys.argv:
        gofile = sys.argv[sys.argv.index("--gofile") + 1]
    if gofile is None:
        rel = rs
        for p in ("src/", "./"):
            if rel.startswith(p):
                rel = rel[len(p):]
        gofile = os.path.splitext(rel)[0] + ".go"
    gopath = os.path.join(goroot(), "src", gofile)
    if not os.path.exists(gopath):
        sys.exit(f"anchor_port: no Go source at {gopath}")
    fill_none = None
    if "--fill-none" in sys.argv:
        fill_none = sys.argv[sys.argv.index("--fill-none") + 1]
    filled = []
    funcs = go_funcs(gopath)
    bykey = {norm(k): v for k, v in funcs.items()}

    lines = open(rs).read().split("\n")
    out, i, added = [], 0, 0
    while i < len(lines):
        m = RS_FN.match(lines[i])
        if not m:
            out.append(lines[i]); i += 1; continue
        indent, name = m.group(1), m.group(2)

        # Walk back over the contiguous comment/attribute block already emitted.
        j = len(out) - 1
        block = []
        while j >= 0 and (out[j].strip().startswith(("//", "///", "#[")) or out[j].strip() == ""):
            if out[j].strip() == "" and block:
                break
            if out[j].strip() == "":
                j -= 1; continue
            block.append(j); j -= 1
        block.reverse()
        comment_lines = [k for k in block if out[k].strip().startswith(("//", "///"))]

        # Already anchored? Only a line matching the real GOISH014 grammar
        # counts — the legacy `// Go: block.go:77` marker lowercases to
        # `// go:` but carries no source, so it must be rewritten.
        if comment_lines:
            first = out[comment_lines[0]].strip()
            body = first.lstrip("/").strip()
            if body.lower().startswith("go:"):
                rest = body[3:].strip().lower()
                if rest.startswith(("sdk ", "none")) or "@" in rest.split(".go:")[0]:
                    out.append(lines[i]); i += 1; continue  # already anchored

        span = None
        for k in comment_lines:
            lm = LEGACY.match(out[k])
            if lm:
                base = os.path.basename(lm.group(1))
                start = int(lm.group(2))
                gf = os.path.join(os.path.dirname(gofile), base)
                key = None
                for kk, vv in funcs.items():
                    if vv[0] <= start <= vv[1]:
                        key = kk; break
                span = (gf, funcs.get(key, (start, start)), key)
                break
        if span is None and norm(name) in bykey:
            span = (gofile, bykey[norm(name)], name)
        if span is None:
            if fill_none:
                reason = fill_none
                out.insert(comment_lines[0] if comment_lines else len(out),
                           f"{indent}// go: none — {reason}")
                added += 1
                filled.append(name)
            out.append(lines[i]); i += 1; continue

        gf, (a, b), sym = span
        anchor = f"{indent}// go: sdk {SDK} {gf}:{a}-{b}" + (f" {sym}" if sym else "")
        ins = comment_lines[0] if comment_lines else len(out)
        out.insert(ins, anchor)
        added += 1
        out.append(lines[i]); i += 1

    if added:
        open(rs, "w").write("\n".join(out))
    print(f"{rs}: {added} anchors added" + (f" ({len(filled)} as `go: none`: {', '.join(filled)})" if filled else ""))


if __name__ == "__main__":
    main()
