#!/usr/bin/env python3
"""Dependency-order the unported declarations of a Go package.

`port_coverage.py --pkg X --by-decl` says WHAT is missing. This says
what can be ported NOW: for each missing declaration it reads the Go
body and finds which other missing declarations it calls, then reports
the ready set and the waves behind it.

Calls are matched receiver-aware where the receiver is recoverable
(`hs.foo(` with `hs` declared as a known type, or `x.foo(` where only
one missing decl has method `foo`). A bare-name match would link
clientHandshakeState.doFullHandshake to serverHandshakeState's
same-named method and report a false block.

  scripts/port_next.py crypto/tls
  scripts/port_next.py crypto/tls --exclude QUIC
"""
import os
import sys, re, sys, subprocess, collections

GOROOT = os.environ.get("GOROOT") or \
    "/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src"

# `go env GOROOT` prints the INSTALL root (/usr/local/go); the sources
# live under its `src`. Accept either spelling, because the failure
# mode of guessing wrong is silent: every anchored file resolves to a
# path that does not exist, every Go body reads as empty, and the
# script reports "0 anchored fns, 0 with a deficit" — which looks
# exactly like a clean sweep.
if not os.path.isdir(os.path.join(GOROOT, "crypto", "tls")):
    _alt = os.path.join(GOROOT, "src")
    if os.path.isdir(os.path.join(_alt, "crypto", "tls")):
        GOROOT = _alt
    else:
        sys.exit("port_next: no Go sources under %r (tried it and %r).\n"
                 "Set GOROOT to the Go install root or its src directory."
                 % (GOROOT, _alt))



def go_bodies(pkgdir):
    """{Recv.Method | Func: body text} for every decl in the package."""
    out = {}
    for f in sorted(os.listdir(pkgdir)):
        if not f.endswith(".go") or f.endswith("_test.go"):
            continue
        src = open(os.path.join(pkgdir, f), errors="replace").read().split("\n")
        for i, l in enumerate(src):
            m = re.match(r"^func\s*(?:\(\s*\w*\s*\*?(\w+)[^)]*\)\s*)?(\w+)", l)
            if not m:
                continue
            name = f"{m.group(1)}.{m.group(2)}" if m.group(1) else m.group(2)
            depth, buf = 0, []
            for j in range(i, len(src)):
                buf.append(src[j])
                depth += src[j].count("{") - src[j].count("}")
                if j > i and depth <= 0:
                    break
            out[name] = "\n".join(buf)
    return out


def main():
    pkg = sys.argv[1] if len(sys.argv) > 1 else "crypto/tls"
    excl = None
    if "--exclude" in sys.argv:
        excl = sys.argv[sys.argv.index("--exclude") + 1]

    sub = pkg.split("/", 1)[1] if "/" in pkg else pkg
    cov = subprocess.run(["python3", "scripts/port_coverage.py", pkg.split("/")[0],
                          "--pkg", sub, "--by-decl"],
                         capture_output=True, text=True).stdout
    missing = [l.split("MISSING ", 1)[1].strip() for l in cov.split("\n") if "MISSING " in l]
    missing = [m for m in missing if m != "_"]
    if excl:
        missing = [m for m in missing if excl.lower() not in m.lower()]

    bodies = go_bodies(os.path.join(GOROOT, pkg))
    by_method = collections.defaultdict(list)
    for m in missing:
        by_method[m.split(".")[-1]].append(m)

    dep = {m: set() for m in missing}
    for m in missing:
        body = re.sub(r"//.*", "", bodies.get(m, ""))
        recv_of = dict(re.findall(r"(\w+)\s*:?=\s*&?(\w+)\{", body))
        for meth, owners in by_method.items():
            for call in re.finditer(r"(?:(\w+)\.)?" + re.escape(meth) + r"\s*\(", body):
                if len(owners) == 1:
                    cand = owners[0]
                else:
                    recv = call.group(1)
                    ty = recv_of.get(recv)
                    cand = next((o for o in owners if o.split(".")[0] == ty), None)
                    if cand is None:
                        continue
                if cand != m:
                    dep[m].add(cand)

    waves, placed = [], set()
    remaining = set(missing)
    while remaining:
        ready = sorted(x for x in remaining if not (dep[x] - placed))
        if not ready:                     # cycle: emit the rest together
            waves.append(sorted(remaining))
            break
        waves.append(ready)
        placed |= set(ready)
        remaining -= set(ready)

    print(f"{pkg}: {len(missing)} declarations left"
          + (f" (excluding {excl})" if excl else "") + "\n")
    for i, w in enumerate(waves, 1):
        head = "READY NOW" if i == 1 else f"wave {i}"
        print(f"{head}  ({len(w)})")
        for m in w:
            blockers = sorted(dep[m])
            note = ""
            if blockers:
                note = "   after " + ", ".join(b.split(".")[-1] for b in blockers[:3])
                if len(blockers) > 3:
                    note += f" +{len(blockers)-3}"
            print(f"    {m}{note}")
        print()


main()
