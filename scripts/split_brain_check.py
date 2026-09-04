#!/usr/bin/env python3
"""Find a type whose trait impl and inherent method are TWO implementations.

Go has one method set. A `*File` IS an `io.Writer`, so there is exactly
one `Write`. Rust needs the trait impl written separately, and the
honest shape is for one side to forward to the other:

    impl io::Writer for File {
        fn Write(&mut self, p: slice<byte>) -> (int, error) {
            return File::Write(self, p);          // <- forwards
        }
    }

When neither side forwards, the type has two implementations of one
operation and they drift. That is not hypothetical: until 9840c49
`io::Writer for File` called write(2) itself and reported
`errors.New("write failed")` — no path, no errno, no closed-file
detection — while the inherent `File::Write` on the same file reported
"write /path: no space left on device". Everything generic goes through
the trait (io::Copy, fmt::Fprintf, every `dyn io::Writer`), so
`io.Copy(f, r)` onto a full disk said "write failed" and `f.Write(…)`
said what actually happened. Nothing failed; the two answers were just
different, and only the worse one reached most callers.

The check reports a pair when ALL of these hold:

  * a type has an inherent method and a trait-impl method of the same
    name, in the same file;
  * neither body calls the other (`Type::meth(`, `self.meth(`, or
    `<Self as Trait>::meth(`);
  * BOTH bodies are more than three lines, so a genuinely different
    small accessor is not reported.

Forwarding in EITHER direction is fine — crypto/md5 puts the real
implementation in the trait and forwards the inherent one, which is
equally single-sourced.

Exit status is 0 unless --strict is given and something is reported,
so it is safe in a pre-commit hook by default.
"""

import argparse
import os
import re
import sys

SRC = "src"

RE_IMPL = re.compile(r"^impl(?:<[^>]*>)?\s+(?:([A-Za-z_][\w:]*)\s+for\s+)?([A-Za-z_]\w*)")
RE_FN = re.compile(r"^\s{4}(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_]\w*)")


def delegates(body, ty, meth):
    """Does this body hand the work to the other implementation?"""
    return bool(
        re.search(r"\b%s::%s\s*\(" % (re.escape(ty), re.escape(meth)), body)
        or re.search(r"self\s*\.\s*%s\s*\(" % re.escape(meth), body)
        or re.search(r"<Self as [^>]*>::\s*%s\s*\(" % re.escape(meth), body)
    )


def scan_file(path):
    """[(ty, meth, trait, inherent_lines, trait_lines)] for this file."""
    lines = open(path, errors="replace").read().split("\n")
    inherent, trait_blocks = {}, []
    cur_trait = cur_ty = None
    i = 0
    while i < len(lines):
        m = RE_IMPL.match(lines[i])
        if m:
            cur_trait, cur_ty = m.group(1), m.group(2)
            i += 1
            continue
        if lines[i].startswith("}"):
            cur_trait = cur_ty = None
            i += 1
            continue
        f = RE_FN.match(lines[i])
        if f and cur_ty:
            j = i + 1
            while j < len(lines) and lines[j] != "    }":
                j += 1
            body = "\n".join(lines[i : j + 1])
            if cur_trait is None:
                inherent[(cur_ty, f.group(1))] = body
            else:
                trait_blocks.append((cur_trait, cur_ty, f.group(1), body))
            i = j + 1
            continue
        i += 1

    out = []
    for tr, ty, meth, tbody in trait_blocks:
        ibody = inherent.get((ty, meth))
        if ibody is None:
            continue
        if delegates(tbody, ty, meth) or delegates(ibody, ty, meth):
            continue
        ni, nt = ibody.count("\n"), tbody.count("\n")
        if ni > 3 and nt > 3:
            out.append((ty, meth, tr, ni, nt))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero when any pair is reported")
    args = ap.parse_args()

    hits = []
    for root, _, files in os.walk(SRC):
        for fn in sorted(files):
            if fn.endswith(".rs"):
                p = os.path.join(root, fn)
                for h in scan_file(p):
                    hits.append((p,) + h)

    if not hits:
        print("split_brain_check: OK — every trait impl forwards.")
        return 0

    print("split_brain_check: %d pair(s) implement one operation twice:" % len(hits))
    for p, ty, meth, tr, ni, nt in hits:
        print("    %s: %s::%s" % (p, ty, meth))
        print("      inherent %d lines, `%s` impl %d lines, neither forwards"
              % (ni, tr, nt))
    print("      (a DELIBERATE divergence is fine — say so above the impl,")
    print("       as crypto/ecdsa's Signer does, so the next reader knows.)")
    return 1 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
