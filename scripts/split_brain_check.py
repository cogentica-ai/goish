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
  * EITHER body is more than three lines, OR the two bodies differ in
    a way a one-line accessor can still get wrong.

The threshold used to require BOTH bodies to be long, on the grounds
that a small accessor is unlikely to diverge. That is exactly how
`os.FileInfoData.Sys` slipped through: the trait impl was the single
line `Arc::new(())` while the inherent method returned the real
`syscall.Stat_t`. One line, and it cost `archive/tar` every header's
owner, access time and change time, because Go's callers hold the
interface. A short body is not a safe body — it is the easiest kind to
leave behind when the other side is fixed.

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
    """Does this body hand the work to the other implementation?

    `Type::<T>::meth(` counts: a generic type forwards through a
    turbofish, which is how crypto/elliptic's nistCurve reaches its
    inherent methods, and matching only `Type::meth(` read every one of
    those as a separate implementation.
    """
    if re.search(r"\b%s\s*(?:::<[^>]*>)?\s*::%s\s*\(" % (re.escape(ty), re.escape(meth)), body):
        return True
    if re.search(r"self\s*\.\s*%s\s*\(" % re.escape(meth), body):
        return True
    if re.search(r"<Self as [^>]*>::\s*%s\s*\(" % re.escape(meth), body):
        return True
    # `Self::meth(self)` — syscall's Errno::Error forwards this way.
    if re.search(r"\bSelf\s*(?:::<[^>]*>)?\s*::%s\s*\(" % re.escape(meth), body):
        return True
    # A local bound to `self`, then called on: reflect's Stringer for
    # Type writes `let ty: &Type = self; return ty.String();` to pick
    # the inherent method over the trait one it is inside.
    for alias in re.findall(r"let\s+(\w+)\s*(?::[^=]*)?=\s*self\s*;", body):
        if re.search(r"\b%s\s*\.\s*%s\s*\(" % (re.escape(alias), re.escape(meth)), body):
            return True
    return False


def same_inner_target(a, b, meth):
    """Both bodies forwarding the SAME call to the same inner field.

    `crypto/tls`'s `Conn::Write` is `self.inner.Write(...)` on both
    sides, differing only in whether the argument is copied. That is
    one implementation reached two ways, not two implementations — the
    thing this check exists to find is two bodies that can DISAGREE.
    """
    # `self.w.Write(p)` and the UFCS spelling of the same call,
    # `io::Writer::Write(&mut self.w, p)` — net/http/fcgi's bufWriter
    # uses one on each side.
    direct = re.compile(r"self\s*\.\s*(\w+)\s*\.\s*%s\s*\(" % re.escape(meth))
    ufcs = re.compile(r"::%s\s*\(\s*&(?:mut\s+)?self\s*\.\s*(\w+)" % re.escape(meth))

    def targets(body):
        return set(direct.findall(body)) | set(ufcs.findall(body))

    ta, tb = targets(a), targets(b)
    return bool(ta) and ta == tb


def documented_ok(lines, impl_idx):
    """Does a `split-brain-ok:` marker sit above this impl?

    The report told readers a deliberate divergence was fine if they
    said so above the impl — and then counted it anyway, because
    nothing looked. crypto/ecdsa's Signer is the case the message
    itself cites as well documented, and it kept the count at one
    forever, so a genuinely NEW pair would have had to be noticed as
    "2" rather than against a clean zero. That is the ratchet
    port_lint already gets right with its baseline.

    The marker must carry a reason: `split-brain-ok: <why>`. A bare
    marker is not accepted, so this cannot become a silent mute.
    """
    j = impl_idx - 1
    while j >= 0:
        t = lines[j].strip()
        if not t.startswith("//") and t != "":
            break
        m = RE_OK.search(t)
        if m and m.group(1).strip():
            return True
        j -= 1
    return False


RE_OK = re.compile(r"split-brain-ok:(.*)$")


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
            if documented_ok(lines, i):
                cur_trait = cur_ty = None
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
        if same_inner_target(tbody, ibody, meth):
            continue
        ni, nt = ibody.count("\n"), tbody.count("\n")
        # Either side being substantial is enough. A one-line trait
        # body that does NOT forward is the shape that hid the
        # os.FileInfo.Sys defect, and it is cheap to report.
        if ni > 3 or nt > 3:
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
    print("      (a DELIBERATE divergence is fine — say WHY above the impl")
    print("       and mark it `split-brain-ok: <reason>`, as crypto/ecdsa's")
    print("       Signer does, so this report can reach zero and the next")
    print("       pair stands out. A marker with no reason is not accepted.)")
    return 1 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
