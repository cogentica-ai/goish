#!/usr/bin/env python3
"""dup_impl_check — free functions goish defines MORE times than Go does.

goish keeps producing second copies of things Go declares once: a
fourth `hasPort` deciding the SNI a TLS client sends, a third walk down
to a certificate's SubjectPublicKeyInfo, a second TLS 1.2 PRF deriving
the master secret. Each was found by hand, and each time the tell was
the same — a name that already existed somewhere else in the tree.

The duplicate is rarely WRONG when found (all three agreed with their
originals). What it costs is the guarantee: two implementations of one
rule drift, and the one a later edit fixes may not be the one the live
path calls.

The comparison that works is against Go's own count, because plenty of
names are legitimately per-package — `GenerateKey` exists once per
algorithm in both trees. A name goish declares MORE often than Go is
the signal.

  scripts/dup_impl_check.py           # Go declares it at most twice
  scripts/dup_impl_check.py --all     # no ceiling on Go's count

Free functions only (column 0). Methods are excluded deliberately: a
trait impl per type is Rust's normal shape and swamps the signal.

Heuristic, not sound. Known limits, both of which make it MISS things
rather than invent them:
  * a goish duplicate spelled under a different name is invisible;
  * Go generics parse fine now (`func pHash[H hash.Hash](`) — they did
    not at first, and `pHash` looked like a duplicate when Go declares
    it twice;
  * Go's `vendor/` is SCANNED, and must be: the stdlib vendors
    golang.org/x/net, goish ports those files, and their anchors point
    at them. Skipping it reported hasPort, canonicalAddr, idnaASCII and
    isASCII as duplicates when every copy is an anchored port.

If a hit looks wrong, check Go's declaration by hand before believing
the count. Both false-positive classes above were found that way.

A RETIRED duplicate still appears here, because what is left at the
site is a delegating adapter and an adapter is a declaration. So the
list does not shrink as you work it, and re-running it is not a
progress bar. The answers live in the code: every entry triaged so far
carries a note at its own definition saying either what it delegates to
or why it does not (`LEUint64`'s owned-vs-borrowed signature is the
clearest case for KEEPING one). Read the site before re-chasing a
name.
"""
import re, os, sys, subprocess, collections

GO_FUNC = re.compile(r'^func (?:\([^)]*\)\s*)?(\w+)\s*[\[(]', re.M)
RS_FUNC = re.compile(r'^(?:pub(?:\([^)]*\))? )?fn (\w+)', re.M)


def main():
    no_ceiling = '--all' in sys.argv
    goroot = subprocess.check_output(['go', 'env', 'GOROOT']).decode().strip()

    goish = collections.defaultdict(set)
    for root, dirs, fs in os.walk('src'):
        for f in sorted(fs):
            if not f.endswith('.rs'):
                continue
            p = os.path.join(root, f)
            for m in RS_FUNC.finditer(open(p).read()):
                goish[m.group(1)].add(p)

    go = collections.Counter()
    for root, dirs, fs in os.walk(os.path.join(goroot, 'src')):
        # NOT 'vendor': Go's stdlib genuinely vendors golang.org/x/net,
        # goish ports those files, and their anchors point at them.
        # Excluding it reported hasPort, canonicalAddr, idnaASCII and
        # isASCII as duplicates when every copy is an anchored port.
        dirs[:] = [d for d in dirs if d not in ('testdata', 'cmd')]
        for f in fs:
            if not f.endswith('.go') or f.endswith('_test.go'):
                continue
            try:
                src = open(os.path.join(root, f)).read()
            except Exception:
                continue
            for m in GO_FUNC.finditer(src):
                go[m.group(1)] += 1

    hits = []
    for name, files in goish.items():
        g = go.get(name, 0)
        if g == 0:
            continue                       # not a Go symbol at all
        if not no_ceiling and g > 2:
            continue                       # Go itself spreads it per package
        if len(files) <= g:
            continue
        hits.append((len(files) - g, len(files), g, name, sorted(files)))
    hits.sort(reverse=True)

    print("%d free fns goish declares more often than Go" % len(hits))
    for extra, n, g, name, files in hits:
        print("  %-30s goish x%d  Go x%d" % (name, n, g))
        for f in files:
            print("        %s" % f)


if __name__ == '__main__':
    main()
