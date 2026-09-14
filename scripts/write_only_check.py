#!/usr/bin/env python3
"""write_only_check — struct fields goish WRITES and never READS.

The sibling of scripts/dead_port_check.py. That one asks which ported
functions nothing calls; this one asks the same about struct fields,
which is how `Transport.idleConnWait`, jsontext's `AllowInvalidUTF8`
and net/lookup's nine ignored contexts were each found by hand.

A field with every write present reads as finished bookkeeping. Only
grepping for a READ tells "wired" from "accepted and ignored" apart.

Two passes, because the first one alone is unreadable:

  1. Every field declared in a struct under src/ whose name never
     appears as `.field` (outside an assignment) anywhere in src/ or
     examples/.  ~200 of ~3,750.
  2. Of those, the ones whose name GO reads in the corresponding
     stdlib package.  ~40, and that list is worth opening.

Pass 2 is the discriminating question, and it is the same one §2e
settled on: a field Go never reads either is faithful (net/http/
cookiejar's `entry.LastAccess` is written twice and read nowhere, in
both trees), and an ASN.1 marshalling shape or a field on a public
error type is written for someone else entirely.

  scripts/write_only_check.py            # pass 2 (the useful list)
  scripts/write_only_check.py --all      # pass 1 as well

Heuristic, not sound: the struct regex catches some non-structs, and
a field read only through reflection or a macro will look unread. It
is a list to triage, not a gate — do not wire it into `make lint`.
"""
import re, os, sys, subprocess, collections


def rust_fields():
    """(file, struct, field) -> declaration line, for every struct under src/."""
    out = {}
    for root, dirs, fs in os.walk('src'):
        for f in sorted(fs):
            if not f.endswith('.rs'):
                continue
            p = os.path.join(root, f)
            src = open(p).read()
            for m in re.finditer(r'(?:pub |pub\(crate\) )?struct (\w+)[^;{]*\{(.*?)\n\}', src, re.S):
                name, body = m.group(1), m.group(2)
                base = src[:m.start()].count('\n') + 1
                for fm in re.finditer(r'^\s*(?:pub(?:\([^)]*\))? )?(\w+)\s*:', body, re.M):
                    fld = fm.group(1)
                    if fld in ('fn', 'impl', 'where', 'type'):
                        continue
                    out[(p, name, fld)] = base + body[:fm.start()].count('\n') + 1
    return out


def corpus():
    blob = []
    for root, dirs, fs in os.walk('src'):
        for f in fs:
            if f.endswith('.rs'):
                blob.append(open(os.path.join(root, f)).read())
    for f in os.listdir('examples'):
        if f.endswith('.rs'):
            blob.append(open(os.path.join('examples', f)).read())
    return '\n'.join(blob)


def go_reads(pkgdir, field):
    """`.Field` not immediately followed by an assignment, in non-test .go."""
    n = 0
    for root, dirs, fs in os.walk(pkgdir):
        dirs[:] = [d for d in dirs if d != 'testdata']
        for f in fs:
            if not f.endswith('.go') or f.endswith('_test.go'):
                continue
            try:
                src = open(os.path.join(root, f)).read()
            except Exception:
                continue
            n += len(re.findall(r'\.' + re.escape(field) + r'\b(?!\s*[:]?=[^=])', src))
    return n


def main():
    show_all = '--all' in sys.argv
    goroot = subprocess.check_output(['go', 'env', 'GOROOT']).decode().strip()

    fields = rust_fields()
    blob = corpus()
    unread = []
    for (p, st, fld), ln in sorted(fields.items()):
        if not re.search(r'\.' + re.escape(fld) + r'\b(?!\s*=[^=])', blob):
            unread.append((p, st, fld, ln))

    print("pass 1: %d fields scanned, %d with no `.field` read" % (len(fields), len(unread)))
    if show_all:
        for p, st, fld, ln in unread:
            print("    %s:%d  %s.%s" % (p, ln, st, fld))

    hits = []
    for p, st, fld, ln in unread:
        d = os.path.join(goroot, 'src', os.path.dirname(p)[len('src/'):])
        if not os.path.isdir(d):
            continue
        n = go_reads(d, fld)
        if n:
            hits.append((n, p, ln, st, fld))
    hits.sort(reverse=True)

    print("pass 2: %d of those are READ by Go in the same package" % len(hits))
    for n, p, ln, st, fld in hits:
        print("    %-46s %-40s Go reads x%d" % ("%s:%s" % (p, ln), "%s.%s" % (st, fld), n))


if __name__ == '__main__':
    main()
