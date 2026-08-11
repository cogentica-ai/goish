#!/usr/bin/env python3
"""anchor_by_name — add GOISH014 provenance anchors to an already-written
port by matching Rust fn names against the Go declarations they came from.

    scripts/anchor_by_name.py <rust-file> <go-import-path> <go-file>...
    scripts/anchor_by_name.py --dry-run <rust-file> <go-import-path> <go-file>...

A port with no anchors is counted by port_coverage.py but proven by
nothing: GOISH018 cannot diff it against Go, so a dropped or subtly
renamed function is invisible. This walks the Go files, records each
declaration's name and line span (methods keyed by both `Method` and
`Recv.Method`), then inserts a matching anchor above every unanchored
`fn` in the Rust file.

A bare method name is often ambiguous — edwards25519.go declares `Zero`
on projP2, projCached and affineCached — but the Rust side is not
ambiguous at all: the fn sits inside `impl projCached { … }`. So the
enclosing impl type is tracked and used to disambiguate, and the anchor
is written with its Go receiver (`projCached.Zero`) rather than the bare
name. Only a name that is still ambiguous after that is reported.

It is conservative on purpose:
  * a Rust fn whose name matches no Go decl is left alone and REPORTED,
    so it can be judged by hand rather than mis-anchored;
  * a name that is ambiguous even after impl-block disambiguation is also
    reported rather than guessed;
  * an fn that already has an anchor is never touched;
  * `--dry-run` prints what would be inserted and writes nothing.

The manifest line is not written — GOISH017 wants a human to decide what
belongs in it, which is the whole point of the check.
"""
import re
import sys

RE_GOFUNC = re.compile(
    r'^func\s+(?:\((?P<recv>\w+)\s+\*?(?P<rtype>[\w\[\]]+)\)\s+)?(?P<name>\w+)\s*[\(\[]')
RE_RUSTFN = re.compile(r'^(?P<indent>\s*)(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+(?P<name>\w+)')
# `impl Foo {`, `impl<'a> Foo {`, `impl Trait for Foo {`, `impl Foo<T> {`.
# The captured group is always the *implementing* type, which is what Go
# spells as the method receiver.
RE_IMPL = re.compile(
    r'^\s*impl(?:\s*<[^>]*>)?\s+(?:.+\s+for\s+)?(?P<ty>[A-Za-z_]\w*)')


def go_decls(path):
    """name -> (file, start, end); methods also under Recv.Method."""
    lines = open(path).read().split('\n')
    out = {}
    i = 0
    base = path.rsplit('/', 1)[-1]
    while i < len(lines):
        m = RE_GOFUNC.match(lines[i])
        if not m:
            i += 1
            continue
        start = i + 1
        depth = lines[i].count('{') - lines[i].count('}')
        j = i
        while depth > 0 and j + 1 < len(lines):
            j += 1
            depth += lines[j].count('{') - lines[j].count('}')
        end = j + 1
        keys = [m.group('name')]
        if m.group('rtype'):
            keys.append('%s.%s' % (m.group('rtype'), m.group('name')))
        for k in keys:
            out.setdefault(k, []).append((base, start, end))
        i = j + 1
    return out


def main():
    argv = sys.argv[1:]
    dry = '--dry-run' in argv
    argv = [a for a in argv if a != '--dry-run']
    rust, pkg = argv[0], argv[1]
    decls = {}
    for g in argv[2:]:
        for k, v in go_decls(g).items():
            decls.setdefault(k, []).extend(v)

    src = open(rust).read().split('\n')
    out, unmatched, ambiguous, anchored = [], [], [], 0
    # Enclosing `impl <Type>` block, tracked by brace depth. A method's
    # impl type is Go's receiver, which is what disambiguates a shared
    # method name like `Zero`.
    impl_ty, impl_depth, depth = None, None, 0
    for idx, line in enumerate(src):
        im = RE_IMPL.match(line)
        if im and impl_ty is None:
            impl_ty, impl_depth = im.group('ty'), depth
        m = RE_RUSTFN.match(line)
        if m:
            # Already anchored, or explicitly declared Goish-only?
            prev = idx - 1
            has = False
            while prev >= 0 and (src[prev].strip().startswith('//')
                                 or src[prev].strip().startswith('///')
                                 or src[prev].strip().startswith('#[')):
                if src[prev].strip().startswith('// go:'):
                    has = True
                    break
                prev -= 1
            name = m.group('name')
            if not has:
                # Prefer the receiver-qualified key when we are inside an
                # impl block: `projCached.Zero` beats a three-way ambiguous
                # `Zero`.
                sym, hits = name, decls.get(name)
                if impl_ty and decls.get('%s.%s' % (impl_ty, name)):
                    sym = '%s.%s' % (impl_ty, name)
                    hits = decls[sym]
                if not hits:
                    unmatched.append(name)
                elif len(hits) > 1:
                    ambiguous.append(sym)
                else:
                    f, s, e = hits[0]
                    anchor = ('%s// go: sdk 1.25.5 %s/%s:%d-%d %s'
                              % (m.group('indent'), pkg, f, s, e, sym))
                    if dry:
                        print('  %s:%d %s' % (rust, idx + 1, anchor.strip()))
                    # GOISH014 wants the anchor as the FIRST line of the
                    # comment block above the fn, not the last — so back
                    # up over any doc comment or attribute already there.
                    k = len(out)
                    while k > 0 and (out[k - 1].strip().startswith('//')
                                     or out[k - 1].strip().startswith('#[')):
                        k -= 1
                    out.insert(k, anchor)
                    anchored += 1
        out.append(line)
        depth += line.count('{') - line.count('}')
        if impl_depth is not None and depth <= impl_depth:
            impl_ty, impl_depth = None, None

    if not dry:
        open(rust, 'w').write('\n'.join(out))
    print('%s %d fn(s) in %s' % ('would anchor' if dry else 'anchored', anchored, rust))
    if unmatched:
        print('  NO GO COUNTERPART (judge by hand): %s' % ', '.join(sorted(set(unmatched))))
    if ambiguous:
        print('  AMBIGUOUS across the given Go files: %s' % ', '.join(sorted(set(ambiguous))))


main()
