#!/usr/bin/env python3
"""fiat64_to_rust — translate Fiat Cryptography's generated Go field
arithmetic into goish Rust.

    scripts/fiat64_to_rust.py <p256_fiat64.go> <out.rs> [prefix]

`prefix` defaults to the curve name in the filename; pass it explicitly
for files that do not follow that convention (edwards25519's
scalar_fiat.go uses `fiatScalar`).

crypto/internal/fips140/nistec/fiat's *_fiat64.go files are 11k lines of
machine-generated, fully-parenthesized straight-line code. Hand-porting
that volume invites exactly the silent transcription errors this repo has
already been bitten by, so it is translated mechanically instead.

The translator is deliberately strict: it parses the closed grammar those
files actually use and RAISES on anything it does not recognise. It can
fail to translate, but it cannot silently mistranslate.

Two shape changes, both forced and both documented in the emitted header:

  * Go's uint64 arithmetic wraps; Rust's panics in debug builds. Every
    `+` becomes wrapping_add and every `*` becomes wrapping_mul.
  * `pNCmovznzU64(&out, c, a, b)` returns its value instead of writing
    through an out-parameter. The out-param is a fiat-crypto calling
    convention, not part of the algorithm.
"""

import re
import sys

# ─── lexer ────────────────────────────────────────────────────────────

TOK = re.compile(r"""
      (?P<space>\s+)
    | (?P<hex>0x[0-9a-fA-F]+)
    | (?P<num>\d+)
    | (?P<ident>[A-Za-z_][A-Za-z_0-9]*)
    | (?P<op><<|>>|[-+*&|^~()\[\],])
""", re.VERBOSE)


def lex(s):
    toks, i = [], 0
    while i < len(s):
        m = TOK.match(s, i)
        if not m:
            raise SyntaxError('cannot lex at %r' % s[i:i + 40])
        i = m.end()
        if m.lastgroup != 'space':
            toks.append((m.lastgroup, m.group()))
    return toks


# ─── expression parser (Go precedence, on the subset used) ────────────
#
# Go binary precedence, highest first: * << >> &  then  + - | ^
# Unary: ^ (bitwise NOT).

MUL_OPS = {'*', '<<', '>>', '&'}
ADD_OPS = {'+', '-', '|', '^'}

# `pNUint1` is declared `type pNUint1 uint64`, so converting to it is
# exactly `uint64(...)`. `pNInt1` is int64 and never appears in a body —
# if that ever changes, the parser must raise rather than guess.
UINT64_CONV = re.compile(r'^(uint64|\w+Uint1)$')


class P:
    def __init__(self, toks, curve):
        self.t, self.i, self.curve = toks, 0, curve

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def next(self):
        v = self.t[self.i]
        self.i += 1
        return v

    def expect(self, val):
        k, v = self.next()
        if v != val:
            raise SyntaxError('expected %r, got %r' % (val, v))

    def parse(self):
        e = self.add()
        if self.i != len(self.t):
            raise SyntaxError('trailing tokens: %r' % (self.t[self.i:],))
        return e

    def add(self):
        left = self.mul()
        while self.peek()[1] in ADD_OPS:
            op = self.next()[1]
            right = self.mul()
            if op == '+':
                left = '%s.wrapping_add(%s)' % (paren(left), right)
            elif op == '-':
                left = '%s.wrapping_sub(%s)' % (paren(left), right)
            else:
                left = '(%s %s %s)' % (left, op, right)
        return left

    def mul(self):
        left = self.unary()
        while self.peek()[1] in MUL_OPS:
            op = self.next()[1]
            right = self.unary()
            if op == '*':
                left = '%s.wrapping_mul(%s)' % (paren(left), right)
            elif op in ('<<', '>>'):
                left = '(%s %s %s)' % (left, op, right)
            else:
                left = '(%s & %s)' % (left, right)
        return left

    def unary(self):
        k, v = self.peek()
        if v == '^':                       # Go's unary ^ is bitwise NOT
            self.next()
            return '(!%s)' % self.unary()
        return self.primary()

    def primary(self):
        k, v = self.next()
        if k in ('hex', 'num'):
            # No suffix: Go's untyped constants adapt to their context and
            # so do Rust's. Suffixing would force u64 into the u8-typed
            # ToBytes expressions. An ambiguous literal is a compile
            # error, never a silent wrong type.
            return v
        if v == '(':
            e = self.add()
            self.expect(')')
            return '(%s)' % e
        if k != 'ident':
            raise SyntaxError('unexpected token %r' % (v,))
        # call or index or plain identifier
        nk, nv = self.peek()
        if nv == '(':
            self.next()
            args = [self.add()]
            while self.peek()[1] == ',':
                self.next()
                args.append(self.add())
            self.expect(')')
            if len(args) == 1 and UINT64_CONV.match(v):
                # Not always identity: `uint64(arg1[i])` on a [N]uint8
                # widens, and dropping it would shift a u8.
                return 'uint64(%s)' % args[0]
            if v == 'uint8' and len(args) == 1:
                return 'uint8(%s)' % args[0]
            raise SyntaxError('unknown call %r' % v)
        if nv == '[':
            self.next()
            idx = self.add()
            self.expect(']')
            return '%s[%s]' % (v, idx)
        return v


def paren(e):
    return e if (e.startswith('(') and balanced(e)) else '(%s)' % e


def balanced(e):
    d = 0
    for i, c in enumerate(e):
        if c == '(':
            d += 1
        elif c == ')':
            d -= 1
            if d == 0 and i != len(e) - 1:
                return False
    return d == 0


def expr(s, curve):
    return P(lex(s), curve).parse()


# ─── statement translation ────────────────────────────────────────────

RE_VAR = re.compile(r'^var (x\d+) uint64$')
RE_ASSIGN = re.compile(r'^(x\d+) := (.+)$')
RE_TUPLE = re.compile(r'^(x\d+|_), (x\d+|_) = bits\.(Mul64|Add64|Sub64)\((.+)\)$')
RE_CMOV = re.compile(r'^\w+CmovznzU64\(&(x\d+), (.+)\)$')
RE_OUTIDX = re.compile(r'^out1\[(\d+)\] = (.+)$')
RE_OUTSTAR = re.compile(r'^\*out1 = (.+)$')


def split_args(s):
    out, depth, cur = [], 0, ''
    for c in s:
        if c == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
            continue
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        cur += c
    out.append(cur.strip())
    return out


def stmt(line, curve):
    s = line.strip()
    if RE_VAR.match(s):
        return None                       # Rust binds at the assignment

    m = RE_TUPLE.match(s)
    if m:
        a, b, fn, argstr = m.groups()
        args = [expr(x, curve) for x in split_args(argstr)]
        want = 2 if fn == 'Mul64' else 3
        if len(args) != want:
            raise SyntaxError('bits.%s with %d args' % (fn, len(args)))
        return 'let (%s, %s) = bits::%s(%s);' % (a, b, fn, ', '.join(args))

    m = RE_CMOV.match(s)
    if m:
        dst, argstr = m.groups()
        args = [expr(x, curve) for x in split_args(argstr)]
        if len(args) != 3:
            raise SyntaxError('Cmovznz with %d args' % len(args))
        return 'let %s = %sCmovznzU64(%s);' % (dst, curve, ', '.join(args))

    m = RE_ASSIGN.match(s)
    if m:
        return 'let %s = %s;' % (m.group(1), expr(m.group(2), curve))

    m = RE_OUTIDX.match(s)
    if m:
        return 'out1[%s] = %s;' % (m.group(1), expr(m.group(2), curve))

    m = RE_OUTSTAR.match(s)
    if m:
        return '*out1 = %s;' % expr(m.group(1), curve)

    raise SyntaxError('unrecognised statement: %r' % s)


# ─── function signatures ──────────────────────────────────────────────

RE_FUNC = re.compile(r'^func (\w+?)((?:Cmovznz|Mul|Square|Add|Sub|Opp|Nonzero|SetOne|FromMontgomery|ToMontgomery|Selectznz|ToBytes|FromBytes)\w*)\((.*)\) \{$')


def rust_params(curve, name, gosig, nlimbs):
    """Translate the Go parameter list. Every signature in these files is
    one of a handful of shapes; anything else raises."""
    mont = '[u64; %d]' % nlimbs
    # Keep Go's type names in the signatures; they are aliases for the
    # same array, but the names are what make the two sources diffable.
    ty = {
        '*%sMontgomeryDomainFieldElement' % curve:
            '%sMontgomeryDomainFieldElement' % curve,
        '*%sNonMontgomeryDomainFieldElement' % curve:
            '%sNonMontgomeryDomainFieldElement' % curve,
        '*uint64': 'u64',
        '%sUint1' % curve: '%sUint1' % curve,
    }
    aliases = set(ty.values())
    # The byte width is the curve's, not nlimbs*8 — p224 is 4 limbs but
    # 28 bytes, p521 is 9 limbs but 66.
    arr = re.compile(r'^\*\[(\d+)\](uint8|uint64)$')
    ps, first = [], True
    for p in split_args(gosig):
        if not p:
            continue
        pname, ptype = p.split(' ', 1)
        m = arr.match(ptype)
        if m:
            rt = '[%s; %s]' % ('u8' if m.group(2) == 'uint8' else 'u64', m.group(1))
        elif ptype in ty:
            rt = ty[ptype]
        else:
            raise SyntaxError('unknown param type %r' % ptype)
        by_ref = rt.startswith('[') or rt.endswith('FieldElement')
        if first and pname == 'out1':
            ps.append('out1: &mut %s' % rt)
        else:
            ps.append('%s: &%s' % (pname, rt) if by_ref else '%s: %s' % (pname, rt))
        first = False
    return ps


def main():
    src, dst = sys.argv[1], sys.argv[2]
    lines = open(src).read().split('\n')
    if len(sys.argv) > 3:
        curve = sys.argv[3]
    else:
        curve = re.search(r'(p224|p256|p384|p521)_fiat64', src).group(1)
    m = re.search(r'type %sMontgomeryDomainFieldElement \[(\d+)\]uint64' % curve,
                  open(src).read())
    if not m:
        raise SystemExit('cannot find %sMontgomeryDomainFieldElement' % curve)
    nlimbs = int(m.group(1))

    out, i = [], 0
    decls = []
    while i < len(lines):
        ln = lines[i]
        m = RE_FUNC.match(ln.strip())
        if not m:
            i += 1
            continue
        _, base, gosig = m.groups()
        fname = curve + base
        decls.append(fname)
        go_start = i + 1                   # 1-based line of the func decl
        body, i = [], i + 1
        while lines[i].strip() != '}':
            body.append(lines[i])
            i += 1
        go_end = i + 1
        i += 1
        anchor = ('// go: sdk 1.25.5 crypto/internal/fips140/nistec/fiat/'
                  '%s_fiat64.go:%d-%d %s' % (curve, go_start, go_end, fname))

        if base == 'CmovznzU64':
            out.append(
                anchor + '\n'
                '/// A single-word conditional move: `if arg1 = 0 then arg2\n'
                '/// else arg3`.\n'
                '///\n'
                '/// Go writes the result through `out1 *uint64`; that is a\n'
                '/// fiat-crypto calling convention, not part of the\n'
                '/// algorithm, so this returns it instead.\n'
                'pub(super) fn %sCmovznzU64(arg1: u64, arg2: u64, arg3: u64) -> u64 {' % curve)
            for b in body:
                s = b.strip()
                if not s or s.startswith('//'):
                    continue
                m2 = RE_OUTSTAR.match(s)
                if m2:
                    out.append('    return %s;' % expr(m2.group(1), curve))
                    continue
                st = stmt(s, curve)
                if st is not None:
                    out.append('    ' + st)
            out.append('}\n')
            continue

        ps = rust_params(curve, base, gosig, nlimbs)
        out.append(anchor)
        out.append('pub(super) fn %s(%s) {' % (fname, ', '.join(ps)))
        for b in body:
            s = b.strip()
            if not s or s.startswith('//'):
                continue
            st = stmt(s, curve)
            if st is not None:
                out.append('    ' + st)
        out.append('}\n')

    open(dst, 'w').write('\n'.join(out) + '\n')
    sys.stderr.write('%s: %d functions -> %s\n' % (curve, len(decls), dst))
    print(','.join(decls))


main()
