#!/usr/bin/env python3
"""Rewrite text/language's base-language tables from an x/text dump.

Input is the TSV that tools/gen_language_base_ref.go prints: one
`code<TAB>canonical` line per accepted base-language subtag.

Two tables come out, and the split is the point:

  VALID_LANGS     every code whose canonical form DIFFERS from itself,
                  plus every code already carrying a script or region
                  (sh -> sr-Latn, mo -> ro-MD). Measured: 314 of 8984.
  LANG3_ACCEPTED  a bit per aaa..zzz for every accepted three-letter
                  code. 26^3 bits is 2197 bytes, where the same
                  information as strings is about a quarter of a
                  megabyte. x/text stores `langNoIndex` the same way
                  for the same reason.

Identity entries need no string at all: the parser uses the input.

Run from the repo root; see the header of tools/gen_language_base_ref.go
for the full recipe.
"""
import sys
import re

TABLE = "src/text/language_tables.rs"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: gen_language_tables.py <accepted.tsv>", file=sys.stderr)
        return 2
    acc = {}
    for line in open(sys.argv[1]):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 2 and parts[0]:
            acc[parts[0]] = parts[1]
    two = {k: v for k, v in acc.items() if len(k) == 2}
    three = {k: v for k, v in acc.items() if len(k) == 3}
    other = {k for k in acc if len(k) not in (2, 3)}
    if other:
        print("unexpected key lengths: %r" % sorted(other)[:5], file=sys.stderr)
        return 1

    # Keep every two-letter code as a pair: there are only 190 and the
    # parser has no bitmap for that half.
    canon = {k: v for k, v in two.items()}
    # Three-letter codes only need a pair when the canonical form is not
    # the code itself.
    canon.update({k: v for k, v in three.items() if v != k})

    bits = bytearray(2197)
    for k in three:
        i = (ord(k[0]) - 97) * 676 + (ord(k[1]) - 97) * 26 + (ord(k[2]) - 97)
        bits[i >> 3] |= 1 << (i & 7)

    src = open(TABLE).read()

    pairs = "".join('    ("%s", "%s"),\n' % (k, canon[k]) for k in sorted(canon))
    new_valid = (
        "pub(super) static VALID_LANGS: &[(&str, &str)] = &[\n" + pairs + "];"
    )
    start = src.index("pub(super) static VALID_LANGS")
    end = src.index("];", start) + 2
    src = src[:start] + new_valid + src[end:]

    rows = []
    for off in range(0, len(bits), 16):
        rows.append("    " + " ".join("0x%02x," % b for b in bits[off:off + 16]))
    bitmap = (
        "/// One bit per three-letter lowercase code, `aaa` at bit 0 through\n"
        "/// `zzz` at bit 17575, set when x/text's `language.Parse` accepts it.\n"
        "///\n"
        "/// This is goish's form of x/text's `langNoIndex`, and it exists for\n"
        "/// the same reason: 26^3 bits is 2197 bytes where the strings are a\n"
        "/// quarter of a megabyte. A code whose bit is set and which is absent\n"
        "/// from VALID_LANGS canonicalises to ITSELF.\n"
        "pub(super) static LANG3_ACCEPTED: [u8; 2197] = [\n"
        + "\n".join(rows)
        + "\n];"
    )
    marker = "pub(super) static LANG3_ACCEPTED"
    if marker in src:
        s2 = src.index(marker)
        # Back up over the doc comment.
        while True:
            prev = src.rfind("\n", 0, s2 - 1)
            line = src[prev + 1 : s2]
            if line.lstrip().startswith("///"):
                s2 = prev + 1
            else:
                break
        e2 = src.index("];", s2) + 2
        src = src[:s2] + bitmap + src[e2:]
    else:
        src = src.rstrip("\n") + "\n\n" + bitmap + "\n"

    open(TABLE, "w").write(src)
    print(
        "VALID_LANGS %d pairs (%d two-letter, %d non-identity three-letter); "
        "LANG3_ACCEPTED %d of 17576 bits set"
        % (
            len(canon),
            len(two),
            len(canon) - len(two),
            len(three),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
