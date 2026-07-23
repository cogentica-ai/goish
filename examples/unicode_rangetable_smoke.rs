// unicode_rangetable_smoke — RangeTable/Range16/Range32 + Is/In and
// the Mn/Zs category tables (the mechanism typescript-go's scanner
// uses with its own ID_Start/ID_Continue tables, plus the two stdlib
// tables its jsnum/organizeimports code names directly).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use goish::unicode;
use goish::{rune, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// A custom table in the shape typescript-go's scanner builds its own
// ID tables (scanner package, unicode.org-derived): R16 + R32 with a
// stride-2 entry, exactly like Go's package-level table vars.
static ODD_LATIN_AND_MUSIC: unicode::RangeTable = unicode::RangeTable {
    R16: &[
        unicode::Range16 { Lo: 0x0041, Hi: 0x0049, Stride: 2 }, // A C E G I
        unicode::Range16 { Lo: 0x00e9, Hi: 0x00e9, Stride: 1 }, // é
    ],
    R32: &[
        unicode::Range32 { Lo: 0x1d100, Hi: 0x1d1ff, Stride: 1 }, // musical symbols
    ],
    LatinOffset: 2,
};

static DIGITS_ONLY: unicode::RangeTable = unicode::RangeTable {
    R16: &[unicode::Range16 { Lo: 0x0030, Hi: 0x0039, Stride: 1 }],
    R32: &[],
    LatinOffset: 1,
};

#[goish::main]
fn main() {
    // ─── 1. constants ──────────────────────────────────────────────
    check(unicode::MaxASCII == 0x7F, b"t1: MaxASCII\n");
    check(unicode::MaxLatin1 == 0xFF, b"t1: MaxLatin1\n");
    check(unicode::MaxRune == 0x10FFFF, b"t1: MaxRune\n");

    // ─── 2. Zs (Separator, space) — incl. stride semantics ─────────
    check(unicode::Is(unicode::Zs, ' ' as rune), b"t2: space in Zs\n");
    check(!unicode::Is(unicode::Zs, '!' as rune), b"t2: '!' not Zs\n");
    // {0x0020, 0x00a0, 128}: only 0x20 and 0xA0 are members.
    check(unicode::Is(unicode::Zs, 0x00A0), b"t2: NBSP in Zs\n");
    check(!unicode::Is(unicode::Zs, 0x0060), b"t2: stride excludes 0x60\n");
    // Tab is Go-IsSpace but NOT category Zs.
    check(!unicode::Is(unicode::Zs, '\t' as rune), b"t2: tab not Zs\n");
    // {0x1680, 0x2000, 2432}: endpoints only.
    check(unicode::Is(unicode::Zs, 0x1680), b"t2: OGHAM mark in Zs\n");
    check(unicode::Is(unicode::Zs, 0x2000), b"t2: EN QUAD in Zs\n");
    check(!unicode::Is(unicode::Zs, 0x1FFF), b"t2: 0x1FFF not Zs\n");
    check(unicode::Is(unicode::Zs, 0x2003), b"t2: EM SPACE in Zs\n");
    check(unicode::Is(unicode::Zs, 0x3000), b"t2: IDEOGRAPHIC SPACE in Zs\n");
    check(!unicode::Is(unicode::Zs, 0x200B), b"t2: ZWSP not Zs\n");

    // ─── 3. Mn (Mark, nonspacing) — 16-bit binary search + 32-bit ──
    check(unicode::Is(unicode::Mn, 0x0301), b"t3: combining acute in Mn\n");
    check(!unicode::Is(unicode::Mn, 'a' as rune), b"t3: 'a' not Mn\n");
    // {0x05bf, 0x05c1, 2}: 0x05BF and 0x05C1, not 0x05C0.
    check(unicode::Is(unicode::Mn, 0x05BF), b"t3: 0x05BF in Mn\n");
    check(!unicode::Is(unicode::Mn, 0x05C0), b"t3: stride excludes 0x05C0\n");
    check(unicode::Is(unicode::Mn, 0x05C1), b"t3: 0x05C1 in Mn\n");
    // Deep in the table — exercises the binary-search path
    // (len(_Mn.R16) >> linearMax and r > MaxLatin1).
    check(unicode::Is(unicode::Mn, 0x20D0), b"t3: combining harpoon in Mn\n");
    check(unicode::Is(unicode::Mn, 0xFE00), b"t3: variation selector in Mn\n");
    // 32-bit ranges.
    check(unicode::Is(unicode::Mn, 0xE0100), b"t3: VS17 in Mn (R32)\n");
    check(unicode::Is(unicode::Mn, 0x1E94A), b"t3: ADLAM nukta in Mn (R32)\n");
    check(!unicode::Is(unicode::Mn, 0x1F600), b"t3: emoji not Mn\n");

    // ─── 4. custom tables (the scanner pattern) + In ───────────────
    check(unicode::Is(&ODD_LATIN_AND_MUSIC, 'A' as rune), b"t4: A in custom\n");
    check(!unicode::Is(&ODD_LATIN_AND_MUSIC, 'B' as rune), b"t4: stride excludes B\n");
    check(unicode::Is(&ODD_LATIN_AND_MUSIC, 'E' as rune), b"t4: E in custom\n");
    check(unicode::Is(&ODD_LATIN_AND_MUSIC, 0x00E9), b"t4: e-acute in custom\n");
    check(unicode::Is(&ODD_LATIN_AND_MUSIC, 0x1D11E), b"t4: G clef in custom R32\n");
    check(!unicode::Is(&ODD_LATIN_AND_MUSIC, 0x1D200), b"t4: past R32 range\n");

    check(
        unicode::In('7' as rune, &[&ODD_LATIN_AND_MUSIC, &DIGITS_ONLY]),
        b"t4b: In finds digit table\n",
    );
    check(
        !unicode::In('z' as rune, &[&ODD_LATIN_AND_MUSIC, &DIGITS_ONLY]),
        b"t4b: In misses both\n",
    );

    // ─── 5. negative runes handled like Go (uint32 compare) ────────
    check(!unicode::Is(unicode::Zs, -1), b"t5: negative rune not in table\n");

    let msg = b"UNICODE_RANGETABLE_OK all 5 test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
