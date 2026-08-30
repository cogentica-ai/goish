// unicode_graphic_ref_smoke — unicode's character classes against Go.
// (unicode/graphic.go, unicode/letter.go, unicode/digit.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_unicode_graphic_ref.go` run in
// `package unicode_test` by `scripts/goref.sh`.
//
// The Latin-1 block is where a hand-written approximation goes wrong:
// '^' and '`' are Symbol, not Punct; U+00A1..U+00BF is a mix of the
// two; and U+00AA, U+00B5, U+00BA are letters. Above Latin-1 the answer
// comes from a range table, so the population counts over a fixed
// sample of the whole domain are what catch a table that is short a
// range.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::syscall;
use goish::types::rune;
use goish::unicode;

// One bitmask per Latin-1 code point, in the order:
//   1 control, 2 punct, 4 number, 8 symbol, 16 space, 32 upper,
//   64 lower, 128 print, 256 graphic, 512 letter, 1024 digit,
//   2048 title, 4096 mark.
const LATIN1: [u16; 256] = [
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0011, 0x0011, 0x0011,
    0x0011, 0x0011, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0190, 0x0182, 0x0182, 0x0182,
    0x0188, 0x0182, 0x0182, 0x0182, 0x0182, 0x0182, 0x0182, 0x0188, 0x0182, 0x0182, 0x0182, 0x0182,
    0x0584, 0x0584, 0x0584, 0x0584, 0x0584, 0x0584, 0x0584, 0x0584, 0x0584, 0x0584, 0x0182, 0x0182,
    0x0188, 0x0188, 0x0188, 0x0182, 0x0182, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0,
    0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0,
    0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x0182, 0x0182, 0x0182, 0x0188, 0x0182,
    0x0188, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0,
    0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0,
    0x03c0, 0x03c0, 0x03c0, 0x0182, 0x0188, 0x0182, 0x0188, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0011, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0110, 0x0182, 0x0188, 0x0188, 0x0188, 0x0188, 0x0188, 0x0182,
    0x0188, 0x0188, 0x0380, 0x0182, 0x0188, 0x0000, 0x0188, 0x0188, 0x0188, 0x0188, 0x0184, 0x0184,
    0x0188, 0x03c0, 0x0182, 0x0182, 0x0188, 0x0184, 0x0380, 0x0182, 0x0184, 0x0184, 0x0184, 0x0182,
    0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0,
    0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x0188,
    0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03a0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0,
    0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0,
    0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x03c0, 0x0188, 0x03c0, 0x03c0, 0x03c0, 0x03c0,
    0x03c0, 0x03c0, 0x03c0, 0x03c0,
];

fn mask(r: rune) -> u16 {
    let mut b: u16 = 0;
    if unicode::IsControl(r) {
        b |= 1;
    }
    if unicode::IsPunct(r) {
        b |= 2;
    }
    if unicode::IsNumber(r) {
        b |= 4;
    }
    if unicode::IsSymbol(r) {
        b |= 8;
    }
    if unicode::IsSpace(r) {
        b |= 16;
    }
    if unicode::IsUpper(r) {
        b |= 32;
    }
    if unicode::IsLower(r) {
        b |= 64;
    }
    if unicode::IsPrint(r) {
        b |= 128;
    }
    if unicode::IsGraphic(r) {
        b |= 256;
    }
    if unicode::IsLetter(r) {
        b |= 512;
    }
    if unicode::IsDigit(r) {
        b |= 1024;
    }
    if unicode::IsTitle(r) {
        b |= 2048;
    }
    if unicode::IsMark(r) {
        b |= 4096;
    }
    return b;
}

// Go's sampled population counts: every rune below U+10000, then every
// 17th rune to U+10FFFF. Order matches the bit order in `mask`.
const SCOUNTS: [(&str, u16, i64); 13] = [
    ("IsControl", 1, 65),
    ("IsPunct", 2, 640),
    ("IsNumber", 4, 797),
    ("IsSymbol", 8, 4078),
    ("IsSpace", 16, 25),
    ("IsUpper", 32, 1172),
    ("IsLower", 64, 1488),
    ("IsPrint", 128, 61003),
    ("IsGraphic", 256, 61019),
    ("IsLetter", 512, 54085),
    ("IsDigit", 1024, 387),
    ("IsTitle", 2048, 31),
    ("IsMark", 4096, 1402),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Every Latin-1 code point, all thirteen predicates at once.
    {
        let mut ok = true;
        let mut i = 0;
        while i < 256 {
            if mask(i as rune) != LATIN1[i] {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] Latin-1 x 13 predicates  PASS");
        } else {
            fmt::Println!("[ 1] Latin-1 x 13 predicates  FAIL");
            failed += 1;
        }
    }

    // 2. Population counts over Go's sample. A table short a range, or
    //    carrying an extra one, moves exactly one of these.
    {
        let mut counts: [i64; 13] = [0; 13];
        let mut r: rune = 0;
        while r < 0x10000 {
            let m = mask(r);
            let mut k = 0;
            while k < 13 {
                if m & SCOUNTS[k].1 != 0 {
                    counts[k] += 1;
                }
                k += 1;
            }
            r += 1;
        }
        r = 0x10000;
        while r <= 0x10FFFF {
            let m = mask(r);
            let mut k = 0;
            while k < 13 {
                if m & SCOUNTS[k].1 != 0 {
                    counts[k] += 1;
                }
                k += 1;
            }
            r += 17;
        }
        let mut ok = true;
        let mut k = 0;
        while k < 13 {
            if counts[k] != SCOUNTS[k].2 {
                ok = false;
            }
            k += 1;
        }
        if ok {
            fmt::Println!("[ 2] population counts        PASS");
        } else {
            fmt::Println!("[ 2] population counts        FAIL");
            let mut k = 0;
            while k < 13 {
                if counts[k] != SCOUNTS[k].2 {
                    fmt::Println!(
                        "     ",
                        SCOUNTS[k].0,
                        "got",
                        counts[k],
                        "want",
                        SCOUNTS[k].2
                    );
                }
                k += 1;
            }
            failed += 1;
        }
    }

    // 3. Negative runes are never anything.
    {
        if mask(-1) == 0 && mask(-2147483648) == 0 {
            fmt::Println!("[ 3] negative runes           PASS");
        } else {
            fmt::Println!("[ 3] negative runes           FAIL");
            failed += 1;
        }
    }

    // 4. The title-case letters that the old ASCII-only IsTitle
    //    returned false for. U+01C5 is LATIN CAPITAL LETTER D WITH
    //    SMALL LETTER Z WITH CARON; it is neither upper nor lower.
    {
        let mut ok = true;
        let titles: [rune; 6] = [0x01C5, 0x01C8, 0x01CB, 0x01F2, 0x1F88, 0x1FFC];
        let mut i = 0;
        while i < titles.len() {
            let r = titles[i];
            if !unicode::IsTitle(r) || unicode::IsUpper(r) || unicode::IsLower(r) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] title-case letters       PASS");
        } else {
            fmt::Println!("[ 4] title-case letters       FAIL");
            failed += 1;
        }
    }

    // 5. The Latin-1 runes an ASCII approximation gets backwards.
    {
        let mut ok = true;
        // '^' and '`' are Symbol, not Punct.
        if unicode::IsPunct(0x5E) || !unicode::IsSymbol(0x5E) {
            ok = false;
        }
        if unicode::IsPunct(0x60) || !unicode::IsSymbol(0x60) {
            ok = false;
        }
        // U+00A1 INVERTED EXCLAMATION MARK is Punct …
        if !unicode::IsPunct(0xA1) || unicode::IsSymbol(0xA1) {
            ok = false;
        }
        // … while U+00A2 CENT SIGN is Symbol.
        if unicode::IsPunct(0xA2) || !unicode::IsSymbol(0xA2) {
            ok = false;
        }
        // U+00AA, U+00B5 and U+00BA are letters.
        if !unicode::IsLetter(0xAA) || !unicode::IsLetter(0xB5) || !unicode::IsLetter(0xBA) {
            ok = false;
        }
        // U+00A0 NBSP is a space and is Graphic but not Print.
        if !unicode::IsSpace(0xA0) || !unicode::IsGraphic(0xA0) || unicode::IsPrint(0xA0) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 5] Latin-1 punct vs symbol  PASS");
        } else {
            fmt::Println!("[ 5] Latin-1 punct vs symbol  FAIL");
            failed += 1;
        }
    }

    // 6. Non-ASCII digits and numbers: Arabic-Indic U+0660 and
    //    Devanagari U+0966 are digits; Roman numeral U+2160 and
    //    superscript U+2070 are numbers but not digits.
    {
        let mut ok = true;
        if !unicode::IsDigit(0x0660) || !unicode::IsDigit(0x0966) {
            ok = false;
        }
        if unicode::IsDigit(0x2160) || !unicode::IsNumber(0x2160) {
            ok = false;
        }
        if unicode::IsDigit(0x2070) || !unicode::IsNumber(0x2070) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 6] non-ASCII digits/numbers PASS");
        } else {
            fmt::Println!("[ 6] non-ASCII digits/numbers FAIL");
            failed += 1;
        }
    }

    // 7. Spaces above Latin-1 come from White_Space, not category Z:
    //    U+2028 LINE SEPARATOR is a space; U+200B ZERO WIDTH SPACE is
    //    not.
    {
        let mut ok = true;
        if !unicode::IsSpace(0x2000) || !unicode::IsSpace(0x2028) || !unicode::IsSpace(0x3000) {
            ok = false;
        }
        if unicode::IsSpace(0x200B) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 7] White_Space above Latin1 PASS");
        } else {
            fmt::Println!("[ 7] White_Space above Latin1 FAIL");
            failed += 1;
        }
    }

    // 8. The four exported constants.
    {
        if unicode::MaxRune == 1114111
            && unicode::ReplacementChar == 65533
            && unicode::MaxASCII == 127
            && unicode::MaxLatin1 == 255
        {
            fmt::Println!("[ 8] constants                PASS");
        } else {
            fmt::Println!("[ 8] constants                FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
