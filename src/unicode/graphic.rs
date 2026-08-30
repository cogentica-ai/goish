// go: file unicode/graphic.go decls: IsGraphic, IsPrint, IsOneOf, In, IsControl, IsLetter, IsMark, IsNumber, IsPunct, IsSpace, IsSymbol
//
// unicode/graphic.go — the character-class predicates.
//
// Every one of them is the same two-step: a bit test against the
// 256-entry `properties` table for anything at or below U+00FF, and a
// range-table search above it. The Latin-1 half is what makes the
// common case one array index, and it is also where a hand-written
// approximation goes wrong — `^` and `` ` `` are Symbol, not Punct, and
// U+00A1..U+00BF are a mix of both.

#![allow(non_snake_case, non_upper_case_globals)]

use super::tables;
use super::{Is, MaxLatin1, RangeTable};
use crate::convert::uint32 as touint32;
use crate::types::rune;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pC
/// A control character.
pub(super) const pC: u8 = 1 << 0;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pP
/// A punctuation character.
pub(super) const pP: u8 = 1 << 1;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pN
/// A numeral.
pub(super) const pN: u8 = 1 << 2;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pS
/// A symbolic character.
pub(super) const pS: u8 = 1 << 3;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pZ
/// A spacing character.
pub(super) const pZ: u8 = 1 << 4;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pLu
/// An upper-case letter.
pub(super) const pLu: u8 = 1 << 5;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pLl
/// A lower-case letter.
pub(super) const pLl: u8 = 1 << 6;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pp
/// A printable character according to Go's definition.
pub(super) const pp: u8 = 1 << 7;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pg
/// A graphical character according to the Unicode definition.
pub(super) const pg: u8 = pp | pZ;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pLo
/// A letter that is neither upper nor lower case.
pub(super) const pLo: u8 = pLl | pLu;

// go: sdk 1.25.5 unicode/graphic.go:8-20 pLmask
const pLmask: u8 = pLo;

// go: sdk 1.25.5 unicode/graphic.go:22-25 GraphicRanges
/// The set of graphic characters according to Unicode.
pub static GraphicRanges: &[&RangeTable] = &[
    &tables::LETTER,
    &tables::MARK,
    &tables::NUMBER,
    &tables::PUNCT,
    &tables::SYMBOL,
    tables::Zs,
];

// go: sdk 1.25.5 unicode/graphic.go:27-31 PrintRanges
/// The set of printable characters according to Go. ASCII space,
/// U+0020, is handled separately.
pub static PrintRanges: &[&RangeTable] = &[
    &tables::LETTER,
    &tables::MARK,
    &tables::NUMBER,
    &tables::PUNCT,
    &tables::SYMBOL,
];

// go: sdk 1.25.5 unicode/graphic.go:33-42 IsGraphic
/// Whether the rune is defined as a Graphic by Unicode: letters, marks,
/// numbers, punctuation, symbols and spaces, from categories L, M, N,
/// P, S and Zs.
pub fn IsGraphic(r: rune) -> bool {
    // Go converts to uint32 to avoid the extra test for negative, and
    // indexes with uint8 to avoid the range check.
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pg != 0;
    }
    return In(r, GraphicRanges);
}

// go: sdk 1.25.5 unicode/graphic.go:44-54 IsPrint
/// Whether the rune is defined as printable by Go. The same set as
/// [`IsGraphic`], except that the only spacing character is ASCII
/// space, U+0020.
pub fn IsPrint(r: rune) -> bool {
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pp != 0;
    }
    return In(r, PrintRanges);
}

// go: sdk 1.25.5 unicode/graphic.go:56-66 IsOneOf
/// Whether the rune is a member of one of the ranges. [`In`] provides
/// a nicer signature and should be used in preference to this.
pub fn IsOneOf(ranges: &[&RangeTable], r: rune) -> bool {
    for inside in ranges.iter() {
        if Is(inside, r) {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 unicode/graphic.go:68-76 In
/// Whether the rune is a member of one of the ranges.
///
/// Go's is variadic (`In(r rune, ranges ...*RangeTable)`); goish takes
/// the slice, which is what the variadic form builds anyway.
pub fn In(r: rune, ranges: &[&RangeTable]) -> bool {
    for inside in ranges.iter() {
        if Is(inside, r) {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 unicode/graphic.go:78-87 IsControl
/// Whether the rune is a control character. The C (Other) Unicode
/// category includes more code points, such as surrogates; use
/// `Is(C, r)` to test for them.
pub fn IsControl(r: rune) -> bool {
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pC != 0;
    }
    // All control characters are < MaxLatin1.
    return false;
}

// go: sdk 1.25.5 unicode/graphic.go:89-95 IsLetter
/// Whether the rune is a letter (category L).
pub fn IsLetter(r: rune) -> bool {
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pLmask != 0;
    }
    return super::isExcludingLatin(&tables::LETTER, r);
}

// go: sdk 1.25.5 unicode/graphic.go:97-101 IsMark
/// Whether the rune is a mark character (category M).
pub fn IsMark(r: rune) -> bool {
    // There are no mark characters in Latin-1.
    return super::isExcludingLatin(&tables::MARK, r);
}

// go: sdk 1.25.5 unicode/graphic.go:103-109 IsNumber
/// Whether the rune is a number (category N).
pub fn IsNumber(r: rune) -> bool {
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pN != 0;
    }
    return super::isExcludingLatin(&tables::NUMBER, r);
}

// go: sdk 1.25.5 unicode/graphic.go:111-118 IsPunct
/// Whether the rune is a Unicode punctuation character (category P).
///
/// Note that Go searches the whole `Punct` table above Latin-1 rather
/// than `isExcludingLatin`, because `_P`'s `LatinOffset` covers only
/// part of what the property bits do.
pub fn IsPunct(r: rune) -> bool {
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pP != 0;
    }
    return Is(&tables::PUNCT, r);
}

// go: sdk 1.25.5 unicode/graphic.go:120-137 IsSpace
/// Whether the rune is a space character as defined by Unicode's
/// White_Space property. In the Latin-1 space that is `\t`, `\n`, `\v`,
/// `\f`, `\r`, ' ', U+0085 (NEL) and U+00A0 (NBSP).
pub fn IsSpace(r: rune) -> bool {
    // This property isn't the same as Z; Go special-cases it.
    if touint32(r) <= touint32(MaxLatin1) {
        if r == 0x09 || r == 0x0A || r == 0x0B || r == 0x0C || r == 0x0D || r == 0x20 {
            return true;
        }
        if r == 0x85 || r == 0xA0 {
            return true;
        }
        return false;
    }
    return super::isExcludingLatin(&tables::WHITE_SPACE, r);
}

// go: sdk 1.25.5 unicode/graphic.go:139-145 IsSymbol
/// Whether the rune is a symbolic character (category S).
pub fn IsSymbol(r: rune) -> bool {
    if touint32(r) <= touint32(MaxLatin1) {
        return tables::properties[(touint32(r) as usize) & 0xFF] & pS != 0;
    }
    return super::isExcludingLatin(&tables::SYMBOL, r);
}
