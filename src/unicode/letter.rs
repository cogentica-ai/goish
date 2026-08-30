// go: file unicode/letter.go decls: is16, is32, Is, isExcludingLatin, IsUpper, IsLower, IsTitle, ToUpper, ToLower, ToTitle, SimpleFold
//
// goishlint:ignore GOISH018 to, To, SpecialCase.ToUpper, SpecialCase.ToTitle, SpecialCase.ToLower, lookupCaseRange, convertCase, CaseRange.Delta — Go maps case
//     through a `CaseRanges` table of `CaseRange{Lo, Hi, Delta}`
//     triples and a `SpecialCase` slice for the Turkish/Azeri dotted
//     I. goish ships a generated flat rune->rune table instead, so
//     `ToUpper`/`ToLower`/`ToTitle` answer identically for the default
//     case but there is no `CaseRange` to hold a `Delta` and no
//     `SpecialCase` to override it. Porting the table shape is its own
//     commit; the flat table is checked against Go over the whole
//     0..0x10FFFF range by `unicode_case_smoke`.
//
// goishlint:ignore GOISH021 CaseRange, SpecialCase, d, UpperCase, LowerCase, TitleCase, MaxCase, UpperLower, CaseRanges, caseOrbit, foldPair, FoldCategory, FoldScript, Categories, Scripts, Properties — see the GOISH018 waiver above for the case
//     machinery, and the module root for the category/script maps goish
//     does not ship.
//
// unicode/letter.go — the `RangeTable` machinery every predicate in the
// package searches, plus the case mappings.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::convert::{rune as torune, uint16 as touint16, uint32 as touint32};
use crate::types::{int, rune};

// go: sdk 1.25.5 unicode/letter.go:11-19 MaxRune
/// Maximum valid Unicode code point.
pub const MaxRune: rune = 0x10FFFF;

// go: sdk 1.25.5 unicode/letter.go:11-19 ReplacementChar
/// Represents invalid code points.
pub const ReplacementChar: rune = 0xFFFD;

// go: sdk 1.25.5 unicode/letter.go:11-19 MaxASCII
/// Maximum ASCII value.
pub const MaxASCII: rune = 0x007F;

// go: sdk 1.25.5 unicode/letter.go:11-19 MaxLatin1
/// Maximum Latin-1 value.
pub const MaxLatin1: rune = 0x00FF;

/// `unicode.Range16` (letter.go:29) — a range of 16-bit code points
/// from `Lo` to `Hi` inclusive, at the given `Stride`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Range16 {
    pub Lo: u16,
    pub Hi: u16,
    pub Stride: u16,
}

/// `unicode.Range32` (letter.go:38) — a range of code points where
/// one or more values exceed 16 bits. `Lo` and `Hi` are always
/// `>= 1<<16`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Range32 {
    pub Lo: u32,
    pub Hi: u32,
    pub Stride: u32,
}

/// `unicode.RangeTable` (letter.go:21) — a set of Unicode code points
/// as sorted, non-overlapping ranges, split into 16-bit and 32-bit
/// slices to save space.
///
/// Goish deviation from the "no `&[T]` in public API" rule: table
/// data is compile-time static (Go's are package-level generated
/// vars; a scanner's ID_Start table is a `static`), so the fields are
/// `&'static` slices — the only const-constructible spelling. Runtime
/// slices never flow through here.
#[derive(Copy, Clone, Debug)]
pub struct RangeTable {
    pub R16: &'static [Range16],
    pub R32: &'static [Range32],
    /// Number of entries in R16 with `Hi <= MaxLatin1`.
    pub LatinOffset: int,
}

// Go: letter.go:87 — maximum table size for linear search of a
// non-Latin1 rune. Derived by running 'go test -calibrate'.
const LINEAR_MAX: usize = 18;

// go: sdk 1.25.5 unicode/letter.go:91-121 is16
// Go: letter.go:90 is16 — whether r is in the sorted slice of 16-bit
// ranges.
pub fn is16(ranges: &[Range16], r: u16) -> bool {
    if ranges.len() <= LINEAR_MAX || torune(r) <= MaxLatin1 {
        for range_ in ranges {
            if r < range_.Lo {
                return false;
            }
            if r <= range_.Hi {
                return range_.Stride == 1 || (r - range_.Lo) % range_.Stride == 0;
            }
        }
        return false;
    }

    // binary search over ranges
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let m = (lo + hi) >> 1;
        let range_ = &ranges[m];
        if range_.Lo <= r && r <= range_.Hi {
            return range_.Stride == 1 || (r - range_.Lo) % range_.Stride == 0;
        }
        if r < range_.Lo {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    return false;
}

// go: sdk 1.25.5 unicode/letter.go:124-154 is32
// Go: letter.go:123 is32 — whether r is in the sorted slice of 32-bit
// ranges.
pub fn is32(ranges: &[Range32], r: u32) -> bool {
    if ranges.len() <= LINEAR_MAX {
        for range_ in ranges {
            if r < range_.Lo {
                return false;
            }
            if r <= range_.Hi {
                return range_.Stride == 1 || (r - range_.Lo) % range_.Stride == 0;
            }
        }
        return false;
    }

    // binary search over ranges
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let m = (lo + hi) >> 1;
        let range_ = &ranges[m];
        if range_.Lo <= r && r <= range_.Hi {
            return range_.Stride == 1 || (r - range_.Lo) % range_.Stride == 0;
        }
        if r < range_.Lo {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    return false;
}

// go: sdk 1.25.5 unicode/letter.go:157-168 Is
/// `unicode.Is(rangeTab, r)` (letter.go:156) — whether the rune is in
/// the specified table of ranges.
pub fn Is(range_tab: &RangeTable, r: rune) -> bool {
    let r16 = range_tab.R16;
    // Compare as u32 to correctly handle negative runes.
    if !r16.is_empty() && touint32(r) <= touint32(r16[r16.len() - 1].Hi) {
        return is16(r16, touint16(r));
    }
    let r32 = range_tab.R32;
    if !r32.is_empty() && r >= torune(r32[0].Lo) {
        return is32(r32, touint32(r));
    }
    return false;
}

// go: sdk 1.25.5 unicode/letter.go:170-181 isExcludingLatin
/// Like [`Is`], but skips the Latin-1 prefix of the table: the caller
/// has already answered for those code points from the `properties`
/// bit table, so `LatinOffset` says how many R16 entries to skip.
pub fn isExcludingLatin(rangeTab: &RangeTable, r: rune) -> bool {
    let r16 = rangeTab.R16;
    // Compare as uint32 to correctly handle negative runes.
    let off = rangeTab.LatinOffset as usize;
    if r16.len() > off && crate::convert::uint32(r) <= crate::convert::uint32(r16[r16.len() - 1].Hi)
    {
        return is16(&r16[off..], crate::convert::uint16(r));
    }
    let r32 = rangeTab.R32;
    if !r32.is_empty() && r >= crate::convert::rune(r32[0].Lo) {
        return is32(r32, crate::convert::uint32(r));
    }
    return false;
}

// go: sdk 1.25.5 unicode/letter.go:150-156 IsUpper
/// Whether the rune is an upper-case letter.
///
/// Both halves are Go's: the Latin-1 test is `properties & pLmask ==
/// pLu`, an equality, not a bit test, because `pLmask` is `pLu | pLl`
/// and a letter is exactly one of the two.
pub fn IsUpper(r: rune) -> bool {
    if crate::convert::uint32(r) <= crate::convert::uint32(MaxLatin1) {
        return super::tables::properties[(crate::convert::uint32(r) as usize) & 0xFF]
            & super::graphic::pLo
            == super::graphic::pLu;
    }
    return isExcludingLatin(&super::tables::UPPER, r);
}

// go: sdk 1.25.5 unicode/letter.go:158-164 IsLower
/// Whether the rune is a lower-case letter.
pub fn IsLower(r: rune) -> bool {
    if crate::convert::uint32(r) <= crate::convert::uint32(MaxLatin1) {
        return super::tables::properties[(crate::convert::uint32(r) as usize) & 0xFF]
            & super::graphic::pLo
            == super::graphic::pLl;
    }
    return isExcludingLatin(&super::tables::LOWER, r);
}

// go: sdk 1.25.5 unicode/letter.go:166-172 IsTitle
/// Whether the rune is a title-case letter.
///
/// This had been a stub returning `false` for everything, with a note
/// that "multi-byte titlecase codepoints like U+01C5 require Unicode
/// tables not yet shipped". They are shipped now: `Lt` is seven ranges.
pub fn IsTitle(r: rune) -> bool {
    if r <= MaxLatin1 {
        return false;
    }
    return isExcludingLatin(&super::tables::TITLE, r);
}

#[path = "case_tables.rs"]
mod case_tables;

// go: none — goish idiom: Go maps case through `CaseRanges`, a table
//     of `{Lo, Hi, Delta}` triples searched with `lookupCaseRange`.
//     goish ships a flat, sorted rune->rune table instead, so the
//     lookup is a binary search on the key rather than a range walk.
//     Same answers for the default case; see the file's GOISH018
//     waiver for what the `Delta` shape would additionally buy.
fn case_lookup(t: &[(u32, u32)], r: rune) -> rune {
    if r < 0 {
        return r;
    }
    return match t.binary_search_by_key(&touint32(r), |e| e.0) {
        Ok(i) => torune(t[i].1),
        Err(_) => r,
    };
}

// go: sdk 1.25.5 unicode/letter.go:268-277 ToUpper
/// `unicode.ToUpper(r)` — full Unicode mapping (generated table;
/// letters.go SpecialCase excluded, matching Go's ToUpper).
pub fn ToUpper(r: rune) -> rune {
    if r < 0x80 {
        // ASCII fast path, mirroring Go's.
        if r >= torune(b'a') && r <= torune(b'z') {
            return r - 32;
        }
        return r;
    }
    return case_lookup(case_tables::UPPER, r);
}

// go: sdk 1.25.5 unicode/letter.go:279-288 ToLower
/// `unicode.ToLower(r)` — full Unicode mapping.
pub fn ToLower(r: rune) -> rune {
    if r < 0x80 {
        if r >= torune(b'A') && r <= torune(b'Z') {
            return r + 32;
        }
        return r;
    }
    return case_lookup(case_tables::LOWER, r);
}

// go: sdk 1.25.5 unicode/letter.go:290-299 ToTitle
/// `unicode.ToTitle(r)` — full Unicode mapping.
pub fn ToTitle(r: rune) -> rune {
    if r < 0x80 {
        if r >= torune(b'a') && r <= torune(b'z') {
            return r - 32;
        }
        return r;
    }
    return case_lookup(case_tables::TITLE, r);
}

// go: sdk 1.25.5 unicode/letter.go:354-388 SimpleFold
/// `unicode.SimpleFold(r)` (letter.go:344) — iterates the closed set
/// of runes equivalent under simple case folding; returns the next
/// rune in the orbit (the smallest > r, wrapping). Generated table
/// stores the full next-in-orbit mapping.
pub fn SimpleFold(r: rune) -> rune {
    return case_lookup(case_tables::FOLD, r);
}
