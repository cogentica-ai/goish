// go: file unicode/letter.go decls: is16, is32, Is, isExcludingLatin, IsUpper, IsLower, IsTitle, lookupCaseRange, convertCase, to, To, ToUpper, ToLower, ToTitle, SpecialCase.ToUpper, SpecialCase.ToTitle, SpecialCase.ToLower, SimpleFold
//
// goishlint:ignore GOISH021 caseOrbit, foldPair, FoldCategory, FoldScript, Categories, Scripts, Properties, linearMax — `caseOrbit`
//     and `foldPair` are what Go's `SimpleFold` walks; goish's
//     `SimpleFold` reads a generated flat next-in-orbit table instead,
//     which answers identically. The `FoldCategory`/`FoldScript`/
//     `Categories`/`Scripts`/`Properties` maps index the ~250 range
//     tables goish does not transcribe — see the module root.
//
// unicode/letter.go — the `RangeTable` machinery every predicate in the
// package searches, plus the case mappings.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::convert::{rune as torune, uint16 as touint16, uint32 as touint32};
use crate::types::{int, rune};

// go: sdk 1.25.5 unicode/letter.go:9-14 MaxRune
/// Maximum valid Unicode code point.
pub const MaxRune: rune = 0x10FFFF;

// go: sdk 1.25.5 unicode/letter.go:9-14 ReplacementChar
/// Represents invalid code points.
pub const ReplacementChar: rune = 0xFFFD;

// go: sdk 1.25.5 unicode/letter.go:9-14 MaxASCII
/// Maximum ASCII value.
pub const MaxASCII: rune = 0x007F;

// go: sdk 1.25.5 unicode/letter.go:9-14 MaxLatin1
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

// go: sdk 1.25.5 unicode/letter.go:184-190 IsUpper
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

// go: sdk 1.25.5 unicode/letter.go:193-199 IsLower
/// Whether the rune is a lower-case letter.
pub fn IsLower(r: rune) -> bool {
    if crate::convert::uint32(r) <= crate::convert::uint32(MaxLatin1) {
        return super::tables::properties[(crate::convert::uint32(r) as usize) & 0xFF]
            & super::graphic::pLo
            == super::graphic::pLl;
    }
    return isExcludingLatin(&super::tables::LOWER, r);
}

// go: sdk 1.25.5 unicode/letter.go:202-207 IsTitle
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

// go: sdk 1.25.5 unicode/letter.go:70-75 UpperCase
/// Index into a [`CaseRange`]'s `Delta` array for the upper-case map.
pub const UpperCase: int = 0;

// go: sdk 1.25.5 unicode/letter.go:70-75 LowerCase
/// Index into a [`CaseRange`]'s `Delta` array for the lower-case map.
pub const LowerCase: int = 1;

// go: sdk 1.25.5 unicode/letter.go:70-75 TitleCase
/// Index into a [`CaseRange`]'s `Delta` array for the title-case map.
pub const TitleCase: int = 2;

// go: sdk 1.25.5 unicode/letter.go:70-75 MaxCase
/// One past the last valid case index.
pub const MaxCase: int = 3;

// go: sdk 1.25.5 unicode/letter.go:79-84 UpperLower
/// A `Delta` of `UpperLower` means the range is an alternating
/// `Upper Lower Upper Lower …` sequence rather than a fixed offset.
/// It cannot be a valid delta.
pub const UpperLower: rune = MaxRune + 1;

// go: sdk 1.25.5 unicode/letter.go:77-77 d
/// Go's `type d [MaxCase]rune`, named only to keep the generated
/// `CaseRanges` text short.
pub type d = [rune; 3];

// go: sdk 1.25.5 unicode/letter.go:53-60 CaseRange
/// `unicode.CaseRange` — a range of code points sharing one case
/// mapping, given as an (upper, lower, title) delta triple.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CaseRange {
    pub Lo: u32,
    pub Hi: u32,
    pub Delta: d,
}

// go: sdk 1.25.5 unicode/letter.go:62-64 SpecialCase
/// `unicode.SpecialCase` — a language-specific case mapping, such as
/// Turkish. Its methods override the standard mappings.
///
/// Go's is a `[]CaseRange` and its methods hang off the slice type;
/// goish cannot add inherent methods to `&[CaseRange]`, so it is a
/// newtype over the same `&'static [CaseRange]`.
#[derive(Copy, Clone, Debug)]
pub struct SpecialCase(pub &'static [CaseRange]);

// go: sdk 1.25.5 unicode/letter.go:209-228 lookupCaseRange
/// The [`CaseRange`] mapping for `r`, or `None` when there is none.
fn lookupCaseRange(r: rune, caseRange: &'static [CaseRange]) -> Option<&'static CaseRange> {
    // Binary search over ranges.
    let mut lo = 0usize;
    let mut hi = caseRange.len();
    while lo < hi {
        let m = (lo + hi) >> 1;
        let cr = &caseRange[m];
        if torune(cr.Lo) <= r && r <= torune(cr.Hi) {
            return Some(cr);
        }
        if r < torune(cr.Lo) {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    return None;
}

// go: sdk 1.25.5 unicode/letter.go:230-249 convertCase
/// Converts `r` to `_case` using the given [`CaseRange`].
fn convertCase(_case: int, r: rune, cr: &CaseRange) -> rune {
    let delta = cr.Delta[_case as usize];
    if delta > MaxRune {
        // In an Upper-Lower sequence, which always starts with an
        // UpperCase letter, the real deltas always look like:
        //      {0, 1, 0}    UpperCase (Lower is next)
        //      {-1, 0, -1}  LowerCase (Upper, Title are previous)
        // The characters at even offsets from the beginning of the
        // sequence are upper case; the ones at odd offsets are lower.
        // The correct mapping is done by clearing or setting the low
        // bit in the sequence offset. UpperCase and TitleCase are even
        // while LowerCase is odd, so the low bit comes from `_case`.
        return torune(cr.Lo) + (((r - torune(cr.Lo)) & !1) | torune(_case & 1));
    }
    return r + delta;
}

// go: sdk 1.25.5 unicode/letter.go:251-260 to
/// Maps `r` using the given case mapping, additionally reporting
/// whether `caseRange` held a mapping for it.
fn to(_case: int, r: rune, caseRange: &'static [CaseRange]) -> (rune, bool) {
    if _case < 0 || MaxCase <= _case {
        // As reasonable an error as any.
        return (ReplacementChar, false);
    }
    return match lookupCaseRange(r, caseRange) {
        Some(cr) => (convertCase(_case, r, cr), true),
        None => (r, false),
    };
}

// go: sdk 1.25.5 unicode/letter.go:262-266 To
/// Maps `r` to the given case: [`UpperCase`], [`LowerCase`] or
/// [`TitleCase`].
pub fn To(_case: int, r: rune) -> rune {
    let (r, _) = to(_case, r, super::tables::CaseRanges);
    return r;
}

impl SpecialCase {
    // go: sdk 1.25.5 unicode/letter.go:300-307 SpecialCase.ToUpper
    /// Maps `r` to upper case, giving priority to the special mapping.
    pub fn ToUpper(&self, r: rune) -> rune {
        let (mut r1, hadMapping) = to(UpperCase, r, self.0);
        if r1 == r && !hadMapping {
            r1 = ToUpper(r);
        }
        return r1;
    }

    // go: sdk 1.25.5 unicode/letter.go:309-316 SpecialCase.ToTitle
    /// Maps `r` to title case, giving priority to the special mapping.
    pub fn ToTitle(&self, r: rune) -> rune {
        let (mut r1, hadMapping) = to(TitleCase, r, self.0);
        if r1 == r && !hadMapping {
            r1 = ToTitle(r);
        }
        return r1;
    }

    // go: sdk 1.25.5 unicode/letter.go:318-325 SpecialCase.ToLower
    /// Maps `r` to lower case, giving priority to the special mapping.
    pub fn ToLower(&self, r: rune) -> rune {
        let (mut r1, hadMapping) = to(LowerCase, r, self.0);
        if r1 == r && !hadMapping {
            r1 = ToLower(r);
        }
        return r1;
    }
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

// go: sdk 1.25.5 unicode/letter.go:267-276 ToUpper
/// Maps `r` to upper case.
pub fn ToUpper(r: rune) -> rune {
    if r <= MaxASCII {
        let mut r = r;
        if torune(b'a') <= r && r <= torune(b'z') {
            r -= torune(b'a') - torune(b'A');
        }
        return r;
    }
    return To(UpperCase, r);
}

// go: sdk 1.25.5 unicode/letter.go:278-287 ToLower
/// Maps `r` to lower case.
pub fn ToLower(r: rune) -> rune {
    if r <= MaxASCII {
        let mut r = r;
        if torune(b'A') <= r && r <= torune(b'Z') {
            r += torune(b'a') - torune(b'A');
        }
        return r;
    }
    return To(LowerCase, r);
}

// go: sdk 1.25.5 unicode/letter.go:289-298 ToTitle
/// Maps `r` to title case.
pub fn ToTitle(r: rune) -> rune {
    if r <= MaxASCII {
        let mut r = r;
        // Title case is upper case for ASCII.
        if torune(b'a') <= r && r <= torune(b'z') {
            r -= torune(b'a') - torune(b'A');
        }
        return r;
    }
    return To(TitleCase, r);
}

// go: sdk 1.25.5 unicode/letter.go:354-388 SimpleFold
/// `unicode.SimpleFold(r)` (letter.go:344) — iterates the closed set
/// of runes equivalent under simple case folding; returns the next
/// rune in the orbit (the smallest > r, wrapping). Generated table
/// stores the full next-in-orbit mapping.
pub fn SimpleFold(r: rune) -> rune {
    return case_lookup(case_tables::FOLD, r);
}
