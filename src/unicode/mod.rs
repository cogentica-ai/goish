// unicode — Go's `unicode` package family. M3 ships the `utf8` subpackage;
// case mapping and full categories land later. v1 exposes ASCII-coverage
// shims for the most common predicates so `strings.Fields` /
// `strings.TrimFunc` / `bytes.Map` work without pulling in unicode tables.

#![allow(non_snake_case)]

pub mod norm;
pub mod utf16;
pub mod utf8;

mod tables;
pub use tables::{Mn, Zs};

mod category_tables;

use crate::types::{int, rune};

// Go: unicode/letter.go:9-14.
/// `unicode.MaxRune` — maximum valid Unicode code point.
pub const MaxRune: rune = '\u{10FFFF}' as rune;
/// `unicode.ReplacementChar` — represents invalid code points.
pub const ReplacementChar: rune = '\u{FFFD}' as rune;
/// `unicode.MaxASCII` — maximum ASCII value.
pub const MaxASCII: rune = '\u{007F}' as rune;
/// `unicode.MaxLatin1` — maximum Latin-1 value.
pub const MaxLatin1: rune = '\u{00FF}' as rune;

// ─── RangeTable + Is (letter.go) ─────────────────────────────────────

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

// Go: letter.go:90 is16 — whether r is in the sorted slice of 16-bit
// ranges.
fn is16(ranges: &[Range16], r: u16) -> bool {
    if ranges.len() <= LINEAR_MAX || r as rune <= MaxLatin1 {
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
    false
}

// Go: letter.go:123 is32 — whether r is in the sorted slice of 32-bit
// ranges.
fn is32(ranges: &[Range32], r: u32) -> bool {
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
    false
}

/// `unicode.Is(rangeTab, r)` (letter.go:156) — whether the rune is in
/// the specified table of ranges.
pub fn Is(range_tab: &RangeTable, r: rune) -> bool {
    let r16 = range_tab.R16;
    // Compare as u32 to correctly handle negative runes.
    if !r16.is_empty() && (r as u32) <= r16[r16.len() - 1].Hi as u32 {
        return is16(r16, r as u16);
    }
    let r32 = range_tab.R32;
    if !r32.is_empty() && r >= r32[0].Lo as rune {
        return is32(r32, r as u32);
    }
    false
}

/// `unicode.In(r, ranges...)` (letter.go:187) — whether the rune is a
/// member of one of the tables (variadic → trailing slice, per the
/// goish lowering).
pub fn In(r: rune, ranges: &[&RangeTable]) -> bool {
    for inside in ranges {
        if Is(inside, r) {
            return true;
        }
    }
    false
}

/// `unicode.IsSpace(r)` — true if `r` is a whitespace character. v1
/// covers the ASCII whitespace set Go matches via `unicode.IsSpace`:
/// ' ', '\t', '\n', '\v', '\f', '\r', plus 0x85 (NEL) and 0xA0 (NBSP)
/// for parity with Go's table.
pub fn IsSpace(r: rune) -> bool {
    matches!(r, 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x20 | 0x85 | 0xA0)
}

/// `unicode.IsLetter(r)` — whether the rune has Unicode category L.
pub fn IsLetter(r: rune) -> bool {
    Is(&category_tables::LETTER, r)
}

/// `unicode.IsMark(r)` — whether the rune has Unicode category M.
pub fn IsMark(r: rune) -> bool {
    Is(&category_tables::MARK, r)
}

/// `unicode.IsNumber(r)` — whether the rune has Unicode category N.
pub fn IsNumber(r: rune) -> bool {
    Is(&category_tables::NUMBER, r)
}

/// `unicode.IsDigit(r)` — ASCII '0'..'9' only in v1.
pub fn IsDigit(r: rune) -> bool {
    r >= b'0' as rune && r <= b'9' as rune
}

/// `unicode.IsUpper(r)` — ASCII 'A'..'Z'.
pub fn IsUpper(r: rune) -> bool {
    r >= b'A' as rune && r <= b'Z' as rune
}

/// `unicode.IsLower(r)` — ASCII 'a'..'z'.
pub fn IsLower(r: rune) -> bool {
    r >= b'a' as rune && r <= b'z' as rune
}

#[path = "case_tables.rs"]
mod case_tables;

fn case_lookup(t: &[(u32, u32)], r: rune) -> rune {
    if r < 0 {
        return r;
    }
    match t.binary_search_by_key(&(r as u32), |e| e.0) {
        Ok(i) => t[i].1 as rune,
        Err(_) => r,
    }
}

/// `unicode.ToUpper(r)` — full Unicode mapping (generated table;
/// letters.go SpecialCase excluded, matching Go's ToUpper).
pub fn ToUpper(r: rune) -> rune {
    if r < 0x80 {
        // ASCII fast path, mirroring Go's.
        if r >= b'a' as rune && r <= b'z' as rune {
            return r - 32;
        }
        return r;
    }
    case_lookup(case_tables::UPPER, r)
}

/// `unicode.ToLower(r)` — full Unicode mapping.
pub fn ToLower(r: rune) -> rune {
    if r < 0x80 {
        if r >= b'A' as rune && r <= b'Z' as rune {
            return r + 32;
        }
        return r;
    }
    case_lookup(case_tables::LOWER, r)
}

/// `unicode.ToTitle(r)` — full Unicode mapping.
pub fn ToTitle(r: rune) -> rune {
    if r < 0x80 {
        if r >= b'a' as rune && r <= b'z' as rune {
            return r - 32;
        }
        return r;
    }
    case_lookup(case_tables::TITLE, r)
}

/// `unicode.SimpleFold(r)` (letter.go:344) — iterates the closed set
/// of runes equivalent under simple case folding; returns the next
/// rune in the orbit (the smallest > r, wrapping). Generated table
/// stores the full next-in-orbit mapping.
pub fn SimpleFold(r: rune) -> rune {
    case_lookup(case_tables::FOLD, r)
}

/// `unicode.IsControl(r)` (graphic.go:81) — ASCII slim. Per Go,
/// "all control characters are < MaxLatin1", so the slim Latin-1
/// fast path is the entire definition. Latin-1 control bytes are
/// 0x00..0x1F (C0), 0x7F (DEL), and 0x80..0x9F (C1).
pub fn IsControl(r: rune) -> bool {
    // Go: properties[uint8(r)]&pC != 0 for r ≤ MaxLatin1.
    if r < 0 {
        return false;
    }
    (r >= 0x00 && r <= 0x1F) || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}

/// `unicode.IsPrint(r)` (graphic.go:50) — slim Latin-1 + valid-Unicode
/// fallback. Identical body to `strconv::IsPrint` (which also consults
/// the Latin-1 properties table); we delegate so the two stay in
/// lockstep without duplicating the deviation note.
pub fn IsPrint(r: rune) -> bool {
    crate::strconv::IsPrint(r)
}

/// `unicode.IsGraphic(r)` (graphic.go:36) — slim. Like `IsPrint` plus
/// U+00A0 (no-break space). Per Go: graphic = print ∪ Zs (spacing
/// separators). In Latin-1 the only Zs spacing char beyond U+0020
/// (already covered by IsPrint) is U+00A0.
pub fn IsGraphic(r: rune) -> bool {
    if r == 0xA0 {
        return true;
    }
    IsPrint(r)
}

/// `unicode.IsPunct(r)` (graphic.go:113) — ASCII slim. Punctuation
/// in ASCII is 0x21..0x2F (`!"#$%&'()*+,-./`), 0x3A..0x40
/// (`:;<=>?@`), 0x5B..0x60 (``[\]^_` ``), 0x7B..0x7E (`{|}~`).
/// Latin-1 punct (0xA1..0xBF) is conservatively NOT included since
/// Go's table marks several of those as Symbol (Sm/So), not Punct.
pub fn IsPunct(r: rune) -> bool {
    // Go's properties[r]&pP for r ≤ 0xFF.
    if r < 0 {
        return false;
    }
    if r >= 0x21 && r <= 0x2F {
        return true;
    }
    if r >= 0x3A && r <= 0x40 {
        return true;
    }
    if r >= 0x5B && r <= 0x60 {
        // Caveat: 0x5E (^), 0x60 (`) are technically Symbol/Sk in
        // Go's table; we accept them here as punct for the slim path.
        // Callers needing strict Unicode parity should defer to
        // upstream tables (not yet shipped).
        return true;
    }
    if r >= 0x7B && r <= 0x7E {
        return true;
    }
    false
}

/// `unicode.IsTitle(r)` (letter.go) — ASCII slim. ASCII has no
/// title-case-only letters (Lu and Lt overlap on uppercase A..Z),
/// so this always returns false. Multi-byte titlecase codepoints
/// like U+01C5 (LJ-titlecase) require Unicode tables not yet shipped.
pub fn IsTitle(_r: rune) -> bool {
    // Go: if r <= MaxLatin1 { return false }; return isExcludingLatin(Title, r)
    false
}
