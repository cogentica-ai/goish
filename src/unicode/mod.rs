// unicode — Go's `unicode` package family. M3 ships the `utf8` subpackage;
// case mapping and full categories land later. v1 exposes ASCII-coverage
// shims for the most common predicates so `strings.Fields` /
// `strings.TrimFunc` / `bytes.Map` work without pulling in unicode tables.

#![allow(non_snake_case)]

pub mod utf8;

use crate::types::rune;

/// `unicode.IsSpace(r)` — true if `r` is a whitespace character. v1
/// covers the ASCII whitespace set Go matches via `unicode.IsSpace`:
/// ' ', '\t', '\n', '\v', '\f', '\r', plus 0x85 (NEL) and 0xA0 (NBSP)
/// for parity with Go's table.
pub fn IsSpace(r: rune) -> bool {
    matches!(r, 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x20 | 0x85 | 0xA0)
}

/// `unicode.IsLetter(r)` — ASCII letters only in v1.
pub fn IsLetter(r: rune) -> bool {
    (r >= b'A' as rune && r <= b'Z' as rune) || (r >= b'a' as rune && r <= b'z' as rune)
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

/// `unicode.ToUpper(r)` — ASCII case fold.
pub fn ToUpper(r: rune) -> rune {
    if IsLower(r) {
        r - 32
    } else {
        r
    }
}

/// `unicode.ToLower(r)` — ASCII case fold.
pub fn ToLower(r: rune) -> rune {
    if IsUpper(r) {
        r + 32
    } else {
        r
    }
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

/// `unicode.ToTitle(r)` (letter.go) — ASCII slim. For ASCII letters
/// titlecase == uppercase, so we delegate to ToUpper. Non-ASCII
/// runes pass through unchanged.
pub fn ToTitle(r: rune) -> rune {
    // Go: To(_TitleCase, r) — for ASCII, _TitleCase folds identically to UpperCase.
    ToUpper(r)
}
