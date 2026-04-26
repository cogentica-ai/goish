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
