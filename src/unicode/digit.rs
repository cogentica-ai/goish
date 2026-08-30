// go: file unicode/digit.go decls: IsDigit
//
// unicode/digit.go — one function.

#![allow(non_snake_case)]

use super::isExcludingLatin;
use super::tables;
use crate::types::rune;

// go: sdk 1.25.5 unicode/digit.go:7-13 IsDigit
/// Whether the rune is a decimal digit.
pub fn IsDigit(r: rune) -> bool {
    if r <= crate::unicode::MaxLatin1 {
        return r >= 0x30 && r <= 0x39;
    }
    return isExcludingLatin(&tables::Nd, r);
}
