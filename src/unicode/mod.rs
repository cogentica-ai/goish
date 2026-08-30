// go: package unicode
//
// unicode — Unicode character classes and case mappings.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   graphic.rs   graphic.go   — the character-class predicates
//   letter.rs    letter.go    — RangeTable search, and the case maps
//   digit.rs     digit.go     — IsDigit
//   tables.rs    tables.go    — the generated data
//
// This file is a module root, so it carries no `// go:` anchors.
//
// goishlint:ignore GOISH021 — tables.go names ~250 category, script and
//     property RangeTables (Arabic, Han, Dash, Hex_Digit, …) plus the
//     `Categories`, `Scripts`, `Properties` and `FoldCategory` maps
//     that index them. goish transcribes only the tables its own code
//     names — L, M, N, Nd, P, S, Lt, White_Space, Mn, Zs — and the
//     Latin-1 `properties` bit array. A caller that needs another one
//     builds it from `RangeTable` literals, which is the same shape
//     the generated data has.
//
// casetables.go (TurkishCase, AzeriCase) is not ported: it is two
// `SpecialCase` values, and goish has no `SpecialCase` type — see the
// waiver in letter.rs.

#![allow(non_snake_case, non_upper_case_globals)]

pub mod digit;
pub mod graphic;
pub mod letter;
mod tables;

pub mod norm;
mod norm_tables;
pub mod utf16;
pub mod utf8;

pub use digit::IsDigit;
pub use graphic::{
    GraphicRanges, In, IsControl, IsGraphic, IsLetter, IsMark, IsNumber, IsOneOf, IsPrint, IsPunct,
    IsSpace, IsSymbol, PrintRanges,
};
pub use letter::{
    is16, is32, isExcludingLatin, Is, IsLower, IsTitle, IsUpper, MaxASCII, MaxLatin1, MaxRune,
    Range16, Range32, RangeTable, ReplacementChar, SimpleFold, ToLower, ToTitle, ToUpper,
};

/// `unicode.Mn` — Mark, nonspacing.
pub use tables::Mn;
/// `unicode.Zs` — Separator, space.
pub use tables::Zs;
