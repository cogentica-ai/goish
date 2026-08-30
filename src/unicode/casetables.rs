// go: file unicode/casetables.go decls:
//
// goishlint:ignore GOISH017 — casetables.go declares no funcs; it is
//     two `SpecialCase` values. Each carries its own `// go: sdk`
//     anchor below.
//
// unicode/casetables.go — the special casing rules for Turkish and
// Azeri.
//
// Go's own TODO says it should cover every language with special
// casing and be generated, but that needs API development first. What
// is here is the dotted/dotless I: Turkish maps 'I' to U+0131 (dotless
// i) in lower case, and 'i' to U+0130 (I with dot above) in upper.

#![allow(non_snake_case, non_upper_case_globals)]

use super::letter::{CaseRange, SpecialCase};

// go: sdk 1.25.5 unicode/casetables.go:12-18 _TurkishCase
static _TurkishCase: &[CaseRange] = &[
    CaseRange {
        Lo: 0x0049,
        Hi: 0x0049,
        Delta: [0, 0x131 - 0x49, 0],
    },
    CaseRange {
        Lo: 0x0069,
        Hi: 0x0069,
        Delta: [0x130 - 0x69, 0, 0x130 - 0x69],
    },
    CaseRange {
        Lo: 0x0130,
        Hi: 0x0130,
        Delta: [0, 0x69 - 0x130, 0],
    },
    CaseRange {
        Lo: 0x0131,
        Hi: 0x0131,
        Delta: [0x49 - 0x131, 0, 0x49 - 0x131],
    },
];

// go: sdk 1.25.5 unicode/casetables.go:12-12 TurkishCase
/// `unicode.TurkishCase` — Turkish's dotted and dotless I.
pub static TurkishCase: SpecialCase = SpecialCase(_TurkishCase);

// go: sdk 1.25.5 unicode/casetables.go:20-20 AzeriCase
/// `unicode.AzeriCase` — the same rules as [`TurkishCase`].
pub static AzeriCase: SpecialCase = SpecialCase(_TurkishCase);
