// go: package sort
//
// sort — Go's `sort` package, ported.
//
// Module root only: one `.rs` per Go `.go`, the `pub use` surface, and
// the three in-place macros, which have no function form.
//
//   sort.rs    sort/sort.go   — Interface, Sort, Stable, IsSorted,
//                                Reverse, IntSlice, Float64Slice,
//                                StringSlice, the *AreSorted predicates
//   search.rs  sort/search.go — Search, Find, SearchInts,
//                                SearchFloat64s, SearchStrings
//   slice.rs   sort/slice.go  — Slice, SliceStable, SliceIsSorted
//
// Deviations:
//   * `Sort` uses heapsort where Go uses pdqsort — same O(n log n), no
//     scratch space, ~30 lines against pdqsort's ~1100. Equal-element
//     placement may differ; `Sort` is not stable in either language, so
//     that is within Go's contract. `Stable` IS ported, faithfully, and
//     is the one to reach for when placement matters.
//   * `Ints`, `Strings` and `Float64s` are macros rather than
//     functions: they mutate in place, and goish keeps such call sites
//     free of a visible `&mut`.
//
// Source files:
//   go1.25.5/src/sort/sort.go
//   go1.25.5/src/sort/search.go
//

#![allow(non_snake_case)]

extern crate alloc;

// ─── Ints / Strings / Float64s — mutating macros ────────────────────
//
// Go signatures: `func Ints(x []int)` etc., where Go slices are
// reference types so caller-side mutations are visible. Goish slices
// own their backing Vec, so the natural goish-style equivalent is a
// macro that takes an lvalue and mutates it through `&mut` (matches
// `slices::Sort!`).

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_sort_ints {
    ($xs:expr) => {{
        let __s: &mut $crate::slice<$crate::int> = &mut $xs;
        __s.sort_unstable();
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_sort_strings {
    ($xs:expr) => {{
        let __s: &mut $crate::slice<$crate::gostring::string> = &mut $xs;
        __s.sort_unstable();
    }};
}

// Float64s — Go orders NaN before any other value via
// `x[i] < x[j] || (isNaN(x[i]) && !isNaN(x[j]))`. f64 has no Ord, so
// we run sort_unstable_by with the NaN-before-others comparator.
#[macro_export]
#[doc(hidden)]
macro_rules! __goish_sort_float64s {
    ($xs:expr) => {{
        let __s: &mut $crate::slice<$crate::float64> = &mut $xs;
        __s.sort_unstable_by(|a, b| {
            // Go: x[i] < x[j] || (isNaN(x[i]) && !isNaN(x[j]))
            let an = a.is_nan();
            let bn = b.is_nan();
            if an && !bn {
                ::core::cmp::Ordering::Less
            } else if !an && bn {
                ::core::cmp::Ordering::Greater
            } else if an && bn {
                ::core::cmp::Ordering::Equal
            } else if a < b {
                ::core::cmp::Ordering::Less
            } else if a > b {
                ::core::cmp::Ordering::Greater
            } else {
                ::core::cmp::Ordering::Equal
            }
        });
    }};
}

/// `sort.Ints!(xs)` (sort.go:170) — sort a slice of ints in ascending
/// order. Macro form so call sites stay Go-shaped: `sort::Ints!(nums)`.
pub use crate::__goish_sort_ints as Ints;

/// `sort.Strings!(xs)` (sort.go:181) — sort a slice of strings.
pub use crate::__goish_sort_strings as Strings;

/// `sort.Float64s!(xs)` (sort.go:176) — sort a slice of f64. NaN
/// values sort before any other value (matches Go).
pub use crate::__goish_sort_float64s as Float64s;

#[path = "sort.rs"]
mod sort_go;
pub use sort_go::*;

// zsortinterface.go declares nothing exported — every name in it is
// package-internal engine, reached only through `Stable`.
#[path = "zsortinterface.rs"]
mod zsortinterface;
use zsortinterface::stable;

#[path = "search.rs"]
mod search;
pub use search::*;

#[path = "slice.rs"]
mod slice;
pub use slice::*;
