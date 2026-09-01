// go: package slices
//
// slices — Go's `slices` package, ported.
//
// Module root only: one `.rs` per Go `.go`, the `pub use` surface, and
// the four in-place macros, which have no function form.
//
//   slices.rs  slices/slices.go — Equal, Compare, Index, Contains,
//                                  Insert, Delete, Replace, Clone,
//                                  Compact, Grow, Clip, Reverse,
//                                  Concat, Repeat
//   sort.rs    slices/sort.go   — IsSorted, Min, Max, BinarySearch
//                                  and their Func variants
//   iter.rs    slices/iter.go   — the iter.Seq bridge
//
// Functions (non-mutating):
//   IsSorted,  IsSortedFunc,
//   Min,       MinFunc,
//   Max,       MaxFunc,
//   BinarySearch, BinarySearchFunc,
//   Equal,     EqualFunc,
//   Compare,   CompareFunc,
//   Index,     IndexFunc,
//   Contains,  ContainsFunc,
//   Compact,   CompactFunc,
//   Concat,    Delete,    DeleteFunc,    Clone.
//
// Macros (in-place mutation, `slices::Sort!`, `slices::Reverse!`,
// `slices::SortFunc!`, `slices::SortStableFunc!`):
//   Sort  — in-place pdqsort, requires `T: Ord`. Backed by Rust's
//           `[T]::sort_unstable()`.
//   SortFunc — in-place pdqsort with a comparator closure that returns
//           `int` (negative: a < b, zero: equal, positive: a > b).
//   SortStableFunc — stable sort with comparator. Backed by `[T]::sort_by`.
//   Reverse — in-place reverse.
//
// Mutation-in-place ops are macros (mirroring `append!` / `copy!` from
// builtin_macros) so call sites stay Go-shaped — no visible `&mut`:
//
//     slices::Sort!(nums);                      // not Sort(&mut nums)
//     slices::SortFunc!(nums, |a, b| *b - *a);  // descending
//     nums = slices::Compact(nums);             // by-value-rebind for new length
//
//
// goishlint:ignore GOISH018 pdqsort, insertionSort, siftDown, heapSort, breakPatterns, choosePivot, order2, median, medianAdjacent, reverseRange, swapRange, symMerge, rotate, stableCmpFunc, stable, partition, partialInsertionSort, partitionEqual, nextPowerOfTwo, isNaN, Sort, SortFunc, SortStableFunc, sortCmpFunc, pdqsortCmpFunc, insertionSortCmpFunc, siftDownCmpFunc, heapSortCmpFunc, breakPatternsCmpFunc, choosePivotCmpFunc, order2CmpFunc, medianCmpFunc, medianAdjacentCmpFunc, reverseRangeCmpFunc, swapRangeCmpFunc, symMergeCmpFunc, rotateCmpFunc, stableCmpFuncCmpFunc, stableCmpFunc, partitionCmpFunc, partialInsertionSortCmpFunc, partitionEqualCmpFunc, sortOrdered, pdqsortOrdered, insertionSortOrdered, siftDownOrdered, heapSortOrdered, breakPatternsOrdered, choosePivotOrdered, order2Ordered, medianOrdered, medianAdjacentOrdered, reverseRangeOrdered, swapRangeOrdered, symMergeOrdered, rotateOrdered, stableOrdered, partitionOrdered, partialInsertionSortOrdered, partitionEqualOrdered — the sort ENGINE. Go's zsortordered.go and zsortanyfunc.go are two generated copies of the same pdqsort, one per element constraint, plus the stable-merge machinery; sort.go's Sort/SortFunc/SortStableFunc are three-line entry points into them. goish delegates to Rust's `sort_unstable`/`sort_unstable_by`/`sort_by`, which are the same algorithms (pdqsort and a TimSort variant), so the ~1000 lines have no counterpart to anchor. The entry points are macros here rather than functions — see the note below — so they are not anchored either. Equal-element placement may differ from Go for the UNSTABLE sorts; that is Go's documented licence too.

#![allow(non_snake_case)]

extern crate alloc;

// ─── Sort! / Reverse! macros ──────────────────────────────────────────
//
// Defined at crate root via #[macro_export], then re-exported below
// under the `slices::` path. Both take `$xs:expr` as a place (lvalue);
// the macro takes `&mut` internally so the call site stays bare.

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_slices_sort {
    ($xs:expr) => {{
        let __s: &mut $crate::slice<_> = &mut $xs;
        // Go: `slices.Sort` orders by `cmp.Less`, not by `<` — a NaN
        // sorts BEFORE every non-NaN. Sorting with Rust's `Ord` needed
        // `T: Ord`, which no float satisfies, so `slices.Sort` could
        // not be called on a `[]float64` at all.
        __s.sort_unstable_by(|a, b| $crate::slices::__go_ordering(a, b));
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_slices_reverse {
    ($xs:expr) => {{
        let __s: &mut $crate::slice<_> = &mut $xs;
        __s.reverse();
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_slices_sort_func {
    ($xs:expr, $cmp:expr) => {{
        let __s: &mut $crate::slice<_> = &mut $xs;
        let mut __cmp = $cmp;
        __s.sort_unstable_by(|a, b| {
            let __n: $crate::int = __cmp(a, b);
            if __n < 0 {
                ::core::cmp::Ordering::Less
            } else if __n == 0 {
                ::core::cmp::Ordering::Equal
            } else {
                ::core::cmp::Ordering::Greater
            }
        });
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! __goish_slices_sort_stable_func {
    ($xs:expr, $cmp:expr) => {{
        let __s: &mut $crate::slice<_> = &mut $xs;
        let mut __cmp = $cmp;
        __s.sort_by(|a, b| {
            let __n: $crate::int = __cmp(a, b);
            if __n < 0 {
                ::core::cmp::Ordering::Less
            } else if __n == 0 {
                ::core::cmp::Ordering::Equal
            } else {
                ::core::cmp::Ordering::Greater
            }
        });
    }};
}

/// `slices::Sort!(xs)` — in-place pdqsort in Go's order, which is
/// `cmp.Less`: a NaN sorts before every non-NaN. Requires `T: PartialOrd`.
pub use crate::__goish_slices_sort as Sort;

/// `slices::Reverse!(xs)` — in-place reverse.
pub use crate::__goish_slices_reverse as Reverse;

/// `slices::SortFunc!(xs, |a, b| <int>)` — in-place comparator pdqsort.
/// Closure returns `int`: negative when `a < b`, zero when equal, positive when `a > b`.
pub use crate::__goish_slices_sort_func as SortFunc;

/// `slices::SortStableFunc!(xs, |a, b| <int>)` — stable sort with comparator.
/// Equal elements keep their original relative order.
pub use crate::__goish_slices_sort_stable_func as SortStableFunc;

// go: none — goish idiom: Rust's sorts want a `core::cmp::Ordering`,
//     and Go's want `cmp.Compare`. This is the bridge, and it is where
//     the NaN rule enters every sort in the package: `T: Ord` would
//     have been the obvious bound and it excludes every float.
#[doc(hidden)]
pub fn __go_ordering<T: PartialOrd>(a: &T, b: &T) -> core::cmp::Ordering {
    let n = crate::cmp::Compare(a, b);
    if n < 0 {
        return core::cmp::Ordering::Less;
    }
    if n > 0 {
        return core::cmp::Ordering::Greater;
    }
    return core::cmp::Ordering::Equal;
}

#[path = "slices.rs"]
mod slices_go;
pub use slices_go::*;

#[path = "sort.rs"]
mod sort;
pub use sort::*;

#[path = "iter.rs"]
mod iter_go;
pub use iter_go::*;
