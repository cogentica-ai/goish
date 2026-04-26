// slices — Go's `slices` package, ported. M12 subset.
//
// Includes (functions):
//   IsSorted, Min, Max, BinarySearch, Equal, Compare,
//   Index, Contains, Compact, Concat, Delete, Clone.
//
// Includes (macros, accessible as `slices::Sort!`, `slices::Reverse!`):
//   Sort  — in-place sort, requires `T: Ord`. Backed by Rust's pdqsort.
//   Reverse — in-place reverse.
//
// Mutation-in-place ops are macros (mirroring `append!` / `copy!` from
// builtin_macros) so call sites stay Go-shaped — no visible `&mut` at
// the call site:
//
//     slices::Sort!(nums);              // not Sort(&mut nums)
//     nums = slices::Compact(nums);     // by-value-rebind for new length
//
// Deferred (need closures or iter):
//   *Func variants, All/Backward/Values/Sorted/Chunk, Insert/Replace,
//   Grow/Clip/Repeat.
//
// Algorithm: `Sort!` calls Rust's `[T]::sort_unstable()` which is a
// pdqsort, the same algorithm Go's slices.Sort uses since 1.21. Saves
// ~250 LOC of port.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::types::int;

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
        __s.sort_unstable();
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

/// `slices::Sort!(xs)` — in-place pdqsort. Requires `T: Ord`.
pub use crate::__goish_slices_sort as Sort;

/// `slices::Reverse!(xs)` — in-place reverse.
pub use crate::__goish_slices_reverse as Reverse;

// ─── Predicate / search ──────────────────────────────────────────────

pub fn IsSorted<T: Ord>(s: &slice<T>) -> bool {
    let raw: &[T] = s;
    for i in 1..raw.len() {
        if raw[i] < raw[i - 1] {
            return false;
        }
    }
    true
}

pub fn Min<T: Ord + Clone>(s: &slice<T>) -> T {
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.Min: empty list");
    }
    let mut best = &raw[0];
    for v in &raw[1..] {
        if v < best {
            best = v;
        }
    }
    best.clone()
}

pub fn Max<T: Ord + Clone>(s: &slice<T>) -> T {
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.Max: empty list");
    }
    let mut best = &raw[0];
    for v in &raw[1..] {
        if v > best {
            best = v;
        }
    }
    best.clone()
}

/// `BinarySearch(s, &target)` — assumes `s` is sorted ascending. Returns
/// `(index, found)`. When not found, `index` is the insertion point
/// (Go-faithful).
pub fn BinarySearch<T: Ord>(s: &slice<T>, target: &T) -> (int, bool) {
    let raw: &[T] = s;
    match raw.binary_search(target) {
        Ok(i) => (i as int, true),
        Err(i) => (i as int, false),
    }
}

pub fn Equal<T: PartialEq>(s1: &slice<T>, s2: &slice<T>) -> bool {
    let a: &[T] = s1;
    let b: &[T] = s2;
    a == b
}

pub fn Compare<T: Ord>(s1: &slice<T>, s2: &slice<T>) -> int {
    use core::cmp::Ordering::*;
    let a: &[T] = s1;
    let b: &[T] = s2;
    match a.cmp(b) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

pub fn Index<T: PartialEq>(s: &slice<T>, v: &T) -> int {
    let raw: &[T] = s;
    let mut i = 0usize;
    while i < raw.len() {
        if &raw[i] == v {
            return i as int;
        }
        i += 1;
    }
    -1
}

pub fn Contains<T: PartialEq>(s: &slice<T>, v: &T) -> bool {
    Index(s, v) >= 0
}

// ─── Producing new slices ─────────────────────────────────────────────

/// `Compact(s)` — removes consecutive equal elements. To dedupe across
/// the whole slice, sort first: `slices::Sort!(xs); let xs = slices::Compact(xs);`.
pub fn Compact<T: PartialEq>(s: slice<T>) -> slice<T> {
    let mut v = s.__into_vec();
    v.dedup();
    slice::__from_vec(v)
}

/// `Concat(&[s1, s2, s3])` — concatenates in order.
pub fn Concat<T: Clone>(parts: &[&slice<T>]) -> slice<T> {
    let total: usize = parts.iter().map(|p| p.Len() as usize).sum();
    let mut v: Vec<T> = Vec::with_capacity(total);
    for p in parts {
        let raw: &[T] = p;
        v.extend_from_slice(raw);
    }
    slice::__from_vec(v)
}

/// `Delete(s, i, j)` — returns a slice with elements `[i:j]` removed.
/// Panics on negative indices, on `j < i`, or on `j > len(s)` — matching
/// Go's runtime panic on bad slice index.
pub fn Delete<T>(s: slice<T>, i: int, j: int) -> slice<T> {
    if i < 0 || j < i {
        panic!("slices.Delete: invalid range");
    }
    let mut v = s.__into_vec();
    let iu = i as usize;
    let ju = j as usize;
    if ju > v.len() {
        panic!("slices.Delete: out of range");
    }
    v.drain(iu..ju);
    slice::__from_vec(v)
}

/// `Clone(s)` — deep copy. Free-function form mirrors Go's
/// `slices.Clone(s)`. Equivalent to `s.clone()`.
pub fn Clone<T: Clone>(s: &slice<T>) -> slice<T> {
    s.clone()
}
