// slices — Go's `slices` package, ported. M12.
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
// Deferred:
//   All/Backward/Values/Sorted/Chunk (iter), Insert/Replace (variadic),
//   Grow/Clip/Repeat (capacity tuning).
//
// Algorithm: leans on Rust's stdlib for both ordered and comparator
// pdqsort variants; `SortStableFunc` uses `[T]::sort_by` (TimSort).
// Saves ~500 LOC of port. Equal-element placement may differ from Go
// for unstable sorts (documented).

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

/// `slices::Sort!(xs)` — in-place pdqsort. Requires `T: Ord`.
pub use crate::__goish_slices_sort as Sort;

/// `slices::Reverse!(xs)` — in-place reverse.
pub use crate::__goish_slices_reverse as Reverse;

/// `slices::SortFunc!(xs, |a, b| <int>)` — in-place comparator pdqsort.
/// Closure returns `int`: negative when `a < b`, zero when equal, positive when `a > b`.
pub use crate::__goish_slices_sort_func as SortFunc;

/// `slices::SortStableFunc!(xs, |a, b| <int>)` — stable sort with comparator.
/// Equal elements keep their original relative order.
pub use crate::__goish_slices_sort_stable_func as SortStableFunc;

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

// ─── Func variants — comparator/predicate closures ────────────────────
//
// Closure conventions match Go:
//   * `cmp(&a, &b) -> int` — negative: a<b, zero: equal, positive: a>b
//   * `eq(&a, &b) -> bool`
//   * `pred(&v)  -> bool` — true means "match" / "delete"
//
// All closures are `FnMut` so they may carry state. Rust closures
// (including captures) flow in directly; no `Box<dyn Fn>` ceremony.

pub fn IsSortedFunc<T, F>(s: &slice<T>, mut cmp: F) -> bool
where
    F: FnMut(&T, &T) -> int,
{
    let raw: &[T] = s;
    for i in 1..raw.len() {
        if cmp(&raw[i], &raw[i - 1]) < 0 {
            return false;
        }
    }
    true
}

pub fn MinFunc<T: Clone, F>(s: &slice<T>, mut cmp: F) -> T
where
    F: FnMut(&T, &T) -> int,
{
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.MinFunc: empty list");
    }
    let mut best = &raw[0];
    for i in 1..raw.len() {
        if cmp(&raw[i], best) < 0 {
            best = &raw[i];
        }
    }
    best.clone()
}

pub fn MaxFunc<T: Clone, F>(s: &slice<T>, mut cmp: F) -> T
where
    F: FnMut(&T, &T) -> int,
{
    let raw: &[T] = s;
    if raw.is_empty() {
        panic!("slices.MaxFunc: empty list");
    }
    let mut best = &raw[0];
    for i in 1..raw.len() {
        if cmp(&raw[i], best) > 0 {
            best = &raw[i];
        }
    }
    best.clone()
}

/// `BinarySearchFunc(s, &target, cmp)` — element type `T` and target type
/// `U` may differ. `cmp(&e, &target)` returns negative when `e` precedes
/// `target`, zero when matching, positive when following.
pub fn BinarySearchFunc<T, U, F>(s: &slice<T>, target: &U, mut cmp: F) -> (int, bool)
where
    F: FnMut(&T, &U) -> int,
{
    let raw: &[T] = s;
    let n = raw.len();
    let mut i = 0usize;
    let mut j = n;
    while i < j {
        let h = (i + j) >> 1; // (i+j) is bounded by 2*n; usize on 64-bit can't overflow for any realistic slice
        if cmp(&raw[h], target) < 0 {
            i = h + 1;
        } else {
            j = h;
        }
    }
    let found = i < n && cmp(&raw[i], target) == 0;
    (i as int, found)
}

pub fn EqualFunc<T, U, F>(s1: &slice<T>, s2: &slice<U>, mut eq: F) -> bool
where
    F: FnMut(&T, &U) -> bool,
{
    let a: &[T] = s1;
    let b: &[U] = s2;
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if !eq(&a[i], &b[i]) {
            return false;
        }
    }
    true
}

pub fn CompareFunc<T, U, F>(s1: &slice<T>, s2: &slice<U>, mut cmp: F) -> int
where
    F: FnMut(&T, &U) -> int,
{
    let a: &[T] = s1;
    let b: &[U] = s2;
    let n = core::cmp::min(a.len(), b.len());
    for i in 0..n {
        let c = cmp(&a[i], &b[i]);
        if c != 0 {
            return if c < 0 {
                -1
            } else {
                1
            };
        }
    }
    if a.len() < b.len() {
        -1
    } else if a.len() > b.len() {
        1
    } else {
        0
    }
}

pub fn IndexFunc<T, F>(s: &slice<T>, mut pred: F) -> int
where
    F: FnMut(&T) -> bool,
{
    let raw: &[T] = s;
    let mut i = 0usize;
    while i < raw.len() {
        if pred(&raw[i]) {
            return i as int;
        }
        i += 1;
    }
    -1
}

pub fn ContainsFunc<T, F>(s: &slice<T>, pred: F) -> bool
where
    F: FnMut(&T) -> bool,
{
    IndexFunc(s, pred) >= 0
}

/// `DeleteFunc(s, pred)` — returns a slice with every element `e` where
/// `pred(&e)` is true removed.
pub fn DeleteFunc<T, F>(s: slice<T>, mut pred: F) -> slice<T>
where
    F: FnMut(&T) -> bool,
{
    let mut v = s.__into_vec();
    v.retain(|e| !pred(e));
    slice::__from_vec(v)
}

/// `CompactFunc(s, eq)` — removes consecutive elements where `eq(&a, &b)`
/// is true. Sort first to dedupe globally.
pub fn CompactFunc<T, F>(s: slice<T>, mut eq: F) -> slice<T>
where
    F: FnMut(&T, &T) -> bool,
{
    let mut v = s.__into_vec();
    v.dedup_by(|a, b| eq(a, b));
    slice::__from_vec(v)
}
