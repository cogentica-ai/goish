// sort — Go's `sort` package, slim port.
//
// Source files:
//   go1.25.5/src/sort/sort.go
//   go1.25.5/src/sort/search.go
//
// What this slim port covers:
//   * `Interface` (Len / Less / Swap)
//   * `Sort(data)` — heapsort instead of pdqsort (smaller code, same
//     O(n log n), in-place, no extra allocation)
//   * `IsSorted(data)`, `Reverse(data)`
//   * `Search(n, f)`, `Find(n, cmp)` — line-by-line ports of search.go
//   * `SearchInts(a, x)`, `SearchStrings(a, x)`, `SearchFloat64s(a, x)`
//   * `Ints!(x)`, `Strings!(x)`, `Float64s!(x)` — mutating macros
//     matching the goish `slices::Sort!()` convention; users write
//     `sort::Ints!(nums)` (no `&mut` at the call site)
//   * `IntsAreSorted(x)`, `StringsAreSorted(x)`, `Float64sAreSorted(x)`
//
// Slim deviations:
//   * `Sort` uses heapsort (Go uses pdqsort). Equal-element placement
//     can differ from Go's output. Worst-case O(n log n) is preserved.
//   * `Slice(slice, less)` and `SliceStable(slice, less)` are deferred —
//     `slices::SortFunc!` is the goish-idiomatic equivalent.
//   * `Stable(data)` deferred (would need symmerge sort).
//   * NaN handling for `Float64Slice.Less` matches Go: NaN sorts before
//     any other value (`x[i] < x[j] || (isNaN(x[i]) && !isNaN(x[j]))`).

#![allow(non_snake_case)]

extern crate alloc;

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{float64, int};

// ─── Interface (sort.go:17) ─────────────────────────────────────────

/// `sort.Interface` (sort.go:17) — collection that can be sorted in
/// place by `Sort` and friends. Implementors expose a length, a
/// pairwise less-than predicate, and an index-pair swap.
#[goish::interface]
pub trait Interface {
    /// `Len()` — number of elements.
    fn Len(&self) -> int;

    /// `Less(i, j)` — true iff element i must sort strictly before j.
    fn Less(&self, i: int, j: int) -> bool;

    /// `Swap(i, j)` — exchange elements at indices i and j.
    fn Swap(&mut self, i: int, j: int);
}

// ─── Sort (sort.go:50) — heapsort fallback ──────────────────────────

/// `sort.Sort(data)` (sort.go:50). Slim deviation: heapsort instead of
/// pdqsort — same O(n log n), no scratch space, ~30 LOC versus
/// pdqsort's ~1100. Equal-element placement may differ from Go.
pub fn Sort<I: Interface + ?Sized>(data: &mut I) {
    // Go: n := data.Len(); if n <= 1 { return }
    let n = data.Len();
    if n <= 1 {
        return;
    }
    // Phase 1 — heapify (build max-heap).
    let mut start = (n - 1) / 2;
    loop {
        siftDown(data, start, n);
        if start == 0 {
            break;
        }
        start -= 1;
    }
    // Phase 2 — drain: largest to the end, restore heap on prefix.
    let mut end = n - 1;
    while end > 0 {
        data.Swap(0, end);
        siftDown(data, 0, end);
        end -= 1;
    }
}

// Internal helper — max-heap sift-down on indices [root, end).
fn siftDown<I: Interface + ?Sized>(data: &mut I, root: int, end: int) {
    let mut r = root;
    loop {
        let mut child = r * 2 + 1;
        if child >= end {
            break;
        }
        if child + 1 < end && data.Less(child, child + 1) {
            child += 1;
        }
        if !data.Less(r, child) {
            break;
        }
        data.Swap(r, child);
        r = child;
    }
}

// ─── IsSorted (sort.go:110) ─────────────────────────────────────────

/// `sort.IsSorted(data)` (sort.go:110) — true iff `data` is sorted
/// according to its `Less`.
pub fn IsSorted<I: Interface + ?Sized>(data: &I) -> bool {
    // Go: for i := n - 1; i > 0; i-- { if data.Less(i, i-1) { return false } }
    let n = data.Len();
    let mut i = n - 1;
    while i > 0 {
        if data.Less(i, i - 1) {
            return false;
        }
        i -= 1;
    }
    true
}

// ─── Reverse (sort.go:90, sort.go:101) ──────────────────────────────

/// `sort.reverse{Interface}` wrapper (sort.go:90) — flips the embedded
/// `Less`. Returned by `Reverse(data)`. The wrapped value is exposed as
/// `pub inner` so tests can recover it after `Sort(&mut Reverse(s))`.
pub struct Reverse<I: Interface> {
    pub inner: I,
}

impl<I: Interface> Interface for Reverse<I> {
    fn Len(&self) -> int {
        self.inner.Len()
    }
    fn Less(&self, i: int, j: int) -> bool {
        // Go: r.Interface.Less(j, i)
        self.inner.Less(j, i)
    }
    fn Swap(&mut self, i: int, j: int) {
        self.inner.Swap(i, j);
    }
}

/// `sort.Reverse(data)` (sort.go:101) — wrap `data` to sort in
/// descending order.
pub fn Reverse<I: Interface>(data: I) -> Reverse<I> {
    Reverse { inner: data }
}

// ─── Search (search.go:58) ──────────────────────────────────────────

/// `sort.Search(n, f)` (search.go:58) — binary-search the smallest
/// index i in [0, n) at which `f(i)` is true. `f` must be monotone:
/// false on a (possibly empty) prefix, true on the rest. Returns `n`
/// if no such index exists.
pub fn Search<F>(n: int, mut f: F) -> int
where
    F: FnMut(int) -> bool,
{
    // Go: i, j := 0, n
    let mut i = 0_i64 as int;
    let mut j = n;
    while i < j {
        // Go: h := int(uint(i+j) >> 1)
        let h = ((i as u64).wrapping_add(j as u64) >> 1) as int;
        // Go: if !f(h) { i = h + 1 } else { j = h }
        if !f(h) {
            i = h + 1;
        } else {
            j = h;
        }
    }
    i
}

/// `sort.Find(n, cmp)` (search.go:99) — binary search using a 3-way
/// `cmp(i)` returning `<0`, `0`, or `>0`. Returns `(i, found)` where
/// `i` is the insertion point and `found` is true iff `cmp(i) == 0`.
pub fn Find<F>(n: int, mut cmp: F) -> (int, bool)
where
    F: FnMut(int) -> int,
{
    // Go: i, j := 0, n
    let mut i = 0_i64 as int;
    let mut j = n;
    while i < j {
        let h = ((i as u64).wrapping_add(j as u64) >> 1) as int;
        // Go: if cmp(h) > 0 { i = h + 1 } else { j = h }
        if cmp(h) > 0 {
            i = h + 1;
        } else {
            j = h;
        }
    }
    // Go: return i, i < n && cmp(i) == 0
    let found = i < n && cmp(i) == 0;
    (i, found)
}

// ─── SearchInts / SearchStrings / SearchFloat64s (search.go:123-141) ─

/// `sort.SearchInts(a, x)` (search.go:123). The slice must be sorted
/// in ascending order; returns the index where x is or would be
/// inserted.
pub fn SearchInts(a: &slice<int>, x: int) -> int {
    // Go: Search(len(a), func(i int) bool { return a[i] >= x })
    let raw: &[int] = a;
    Search(raw.len() as int, |i| raw[i as usize] >= x)
}

/// `sort.SearchFloat64s(a, x)` (search.go:131).
pub fn SearchFloat64s(a: &slice<float64>, x: float64) -> int {
    let raw: &[float64] = a;
    Search(raw.len() as int, |i| raw[i as usize] >= x)
}

/// `sort.SearchStrings(a, x)` (search.go:139).
pub fn SearchStrings<X: Into<string>>(a: &slice<string>, x: X) -> int {
    let x: string = x.into();
    let raw: &[string] = a;
    Search(raw.len() as int, |i| raw[i as usize] >= x)
}

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

// ─── Slice / SliceStable (sort.go:210, :224) ────────────────────────

/// `sort.Slice(x, less)` (sort.go:210) — sort the slice `x` in place
/// using the `less` function for comparisons. Not guaranteed to be
/// stable; equal elements may be swapped.
///
/// Slim port: wraps the `less` closure in a temporary `Interface` adapter
/// and calls `Sort`. The heapsort backend is not stable.
///
/// `x` is passed as `&mut slice<T>` so the call site matches Go's
/// `sort.Slice(x, func(i, j int) bool { ... })` shape. Call sites that
/// hold a plain `slice<T>` write `sort::Slice(&mut x, |i, j| …)`.
pub fn Slice<T, F>(x: &mut slice<T>, mut less: F)
where
    F: FnMut(int, int) -> bool,
{
    let n = x.Len();
    if n <= 1 {
        return;
    }
    // Build a heapsort over indices, using the closure for Less.
    // We need to swap elements in x — use raw-pointer swap to avoid
    // borrowing conflicts when the closure captures x.
    let ptr = x.as_mut_ptr();

    // Heapsort using our Less closure.
    let sift_down = |less: &mut F, ptr: *mut T, mut r: int, end: int| {
        loop {
            let mut child = r * 2 + 1;
            if child >= end {
                break;
            }
            if child + 1 < end && less(child, child + 1) {
                child += 1;
            }
            if !less(r, child) {
                break;
            }
            unsafe { core::ptr::swap(ptr.offset(r as isize), ptr.offset(child as isize)); }
            r = child;
        }
    };

    let mut start = (n - 1) / 2;
    loop {
        sift_down(&mut less, ptr, start, n);
        if start == 0 { break; }
        start -= 1;
    }
    let mut end = n - 1;
    while end > 0 {
        unsafe { core::ptr::swap(ptr, ptr.offset(end as isize)); }
        sift_down(&mut less, ptr, 0, end);
        end -= 1;
    }
}

/// `sort.SliceStable(x, less)` (sort.go:224) — sort the slice `x` in
/// place using the `less` function, preserving the original order of
/// equal elements.
///
/// Slim port: delegates to the stdlib's `[T]::sort_by` (TimSort),
/// which is stable. `less(i, j)` must return `true` iff `x[i] < x[j]`.
pub fn SliceStable<T, F>(x: &mut slice<T>, mut less: F)
where
    F: FnMut(int, int) -> bool,
{
    // Build an index table, sort indices stably, then permute x.
    // This avoids having to expose the raw Vec mutation path directly.
    let n = x.Len() as usize;
    if n <= 1 {
        return;
    }
    let mut idx: alloc::vec::Vec<usize> = (0..n).collect();
    idx.sort_by(|&a, &b| {
        if less(a as int, b as int) {
            core::cmp::Ordering::Less
        } else if less(b as int, a as int) {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    });
    // Apply the permutation using cycle-following.
    let mut done: alloc::vec::Vec<bool> = alloc::vec::from_elem(false, n);
    let ptr = x.as_mut_ptr();
    for i in 0..n {
        if done[i] || idx[i] == i {
            done[i] = true;
            continue;
        }
        let mut j = i;
        loop {
            let k = idx[j];
            done[j] = true;
            if k == i {
                break;
            }
            unsafe { core::ptr::swap(ptr.offset(j as isize), ptr.offset(k as isize)); }
            j = k;
        }
    }
}

/// `sort.SliceIsSorted(x, less)` (sort.go:234) — reports whether `x`
/// is sorted in the order defined by `less`.
pub fn SliceIsSorted<T, F>(x: &slice<T>, mut less: F) -> bool
where
    F: FnMut(int, int) -> bool,
{
    let n = x.Len();
    let mut i: int = 1;
    while i < n {
        if less(i, i - 1) {
            return false;
        }
        i += 1;
    }
    true
}

// ─── *AreSorted predicates (sort.go:186, :192, :197) ────────────────

/// `sort.IntsAreSorted(x)` (sort.go:186).
pub fn IntsAreSorted(x: &slice<int>) -> bool {
    let raw: &[int] = x;
    let mut i = raw.len();
    while i > 1 {
        if raw[i - 1] < raw[i - 2] {
            return false;
        }
        i -= 1;
    }
    true
}

/// `sort.StringsAreSorted(x)` (sort.go:197).
pub fn StringsAreSorted(x: &slice<string>) -> bool {
    let raw: &[string] = x;
    let mut i = raw.len();
    while i > 1 {
        if raw[i - 1] < raw[i - 2] {
            return false;
        }
        i -= 1;
    }
    true
}

/// `sort.Float64sAreSorted(x)` (sort.go:192) — NaN-before-others
/// ordering, matching `Float64s`.
pub fn Float64sAreSorted(x: &slice<float64>) -> bool {
    // Go: slices.IsSorted with Float64Slice's Less
    let raw: &[float64] = x;
    let mut i = raw.len();
    while i > 1 {
        let a = raw[i - 2];
        let b = raw[i - 1];
        // a must be <= b under Float64Slice.Less:
        //   Less(i-1, i-2)  =  b < a || (isNaN(b) && !isNaN(a))
        // is the "out of order" predicate.
        let an = a.is_nan();
        let bn = b.is_nan();
        let out_of_order = (b < a) || (bn && !an);
        if out_of_order {
            return false;
        }
        i -= 1;
    }
    true
}
