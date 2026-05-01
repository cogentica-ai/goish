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

/// Line-by-line port of `slices.Reverse` (slices/slices.go:481) — reverse
/// the elements of `s` in place.
pub fn Reverse<T>(s: &mut slice<T>) {
    // Go: for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 { s[i], s[j] = s[j], s[i] }
    let raw: &mut [T] = s;
    let mut i: usize = 0;
    if raw.is_empty() {
        return;
    }
    let mut j: usize = raw.len() - 1;
    while i < j {
        raw.swap(i, j);
        i += 1;
        j -= 1;
    }
}

/// Line-by-line port of `slices.Repeat` (slices/slices.go:512) — return
/// a new slice that repeats `x` `count` times. Result length is
/// `len(x) * count`. Panics on negative `count` (Go semantics).
pub fn Repeat<T: Clone>(x: &slice<T>, count: int) -> slice<T> {
    // Go: if count < 0 { panic("cannot be negative") }
    if count < 0 {
        panic!("slices.Repeat: count cannot be negative");
    }
    let raw: &[T] = x;
    let n = raw.len();
    // Go: hi, lo := bits.Mul(uint(len(x)), uint(count))
    //     if hi > 0 || lo > maxInt { panic("overflow") }
    // Goish: usize::checked_mul covers both cases.
    let total = match n.checked_mul(count as usize) {
        Some(t) => t,
        None => panic!("slices.Repeat: len(x) * count overflows"),
    };
    // Go: newslice := make(S, int(lo)); copy + double-up loop.
    // Goish: doubling-copy mirrors Go's algorithm verbatim.
    let mut out: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(total);
    if n == 0 || count == 0 {
        return slice::__from_vec(out);
    }
    // First copy of x.
    for el in raw.iter() {
        out.push(el.clone());
    }
    // Go: for n < len(newslice) { n += copy(newslice[n:], newslice[:n]) }
    let mut filled = n;
    while filled < total {
        let take = core::cmp::min(filled, total - filled);
        // Clone the prefix [0..take) to extend.
        for k in 0..take {
            let elem = out[k].clone();
            out.push(elem);
        }
        filled += take;
    }
    slice::__from_vec(out)
}

/// Line-by-line port of `slices.Insert` (slices/slices.go:135) — insert
/// the values `v...` into `s` at index `i`. Returns the modified slice.
/// Panics if `i > len(s)` or `i < 0` (matches Go's bounds check).
///
/// Goish deviation: Go's `v ...E` variadic becomes `v: &slice<T>`. Goish
/// slices are not aliased the way Go slices are, so we don't need the
/// overlap detection / rotateRight branches — we always own the buffer.
pub fn Insert<T: Clone>(s: slice<T>, i: int, v: &slice<T>) -> slice<T> {
    // Go: _ = s[i:] // bounds check
    if i < 0 || (i as usize) > s.Len() as usize {
        panic!("slices.Insert: index out of range");
    }
    // Go: m := len(v); if m == 0 { return s }
    let m = v.Len() as usize;
    if m == 0 {
        return s;
    }
    // Goish: own the backing Vec and splice in.
    let mut out = s.__into_vec();
    let iu = i as usize;
    // Build the insert payload by cloning v elementwise.
    let raw_v: &[T] = v;
    let mut payload: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(m);
    for el in raw_v.iter() {
        payload.push(el.clone());
    }
    // Vec::splice handles all the shifting in one shot.
    out.splice(iu..iu, payload);
    slice::__from_vec(out)
}

/// Line-by-line port of `slices.Replace` (slices/slices.go:260) — replaces
/// `s[i:j]` with the given `v` and returns the modified slice. Panics if
/// `j > len(s)` or `i > j` (Go's bounds-check semantics).
///
/// Goish deviation: variadic `v...E` becomes `v: &slice<T>`; aliasing
/// concerns absent since the backing Vec is owned.
pub fn Replace<T: Clone>(s: slice<T>, i: int, j: int, v: &slice<T>) -> slice<T> {
    // Go: _ = s[i:j] // bounds check
    if i < 0 || j < i || (j as usize) > s.Len() as usize {
        panic!("slices.Replace: invalid range");
    }
    // Go: if i == j { return Insert(s, i, v...) }
    if i == j {
        return Insert(s, i, v);
    }
    let mut out = s.__into_vec();
    let iu = i as usize;
    let ju = j as usize;
    // Build the replacement payload by cloning v elementwise.
    let raw_v: &[T] = v;
    let mut payload: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(raw_v.len());
    for el in raw_v.iter() {
        payload.push(el.clone());
    }
    out.splice(iu..ju, payload);
    slice::__from_vec(out)
}

/// Line-by-line port of `slices.Grow` (slices/slices.go:420) — grows
/// the slice's capacity, if necessary, to guarantee space for another
/// `n` elements. Panics on negative `n`.
///
/// Goish: backing Vec is always owned, so we can call reserve directly.
pub fn Grow<T>(s: slice<T>, n: int) -> slice<T> {
    // Go: if n < 0 { panic("cannot be negative") }
    if n < 0 {
        panic!("slices.Grow: cannot be negative");
    }
    let mut v = s.__into_vec();
    // Go: if n -= cap(s) - len(s); n > 0 { ... }
    // Goish: reserve already amortizes; let Vec handle the math.
    v.reserve(n as usize);
    slice::__from_vec(v)
}

/// Line-by-line port of `slices.Clip` (slices/slices.go:433) — drops
/// unused capacity. In Go: `s[:len(s):len(s)]`. In goish: shrink_to_fit.
pub fn Clip<T>(s: slice<T>) -> slice<T> {
    let mut v = s.__into_vec();
    v.shrink_to_fit();
    slice::__from_vec(v)
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

// ─── Sorted (Go 1.23+) ────────────────────────────────────────────────
//
// Go's signature is `Sorted[E cmp.Ordered](seq iter.Seq[E]) []E`, but
// goish has no iter.Seq yet, so the slim version takes `slice<T>` and
// returns a fresh sorted slice.  Once an iter package lands, the
// existing `Sorted(s)` callers can stay valid since `slice<T>` is the
// natural single-pass source.

/// `slices.Sorted(s)` (sort.go: Sorted) — clone `s`, sort ascending,
/// return. Equivalent to `let s2 = s.clone(); slices::Sort!(s2); s2`.
/// Slim: takes a `slice<T>` instead of `iter.Seq[T]`.
pub fn Sorted<T: Ord + Clone>(s: &slice<T>) -> slice<T> {
    // Go: s := slices.Collect(seq); Sort(s); return s
    let mut v = (s.clone()).__into_vec();
    v.sort_unstable();
    slice::__from_vec(v)
}

/// `slices.SortedFunc(s, cmp)` (sort.go: SortedFunc) — clone `s`, sort
/// using `cmp(a, b) -> int` (negative = a<b, 0 = equal, positive = a>b),
/// return. Slim: takes a `slice<T>` instead of `iter.Seq[T]`.
pub fn SortedFunc<T: Clone, F>(s: &slice<T>, mut cmp: F) -> slice<T>
where
    F: FnMut(&T, &T) -> int,
{
    let mut v = (s.clone()).__into_vec();
    // Go: SortFunc(s, cmp)
    v.sort_unstable_by(|a, b| {
        let n = cmp(a, b);
        if n < 0 {
            core::cmp::Ordering::Less
        } else if n == 0 {
            core::cmp::Ordering::Equal
        } else {
            core::cmp::Ordering::Greater
        }
    });
    slice::__from_vec(v)
}

/// `slices.SortedStableFunc(s, cmp)` — stable variant of `SortedFunc`.
/// Equal elements keep their original relative order.
pub fn SortedStableFunc<T: Clone, F>(s: &slice<T>, mut cmp: F) -> slice<T>
where
    F: FnMut(&T, &T) -> int,
{
    let mut v = (s.clone()).__into_vec();
    v.sort_by(|a, b| {
        let n = cmp(a, b);
        if n < 0 {
            core::cmp::Ordering::Less
        } else if n == 0 {
            core::cmp::Ordering::Equal
        } else {
            core::cmp::Ordering::Greater
        }
    });
    slice::__from_vec(v)
}

/// `slices.Chunk(s, n)` (slices/iter.go:97) — return consecutive
/// sub-slices of up to `n` elements of `s`. All but the last sub-slice
/// have size `n`. If `s` is empty, the result is empty (no empty
/// slice in the sequence). Panics if `n < 1`, matching Go.
///
/// Slim deviation: Go returns `iter.Seq[Slice]`; goish has no
/// `iter.Seq`, so this returns `slice<slice<T>>` eagerly. Each chunk
/// is a fresh `slice<T>` cloned from the source.
pub fn Chunk<T: Clone>(s: slice<T>, n: int) -> slice<slice<T>> {
    // Go: if n < 1 { panic("cannot be less than 1") }
    if n < 1 {
        panic!("cannot be less than 1");
    }
    let raw: &[T] = &s;
    let total = raw.len();
    // Go: for i := 0; i < len(s); i += n { ... yield(s[i : i+end : i+end]) }
    let mut out: alloc::vec::Vec<slice<T>> = alloc::vec::Vec::new();
    let n_us = n as usize;
    let mut i: usize = 0;
    while i < total {
        // Go: end := min(n, len(s[i:]))
        let remaining = total - i;
        let end = if n_us < remaining { n_us } else { remaining };
        // Go: yield(s[i : i+end : i+end]) — fresh chunk, no shared cap.
        let mut chunk: alloc::vec::Vec<T> = alloc::vec::Vec::with_capacity(end);
        for j in 0..end {
            chunk.push(raw[i + j].clone());
        }
        out.push(slice::__from_vec(chunk));
        i += n_us;
    }
    slice::__from_vec(out)
}
