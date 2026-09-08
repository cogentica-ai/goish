// go: file sort/sort.go decls: Sort, IsSorted, reverse.Less, Reverse, IntsAreSorted, StringsAreSorted, Float64sAreSorted, Stable, IntSlice.Len, IntSlice.Less, IntSlice.Swap, IntSlice.Sort, isNaN, Float64Slice.Len, Float64Slice.Less, Float64Slice.Swap, Float64Slice.Sort, StringSlice.Len, StringSlice.Less, StringSlice.Swap, StringSlice.Sort, Ints, Float64s, Strings
//
// sort.go — Interface, Sort, Stable, IsSorted, Reverse, the
// three convenience Slice types, and the *AreSorted predicates.
//
// goishlint:ignore GOISH018 Next, nextPowerOfTwo — `Next` and `nextPowerOfTwo` belong to `xorshift`, the PRNG pdqsort uses to break adversarial patterns, and goish's Sort is a heapsort. `Ints`, `Float64s` and `Strings` were listed here too, described as "macros in the module root rather than functions". They are `pub fn`s in this file, anchored to sort.go, and taking `&mut slice<T>` — so the waiver was suppressing GOISH018 over three ported declarations, on a reason that had stopped being true. Re-checked 2026-09-06.
// goishlint:ignore GOISH021 sortedHint, unknownHint, increasingHint, decreasingHint, xorshift, lessSwap — pdqsort's internals: the hint it passes down about a partition's existing order, its PRNG, and the closure pair `Slice` builds to drive the generated `zsortfunc.go`. goish's Slice delegates to Rust's sort, which needs none of them.

extern crate alloc;

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{float64, int};

// ─── Interface (sort.go:17) ─────────────────────────────────────────

// go: sdk 1.25.5 sort/sort.go:17-46 Interface
/// `sort.Interface` (sort.go:17) — collection that can be sorted in
/// place by `Sort` and friends. Implementors expose a length, a
/// pairwise less-than predicate, and an index-pair swap.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Interface {
    /// `Len()` — number of elements.
    fn Len(&self) -> int;

    /// `Less(i, j)` — true iff element i must sort strictly before j.
    fn Less(&self, i: int, j: int) -> bool;

    /// `Swap(i, j)` — exchange elements at indices i and j.
    fn Swap(&mut self, i: int, j: int);
}

// go: waived breakPatterns — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived breakPatterns_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived choosePivot — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived choosePivot_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived heapSort — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived heapSort_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived insertionSort_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived median — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived median_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived medianAdjacent — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived medianAdjacent_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived nextPowerOfTwo — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived order2 — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived order2_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived partialInsertionSort — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived partialInsertionSort_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived partition — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived partitionEqual — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived partitionEqual_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived partition_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived pdqsort — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived pdqsort_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived reverseRange — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived reverseRange_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived rotate_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived siftDown_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived stable_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived swapRange_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived symMerge_func — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.
// go: waived xorshift.Next — Go's pdqsort engine, plus the zsortfunc/zsortinterface copies the generator emits of each piece; goish's Sort is a heapsort (see the deviation note on Sort above), so there is no counterpart to name.

// ─── Sort (sort.go:50) — heapsort fallback ──────────────────────────

// go: sdk 1.25.5 sort/sort.go:50-57 Sort
/// `sort.Sort(data)` (sort.go:50). Deviation: heapsort instead of
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

// go: none — goish idiom: Go's `Sort` is pdqsort, generated into
//     zsortinterface.go along with a dozen helpers. goish's is a
//     heapsort — the same O(n log n) with no scratch space, in about
//     thirty lines — and this is its sift-down. Go's `siftDown` there
//     belongs to a different algorithm and takes a `first` offset this
//     one has no use for.
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

// go: sdk 1.25.5 sort/sort.go:110-118 IsSorted
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
    return true;
}

// ─── Reverse (sort.go:90, sort.go:101) ──────────────────────────────

/// `sort.reverse{Interface}` wrapper (sort.go:90) — flips the embedded
/// `Less`. Returned by `Reverse(data)`. The wrapped value is exposed as
/// `pub inner` so tests can recover it after `Sort(&mut Reverse(s))`.
pub struct Reverse<I: Interface> {
    pub inner: I,
}

impl<I: Interface> Interface for Reverse<I> {
    // go: none — goish idiom: Go's `reverse` EMBEDS the Interface, so Len
    //     and Swap are promoted for free and only Less is written out
    //     (sort.go:90-94). Rust has no embedding, so the two forwards
    //     are spelled here.
    fn Len(&self) -> int {
        return self.inner.Len();
    }
    // go: sdk 1.25.5 sort/sort.go:97-99 reverse.Less
    fn Less(&self, i: int, j: int) -> bool {
        // Go: r.Interface.Less(j, i)
        return self.inner.Less(j, i);
    }
    // go: none — goish idiom: the promoted `Swap` of Go's embedded
    //     Interface, written out; see `Len` above.
    fn Swap(&mut self, i: int, j: int) {
        self.inner.Swap(i, j);
    }
}

// go: sdk 1.25.5 sort/sort.go:102-104 Reverse
/// `sort.Reverse(data)` (sort.go:101) — wrap `data` to sort in
/// descending order.
pub fn Reverse<I: Interface>(data: I) -> Reverse<I> {
    return Reverse { inner: data };
}

// ─── Ints / Float64s / Strings (sort.go:170, :176, :181) ────────────
//
// Go: "as of Go 1.22, this function simply calls slices.Sort." goish
// had the three AreSorted predicates below but not one of the three
// sorts they are about — so `sort.Ints(x)`, which is in more Go code
// than any other call in this package, did not exist.

// go: sdk 1.25.5 sort/sort.go:170-170 Ints
/// `sort.Ints(x)` — sort a slice of ints in increasing order.
pub fn Ints(x: &mut slice<int>) {
    // Go: slices.Sort(x)
    crate::slices::Sort!(*x);
}

// go: sdk 1.25.5 sort/sort.go:176-176 Float64s
/// `sort.Float64s(x)` — Go: "sorts a slice of float64s in increasing
/// order. Not-a-number (NaN) values are ordered before other values."
pub fn Float64s(x: &mut slice<float64>) {
    // Go: slices.Sort(x)
    crate::slices::Sort!(*x);
}

// go: sdk 1.25.5 sort/sort.go:181-181 Strings
/// `sort.Strings(x)` — sort a slice of strings in increasing order.
pub fn Strings(x: &mut slice<string>) {
    // Go: slices.Sort(x)
    crate::slices::Sort!(*x);
}

// ─── *AreSorted predicates (sort.go:186, :192, :197) ────────────────

// go: sdk 1.25.5 sort/sort.go:186-186 IntsAreSorted
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
    return true;
}

// go: sdk 1.25.5 sort/sort.go:197-197 StringsAreSorted
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
    return true;
}

// go: sdk 1.25.5 sort/sort.go:192-192 Float64sAreSorted
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
    return true;
}

// ─── Stable (sort.go:233) ───────────────────────────────────────────

// go: sdk 1.25.5 sort/sort.go:233-235 Stable
/// `sort.Stable(data)` — sort in ascending order by `Less`, keeping the
/// original order of equal elements.
///
/// This was deferred, with "would need symmerge sort" as the reason. It
/// does, and here it is: [`stable`] below. Without it a caller who needs
/// stability had only `slices::SortStableFunc!`, which takes a
/// comparator over a concrete slice rather than a `sort::Interface` — so
/// a type that sorts several parallel arrays through Swap had no stable
/// option at all.
pub fn Stable<I: Interface + ?Sized>(data: &mut I) {
    super::stable(data, data.Len());
}

// ─── IntSlice / Float64Slice / StringSlice (sort.go:123-167) ────────

// go: sdk 1.25.5 sort/sort.go:123-123 IntSlice
/// `sort.IntSlice` — attaches the methods of [`Interface`] to a
/// `slice<int>`, sorting in increasing order.
pub struct IntSlice(pub slice<int>);

impl Interface for IntSlice {
    // go: sdk 1.25.5 sort/sort.go:125-125 IntSlice.Len
    fn Len(&self) -> int {
        return self.0.Len();
    }
    // go: sdk 1.25.5 sort/sort.go:126-126 IntSlice.Less
    fn Less(&self, i: int, j: int) -> bool {
        return self.0[i as usize] < self.0[j as usize];
    }
    // go: sdk 1.25.5 sort/sort.go:127-127 IntSlice.Swap
    fn Swap(&mut self, i: int, j: int) {
        self.0.swap(i, j);
    }
}

impl IntSlice {
    // go: sdk 1.25.5 sort/sort.go:130-130 IntSlice.Sort
    /// `x.Sort()` — a convenience method for `Sort(x)`.
    pub fn Sort(&mut self) {
        Sort(self);
    }
}

// go: sdk 1.25.5 sort/sort.go:148-150 isNaN
/// A copy of `math.IsNaN`, so `sort` does not depend on `math`. Go
/// keeps its own for the same reason.
fn isNaN(f: float64) -> bool {
    return f != f;
}

// go: sdk 1.25.5 sort/sort.go:134-134 Float64Slice
/// `sort.Float64Slice` — attaches the methods of [`Interface`] to a
/// `slice<float64>`, sorting in increasing order with NaN FIRST.
pub struct Float64Slice(pub slice<float64>);

impl Interface for Float64Slice {
    // go: sdk 1.25.5 sort/sort.go:136-136 Float64Slice.Len
    fn Len(&self) -> int {
        return self.0.Len();
    }
    // go: sdk 1.25.5 sort/sort.go:144-144 Float64Slice.Less
    /// Floating-point `<` is not a transitive relation — it gives no
    /// consistent ordering for NaN — so this places every NaN before
    /// everything else, which does.
    fn Less(&self, i: int, j: int) -> bool {
        let (a, b) = (self.0[i as usize], self.0[j as usize]);
        return a < b || (isNaN(a) && !isNaN(b));
    }
    // go: sdk 1.25.5 sort/sort.go:145-145 Float64Slice.Swap
    fn Swap(&mut self, i: int, j: int) {
        self.0.swap(i, j);
    }
}

impl Float64Slice {
    // go: sdk 1.25.5 sort/sort.go:153-153 Float64Slice.Sort
    /// `x.Sort()` — a convenience method for `Sort(x)`.
    pub fn Sort(&mut self) {
        Sort(self);
    }
}

// go: sdk 1.25.5 sort/sort.go:156-156 StringSlice
/// `sort.StringSlice` — attaches the methods of [`Interface`] to a
/// `slice<string>`, sorting in increasing order.
pub struct StringSlice(pub slice<string>);

impl Interface for StringSlice {
    // go: sdk 1.25.5 sort/sort.go:158-158 StringSlice.Len
    fn Len(&self) -> int {
        return self.0.Len();
    }
    // go: sdk 1.25.5 sort/sort.go:159-159 StringSlice.Less
    fn Less(&self, i: int, j: int) -> bool {
        return self.0[i as usize].as_bytes() < self.0[j as usize].as_bytes();
    }
    // go: sdk 1.25.5 sort/sort.go:160-160 StringSlice.Swap
    fn Swap(&mut self, i: int, j: int) {
        self.0.swap(i, j);
    }
}

impl StringSlice {
    // go: sdk 1.25.5 sort/sort.go:163-163 StringSlice.Sort
    /// `x.Sort()` — a convenience method for `Sort(x)`.
    pub fn Sort(&mut self) {
        Sort(self);
    }
}
