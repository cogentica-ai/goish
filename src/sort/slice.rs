// go: file sort/slice.go decls: Slice, SliceStable, SliceIsSorted
//
// slice.go — Slice, SliceStable, SliceIsSorted.

extern crate alloc;

use crate::convert::int as toint;
use crate::goslice::slice;
use crate::types::int;

// ─── Slice / SliceStable (sort.go:210, :224) ────────────────────────

// go: sdk 1.25.5 sort/slice.go:24-30 Slice
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
    let sift_down = |less: &mut F, ptr: *mut T, mut r: int, end: int| loop {
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
        unsafe {
            core::ptr::swap(ptr.offset(r as isize), ptr.offset(child as isize));
        }
        r = child;
    };

    let mut start = (n - 1) / 2;
    loop {
        sift_down(&mut less, ptr, start, n);
        if start == 0 {
            break;
        }
        start -= 1;
    }
    let mut end = n - 1;
    while end > 0 {
        unsafe {
            core::ptr::swap(ptr, ptr.offset(end as isize));
        }
        sift_down(&mut less, ptr, 0, end);
        end -= 1;
    }
}

// go: sdk 1.25.5 sort/slice.go:41-45 SliceStable
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
        if less(toint(a), toint(b)) {
            core::cmp::Ordering::Less
        } else if less(toint(b), toint(a)) {
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
            unsafe {
                core::ptr::swap(ptr.offset(j as isize), ptr.offset(k as isize));
            }
            j = k;
        }
    }
}

// go: sdk 1.25.5 sort/slice.go:52-61 SliceIsSorted
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
    return true;
}
