// go: file sort/zsortinterface.go decls: stable, insertionSort, symMerge, rotate, swapRange
//
// zsortinterface.go — the STABLE half of Go's generated sort engine.
//
// Go generates this file and zsortfunc.go from one template, once per
// dispatch shape. goish takes pdqsort from Rust's stdlib, so the
// unstable half has no counterpart; the stable half does not exist
// there in a form `sort.Interface` can use — Rust's `sort_by` needs a
// comparator over elements, and an Interface has only Len, Less and
// Swap — so it is ported here, line for line.
//
// goishlint:ignore GOISH018 siftDown, heapSort, pdqsort, partition, partitionEqual, partialInsertionSort, breakPatterns, choosePivot, order2, median, medianAdjacent, reverseRange — the UNSTABLE half: pdqsort and its helpers. goish's `Sort` is a heapsort (see the deviation note in the module root) and `Slice`/`SliceStable` delegate to Rust's, so none of these has a counterpart.

extern crate alloc;

use crate::convert::{int as toint, uint as touint};
use crate::types::int;

use super::Interface;

// go: sdk 1.25.5 sort/zsortinterface.go:335-357 stable
/// Insertion-sort blocks of 20, then merge adjacent blocks pairwise,
/// doubling the block size until the whole range is one block.
pub(super) fn stable<I: Interface + ?Sized>(data: &mut I, n: int) {
    let mut blockSize: int = 20; // must be > 0
    let (mut a, mut b) = (0, blockSize);
    while b <= n {
        insertionSort(data, a, b);
        a = b;
        b += blockSize;
    }
    insertionSort(data, a, n);

    while blockSize < n {
        a = 0;
        b = 2 * blockSize;
        while b <= n {
            symMerge(data, a, a + blockSize, b);
            a = b;
            b += 2 * blockSize;
        }
        let m = a + blockSize;
        if m < n {
            symMerge(data, a, m, n);
        }
        blockSize *= 2;
    }
}

// go: sdk 1.25.5 sort/zsortinterface.go:10-16 insertionSort
fn insertionSort<I: Interface + ?Sized>(data: &mut I, a: int, b: int) {
    let mut i = a + 1;
    while i < b {
        let mut j = i;
        while j > a && data.Less(j, j - 1) {
            data.Swap(j, j - 1);
            j -= 1;
        }
        i += 1;
    }
}

// go: sdk 1.25.5 sort/zsortinterface.go:378-458 symMerge
/// Merge the sorted runs `data[a:m]` and `data[m:b]` in place, using the
/// SymMerge algorithm of Kim and Kutzner. `Swap` is the only move this
/// has, which is why it costs O(n log n) swaps rather than O(n).
fn symMerge<I: Interface + ?Sized>(data: &mut I, a: int, m: int, b: int) {
    // A single element on the left: binary-search its home and walk it
    // there. Avoids a recursion.
    if m - a == 1 {
        let mut i = m;
        let mut j = b;
        while i < j {
            let h = toint((touint(i) + touint(j)) >> 1);
            if data.Less(h, a) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        let mut k = a;
        while k < i - 1 {
            data.Swap(k, k + 1);
            k += 1;
        }
        return;
    }

    // A single element on the right: the mirror of the above.
    if b - m == 1 {
        let mut i = a;
        let mut j = m;
        while i < j {
            let h = toint((touint(i) + touint(j)) >> 1);
            if !data.Less(m, h) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        let mut k = m;
        while k > i {
            data.Swap(k, k - 1);
            k -= 1;
        }
        return;
    }

    let mid = toint((touint(a) + touint(b)) >> 1);
    let n = mid + m;
    let (mut start, mut r);
    if m > mid {
        start = n - b;
        r = mid;
    } else {
        start = a;
        r = m;
    }
    let p = n - 1;

    while start < r {
        let c = toint((touint(start) + touint(r)) >> 1);
        if !data.Less(p - c, c) {
            start = c + 1;
        } else {
            r = c;
        }
    }

    let end = n - start;
    if start < m && m < end {
        rotate(data, start, m, end);
    }
    if a < start && start < mid {
        symMerge(data, a, start, mid);
    }
    if mid < end && end < b {
        symMerge(data, mid, end, b);
    }
}

// go: sdk 1.25.5 sort/zsortinterface.go:464-478 rotate
/// Rotate the two consecutive blocks `data[a:m]` and `data[m:b]`, so
/// `x u v y` becomes `x v u y`. At most `b-a` swaps, and it assumes
/// `a < m && m < b`.
fn rotate<I: Interface + ?Sized>(data: &mut I, a: int, m: int, b: int) {
    let mut i = m - a;
    let mut j = b - m;

    while i != j {
        if i > j {
            swapRange(data, m - i, m, j);
            i -= j;
        } else {
            swapRange(data, m - i, m + j - i, i);
            j -= i;
        }
    }
    // i == j
    swapRange(data, m - i, m, i);
}

// go: sdk 1.25.5 sort/zsortinterface.go:329-333 swapRange
fn swapRange<I: Interface + ?Sized>(data: &mut I, a: int, b: int, n: int) {
    let mut i: int = 0;
    while i < n {
        data.Swap(a + i, b + i);
        i += 1;
    }
}
