// container/heap — heap operations over a user-supplied data structure.
//
// Reference: /share/go/src/container/heap/heap.go.
//
// Slim deviations:
//
//   * `Interface` is a goish trait with an associated `Item` type
//     instead of Go's `any`. The user's data structure decides what
//     it stores; Push/Pop accept/return that exact `Item` type.
//
//   * `sort.Interface` (Len/Less/Swap) merged into the same trait
//     rather than embedded, since goish doesn't have `sort` yet
//     and the trait surface is small.
//
//   * Free functions (Init / Push / Pop / Remove / Fix) take
//     `&mut H` rather than the Go `Interface` argument; the trait
//     methods Len/Less/Swap/Push/Pop dispatch internally.

#![allow(non_snake_case)]

use crate::types::int;

/// `heap.Interface` — the requirements for a min-heap.
/// Goish flavor: associated `Item` type replaces `any`.
pub trait Interface {
    /// The element type pushed into and popped out of the heap.
    type Item;

    /// `Len()` — number of elements.
    fn Len(&self) -> int;

    /// `Less(i, j)` — true iff element i should sort before j.
    fn Less(&self, i: int, j: int) -> bool;

    /// `Swap(i, j)` — exchange elements i and j.
    fn Swap(&mut self, i: int, j: int);

    /// `Push(x)` — append `x` as element Len(). Called by the heap
    /// machinery; user code uses `heap::Push` instead.
    fn Push(&mut self, x: Self::Item);

    /// `Pop()` — remove and return the last element. Called by the
    /// heap machinery; user code uses `heap::Pop` instead.
    fn Pop(&mut self) -> Self::Item;
}

/// `heap.Init(h)` (heap.go:41) — establish heap invariants.
/// Idempotent; safe to call after invariants may have been broken.
/// Complexity: O(n).
pub fn Init<H: Interface>(h: &mut H) {
    // Go: n := h.Len(); for i := n/2 - 1; i >= 0; i-- { down(h, i, n) }
    let n = h.Len();
    let mut i = n / 2 - 1;
    while i >= 0 {
        down(h, i, n);
        i -= 1;
    }
}

/// `heap.Push(h, x)` (heap.go:51) — add `x` to the heap.
/// Complexity: O(log n).
pub fn Push<H: Interface>(h: &mut H, x: H::Item) {
    h.Push(x);
    let len = h.Len();
    up(h, len - 1);
}

/// `heap.Pop(h)` (heap.go:59) — remove and return the minimum.
/// Complexity: O(log n).
pub fn Pop<H: Interface>(h: &mut H) -> H::Item {
    // Go: n := h.Len() - 1; h.Swap(0, n); down(h, 0, n); return h.Pop()
    let n = h.Len() - 1;
    h.Swap(0, n);
    down(h, 0, n);
    h.Pop()
}

/// `heap.Remove(h, i)` (heap.go:68) — remove and return element at
/// index `i`. Complexity: O(log n).
pub fn Remove<H: Interface>(h: &mut H, i: int) -> H::Item {
    // Go: n := h.Len() - 1; if n != i { h.Swap(i, n); if !down(h, i, n) { up(h, i) } }; return h.Pop()
    let n = h.Len() - 1;
    if n != i {
        h.Swap(i, n);
        if !down(h, i, n) {
            up(h, i);
        }
    }
    h.Pop()
}

/// `heap.Fix(h, i)` (heap.go:83) — re-establish heap ordering after
/// the element at index `i` has changed. Complexity: O(log n).
pub fn Fix<H: Interface>(h: &mut H, i: int) {
    // Go: if !down(h, i, h.Len()) { up(h, i) }
    let n = h.Len();
    if !down(h, i, n) {
        up(h, i);
    }
}

// ─── internal sift helpers (heap.go:89, heap.go:100) ────────────────

fn up<H: Interface>(h: &mut H, mut j: int) {
    loop {
        // Go: i := (j - 1) / 2  // parent
        let i = (j - 1) / 2;
        if i == j || !h.Less(j, i) {
            break;
        }
        h.Swap(i, j);
        j = i;
    }
}

fn down<H: Interface>(h: &mut H, i0: int, n: int) -> bool {
    let mut i = i0;
    loop {
        // Go: j1 := 2*i + 1; if j1 >= n || j1 < 0 { break }
        let j1 = 2 * i + 1;
        if j1 >= n || j1 < 0 {
            break;
        }
        let mut j = j1;
        // Go: if j2 := j1 + 1; j2 < n && h.Less(j2, j1) { j = j2 }
        let j2 = j1 + 1;
        if j2 < n && h.Less(j2, j1) {
            j = j2;
        }
        if !h.Less(j, i) {
            break;
        }
        h.Swap(i, j);
        i = j;
    }
    i > i0
}
