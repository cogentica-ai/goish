// go: file container/heap/heap.go decls: Init, Push, Pop, Remove, Fix, up, down
//
// The `decls:` manifest above lists heap.go's funcs only. GOISH017
// matches a manifest entry against Rust `fn` items, so naming the
// `Interface` type there would report it as a dropped port. It is not
// dropped — it carries its own `// go: sdk` anchor below.
//
// container/heap/heap.go — heap operations for any type implementing
// `heap.Interface`. A heap is a tree with the property that each node
// is the minimum-valued node in its subtree.
//
// The invariant is maintained by exactly two sift routines, `up` and
// `down`, and every public entry point is a thin wrapper around one of
// them. `Remove` is the one that looks surprising: it swaps the doomed
// element with the last, pops it, and then has to sift the replacement
// *both* ways — `down` first, and `up` only if `down` made no progress,
// because the replacement may belong either above or below the hole.
// That `if !down(...) { up(...) }` is Go's, and is reproduced rather
// than replaced with an unconditional pair.
//
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

// go: sdk 1.25.5 container/heap/heap.go:31-39 Interface
/// `heap.Interface` — the requirements for a min-heap.
/// Goish flavor: associated `Item` type replaces `any`.
pub trait Interface {
    /// The element type pushed into and popped out of the heap.
    type Item;

    // go: none — goish idiom: Go's `heap.Interface` embeds
    //     `sort.Interface`, so `Len`/`Less`/`Swap` are declared in
    //     sort, not in heap.go. goish inlines the three methods here
    //     rather than embedding a second trait.
    /// `Len()` — number of elements.
    fn Len(&self) -> int;

    // go: none — goish idiom: from the embedded `sort.Interface`; see `Len`.
    /// `Less(i, j)` — true iff element i should sort before j.
    fn Less(&self, i: int, j: int) -> bool;

    // go: none — goish idiom: from the embedded `sort.Interface`; see `Len`.
    /// `Swap(i, j)` — exchange elements i and j.
    fn Swap(&mut self, i: int, j: int);

    // go: none — goish idiom: an interface *method* declaration, which
    //     lives inside Go's `type Interface interface { … }` at
    //     heap.go:31-39 rather than in a `func`. The free `Push` below
    //     is the anchored port of `heap.Push`.
    /// `Push(x)` — append `x` as element Len(). Called by the heap
    /// machinery; user code uses `heap::Push` instead.
    fn Push(&mut self, x: Self::Item);

    // go: none — goish idiom: an interface method declaration; see
    //     `Interface::Push`. The free `Pop` below is the anchored port
    //     of `heap.Pop`.
    /// `Pop()` — remove and return the last element. Called by the
    /// heap machinery; user code uses `heap::Pop` instead.
    fn Pop(&mut self) -> Self::Item;
}

// go: sdk 1.25.5 container/heap/heap.go:41-47 Init
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

// go: sdk 1.25.5 container/heap/heap.go:51-54 Push
/// `heap.Push(h, x)` (heap.go:51) — add `x` to the heap.
/// Complexity: O(log n).
pub fn Push<H: Interface>(h: &mut H, x: H::Item) {
    h.Push(x);
    let len = h.Len();
    up(h, len - 1);
}

// go: sdk 1.25.5 container/heap/heap.go:59-64 Pop
/// `heap.Pop(h)` (heap.go:59) — remove and return the minimum.
/// Complexity: O(log n).
pub fn Pop<H: Interface>(h: &mut H) -> H::Item {
    // Go: n := h.Len() - 1; h.Swap(0, n); down(h, 0, n); return h.Pop()
    let n = h.Len() - 1;
    h.Swap(0, n);
    down(h, 0, n);
    return h.Pop();
}

// go: sdk 1.25.5 container/heap/heap.go:68-77 Remove
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
    return h.Pop();
}

// go: sdk 1.25.5 container/heap/heap.go:83-87 Fix
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

// go: sdk 1.25.5 container/heap/heap.go:89-98 up
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

// go: sdk 1.25.5 container/heap/heap.go:100-118 down
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
    return i > i0;
}
