// go: file slices/iter.go decls: Collect, AppendSeq, Values, All, Backward, Sorted, SortedFunc, SortedStableFunc, Chunk
//
// iter.go — the iter.Seq bridge: All, Backward, Values,
// AppendSeq, Collect, Sorted, SortedFunc, SortedStableFunc, Chunk.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::goslice::slice;
use crate::types::int;

// go: none — goish idiom: Go writes the drain inline in each of
/// Drain a seq into a Vec (shared body of Collect/Sorted*).
//     Collect, Sorted, SortedFunc and SortedStableFunc, because
//     `for x := range seq` is three tokens. goish's `Seq::run` takes a
//     closure, so the four would repeat it; named once here.
fn collect_vec<T>(seq: impl crate::iter::Seq<T>) -> Vec<T> {
    let mut v: Vec<T> = Vec::new();
    seq.run(&mut |x| {
        v.push(x);
        true
    });
    return v;
}

// go: sdk 1.25.5 slices/iter.go:59-61 Collect
/// `slices.Collect(seq)` (iter.go:Collect) — gather the values of a
/// seq into a new slice.
pub fn Collect<T>(seq: impl crate::iter::Seq<T>) -> slice<T> {
    return slice::__from_vec(collect_vec(seq));
}

// go: sdk 1.25.5 slices/iter.go:50-55 AppendSeq
/// `slices.AppendSeq(s, seq)` (iter.go:AppendSeq) — append the values
/// of `seq` to a copy of `s`, returning the extended slice.
pub fn AppendSeq<T: Clone>(s: slice<T>, seq: impl crate::iter::Seq<T>) -> slice<T> {
    let mut v = s.__into_vec();
    seq.run(&mut |x| {
        v.push(x);
        true
    });
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/iter.go:37-45 Values
/// `slices.Values(s)` (iter.go:Values) — seq over the elements of
/// `s` (a snapshot of the handle at call time).
pub fn Values<T>(s: &slice<T>) -> impl crate::iter::Seq<T>
where
    T: Clone + Send + Sync + 'static,
{
    let snap = s.clone();
    return move |yield_: &mut dyn FnMut(T) -> bool| {
        for v in snap.as_ref() {
            if !yield_(v.clone()) {
                return;
            }
        }
    };
}

// go: sdk 1.25.5 slices/iter.go:14-22 All
/// `slices.All(s)` (iter.go:All) — seq over (index, element) pairs.
pub fn All<T>(s: &slice<T>) -> impl crate::iter::Seq2<int, T>
where
    T: Clone + Send + Sync + 'static,
{
    let snap = s.clone();
    return move |yield_: &mut dyn FnMut(int, T) -> bool| {
        for (i, v) in snap.as_ref().iter().enumerate() {
            if !yield_(toint(i), v.clone()) {
                return;
            }
        }
    };
}

// go: sdk 1.25.5 slices/iter.go:26-34 Backward
/// `slices.Backward(s)` (iter.go:Backward) — seq over (index,
/// element) pairs, walking backward.
pub fn Backward<T>(s: &slice<T>) -> impl crate::iter::Seq2<int, T>
where
    T: Clone + Send + Sync + 'static,
{
    let snap = s.clone();
    return move |yield_: &mut dyn FnMut(int, T) -> bool| {
        for (i, v) in snap.as_ref().iter().enumerate().rev() {
            if !yield_(toint(i), v.clone()) {
                return;
            }
        }
    };
}

// go: sdk 1.25.5 slices/iter.go:66-70 Sorted
/// `slices.Sorted(seq)` (sort.go:Sorted) — collect `seq`, sort
/// ascending, return.
pub fn Sorted<T: Ord>(seq: impl crate::iter::Seq<T>) -> slice<T> {
    // Go: s := slices.Collect(seq); Sort(s); return s
    let mut v = collect_vec(seq);
    v.sort_unstable();
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/iter.go:75-79 SortedFunc
/// `slices.SortedFunc(seq, cmp)` (sort.go:SortedFunc) — collect
/// `seq`, sort with `cmp(a, b) -> int` (negative = a<b, 0 = equal,
/// positive = a>b), return.
pub fn SortedFunc<T, F>(seq: impl crate::iter::Seq<T>, mut cmp: F) -> slice<T>
where
    F: FnMut(&T, &T) -> int,
{
    let mut v = collect_vec(seq);
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
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/iter.go:86-90 SortedStableFunc
/// `slices.SortedStableFunc(seq, cmp)` — stable variant of
/// `SortedFunc`. Equal elements keep their collection order.
pub fn SortedStableFunc<T, F>(seq: impl crate::iter::Seq<T>, mut cmp: F) -> slice<T>
where
    F: FnMut(&T, &T) -> int,
{
    let mut v = collect_vec(seq);
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
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 slices/iter.go:97-114 Chunk
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
    return slice::__from_vec(out);
}
