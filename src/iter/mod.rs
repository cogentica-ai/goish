// iter — Go 1.23 function iterators (Go 1.25.5 src/iter/iter.go).
//
// Go:
//   type Seq[V any]     func(yield func(V) bool)
//   type Seq2[K, V any] func(yield func(K, V) bool)
//
// Goish models these as traits (the settled v1 decision): a push
// iterator is anything
// with `run(&self, yield)`, where the yield callback returns `false`
// to stop early (Go's `break`). The blanket impls below make plain
// closures the everyday spelling, so an iterator-returning function
// reads like its Go original:
//
//   // Go: func (t *Tree) Walk() iter.Seq[int] {
//   //         return func(yield func(int) bool) { t.walk(yield) }
//   //     }
//   pub fn Walk(&self) -> impl iter::Seq<int> {
//       let t = self.clone();
//       move |yield_: &mut dyn FnMut(int) -> bool| { t.walk(yield_); }
//   }
//
// Consumption:
//   - stdlib sinks: `slices::Collect`, `slices::Sorted`,
//     `slices::AppendSeq` take `impl iter::Seq<T>`.
//   - direct: `seq.run(&mut |v| { …; true })` — the same closure-call
//     shape the transpiler lowers `for v := range seq { … }` to
//     (RANGE_OVER_FUNC.md §3.4: range-over-func bypasses `range!`).
//   - stored: `Arc<dyn iter::Seq<V> + Send + Sync>` when the Go value
//     is known to cross goroutines. Ordinary Go func values carry no
//     implicit thread-safety constraint, so Seq itself does not require
//     Send or Sync.
//
// Sources shipped elsewhere: `slices::Values/All`, `maps::Keys/
// Values`, `strings::SplitSeq/Lines`.
//
// Conveniences beyond Go (documented): `slice<T>` / `&slice<T>` are
// themselves `Seq<T>` sources, so `slices::Sorted(&s)` keeps working
// alongside `slices::Sorted(maps::Keys(&m))`.
//
// Deferred: `iter.Pull` / `Pull2` (push→pull inversion). Go builds
// them on runtime coroutines (iter.go:Pull, runtime coroswitch);
// goish would use a goroutine + chan pair. No target workload uses
// them yet (typescript-go: zero call sites) — file a gap when one
// appears.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

/// `iter.Seq[V]` (iter.go) — a push iterator over single values.
/// `run` calls `yield_` once per element until exhaustion or until
/// `yield_` returns `false`.
pub trait Seq<V> {
    fn run(&self, yield_: &mut dyn FnMut(V) -> bool);
}

/// `iter.Seq2[K, V]` (iter.go) — a push iterator over pairs.
pub trait Seq2<K, V> {
    fn run(&self, yield_: &mut dyn FnMut(K, V) -> bool);
}

// Closures of the Go iterator shape are Seqs — this is the everyday
// spelling for user-defined iterators.
impl<V, F> Seq<V> for F
where
    F: Fn(&mut dyn FnMut(V) -> bool),
{
    fn run(&self, yield_: &mut dyn FnMut(V) -> bool) {
        self(yield_)
    }
}

impl<K, V, F> Seq2<K, V> for F
where
    F: Fn(&mut dyn FnMut(K, V) -> bool),
{
    fn run(&self, yield_: &mut dyn FnMut(K, V) -> bool) {
        self(yield_)
    }
}

// Boxed/shared iterator values (struct fields, interface returns)
// forward to the inner iterator, so an `Arc<dyn Seq<V>>` flows into
// any `impl Seq<V>` sink.
impl<V> Seq<V> for Arc<dyn Seq<V> + Send + Sync> {
    fn run(&self, yield_: &mut dyn FnMut(V) -> bool) {
        (**self).run(yield_)
    }
}

impl<K, V> Seq2<K, V> for Arc<dyn Seq2<K, V> + Send + Sync> {
    fn run(&self, yield_: &mut dyn FnMut(K, V) -> bool) {
        (**self).run(yield_)
    }
}

// `slice<T>` is a natural single-pass source (yields element clones,
// like Go's `slices.Values`). Keeps pre-iter call sites such as
// `slices::Sorted(&s)` valid — the widening the slices module's v0
// comments anticipated.
impl<T> Seq<T> for crate::goslice::slice<T>
where
    T: Clone + Send + Sync,
{
    fn run(&self, yield_: &mut dyn FnMut(T) -> bool) {
        for v in self.as_ref() {
            if !yield_(v.clone()) {
                return;
            }
        }
    }
}

impl<T> Seq<T> for &crate::goslice::slice<T>
where
    T: Clone + Send + Sync,
{
    fn run(&self, yield_: &mut dyn FnMut(T) -> bool) {
        (**self).run(yield_)
    }
}
