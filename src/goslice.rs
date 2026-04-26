// goslice — Go's `[]T`, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var xs []int                         let xs: slice<int> = ...
//   xs := []int{1, 2, 3}                 let xs = ...               ← M5: make!/slice!
//   len(xs), cap(xs)                     len(xs), cap(xs)
//   xs[i]                                xs[i]                      ← Index<int>
//   xs[low:high]                         xs.slice(low, high)        ← copy semantics
//   for i, v := range xs                 for (i, v) in range!(xs)
//   xs = append(xs, x)                   xs = append(xs, x)         ← M5
//
// The struct is named lowercase `slice` to match Go's type. The
// generic parameter T means call sites read `slice<int>`, `slice<byte>`,
// etc., mirroring Go's `[]int`, `[]byte`.
//
// Backing: `Vec<T>`. Subslicing **copies** rather than aliasing the
// backing array (the documented v1 deviation from Go semantics — see
// ROADMAP.md). This buys Rust's borrow-checker safety; the cost is a
// copy on `xs[low:high]`, which is uncommon in idiomatic Go anyway.

#![allow(non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut, Index};

use crate::builtin::{Cap as CapTrait, Len as LenTrait};
use crate::types::int;

#[derive(Clone)]
pub struct slice<T> {
    inner: Vec<T>,
}

impl<T> slice<T> {
    /// Empty slice. Matches Go's `nil` slice for length/cap purposes;
    /// goish slices are never literally nil — empty owned Vec instead.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Internal hook used by `slice!`/`make!`/`append!` macros and by
    /// utf8 builders. Dunder + `#[doc(hidden)]` mark it "do not call
    /// directly" — public only because macros need a path that resolves
    /// at user call sites.
    #[doc(hidden)]
    pub fn __from_vec(v: Vec<T>) -> Self {
        Self { inner: v }
    }

    /// Internal hook for `append!`. Same caveats as `__from_vec`.
    #[doc(hidden)]
    pub fn __into_vec(self) -> Vec<T> {
        self.inner
    }

    /// `len(xs)` — number of elements.
    #[allow(non_snake_case)]
    pub fn Len(&self) -> int {
        self.inner.len() as int
    }

    /// `cap(xs)` — capacity of the backing array.
    #[allow(non_snake_case)]
    pub fn Cap(&self) -> int {
        self.inner.capacity() as int
    }
}

impl<T: Clone> slice<T> {
    /// `xs[low:high]` — Go's subslicing.
    ///
    /// **v1 deviation**: returns an *independent copy*, not a view into
    /// the original backing. Reads behave identically; mutations on the
    /// returned slice do not propagate to the parent. See ROADMAP.md.
    pub fn slice(&self, low: int, high: int) -> Self {
        let lo = low as usize;
        let hi = high as usize;
        Self {
            inner: self.inner[lo..hi].to_vec(),
        }
    }
}

impl<T> Default for slice<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── builtin len(xs) / cap(xs) — see builtin.rs for `len` ─────────────

impl<T> LenTrait for slice<T> {
    #[inline]
    fn __len(&self) -> int {
        self.inner.len() as int
    }
}

impl<T> CapTrait for slice<T> {
    #[inline]
    fn __cap(&self) -> int {
        self.inner.capacity() as int
    }
}

// ─── xs[i] — Go-faithful indexing (panics on out-of-range) ────────────

impl<T> Index<int> for slice<T> {
    type Output = T;
    fn index(&self, i: int) -> &T {
        &self.inner[i as usize]
    }
}

// ─── &xs auto-derefs to &[T] for low-level helpers (utf8, etc.) ───────
//
// `Deref` is a Rust internal — users never see it directly. It just
// makes `&[T]`-taking helpers accept `&slice<T>` without ceremony,
// matching Go's habit of treating slices as their underlying arrays.

impl<T> Deref for slice<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

// `DerefMut` enables `copy!(dst, src)` to take `&mut dst` (auto-deref to
// `&mut [T]`) without leaking Rust borrow syntax to the user.
impl<T> DerefMut for slice<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}
