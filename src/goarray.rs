// goarray — Go's `[N]T`, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var a [12]byte                       let a: array<byte, 12> = array!([12]byte);
//   a := [3]int{1, 2, 3}                 let a = array!([3]int{1, 2, 3});
//   a := [...]int{1, 2, 3}               let a = array!([...]int{1, 2, 3});
//   len(a)                               len(&a)
//   a[i]                                 a[i]                ← Index<int>
//   a[low:high]                          a.slice(low, high)  ← copy semantics
//   a[:]                                 a.to_slice()        ← copy semantics
//   for i, v := range a                  for (i, v) in range!(a)
//   b := a                               let b = a;          ← Copy when T: Copy,
//                                                              else b = a.clone()
//
// Backing: `[T; N]` (a Rust fixed array). All ergonomic traits derive
// through to `T`'s bounds: `Clone`, `Copy`, `PartialEq`, `Eq`,
// `PartialOrd`, `Ord`, `Hash`, plus `Default` via `core::array::from_fn`.
// Public methods return goish `slice<T>` / `int` — never raw `&[T]` or
// `[T; N]` in user-facing APIs.
//
// **v1 deviation** — same as `slice<T>`: subslicing copies. Go's
// `a[:]` shares the underlying array; `a.to_slice()` here allocates a
// fresh `slice<T>` with cloned elements. Consistent with the existing
// goslice deviation; tracked in ROADMAP.md alongside it.

#![allow(non_camel_case_types)]

extern crate alloc;
use core::ops::{Deref, DerefMut, Index, IndexMut};

use crate::builtin::Len as LenTrait;
use crate::goslice::slice;
use crate::types::int;

/// Go's `[N]T`. Length is part of the type (distinct `array<T, N>`
/// per `N`), assignment copies (when `T: Copy`), comparison is
/// element-wise. Const generic `N` mirrors Go's compile-time length.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct array<T, const N: usize> {
    inner: [T; N],
}

impl<T: Default, const N: usize> Default for array<T, N> {
    fn default() -> Self {
        Self {
            inner: core::array::from_fn(|_| T::default()),
        }
    }
}

impl<T, const N: usize> array<T, N> {
    /// Internal hook used by the `array!` macro and ports that need to
    /// move a Rust `[T; N]` into a goish array. Dunder + `#[doc(hidden)]`
    /// mark it "do not call directly".
    #[doc(hidden)]
    pub const fn __from_arr(inner: [T; N]) -> Self {
        Self { inner }
    }

    /// Internal hook for tear-down — extract the raw `[T; N]`.
    #[doc(hidden)]
    pub fn __into_arr(self) -> [T; N] {
        self.inner
    }

    /// `len(a)` — number of elements. `const fn` so call sites that
    /// invoke `a.Len()` directly get a compile-time constant; the
    /// `len()` builtin (via `Len` trait) is also constant-foldable.
    #[allow(non_snake_case)]
    pub const fn Len(&self) -> int {
        N as int
    }
}

impl<T: Clone, const N: usize> array<T, N> {
    /// `a[low:high]` — Go-faithful subslice expression. **v1 deviation**:
    /// returns an *independent copy*; mutations on the returned slice
    /// do not propagate back into `a`. Same deviation as `slice<T>`
    /// subslicing; see goslice.rs.
    pub fn slice(&self, low: int, high: int) -> slice<T> {
        let lo = low as usize;
        let hi = high as usize;
        slice::__from_vec(self.inner[lo..hi].to_vec())
    }

    /// `a[:]` — full subslice. Equivalent to `a.slice(0, len(a))`.
    /// Same v1 deviation as `slice()` (copies, doesn't share backing).
    pub fn to_slice(&self) -> slice<T> {
        slice::__from_vec(self.inner.to_vec())
    }
}

// ─── a[i] — Go-faithful indexing (panics on out-of-range) ─────────────
//
// Single-element only — same shape as `slice<T>::Index<int>`. Range
// expressions like `a[0..4]` go through `Deref<Target=[T]>` (write
// `&(*a)[0..4]` or `&a[..][0..4]` for raw `&[T]` access) or use the
// `a.slice(low, high)` method for a copy as `slice<T>`.
//
// We can't have both `Index<int>` and `Index<I: SliceIndex<[T]>>` —
// Rust's coherence rules reject the two impls because `int: i64`
// could in principle gain a `SliceIndex<[T]>` impl in the future.

impl<T, const N: usize> Index<int> for array<T, N> {
    type Output = T;
    fn index(&self, i: int) -> &T {
        &self.inner[i as usize]
    }
}

impl<T, const N: usize> IndexMut<int> for array<T, N> {
    fn index_mut(&mut self, i: int) -> &mut T {
        &mut self.inner[i as usize]
    }
}

// ─── &a auto-derefs to &[T] for low-level helpers ────────────────────
//
// Same pattern as `slice<T>`: `Deref<Target=[T]>` lets `&array<T, N>`
// flow into APIs that take `&[T]` (e.g., binary::BigEndian.PutUint32,
// internal hot-loop helpers). `Deref` is a Rust internal — users never
// see it directly.

impl<T, const N: usize> Deref for array<T, N> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for array<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

// ─── builtin len(a) — see builtin.rs for `len` ────────────────────────

impl<T, const N: usize> LenTrait for array<T, N> {
    #[inline]
    fn __len(&self) -> int {
        N as int
    }
}

// ─── From<[T; N]> ↔ array<T, N> — boundary helpers ───────────────────
//
// Internal-only: ports that already have a Rust `[T; N]` (e.g. from
// `core::array::from_fn` or a literal) wrap it into `array<T, N>`
// without a clone. The reverse direction unwraps to the raw array
// for Rust-side interop. Neither shape should appear in *public Go-API
// signatures* (Doctrine 3).

impl<T, const N: usize> From<[T; N]> for array<T, N> {
    #[inline]
    fn from(inner: [T; N]) -> Self {
        Self { inner }
    }
}

impl<T, const N: usize> From<array<T, N>> for [T; N] {
    #[inline]
    fn from(a: array<T, N>) -> [T; N] {
        a.inner
    }
}

// ─── nil ↔ array<T, N> wiring (polymorphic Nil sentinel) ─────────────
//
// `let a: array<byte, 12> = nil.into();` produces the all-default
// array (Go's zero value). `if a == nil` reports true iff every
// element equals its `Default::default()`. Mirrors the slice/map
// nil-equality convention.

impl<T: Default, const N: usize> From<crate::nilval::Nil> for array<T, N> {
    #[inline]
    fn from(_: crate::nilval::Nil) -> Self {
        <Self as Default>::default()
    }
}

impl<T: Default + PartialEq, const N: usize> PartialEq<crate::nilval::Nil> for array<T, N> {
    #[inline]
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        let zero: Self = <Self as Default>::default();
        self == &zero
    }
}

impl<T: Default + PartialEq, const N: usize> PartialEq<array<T, N>> for crate::nilval::Nil {
    #[inline]
    fn eq(&self, other: &array<T, N>) -> bool {
        let zero: array<T, N> = <array<T, N> as Default>::default();
        other == &zero
    }
}
