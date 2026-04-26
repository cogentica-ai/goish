// builtin — Go's predeclared functions: len, cap, ...
//
// In Go these are always-available identifiers, not methods. We mirror
// that with free functions backed by a trait so the call site reads as
// `len(s)` rather than `s.len()`.
//
//   Go              goish
//   ─────────────   ─────────────
//   len(s)          len(s)        ← free function, signed result
//   cap(s)          cap(s)        ← (slice<T>::Cap)

use crate::types::int;

/// Anything that has a Go-shaped length.
///
/// Underscored method name keeps the trait method out of normal name
/// resolution — `s.len()` (Rust slice method) and `len(s)` (this trait)
/// stay separate and unambiguous.
pub trait Len {
    fn __len(&self) -> int;
}

impl<T> Len for [T] {
    #[inline]
    fn __len(&self) -> int {
        self.len() as int
    }
}

impl<T, const N: usize> Len for [T; N] {
    #[inline]
    fn __len(&self) -> int {
        N as int
    }
}

impl Len for str {
    #[inline]
    fn __len(&self) -> int {
        self.len() as int
    }
}

/// Go's `len`: returns the number of elements. Returns `int` (signed,
/// platform-sized) to match Go. Auto-borrow makes call sites match Go:
///
///   let s = string("hello");
///   len(s)                       // → 5
///   let xs = b"hello";           // &[u8; 5]
///   len(xs)                      // → 5
#[inline]
#[allow(non_snake_case)]
pub fn len<T: Len + ?Sized>(x: &T) -> int {
    x.__len()
}

// ─── cap(x) — Go's polymorphic capacity builtin ───────────────────────
//
// Slice (M5): backing capacity. Channel (M16+) and array (later) join
// the same trait when those types arrive.

pub trait Cap {
    fn __cap(&self) -> int;
}

/// Go's `cap`: capacity of the underlying backing.
///
///   let xs = make!([]int, 0, 10);
///   cap(&xs)                     // → 10
#[inline]
#[allow(non_snake_case)]
pub fn cap<T: Cap + ?Sized>(x: &T) -> int {
    x.__cap()
}

// ─── make/slice size coercion ──────────────────────────────────────────
//
// `make!([]T, n)` accepts `n` as `int` (the user-facing type), `usize`,
// untyped integer literals, etc. This helper widens to `usize` and
// panics on negative values, matching Go's runtime check on
// `make([]T, n)` with n < 0.

/// Internal helper for `make!` macros. Hidden from docs.
#[doc(hidden)]
#[inline]
pub fn __make_size(n: int) -> usize {
    if n < 0 {
        panic!("makeslice: len out of range");
    }
    n as usize
}
