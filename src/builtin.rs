// builtin — Go's predeclared functions: len, cap, ...
//
// In Go these are always-available identifiers, not methods. We mirror
// that with free functions backed by a trait so the call site reads as
// `len(s)` rather than `s.len()`.
//
//   Go              goish
//   ─────────────   ─────────────
//   len(s)          len(s)        ← free function, signed result
//   cap(s)          cap(s)        ← (added when GoSlice lands)

/// Anything that has a Go-shaped length.
///
/// Underscored method name keeps the trait method out of normal name
/// resolution — `s.len()` (Rust slice method) and `len(s)` (this trait)
/// stay separate and unambiguous.
pub trait Len {
    fn __len(&self) -> isize;
}

impl<T> Len for [T] {
    #[inline]
    fn __len(&self) -> isize {
        self.len() as isize
    }
}

impl<T, const N: usize> Len for [T; N] {
    #[inline]
    fn __len(&self) -> isize {
        N as isize
    }
}

impl Len for str {
    #[inline]
    fn __len(&self) -> isize {
        self.len() as isize
    }
}

/// Go's `len`: returns the number of elements. Signed (`isize`) to match
/// Go's `int` return type. Auto-borrow makes call sites match Go:
///
///   let s = b"hello";    // &[u8; 5]
///   len(s)               // → 5
#[inline]
#[allow(non_snake_case)]
pub fn len<T: Len + ?Sized>(x: &T) -> isize {
    x.__len()
}
