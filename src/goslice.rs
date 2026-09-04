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
use core::ops::{Deref, DerefMut, Index, IndexMut};

use crate::builtin::{Cap as CapTrait, Len as LenTrait};
use crate::convert::__SliceIndex;
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

    /// `xs.swap(i, j)` — swap two elements in place.
    ///
    /// Goishc lowers Go's tuple-swap idiom `xs[i], xs[j] = xs[j],
    /// xs[i]` (canonical in `sort.Interface.Swap`) to this call. The
    /// underlying `[T]::swap` is reachable via `DerefMut`, but its
    /// `usize` argument types would force callers to cast `int` →
    /// `usize` at every site; this inherent shim accepts `int`
    /// (Go's natural integer kind) and does the cast once. Works for
    /// any element type — no `Copy` / `Clone` bound — because the
    /// underlying swap is a pointer-level exchange.
    pub fn swap(&mut self, i: int, j: int) {
        self.inner.swap(i as usize, j as usize);
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

    /// `xs[low:high:max]` — Go's three-index ("full") slice expression.
    /// Length is `high - low`; capacity is `max - low`. Bounds checked
    /// against `0 <= low <= high <= max <= cap(xs)` (panic on violation,
    /// matching Go's runtime panic).
    ///
    /// **v1 deviation**: same as `slice()` — returns an independent copy
    /// rather than a view. The `max` parameter is honored as the
    /// allocated capacity of the new backing Vec, so subsequent
    /// `append` against the result reallocates at the same boundary
    /// Go would.
    pub fn slice3(&self, low: int, high: int, max: int) -> Self {
        let lo = low as usize;
        let hi = high as usize;
        let mx = max as usize;
        if !(lo <= hi && hi <= mx && mx <= self.inner.capacity()) {
            panic!(
                "slice bounds out of range [{}:{}:{}] with capacity {}",
                lo,
                hi,
                mx,
                self.inner.capacity()
            );
        }
        let mut v: Vec<T> = Vec::with_capacity(mx - lo);
        v.extend_from_slice(&self.inner[lo..hi]);
        Self { inner: v }
    }
}

impl<T> Default for slice<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── From<&[T]> / From<&[T; N]> — let byte literals flow ──────────────
//
// `b","` has type `&'static [u8; 1]`; these impls let it flow into any
// `Into<slice<byte>>`-bound argument. Generic over T so the same impls
// also cover `&[i64]`, `&[string]`, etc., which composes with `slice!`
// macro internals (we never go through here for those, but it's safe).

impl<T: Clone> From<&'static [T]> for slice<T> {
    #[inline]
    fn from(b: &'static [T]) -> Self {
        slice::__from_vec(b.to_vec())
    }
}

impl<T: Clone, const N: usize> From<&'static [T; N]> for slice<T> {
    #[inline]
    fn from(arr: &'static [T; N]) -> Self {
        slice::__from_vec(arr.to_vec())
    }
}

// Pass-by-shared-reference flow: `&slice<T>` clones into `slice<T>`.
// Lets read-only function arguments accept either a borrowed handle or
// an owned value uniformly, matching how Go's slice-typed args feel
// "shared" at the call site.
impl<T: Clone> From<&slice<T>> for slice<T> {
    #[inline]
    fn from(s: &slice<T>) -> Self {
        s.clone()
    }
}

// ─── nil ↔ slice<T> wiring (polymorphic Nil sentinel) ────────────────
//
// `let s: slice<int> = nil.into();` produces a zero-length slice.
// `if s == nil` reports `true` for empty slices. Goish's slice is
// always allocated (no separate "nil header"), so the equality is
// "len == 0" — matches user intent for `if s == nil` even though
// it's slightly looser than Go's strict `slice header == zero` test.

impl<T: Clone> From<crate::nilval::Nil> for slice<T> {
    #[inline]
    fn from(_: crate::nilval::Nil) -> Self {
        slice::<T>::__from_vec(alloc::vec::Vec::new())
    }
}

impl<T> PartialEq<crate::nilval::Nil> for slice<T> {
    #[inline]
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.Len() == 0
    }
}

// Element-wise equality. Mirrors Go's `bytes.Equal` / element-by-
// element `==` chain that Go's spec defines for slices via reflect
// (with the caveat that `==` on slice values is a compile error in
// Go for non-byte slices; Goish takes the more permissive route of
// providing the operator for any cheap-clone `T: PartialEq`, since
// the alternative — requiring callers to spell `bytes::Equal`
// explicitly — adds noise without semantic value).
//
// Eq is intentionally NOT derived: Go's `[]float64` with NaN
// elements would violate the Eq reflexivity contract.
impl<T: PartialEq> PartialEq for slice<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

// Go's `[]rune(s)` and `[]byte(s)` string→slice conversions. Goish
// emits these as `<slice<rune>>::from(s)` / `<slice<byte>>::from(s)`
// at the buildTypeConversion call site.
//
// `[]rune(s)` decodes UTF-8 codepoints — each rune is the int32
// code point. Mirrors Go's runtime behaviour where invalid bytes
// emit U+FFFD (replacement char). `chars()` on `&str` does the
// same routing through std::char::from_u32.
//
// `[]byte(s)` is a copy of the underlying byte buffer.

impl From<&crate::gostring::string> for slice<crate::types::rune> {
    fn from(s: &crate::gostring::string) -> Self {
        let bytes = s.as_bytes();
        let str_view = match core::str::from_utf8(bytes) {
            Ok(v) => v,
            Err(_) => {
                // Invalid UTF-8 — Go's runtime would replace with
                // U+FFFD; fall back to a lossy decode. The valid
                // prefix is yielded; replacement filles the rest.
                let mut out: alloc::vec::Vec<crate::types::rune> = alloc::vec::Vec::new();
                let mut i = 0;
                while i < bytes.len() {
                    match core::str::from_utf8(&bytes[i..]) {
                        Ok(rest) => {
                            for c in rest.chars() {
                                out.push(c as crate::types::rune);
                            }
                            i = bytes.len();
                        }
                        Err(e) => {
                            let valid = e.valid_up_to();
                            if valid > 0 {
                                if let Ok(prefix) = core::str::from_utf8(&bytes[i..i + valid]) {
                                    for c in prefix.chars() {
                                        out.push(c as crate::types::rune);
                                    }
                                }
                            }
                            out.push(0xFFFD);
                            i += valid + 1;
                        }
                    }
                }
                return slice::<crate::types::rune>::__from_vec(out);
            }
        };
        let mut out: alloc::vec::Vec<crate::types::rune> =
            alloc::vec::Vec::with_capacity(str_view.len());
        for c in str_view.chars() {
            out.push(c as crate::types::rune);
        }
        slice::<crate::types::rune>::__from_vec(out)
    }
}

// `[]byte(s)` — Go's idiomatic string-to-bytes conversion. Goish's
// `bytes(s)` builtin is the same op spelled differently; this impl
// covers the explicit `slice<byte>::from(s)` path that some emit
// sites take.
impl From<&crate::gostring::string> for slice<crate::types::byte> {
    fn from(s: &crate::gostring::string) -> Self {
        let bytes = s.as_bytes();
        let mut out: alloc::vec::Vec<crate::types::byte> =
            alloc::vec::Vec::with_capacity(bytes.len());
        out.extend_from_slice(bytes);
        slice::<crate::types::byte>::__from_vec(out)
    }
}

// Owned-string variants — emitted call sites often have `string` by
// value rather than `&string`. Forwarding to the borrowed impls keeps
// the conversion logic in one place; the `&` produces a temporary
// borrow that's valid for the duration of the call.
impl From<crate::gostring::string> for slice<crate::types::rune> {
    #[inline]
    fn from(s: crate::gostring::string) -> Self {
        Self::from(&s)
    }
}

impl From<crate::gostring::string> for slice<crate::types::byte> {
    #[inline]
    fn from(s: crate::gostring::string) -> Self {
        Self::from(&s)
    }
}

// go: none — `string(rs)` for a []rune is a Go CONVERSION, not a
//     stdlib function, so there is no Go decl to anchor to. The
//     encoding rule it implements is utf8.EncodeRune's
//     (unicode/utf8/utf8.go:336-348), and the runtime routine behind
//     the conversion is runtime.rawruneslice + encoderune.
//
// The mirror of `[]rune(s)` above. Go encodes each rune as UTF-8 and
// substitutes U+FFFD for anything that is not a valid code point — a
// negative value, a surrogate half, or anything above MaxRune — so
// `string([]rune{0xD800})` is the three bytes EF BF BD, not an error
// and not a lost element. `AppendRune` is Go's own function and
// already applies that rule, so this walks the runes through it
// rather than repeating the test.
impl From<&slice<crate::types::rune>> for crate::gostring::string {
    // go: none — see the anchor on the impl above.
    fn from(rs: &slice<crate::types::rune>) -> Self {
        let mut buf: slice<crate::types::byte> = slice::new();
        for r in rs.iter() {
            buf = crate::unicode::utf8::AppendRune(buf, *r);
        }
        return crate::gostring::string::from_bytes(&buf);
    }
}

// go: none — the by-value half of the same conversion; Go has one
//     `string(rs)` and no notion of an owned vs borrowed operand.
//     Forwards so the rule lives in one place.
impl From<slice<crate::types::rune>> for crate::gostring::string {
    // go: none — see the anchor on the impl above.
    #[inline]
    fn from(rs: slice<crate::types::rune>) -> Self {
        return Self::from(&rs);
    }
}

impl<T> PartialEq<slice<T>> for crate::nilval::Nil {
    #[inline]
    fn eq(&self, other: &slice<T>) -> bool {
        other.Len() == 0
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

// Generic over any integer type to match Go's `s[i]` (where i can be
// any integer kind, including byte). See convert.rs::__SliceIndex.
impl<T, I: __SliceIndex> Index<I> for slice<T> {
    type Output = T;
    fn index(&self, i: I) -> &T {
        &self.inner[i.__sidx()]
    }
}

impl<T, I: __SliceIndex> IndexMut<I> for slice<T> {
    fn index_mut(&mut self, i: I) -> &mut T {
        &mut self.inner[i.__sidx()]
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

// `AsRef<[T]>` lets generic helpers in goish (`utf8::RuneCount<P:
// AsRef<[u8]>>`, etc.) accept `slice<T>` directly — no manual `.as_slice()`
// at the call site, and ports stay free of `&[T]` leaks per §3.
impl<T> AsRef<[T]> for slice<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        &self.inner
    }
}

// `AsMut<[T]>` is the by-value mirror used by stdlib write methods
// (binary::BigEndian::PutUint32 et al) that take `impl AsMut<[u8]>`
// so callers can pass `slice<byte>` directly. Mutation flows into
// the slice's owned `Vec<T>` — caller must hold a `&mut` to the
// slice for the AsMut bound to fire.
impl<T> AsMut<[T]> for slice<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}
