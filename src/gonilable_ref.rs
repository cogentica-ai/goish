// nilable_ref — Goish's borrow-shaped nullable pointer.
//
// Why this exists
// ───────────────
//
// Go's `*T` is "either a pointer to a T, or nil". Goish has two distinct
// post-emit shapes for that source-level concept:
//
//   nilable<T>      — owned-Option-Arc-shaped (Option<Arc<T>>). The
//                     binding owns the pointee through shared refcount.
//                     Used for locals from new(T), returns, fields.
//   nilable_ref<T>  — borrow-Option-shaped (Option<&'a T>). The binding
//                     views a pointee owned elsewhere. Used for function
//                     params and address-of-local borrows.
//
// `nilable_ref<'a, T>` is `#[repr(transparent)]` over `Option<&'a T>`,
// so Rust's niche optimisation keeps it pointer-sized at runtime — same
// size as `&T`, with `None` = the null bit pattern. The Goish surface
// hides the lifetime parameter via the per-position naming convention
// (`nilable<&T>` at param position is `nilable_ref<'_, T>` with elision).
//
// This is pointer-Design B's empty-cell filler.
//
// API surface (mirrors nilable<T> where the operation is meaningful for
// borrows — owning operations like MustTake and OrDefault don't appear
// because a borrow can't deliver ownership):
//
//   nilable_ref::new(r)          — wrap a `&T` as non-nil
//   nilable_ref::<T>::nil()      — the nil borrow (const fn)
//   x.IsNil()                    — does this hold nil?
//   x.Must() / x.Try()           — &T / Option<&T>
//   x.OrElse(|| &default)        — &T fallback
//   x.If(|t| …)                  — Option<R>, run only if non-nil
//   x == nil / nil == x          — same Nil-equality convention
//
// `nilable_refmut<'a, T>` is the `&mut` sibling. Same shape, exclusive
// borrow semantics. `MustMut() -> &mut T`; `TryMut() -> Option<&mut T>`.
//
// Goro: Go-idioms-first — call sites read like Go (`if p == nil`,
// `p.Field`, `p.Method()`), Rust idioms (Some/None, ?, lifetimes) stay
// behind the wrapper.

#![allow(non_snake_case, non_camel_case_types)]

use crate::nilval::Nil;

/// `nilable_ref<'a, T>` — Goish's borrow-shaped `*T` for view positions.
///
/// Storage is `Option<&'a T>` with `#[repr(transparent)]` so Rust's
/// niche optimisation keeps the runtime layout identical to `&T` (a
/// non-null pointer-sized cell, with `None` = the null bit pattern).
///
/// `T: ?Sized` lets the type carry `dyn Trait` payloads behind a
/// borrow — e.g., `nilable_ref<'_, dyn Reader>` for an optional
/// reader-borrow param. Mirrors the `?Sized` flexibility of the
/// owned `nilable<T>`.
#[repr(transparent)]
pub struct nilable_ref<'a, T: ?Sized + 'a>(Option<&'a T>);

// Manual Clone / Copy so the type is unconditionally Clone+Copy
// (shared borrows are always Clone+Copy in Rust, regardless of T).
impl<'a, T: ?Sized + 'a> Clone for nilable_ref<'a, T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, T: ?Sized + 'a> Copy for nilable_ref<'a, T> {}

impl<'a, T: ?Sized + 'a> nilable_ref<'a, T> {
    /// The nil borrow. `const fn` for use in const contexts.
    #[inline]
    pub const fn nil() -> Self {
        nilable_ref(None)
    }

    /// Wrap a non-nil borrow.
    #[inline]
    pub const fn new(r: &'a T) -> Self {
        nilable_ref(Some(r))
    }

    /// Is this the nil borrow?
    #[inline]
    pub fn IsNil(&self) -> bool {
        self.0.is_none()
    }

    /// Yield the inner borrow, panicking on nil. Mirrors
    /// `nilable<T>::Must` semantics — panics loudly, caller has
    /// asserted non-nil. Pairs with `Try()`.
    #[inline]
    #[track_caller]
    pub fn Must(self) -> &'a T {
        match self.0 {
            Some(r) => r,
            None => nil_deref_panic(),
        }
    }

    /// Safe shared borrow — `Some(&T)` if non-nil, `None` if nil.
    /// Same shape as `nilable<T>::Try`. The returned reference has
    /// the same lifetime as `self`'s inner borrow, not `&self`.
    #[inline]
    pub fn Try(self) -> Option<&'a T> {
        self.0
    }

    /// Borrowed-or-fallback. Lets the caller supply a default
    /// reference when nil. Returns `&'a T` borrowing from whichever
    /// source produced the non-nil value.
    #[inline]
    pub fn OrElse<F>(self, f: F) -> &'a T
    where
        F: FnOnce() -> &'a T,
    {
        match self.0 {
            Some(r) => r,
            None => f(),
        }
    }

    /// Apply `f` if non-nil, returning `Some(f(&t))`; `None` if nil.
    /// Mirrors `nilable<T>::If`.
    #[inline]
    pub fn If<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.0.map(f)
    }

    /// Pointer-equality test — true iff both borrows alias the same
    /// underlying memory (or both are nil). Mirrors Go's `==` on
    /// pointer values. Doesn't require `T: PartialEq`.
    #[inline]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (self.0, other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => core::ptr::eq(a as *const T, b as *const T),
            _ => false,
        }
    }
}

/// `nilable_refmut<'a, T>` — exclusive-borrow nullable pointer for
/// pass-by-`&mut` view positions.
///
/// Same `Option<&'a mut T>` storage, same niche optimisation. Cannot
/// be Clone/Copy because `&mut T` is exclusive — so `MustMut` /
/// `TryMut` consume `self` rather than returning a re-borrow.
#[repr(transparent)]
pub struct nilable_refmut<'a, T: ?Sized + 'a>(Option<&'a mut T>);

impl<'a, T: ?Sized + 'a> nilable_refmut<'a, T> {
    #[inline]
    pub const fn nil() -> Self {
        nilable_refmut(None)
    }

    #[inline]
    pub fn new(r: &'a mut T) -> Self {
        nilable_refmut(Some(r))
    }

    #[inline]
    pub fn IsNil(&self) -> bool {
        self.0.is_none()
    }

    /// Yield the inner mutable borrow, panicking on nil.
    #[inline]
    #[track_caller]
    pub fn MustMut(self) -> &'a mut T {
        match self.0 {
            Some(r) => r,
            None => nil_deref_panic(),
        }
    }

    /// Safe shared/immutable borrow of the inner — `Some(&T)` if
    /// non-nil, `None` if nil. Provided so a `nilable_refmut` can
    /// be inspected without consuming the mutable borrow.
    #[inline]
    pub fn Must(&self) -> &T {
        match self.0 {
            Some(ref r) => r,
            None => nil_deref_panic(),
        }
    }

    /// Downgrade to the read-only wrapper, reborrowing the inner
    /// `&mut T` as `&T` for as long as `self` is borrowed. Used by
    /// goishc at call sites where the caller's joined trait signature
    /// carries `nilable![&mut T]` but the callee's inherent method
    /// only needs `nilable![&T]`.
    #[inline]
    pub fn AsRef(&self) -> nilable_ref<'_, T> {
        match self.0 {
            Some(ref r) => nilable_ref::new(r),
            None => nilable_ref::nil(),
        }
    }

    /// Safe exclusive borrow — `Some(&mut T)` if non-nil, `None` if
    /// nil. Consumes `self` because `&mut` is exclusive.
    #[inline]
    pub fn TryMut(self) -> Option<&'a mut T> {
        self.0
    }

    /// Borrow-shaped mutable peek — `Some(&mut T)` if non-nil, `None`
    /// if nil, without consuming `self`. The reborrowed lifetime is
    /// tied to `&mut self`, not to `'a`. Used where a method on a
    /// nilable_refmut field needs to mutate through the wrapper
    /// without giving up the wrapper itself.
    #[inline]
    pub fn TryMutRef(&mut self) -> Option<&mut T> {
        self.0.as_deref_mut()
    }

    /// `&mut self`-shaped peek that panics on nil. Mirrors
    /// `nilable<T>::MustMut` semantics but works through a `&mut`
    /// reborrow rather than consuming the wrapper.
    #[inline]
    #[track_caller]
    pub fn MustMutRef(&mut self) -> &mut T {
        match self.0.as_deref_mut() {
            Some(r) => r,
            None => nil_deref_panic(),
        }
    }

    /// Apply `f` if non-nil, with `&T` access (read-only). Mirrors
    /// `nilable<T>::If`. Doesn't consume the mut borrow.
    #[inline]
    pub fn If<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.0.as_deref().map(f)
    }

    /// Apply `f` to the mutable borrow if non-nil, returning whether
    /// the closure ran. Mirrors `nilable<T>::IfMut`. Consumes `self`
    /// because the closure receives `&mut T`.
    #[inline]
    pub fn IfMut<F>(self, f: F) -> bool
    where
        F: FnOnce(&mut T),
    {
        match self.0 {
            Some(r) => {
                f(r);
                true
            }
            None => false,
        }
    }
}

#[cold]
#[inline(never)]
#[track_caller]
fn nil_deref_panic() -> ! {
    panic!("nil-pointer deref")
}

// ── Default impls — match nilable<T>'s nil-by-default convention. ───
impl<'a, T: ?Sized + 'a> Default for nilable_ref<'a, T> {
    #[inline]
    fn default() -> Self {
        nilable_ref(None)
    }
}

impl<'a, T: ?Sized + 'a> Default for nilable_refmut<'a, T> {
    #[inline]
    fn default() -> Self {
        nilable_refmut(None)
    }
}

// ── Nil-sentinel equality — `if p == nil { … }` per AGENTS.md §6. ───
impl<'a, T: ?Sized + 'a> PartialEq<Nil> for nilable_ref<'a, T> {
    #[inline]
    fn eq(&self, _: &Nil) -> bool {
        self.IsNil()
    }
}

impl<'a, T: ?Sized + 'a> PartialEq<nilable_ref<'a, T>> for Nil {
    #[inline]
    fn eq(&self, other: &nilable_ref<'a, T>) -> bool {
        other.IsNil()
    }
}

impl<'a, T: ?Sized + 'a> PartialEq<Nil> for nilable_refmut<'a, T> {
    #[inline]
    fn eq(&self, _: &Nil) -> bool {
        self.IsNil()
    }
}

impl<'a, T: ?Sized + 'a> PartialEq<nilable_refmut<'a, T>> for Nil {
    #[inline]
    fn eq(&self, other: &nilable_refmut<'a, T>) -> bool {
        other.IsNil()
    }
}

// ── Nil-coercion — `let r: nilable_ref<T> = nil.into()` per §6. ─────
impl<'a, T: ?Sized + 'a> From<Nil> for nilable_ref<'a, T> {
    #[inline]
    fn from(_: Nil) -> Self {
        nilable_ref(None)
    }
}

impl<'a, T: ?Sized + 'a> From<Nil> for nilable_refmut<'a, T> {
    #[inline]
    fn from(_: Nil) -> Self {
        nilable_refmut(None)
    }
}

// ── Lift a known-non-null borrow into the nullable cell. ────────────
// `&T` → `nilable_ref<T>` and `&mut T` → `nilable_refmut<T>` via
// `.into()`. The transpiler emits this at call-sites where a caller
// holds a non-null borrow but the callee's signature takes the
// nullable shape (`nilable<&T>` / `nilable<&mut T>`).
impl<'a, T: ?Sized + 'a> From<&'a T> for nilable_ref<'a, T> {
    #[inline]
    fn from(r: &'a T) -> Self {
        nilable_ref(Some(r))
    }
}

impl<'a, T: ?Sized + 'a> From<&'a mut T> for nilable_refmut<'a, T> {
    #[inline]
    fn from(r: &'a mut T) -> Self {
        nilable_refmut(Some(r))
    }
}

// `Option<&T>` ↔ `nilable_ref<T>` conversions for internal interop.
// `nilable<T>::Borrow()` produces an `Option<&T>` and routes through
// the `From` impl below.
impl<'a, T: ?Sized + 'a> From<Option<&'a T>> for nilable_ref<'a, T> {
    #[inline]
    fn from(o: Option<&'a T>) -> Self {
        nilable_ref(o)
    }
}

impl<'a, T: ?Sized + 'a> From<Option<&'a mut T>> for nilable_refmut<'a, T> {
    #[inline]
    fn from(o: Option<&'a mut T>) -> Self {
        nilable_refmut(o)
    }
}

// `&mut nilable<T>` → `nilable_refmut<T>`. Mirrors the read-only
// `From<&nilable<T>> for nilable_ref<T>` path below; the transpiler
// emits `(&mut buf).into()` at call sites where a local
// `let mut buf = new!(bytes::Buffer)` flows into a `nilable![&mut T]`
// parameter slot. Routes through `TryMut()` so the shared-mutation
// guard fires uniformly (returns `None` on shared / nil instead of
// panicking; pairs with `nilable_refmut::Must()` at the read site).
impl<'a, T: 'a> From<&'a mut crate::nilable<T>> for nilable_refmut<'a, T> {
    #[inline]
    fn from(n: &'a mut crate::nilable<T>) -> Self {
        nilable_refmut(n.TryMut())
    }
}

// `&nilable<T>` → `nilable_ref<T>`. Read-only counterpart to the
// above. Routes through `Try()` so the surface stays purely
// shared-borrow.
impl<'a, T: 'a> From<&'a crate::nilable<T>> for nilable_ref<'a, T> {
    #[inline]
    fn from(n: &'a crate::nilable<T>) -> Self {
        nilable_ref(n.Try())
    }
}

// ── Debug / Display forwarders — same conventions as nilable<T>. ────
impl<'a, T: ?Sized + 'a + core::fmt::Debug> core::fmt::Debug for nilable_ref<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(r) => r.fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}

impl<'a, T: ?Sized + 'a + core::fmt::Display> core::fmt::Display for nilable_ref<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(r) => r.fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}

impl<'a, T: ?Sized + 'a + core::fmt::Debug> core::fmt::Debug for nilable_refmut<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(ref r) => r.fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}

impl<'a, T: ?Sized + 'a + core::fmt::Display> core::fmt::Display for nilable_refmut<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(ref r) => r.fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}
