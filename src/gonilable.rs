// nilable — Goish's `*T` representation for pointer types that may
// carry nil.
//
// Why this exists
// ───────────────
//
// Go's `*T` is "either a pointer to a T, or nil". Goish previously
// mapped `*T` to Rust's `&T`/`&mut T`, which has no null state. That
// works for non-nil pointer flows (method receivers, owned-then-passed
// args) but breaks the common `func F() (*T, error) { return nil,
// err }` pattern — there's no Rust value to put in the pointer slot
// when the construction failed.
//
// `nilable<T>` is a thin newtype around `Option<Arc<T>>` with a
// Go-idiomatic API surface — `IsNil`, equality with `Nil`, `Must`/
// `MustMut`/`MustTake` for non-nil access. The Arc-internal storage
// gives Go-faithful pointer semantics: cloning a nilable<T> is a
// refcount bump (free, regardless of `T: Clone`); two clones of the
// same nilable refer to the same underlying T (shared mutation
// through `MustMut`'s `Arc::make_mut`).
//
// `?Sized` on the T parameter lets `nilable<dyn Trait + Send + Sync>`
// exist — needed by the per-trait forwarding `impl Trait for nilable<T>`
// that `#[goish::interface]` emits so a `nilable<MyTracer>` flows into
// `impl Tracer + 'static` slots without a wrapper type. Methods that
// take/return T by value (new, MustTake, Take, OrDefault, OrElse) live
// in a separate Sized-only impl block; methods that work through &T
// (Must, Try, IfNotNil, ptr_eq, …) work for any T.
//
// API surface (mirrors Go's `*T` behaviour where possible):
//
//   nilable::new(t)              — wrap an owned T (non-nil); allocates Arc
//   nilable::<T>::nil()          — the nil pointer (const fn; same shape as below)
//   nilable::<T>::default()      — the nil pointer (Default::default form)
//   nil.into() at nilable<T> slot— same shape, via `From<Nil> for nilable<T>`
//   x.IsNil()                    — does this hold nil?
//   x == nil / nil == x          — false unless x.IsNil()
//
// Panic-bearing extractors (Go-style `Must` prefix — only the
// transpiler emits these inside scopes it has flow-proven non-nil;
// hand-written Goish code generally uses `Try`/`IfNotNil`/`OrDefault`
// instead). Naming follows Go's `regexp.MustCompile` convention: the
// `Must` prefix signals "panics if the precondition fails":
//
//   x.Must()         — &T, panics on nil
//   x.MustMut()      — &mut T (Arc::get_mut, panics on shared), panics on nil
//   x.MustTake()     — T (consuming, Arc::try_unwrap), panics on nil or shared
//
// Goro: Go-idioms-first — call sites read like Go (`if id == nil`,
// `id.Method()`, `*id = …`), Rust idioms (Some/None, ?, etc.) stay
// behind the wrapper.

#![allow(non_snake_case, non_camel_case_types)]

use crate::nilval::Nil;
use alloc::sync::Arc;

/// `nilable<T>` — Goish's `*T` shape with a Go-idiomatic API.
///
/// Storage is `Option<Arc<T>>`. Clone is always cheap (Arc refcount
/// bump); two clones share the underlying T. `T: ?Sized` lets the
/// type carry `dyn Trait` payloads — used by per-trait forwarding
/// impls emitted by `#[goish::interface]`.
pub struct nilable<T: ?Sized>(Option<Arc<T>>);

// Manual Clone impl so nilable<T> is Clone for ALL T (not just T: Clone)
// — Arc's Clone is the refcount bump, not T's clone.
impl<T: ?Sized> Clone for nilable<T> {
    #[inline]
    fn clone(&self) -> Self {
        nilable(self.0.clone())
    }
}

// ── `?Sized` methods — work for `nilable<dyn Trait>` etc. ───────────
impl<T: ?Sized> nilable<T> {
    /// The nil nilable. `const fn` so it works in const contexts —
    /// `Default::default()` isn't const, so this is the entry point
    /// when a nil is needed at compile time. Same shape as
    /// `<nilable<T>>::default()` and `nil.into()`.
    #[inline]
    pub const fn nil() -> Self {
        nilable(None)
    }

    /// Is this the nil pointer?
    #[inline]
    pub fn IsNil(&self) -> bool {
        self.0.is_none()
    }

    /// Borrow the inner T, panicking on nil. Go-style `Must` prefix
    /// signals that the precondition (non-nil) is asserted by the
    /// caller; failure crashes loudly. Pairs with `Try()` (which
    /// returns `Option<&T>`). Transpiler emits this inside scopes
    /// it has flow-proven non-nil — never as auto-deref.
    #[inline]
    #[track_caller]
    pub fn Must(&self) -> &T {
        match &self.0 {
            Some(t) => t.as_ref(),
            None => nil_deref_panic(),
        }
    }

    /// Mutably borrow the inner T, panicking on nil OR on a shared
    /// alias (refcount > 1). Pairs with `TryMut()`. Same `Must`
    /// rationale as `Must()`.
    ///
    /// Goish-shared-mutation rule: a shared pointer can't yield
    /// `&mut T` directly without breaking aliasing. Wrap T in
    /// `sync::Mutex` for shared mutation.
    #[inline]
    #[track_caller]
    pub fn MustMut(&mut self) -> &mut T {
        match &mut self.0 {
            Some(arc) => match Arc::get_mut(arc) {
                Some(t) => t,
                None => shared_mut_panic(),
            },
            None => nil_deref_panic(),
        }
    }

    /// Safe shared borrow — `Some(&T)` if non-nil, `None` if nil.
    /// Use with `if let Some(t) = p.Try() { … }` for pattern-match
    /// style, or `p.Try().map(|t| …)` for chained transforms.
    #[inline]
    pub fn Try(&self) -> Option<&T> {
        self.0.as_deref()
    }

    /// Safe mutable borrow — `Some(&mut T)` if non-nil AND uniquely
    /// owned (refcount 1), `None` if nil OR shared. The shared case
    /// returns None instead of panicking (the safe sibling of
    /// `MustMut`). Doesn't require `T: Clone`.
    #[inline]
    pub fn TryMut(&mut self) -> Option<&mut T> {
        match &mut self.0 {
            Some(arc) => Arc::get_mut(arc),
            None => None,
        }
    }

    /// Apply `f` if non-nil, returning `Some(f(&t))`; `None` if nil.
    /// Useful for read-only transforms: `p.If(|t| t.Len()).
    /// unwrap_or(0)`.
    #[inline]
    pub fn If<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.0.as_deref().map(f)
    }

    /// Apply `f` if non-nil AND uniquely owned, mutating in place;
    /// no-op if nil OR shared. Returns `true` when the closure ran,
    /// `false` otherwise.
    #[inline]
    pub fn IfMut<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut T),
    {
        match self.TryMut() {
            Some(t) => {
                f(t);
                true
            }
            None => false,
        }
    }

    /// Pointer-equality test — true iff both nilables alias the same
    /// underlying allocation (or both are nil). Mirrors Go's `==` on
    /// pointer values, which compares pointer identity rather than
    /// dereferenced equality. Doesn't require `T: PartialEq`.
    #[inline]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    /// View the inner T as a borrow. Returns a `nilable_ref<T>`
    /// (Option<&T>-shaped, pointer-sized) that aliases the inner
    /// Arc'd T. Pairs with `BorrowMut`. The lifetime is bound to
    /// `&self`'s borrow.
    ///
    /// Bridge for Design B (#121): converts the owned cell
    /// `nilable<T>` to the borrowed cell `nilable_ref<T>` so a
    /// caller holding `nilable<T>` can supply a `nilable<&T>`-typed
    /// param without cloning.
    #[inline]
    pub fn Borrow(&self) -> crate::gonilable_ref::nilable_ref<'_, T> {
        self.0.as_deref().into()
    }

    /// Mutably view the inner T as an exclusive borrow. Returns a
    /// `nilable_refmut<T>` aliasing the inner Arc'd T. Pairs with
    /// `Borrow`.
    ///
    /// Panics with the same shared-Arc message as `MustMut` when
    /// the inner Arc is shared (refcount > 1) AND non-nil. The
    /// shared-and-nil case is impossible (None has no refcount).
    /// Nil → returns a nil `nilable_refmut`.
    #[inline]
    #[track_caller]
    pub fn BorrowMut(&mut self) -> crate::gonilable_ref::nilable_refmut<'_, T> {
        match &mut self.0 {
            Some(arc) => match Arc::get_mut(arc) {
                Some(t) => crate::gonilable_ref::nilable_refmut::new(t),
                None => shared_mut_panic(),
            },
            None => crate::gonilable_ref::nilable_refmut::nil(),
        }
    }
}

// ── Sized-only methods — those that take or return `T` by value ─────
impl<T> nilable<T> {
    /// Wrap an owned T as a non-nil nilable. Mirrors Go's `&T{…}`
    /// construction. Allocates a new `Arc<T>`; the resulting nilable
    /// has refcount 1 until a clone bumps it.
    #[inline]
    pub fn new(value: T) -> Self {
        nilable(Some(Arc::new(value)))
    }

    /// Consume the nilable and return the inner T, panicking on nil
    /// or on a shared alias. Pairs with `Take()` (which returns
    /// `Option<T>`).
    #[inline]
    #[track_caller]
    pub fn MustTake(self) -> T {
        match self.0 {
            Some(arc) => Arc::try_unwrap(arc).unwrap_or_else(|_| shared_mut_panic()),
            None => nil_deref_panic(),
        }
    }

    /// Cloned-or-default — return a clone of the inner T, or
    /// `T::default()` if nil. Mirrors Go's "nil-tolerant" idiom
    /// where reads from a nil pointer return the zero value.
    #[inline]
    pub fn OrDefault(&self) -> T
    where
        T: Default + Clone,
    {
        match &self.0 {
            Some(arc) => (**arc).clone(),
            None => T::default(),
        }
    }

    /// Cloned-or-fallback — return a clone of the inner T, or call
    /// `f()` if nil. Lets the caller compute a fallback lazily.
    #[inline]
    pub fn OrElse<F>(&self, f: F) -> T
    where
        T: Clone,
        F: FnOnce() -> T,
    {
        match &self.0 {
            Some(arc) => (**arc).clone(),
            None => f(),
        }
    }

    /// Take the inner T, leaving nil behind. Returns `None` if
    /// already nil OR shared, `Some(t)` otherwise.
    #[inline]
    pub fn Take(&mut self) -> Option<T> {
        self.0
            .take()
            .and_then(|arc| Arc::try_unwrap(arc).ok())
    }
}

#[cold]
#[inline(never)]
#[track_caller]
fn nil_deref_panic() -> ! {
    panic!("nil-pointer deref")
}

#[cold]
#[inline(never)]
#[track_caller]
fn shared_mut_panic() -> ! {
    panic!(
        "nilable<T>::MustMut on shared pointer (refcount > 1) — wrap T in sync::Mutex for shared mutation"
    )
}

impl<T: ?Sized> Default for nilable<T> {
    #[inline]
    fn default() -> Self {
        nilable(None)
    }
}

// NO `Deref` / `DerefMut` impls (policy commit, 2026-05-09).
//
// Goish enforces nil-safety at compile time: an unguarded `*p` /
// `p.field` / `p.Method()` against a `nilable<T>` is a Rust type
// error. Authors must:
//   - Use `if p != nil { … }` (transpiler injects a `let p = p.Must()`
//     shadow inside the guarded block — see pass5_nil_narrow), or
//   - Reach for `Try`/`IfNotNil`/`OrDefault`/`Take` (safe, never
//     panic), or
//   - Call `Must`/`MustMut`/`MustTake` explicitly when the
//     non-nil precondition has been asserted by other means.
//
// This is the one Go-semantic exception: `p.field` on nil-pointer
// in Go panics at runtime; in Goish the same access is rejected at
// compile time. See project_nilable_deref_panics.md.

// Equality with the universal Nil sentinel — `if x == nil { … }` and
// `if nil == x { … }`. Symmetric impls.
impl<T: ?Sized> PartialEq<Nil> for nilable<T> {
    #[inline]
    fn eq(&self, _: &Nil) -> bool {
        self.IsNil()
    }
}

impl<T: ?Sized> PartialEq<nilable<T>> for Nil {
    #[inline]
    fn eq(&self, other: &nilable<T>) -> bool {
        other.IsNil()
    }
}

// `nilable<T> == nilable<T>` — Go's pointer-equality compares pointer
// identity, NOT dereferenced equality. Two nilables are equal iff
// they alias the same allocation (or both are nil). This matches
// `Arc::ptr_eq` exactly and doesn't require `T: PartialEq`.
//
// Callers wanting deep equality should use `*a == *b` (i.e. compare
// `a.Must()` and `b.Must()`) once they've nil-guarded.
impl<T: ?Sized> PartialEq for nilable<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ptr_eq(other)
    }
}

impl<T: ?Sized> Eq for nilable<T> {}

// `From<T>` is intentionally NOT implemented here — it would conflict
// with the blanket `From<T> for T` (instantiating T = nilable<T>) and
// with `From<Nil> for nilable<T>` when T = Nil. The transpiler emits
// `nilable::new(<expr>)` explicitly at constructor sites.

// `From<Nil>` — `let x: nilable<T> = nil.into();` and the auto-coerce
// at `nil` literals in nilable<T>-typed slots. Routes to the same
// shape as `<nilable<T>>::default()` — single nil semantics.
impl<T: ?Sized> From<Nil> for nilable<T> {
    #[inline]
    fn from(_: Nil) -> Self {
        nilable(None)
    }
}

// Display / Debug forwarders — delegate to the inner T so user
// formatting code (println, fmt::Errorf with %v) prints something
// useful. nil prints as "<nil>" matching Go's fmt %v on nil pointers.
impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for nilable<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(t) => t.as_ref().fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}

impl<T: ?Sized + core::fmt::Display> core::fmt::Display for nilable<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(t) => t.as_ref().fmt(f),
            None => f.write_str("<nil>"),
        }
    }
}
