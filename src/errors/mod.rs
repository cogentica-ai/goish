// errors — Go's `errors` package, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var err error                         let err: error = ...
//   err := errors.New("boom")             let err = errors::New("boom");
//   if err == nil { ... }                 if err == nil { ... }
//   if err != nil { ... }                 if err != nil { ... }
//   return nil                            return nil           ← in (-> error) tail
//   if errors.Is(err, ErrX) { ... }       if errors::Is(err, err_x) { ... }
//   inner := errors.Unwrap(err)           let inner = errors::Unwrap(err);
//
// `error` is a newtype around `Option<Arc<dyn ErrorTrait>>`. That gives
// us:
//   - `nil` is literally `error(None)`, a `pub const`
//   - `if err == nil` works via the impl `PartialEq for error`
//   - non-nil errors compare by Arc pointer identity (Go's default for
//     pointer-typed errors — what `errors.Is(err, sentinel)` uses)
//   - `error: Clone` is cheap (atomic refcount) so values pass freely
//
// One unified path (Arc<dyn>) for both `errors::New` and user-defined
// types — improves on v0's two-variant ErrorKind enum which doubled
// the comparison/wrap logic.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

extern crate alloc;
use alloc::sync::Arc;

use core::any::{Any, TypeId};

use crate::convert::__StringConv;
use crate::gostring::string;

// ─── ErrorTrait — Go's `error` interface ───────────────────────────────

/// Anything with `Error() string` is a goish error. User code defines a
/// custom error type by writing `impl errors::ErrorTrait for MyType`.
///
/// `Send + Sync + 'static` so errors can cross goroutines (M15) and
/// be stored in long-lived sentinels. `Any` supertrait enables
/// `errors::As` to recover the concrete type from the chain.
pub trait ErrorTrait: Any + Send + Sync + 'static {
    /// Go's `Error() string` — the one method the interface requires.
    fn Error(&self) -> string;

    /// Default: this error doesn't wrap anything. Override to expose a
    /// chained cause for `errors::Is` / `errors::Unwrap` walking.
    fn Unwrap(&self) -> error {
        nil
    }
}

// ─── error — the Go-style return type ──────────────────────────────────

/// Goish's `error` type. Holds either an `Arc<dyn ErrorTrait>` or
/// `None` (the nil error).
#[derive(Clone)]
pub struct error(Option<Arc<dyn ErrorTrait>>);

/// The zero value. `if err == nil` and `return nil` work via the
/// `PartialEq` impl below.
pub const nil: error = error(None);

impl error {
    /// Go's `err.Error()` — the message string. Panics on nil, mirroring
    /// Go's runtime panic on nil-receiver method calls.
    pub fn Error(&self) -> string {
        match &self.0 {
            Some(e) => e.Error(),
            None => panic!("nil error: Error() called"),
        }
    }

    /// Convenience: `err.IsNil()` for explicit checks. The idiomatic
    /// form is `err == nil` / `err != nil`; this is for cases where a
    /// generic context can't compare against `nil`.
    pub fn IsNil(&self) -> bool {
        self.0.is_none()
    }

    /// Internal: Arc pointer-equality between two `error` values. Used by
    /// the `goish::var!` macro to implement `PartialEq<Marker> for error`
    /// without exposing the inner Option<Arc<dyn>>.
    #[doc(hidden)]
    pub fn __ptr_eq(&self, other: &error) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Default for error {
    fn default() -> Self {
        nil
    }
}

// ─── Equality ───────────────────────────────────────────────────────────
//
// Two non-nil errors compare equal iff they share the same Arc. This
// matches Go's pointer-identity `==` on errors created from
// `&errorString{...}` (the canonical pattern). It's what `errors.Is`
// relies on when walking chains for sentinel matches.

impl PartialEq for error {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

// ─── nil ↔ error wiring (polymorphic Nil sentinel) ──────────────────
//
// Lets Goish users write:
//   let e: error = nil.into();         // nil → error(None)
//   if err == nil { … }                // PartialEq<Nil>
//   if nil != err { … }                // commutative
// without ever touching `errors::nil` directly.

impl From<crate::nilval::Nil> for error {
    #[inline]
    fn from(_: crate::nilval::Nil) -> Self { nil }
}

impl PartialEq<crate::nilval::Nil> for error {
    #[inline]
    fn eq(&self, _: &crate::nilval::Nil) -> bool { self.IsNil() }
}

impl PartialEq<error> for crate::nilval::Nil {
    #[inline]
    fn eq(&self, other: &error) -> bool { other.IsNil() }
}

// Same comparison through a borrow — needed when the call site holds
// `&error` (e.g. transpiled-through-pointer-receiver code, or
// `for (_, err) in range!(errs)` which yields `&error`).
impl PartialEq<crate::nilval::Nil> for &error {
    #[inline]
    fn eq(&self, _: &crate::nilval::Nil) -> bool { (*self).IsNil() }
}
impl PartialEq<&error> for crate::nilval::Nil {
    #[inline]
    fn eq(&self, other: &&error) -> bool { (*other).IsNil() }
}
// `&mut error` flavour — Goish lowers Go's `*error` write-through
// parameters to `&mut error`, and those still need `if (*p == nil)`
// guards to compile.
impl PartialEq<crate::nilval::Nil> for &mut error {
    #[inline]
    fn eq(&self, _: &crate::nilval::Nil) -> bool { (**self).IsNil() }
}
impl PartialEq<&mut error> for crate::nilval::Nil {
    #[inline]
    fn eq(&self, other: &&mut error) -> bool { (**other).IsNil() }
}
impl Eq for error {}

// ─── Display / Debug ─────────────────────────────────────────────────────
//
// Lets `panic!("{}", err)`, `format_args!`, and any core-formatter consumer
// render an `error` directly — the natural Goish lowering of Go's
// `panic(err)` and `log.Fatal(err)`. Delegates to `Error()` for the
// message; nil renders as `<nil>` (mirroring Go's `fmt.Println(nilErr)`
// which prints "<nil>"), so we don't panic from the formatter on a stray
// nil.

impl core::fmt::Display for error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(e) => core::fmt::Display::fmt(&e.Error(), f),
            None => f.write_str("<nil>"),
        }
    }
}

impl core::fmt::Debug for error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(e) => write!(f, "error({:?})", e.Error()),
            None => f.write_str("error(<nil>)"),
        }
    }
}

// ─── New / Wrap ─────────────────────────────────────────────────────────

/// Internal: the trivial `error` produced by `errors::New`. Mirrors Go's
/// `*errorString`. Each `New` call allocates a fresh Arc, so two errors
/// with the same text compare *not equal* — matches Go's "Each call to
/// New returns a distinct error value even if the text is identical."
struct __ErrorString {
    msg: string,
}

impl ErrorTrait for __ErrorString {
    fn Error(&self) -> string {
        self.msg.clone()
    }
}

/// `errors.New(text)` — basic error from a message.
pub fn New<S: __StringConv>(text: S) -> error {
    error(Some(Arc::new(__ErrorString {
        msg: text.__to_string(),
    })))
}

// `errors.ErrUnsupported` (errors/errors.go:90) — sentinel returned
// when a feature is unsupported. Use sites compare bare:
// `errors::Is(x, errors::ErrUnsupported)` and `if x == errors::ErrUnsupported`.
crate::var! { pub ErrUnsupported: error = "unsupported operation"; }

impl error {
    /// Type-assertion comma-ok form. Mirrors Go's `merr, ok := err.(*T)`.
    /// On success returns `(Arc<T>, true)`; on failure returns
    /// `(Arc<T::default()>, false)` so the caller's `ok` check is the
    /// gate (matching Go's "zero value plus false" semantics).
    ///
    /// Requires `T: Default` because the failure case has no concrete
    /// `T` to hand back; user-defined error types declared via goishc
    /// auto-derive Default, so this bound is satisfied transparently.
    /// For hand-written types, derive or implement Default alongside
    /// the ErrorTrait impl.
    pub fn As<T: ErrorTrait + Default>(&self) -> (Arc<T>, bool) {
        match As::<T>(self.clone()) {
            Some(arc) => (arc, true),
            None => (Arc::new(T::default()), false),
        }
    }

    /// Panic-on-miss form. Mirrors Go's `merr := err.(*T)` (no comma-ok),
    /// which panics at runtime when the dynamic type doesn't match.
    /// Goishc lowers single-value type assertions into this; the
    /// comma-ok form `v, ok := err.(*T)` lowers into `As<T>` instead.
    ///
    /// Unlike `As`, no `Default` bound is required — failure raises a
    /// panic rather than synthesizing a zero `T`.
    pub fn MustAs<T: ErrorTrait>(&self) -> Arc<T> {
        match As::<T>(self.clone()) {
            Some(arc) => arc,
            None => panic!(
                "interface conversion: error is not {}",
                core::any::type_name::<T>()
            ),
        }
    }
}

/// `errors.Wrap` (goish helper, no Go equivalent in the stdlib but the
/// idiomatic way to lift a custom `ErrorTrait` impl into `error`).
///
///   struct ParseErr { line: int }
///   impl errors::ErrorTrait for ParseErr { ... }
///   return errors::Wrap(ParseErr { line: 7 });
pub fn Wrap<E: ErrorTrait>(e: E) -> error {
    error(Some(Arc::new(e)))
}

// Lets transpiled code write `return MyErr { ... }.into();` for any
// user struct with an `errors::ErrorTrait` impl — same lift as
// `errors::Wrap` but reachable through Rust's `From`/`Into` traits so
// goishc can emit `.into()` uniformly at error-slot return sites.
//
// Coherence note: this conflicts with neither the reflexive `From<T>
// for T` (which makes `error: From<error>`) nor the existing
// `From<Nil> for error` impl, since `error` and `Nil` neither
// implement `ErrorTrait`. User types that opt into `ErrorTrait` flow
// through this blanket; the `error` and `Nil` paths stay on their
// dedicated impls.
impl<E: ErrorTrait> From<E> for error {
    #[inline]
    fn from(e: E) -> Self { Wrap(e) }
}

// ─── Is / Unwrap ────────────────────────────────────────────────────────

/// Marker-or-error dispatch trait used by `errors::Is`. Implemented
/// reflexively for `error` (cheap clone) and emitted per-sentinel by the
/// `goish::var!` macro for marker ZSTs (returns the lazily-cached Arc).
///
/// Distinct from `Borrow<error>` so call sites stay unambiguous: only
/// `error` and macro-emitted markers satisfy this bound, never user
/// types that happen to expose a `Borrow<error>` accidentally.
pub trait IsTarget {
    /// Resolve to an owned `error`. For markers, this triggers the
    /// lazy cache lookup and clones the cached Arc; for `error` itself,
    /// it clones (one atomic refcount bump).
    fn __resolve(&self) -> error;
}

impl IsTarget for error {
    #[inline]
    fn __resolve(&self) -> error { self.clone() }
}

/// `errors.Is(err, target)` — walks `err`'s `Unwrap()` chain looking for
/// an error that compares equal to `target` (pointer-identity). Returns
/// true if `target == nil` and `err == nil`.
///
/// Generic over `IsTarget` so call sites can pass either an `error`
/// value or a sentinel marker (Copy ZST emitted by `goish::var!`).
pub fn Is<T: IsTarget>(err: error, target: T) -> bool {
    let target: error = target.__resolve();
    if target == nil {
        return err == nil;
    }
    let mut cur = err;
    loop {
        if cur == nil {
            return false;
        }
        if cur.__ptr_eq(&target) {
            return true;
        }
        // Walk the chain via Unwrap().
        let next = match &cur.0 {
            Some(e) => e.Unwrap(),
            None => return false,
        };
        cur = next;
    }
}

/// `errors.Unwrap(err)` — return the next error in the chain, or `nil`
/// if `err` doesn't wrap anything.
pub fn Unwrap(err: error) -> error {
    match &err.0 {
        Some(e) => e.Unwrap(),
        None => nil,
    }
}

// ─── As (slim port of errors/wrap.go:97) ────────────────────────────────

/// `errors.As(err)` — finds the first error in `err`'s chain whose
/// concrete type is `T` and returns it.
///
/// Slim: Go's signature `As(err error, target any) bool` uses
/// reflection to mutate a caller-supplied target pointer. Goish
/// returns `Option<Arc<T>>` instead — idiomatic Rust, same effect.
/// The caller writes:
///
/// ```ignore
/// if let Some(pe) = errors::As::<ParseError>(err) {
///     /* use pe.line / pe.col */
/// }
/// ```
///
/// Slim deviations:
///   * No `As(any) bool` method on the error type — goish doesn't have
///     a `Box<dyn Any>`-shaped target, so the "error provides custom
///     As" extension point is omitted.
///   * Unwrap()-of-multi-errors not walked; goish's Unwrap returns a
///     single error (matching `Unwrap() error` only).
pub fn As<T: ErrorTrait>(err: error) -> Option<Arc<T>> {
    let mut cur = err;
    loop {
        if cur.IsNil() {
            return None;
        }
        // Try the head of the chain.
        if let Some(arc) = cur.0.as_ref() {
            // Use Any::type_id via the supertrait. Calls into the
            // ErrorTrait vtable, which dispatches to Any's type_id
            // implementation for the underlying concrete type.
            let dyn_ref: &dyn ErrorTrait = arc.as_ref();
            if (dyn_ref as &dyn Any).type_id() == TypeId::of::<T>() {
                // SAFETY: the type id matches, so the data behind the
                // fat pointer is a `T`. Convert Arc<dyn ErrorTrait> →
                // Arc<T> by stripping the vtable from the fat pointer.
                let arc_clone = arc.clone();
                let raw = Arc::into_raw(arc_clone) as *const T;
                return Some(unsafe { Arc::from_raw(raw) });
            }
        }
        // Walk the chain via Unwrap().
        let next = match &cur.0 {
            Some(e) => e.Unwrap(),
            None => return None,
        };
        cur = next;
    }
}

// ─── Join (slim port of errors/join.go:19) ───────────────────────────

/// `errors.Join(errs...)` (errors/join.go:19) — combine multiple
/// errors into one. Nil entries are discarded. Returns `nil` if all
/// entries are nil; the original error if exactly one is non-nil.
///
/// Goish flavor: variadic ...error maps to slice<error>. The joined
/// error's Error() message concatenates each component's message with
/// a newline between them; Unwrap walks to the first non-nil entry
/// (mirroring single-chain Unwrap rather than Go 1.20's
/// `Unwrap() []error` multi-chain — goish's errors::Is doesn't yet
/// fan out across multiple parents).
pub fn Join(errs: crate::goslice::slice<error>) -> error {
    let mut n: crate::types::int = 0;
    let mut i: crate::types::int = 0;
    while i < errs.Len() {
        if !errs[i].IsNil() {
            n += 1;
        }
        i += 1;
    }
    if n == 0 {
        return nil;
    }
    if n == 1 {
        let mut j: crate::types::int = 0;
        while j < errs.Len() {
            if !errs[j].IsNil() {
                return errs[j].clone();
            }
            j += 1;
        }
    }
    let mut filtered: alloc::vec::Vec<error> =
        alloc::vec::Vec::with_capacity(n as usize);
    let mut k: crate::types::int = 0;
    while k < errs.Len() {
        if !errs[k].IsNil() {
            filtered.push(errs[k].clone());
        }
        k += 1;
    }
    error(Some(Arc::new(JoinError { errs: filtered })))
}

struct JoinError {
    errs: alloc::vec::Vec<error>,
}

impl ErrorTrait for JoinError {
    fn Error(&self) -> crate::gostring::string {
        if self.errs.is_empty() {
            return crate::gostring::string::new();
        }
        if self.errs.len() == 1 {
            return self.errs[0].Error();
        }
        let mut b: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        b.extend_from_slice(self.errs[0].Error().as_bytes());
        for e in self.errs.iter().skip(1) {
            b.push(b'\n');
            b.extend_from_slice(e.Error().as_bytes());
        }
        crate::gostring::string::from_bytes(&b)
    }
    fn Unwrap(&self) -> error {
        // Slim chain: walk to the first wrapped error. Go's actual
        // joinError.Unwrap returns []error, but goish's errors::Is is
        // single-chain; chaining to the first non-nil keeps "is this
        // a wrapped X" predicates working for the common case.
        if self.errs.is_empty() {
            nil
        } else {
            self.errs[0].clone()
        }
    }
}

