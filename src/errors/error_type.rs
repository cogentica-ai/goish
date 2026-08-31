// go: none — goish idiom: Go's `error` is a BUILTIN interface,
//     declared by the language and not by package errors. Everything
//     here exists to give it a Rust shape — the trait, the nil-able
//     handle, the equality that is Go's pointer comparison, the
//     Display/Debug bridges, and the lift from a user type into the
//     handle. None of it has a Go file to be anchored against.
//
// error_type.rs — goish-only. No `// go: file` manifest.

extern crate alloc;
use alloc::sync::Arc;

use core::any::Any;

use crate::gostring::string;

// ─── ErrorTrait — Go's `error` interface ───────────────────────────────

/// Anything with `Error() string` is a goish error. User code defines a
/// custom error type by writing `impl errors::ErrorTrait for MyType`.
///
/// `Send + Sync + 'static` so errors can cross goroutines (M15) and
/// be stored in long-lived sentinels. `Any` supertrait enables
/// `errors::As` to recover the concrete type from the chain.
pub trait ErrorTrait: Any + Send + Sync + 'static {
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Go's `Error() string` — the one method the interface requires.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn Error(&self) -> string;

    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Default: this error doesn't wrap anything. Override to expose a
    /// chained cause for `errors::Is` / `errors::Unwrap` walking.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn Unwrap(&self) -> error {
        return nil;
    }

    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Go's `interface{ Unwrap() []error }`, which `errors.Is`,
    /// `errors.As` and nothing else assert for. An error that wraps
    /// SEVERAL others — `errors.Join`'s result, above all — answers
    /// here instead of through [`Unwrap`](ErrorTrait::Unwrap), and the
    /// tree walk fans out over what it returns.
    ///
    /// Go has two distinct optional methods and picks whichever the
    /// concrete type has; Rust has one trait, so both are declared with
    /// defaults and an error overrides the one that applies. Returning
    /// a non-empty vec here is what `Unwrap() []error` means; leaving
    /// it empty is what not having the method means.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn UnwrapMulti(&self) -> alloc::vec::Vec<error> {
        return alloc::vec::Vec::new();
    }

    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Go's `interface{ Is(error) bool }` — the hook an error type
    /// provides so it can be treated as equivalent to some other error.
    /// `syscall.Errno.Is` is the standard-library example: it is what
    /// makes `errors.Is(ENOENT, fs.ErrNotExist)` true even though the
    /// two values are unrelated.
    ///
    /// Go's docs are explicit that this should compare shallowly and
    /// must not call `Unwrap` on either side — the walk is `errors.Is`'s
    /// job, not the hook's.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn Is(&self, _target: &error) -> bool {
        return false;
    }
}

// ─── error — the Go-style return type ──────────────────────────────────

/// Goish's `error` type. Holds either an `Arc<dyn ErrorTrait>` or
/// `None` (the nil error).
#[derive(Clone)]
pub struct error(pub(super) Option<Arc<dyn ErrorTrait>>);

/// The zero value. `if err == nil` and `return nil` work via the
/// `PartialEq` impl below.
pub const nil: error = error(None);

impl error {
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Go's `err.Error()` — the message string. Panics on nil, mirroring
    /// Go's runtime panic on nil-receiver method calls.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    pub fn Error(&self) -> string {
        return match &self.0 {
            Some(e) => e.Error(),
            None => panic!("nil error: Error() called"),
        };
    }

    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Convenience: `err.IsNil()` for explicit checks. The idiomatic
    /// form is `err == nil` / `err != nil`; this is for cases where a
    /// generic context can't compare against `nil`.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    pub fn IsNil(&self) -> bool {
        return self.0.is_none();
    }

    /// Internal: Arc pointer-equality between two `error` values. Used by
    /// the `goish::var!` macro to implement `PartialEq<Marker> for error`
    /// without exposing the inner Option<Arc<dyn>>.
    #[doc(hidden)]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    pub fn __ptr_eq(&self, other: &error) -> bool {
        return match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
    }
}

impl Default for error {
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn default() -> Self {
        return nil;
    }
}

// ─── Equality ───────────────────────────────────────────────────────────
//
// Two non-nil errors compare equal iff they share the same Arc. This
// matches Go's pointer-identity `==` on errors created from
// `&errorString{...}` (the canonical pattern). It's what `errors.Is`
// relies on when walking chains for sentinel matches.

impl PartialEq for error {
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, other: &Self) -> bool {
        return match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
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
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn from(_: crate::nilval::Nil) -> Self {
        return nil;
    }
}

impl PartialEq<crate::nilval::Nil> for error {
    #[inline]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return self.IsNil();
    }
}

impl PartialEq<error> for crate::nilval::Nil {
    #[inline]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, other: &error) -> bool {
        return other.IsNil();
    }
}

// Same comparison through a borrow — needed when the call site holds
// `&error` (e.g. transpiled-through-pointer-receiver code, or
// `for (_, err) in range!(errs)` which yields `&error`).
impl PartialEq<crate::nilval::Nil> for &error {
    #[inline]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return (*self).IsNil();
    }
}
impl PartialEq<&error> for crate::nilval::Nil {
    #[inline]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, other: &&error) -> bool {
        return (*other).IsNil();
    }
}
// `&mut error` flavour — Goish lowers Go's `*error` write-through
// parameters to `&mut error`, and those still need `if (*p == nil)`
// guards to compile.
impl PartialEq<crate::nilval::Nil> for &mut error {
    #[inline]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return (**self).IsNil();
    }
}
impl PartialEq<&mut error> for crate::nilval::Nil {
    #[inline]
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn eq(&self, other: &&mut error) -> bool {
        return (**other).IsNil();
    }
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
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        return match &self.0 {
            Some(e) => core::fmt::Display::fmt(&e.Error(), f),
            None => f.write_str("<nil>"),
        };
    }
}

impl core::fmt::Debug for error {
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        return match &self.0 {
            Some(e) => write!(f, "error({:?})", e.Error()),
            None => f.write_str("error(<nil>)"),
        };
    }
}

impl error {
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
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
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    pub fn As<T: ErrorTrait + Default>(&self) -> (Arc<T>, bool) {
        return match super::wrap::As::<T>(self.clone()) {
            Some(arc) => (arc, true),
            None => (Arc::new(T::default()), false),
        };
    }

    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    /// Panic-on-miss form. Mirrors Go's `merr := err.(*T)` (no comma-ok),
    /// which panics at runtime when the dynamic type doesn't match.
    /// Goishc lowers single-value type assertions into this; the
    /// comma-ok form `v, ok := err.(*T)` lowers into `As<T>` instead.
    ///
    /// Unlike `As`, no `Default` bound is required — failure raises a
    /// panic rather than synthesizing a zero `T`.
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    pub fn MustAs<T: ErrorTrait>(&self) -> Arc<T> {
        return match super::wrap::As::<T>(self.clone()) {
            Some(arc) => arc,
            None => panic!(
                "interface conversion: error is not {}",
                core::any::type_name::<T>()
            ),
        };
    }
}

// go: none — goish idiom: Go's `error` is a BUILTIN interface, so
/// `errors.Wrap` (goish helper, no Go equivalent in the stdlib but the
/// idiomatic way to lift a custom `ErrorTrait` impl into `error`).
///
///   struct ParseErr { line: int }
///   impl errors::ErrorTrait for ParseErr { ... }
///   return errors::Wrap(ParseErr { line: 7 });
//     none of this machinery has a Go file behind it. See the banner
//     at the top of error_type.rs.
pub fn Wrap<E: ErrorTrait>(e: E) -> error {
    return error(Some(Arc::new(e)));
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
    // go: none — goish idiom: Go's `error` is a BUILTIN interface, so
    //     none of this machinery has a Go file behind it. See the banner
    //     at the top of error_type.rs.
    fn from(e: E) -> Self {
        return Wrap(e);
    }
}
