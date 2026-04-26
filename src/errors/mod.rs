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

use crate::convert::__StringConv;
use crate::gostring::string;

// ─── ErrorTrait — Go's `error` interface ───────────────────────────────

/// Anything with `Error() string` is a goish error. User code defines a
/// custom error type by writing `impl errors::ErrorTrait for MyType`.
///
/// `Send + Sync + 'static` so errors can cross goroutines (M15) and
/// be stored in long-lived sentinels.
pub trait ErrorTrait: Send + Sync + 'static {
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
impl Eq for error {}

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

/// `errors.Wrap` (goish helper, no Go equivalent in the stdlib but the
/// idiomatic way to lift a custom `ErrorTrait` impl into `error`).
///
///   struct ParseErr { line: int }
///   impl errors::ErrorTrait for ParseErr { ... }
///   return errors::Wrap(ParseErr { line: 7 });
pub fn Wrap<E: ErrorTrait>(e: E) -> error {
    error(Some(Arc::new(e)))
}

// ─── Is / Unwrap ────────────────────────────────────────────────────────

/// `errors.Is(err, target)` — walks `err`'s `Unwrap()` chain looking for
/// an error that compares equal to `target` (pointer-identity). Returns
/// true if `target == nil` and `err == nil`.
pub fn Is(err: error, target: error) -> bool {
    if target == nil {
        return err == nil;
    }
    let mut cur = err;
    loop {
        if cur == nil {
            return false;
        }
        if cur == target {
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
