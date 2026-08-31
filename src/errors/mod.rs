// go: package errors
//
// errors — Go's `errors` package, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   errors.rs      errors/errors.go — New, errorString, ErrUnsupported
//   wrap.rs        errors/wrap.go   — Unwrap, Is, As
//   join.rs        errors/join.go   — Join, joinError
//   error_type.rs  (goish-only)     — the ErrorTrait/error machinery
//                                     behind Go's BUILTIN error type
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

#[path = "error_type.rs"]
mod error_type;
pub use error_type::*;

#[path = "errors.rs"]
mod errors_go;
pub use errors_go::*;

#[path = "wrap.rs"]
pub(crate) mod wrap;
pub use wrap::*;

#[path = "join.rs"]
mod join;
pub use join::*;
