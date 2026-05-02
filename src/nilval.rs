//! `Nil` — Goish's polymorphic zero-value sentinel.
//!
//! Mirrors Go's untyped `nil` constant: a single identifier that
//! flows into any nilable type via `From<Nil>` impls living in each
//! type's own module. Stable Rust forces one concession — `.into()`
//! is mandatory at return / let / struct-field positions because
//! the language doesn't auto-call `From` there.
//!
//! ## Where bare `nil` works (no `.into()` needed)
//!
//! - **Function arg with `impl Into<T>`**: `mux.Handle("/", nil)`
//!   if the parameter is `H: Into<…>`.
//! - **Equality**: `if err == nil { … }` and `if nil != err { … }`
//!   via per-type `PartialEq<Nil>` impls.
//! - **Generic over `From<Nil>`**: `fn zero<T: From<Nil>>() -> T`.
//!
//! ## Where `.into()` is required
//!
//! - **Return**: `fn foo() -> error { nil.into() }`.
//! - **Let binding**: `let e: error = nil.into();`.
//! - **Struct field**: `Cookie { name: nil.into(), … }`.
//! - **Match arm value**: `match x { _ => nil.into() }`.
//!
//! ## Crate-internal access to the typed nil-error
//!
//! Goish's own `errors` module needs the **typed** `error(None)`
//! sentinel for chain walking, ErrorTrait::Unwrap defaults, etc.
//! That value is still `errors::nil: error` — kept as a typed
//! constant. External callers should use the polymorphic `nil`
//! (this module) plus `.into()` instead.

#![allow(non_upper_case_globals, non_camel_case_types)]

/// The polymorphic-nil sentinel type. Zero-sized; users never
/// construct it directly — they use the `nil` constant.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Nil;

/// `nil` — Goish's polymorphic zero value.
pub const nil: Nil = Nil;
