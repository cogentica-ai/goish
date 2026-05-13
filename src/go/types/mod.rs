// go/types — minimal Goish surface for Go's go/types package.
//
// The reasoner cache shows 146 stdlib call sites carry values of
// type `Arc<dyn go::types::Type>`. This module provides just enough
// of `Type` so those call sites compile; concrete implementations
// (Basic, Named, Pointer, etc.) live in the ports that need them.

#![allow(non_camel_case_types, non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::gostring::string;
use crate::types::int;

/// Go's `go/types.Type` interface — the carry trait for every
/// type expression the type-checker can produce.
///
/// The full interface is `Underlying()` + `String()`. Specialised
/// kinds (Basic, Named, Pointer, Slice, …) appear as concrete
/// structs implementing this trait in ports.
pub trait Type: Send + Sync {
    fn Underlying(&self) -> Arc<dyn Type>;
    fn String(&self) -> string;
}

/// Go's `go/types.Object` — the named declarations the type-checker
/// produces (Var, Const, TypeName, Func).
pub trait Object: Send + Sync {
    fn Name(&self) -> string;
    fn Type(&self) -> Arc<dyn Type>;
    fn Pos(&self) -> int;
}
