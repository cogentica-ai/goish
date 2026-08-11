// go: file reflect/value.go decls: New, Value.SetInt
//
// Two entry points from Go's reflect/value.go that goish did not have.
//
// Scope: only these two. `Value` itself, and the rest of its accessors,
// live in this package's mod.rs; inherent impls may be split across
// modules of the same crate, so the method lands here beside the function
// that motivates it rather than growing the module root further.
//
// Why they exist: `encoding/asn1`'s `makeField` materialises a declared
// `asn1:"default:N"` value with
//     defaultValue := reflect.New(v.Type()).Elem()
//     defaultValue.SetInt(*params.defaultValue)
// and DeepEqual-compares it against the field. Without these, that branch
// of makeField — and therefore Marshal, and therefore crypto/x509 and
// crypto/tls behind it — cannot be written.

#![allow(non_snake_case)]

extern crate alloc;

use super::{Value, Zero};
use crate::types::int64;

// go: sdk 1.25.5 reflect/value.go:3376-3383 New
/// Return a Value representing a pointer to a new zero value of the
/// specified type.
///
/// Deviation: Go allocates and returns an *addressable* pointer Value so
/// that `New(t).Elem()` can be assigned through. goish's `Value` is an
/// owned enum with no addressability, so this is `Pointer(Zero(t))` and
/// `Elem` hands back an owned zero the caller mutates directly with
/// [`Value::SetInt`]. The observable result for makeField's use — build a
/// typed zero, set it, compare — is the same.
pub fn New(t: super::Type) -> Value {
    return Value::Pointer(alloc::boxed::Box::new(Zero(t)));
}

impl Value {
    // go: sdk 1.25.5 reflect/value.go:2621-2640 Value.SetInt
    /// Set the underlying value to `x`.
    ///
    /// Go panics if the Value is unaddressable or not of an integer kind;
    /// goish has no addressability, so only the kind check applies.
    ///
    /// Like Go, a value too wide for the kind is **truncated**, not
    /// rejected: `SetInt(300)` on an int8 yields 44. Verified against the
    /// Go reference rather than assumed.
    pub fn SetInt(&mut self, x: int64) {
        match self {
            Value::Int(v) => {
                *v = x;
            }
            Value::Int8(v) => {
                *v = crate::int8(x);
            }
            Value::Int16(v) => {
                *v = crate::int16(x);
            }
            Value::Int32(v) => {
                *v = crate::int32(x);
            }
            _ => panic!("reflect: call of reflect.Value.SetInt on non-integer Value"),
        }
    }
}
