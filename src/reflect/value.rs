// go: file reflect/value.go decls: New, Value.Set, Value.SetBool, Value.SetBytes, Value.SetFloat, Value.SetInt, Value.SetString, Value.SetUint
//
// The write side of Go's reflect/value.go — the entry points goish did
// not have.
//
// Scope: only these. `Value` itself, and the rest of its accessors, live
// in this package's mod.rs; inherent impls may be split across modules of
// the same crate, so the methods land here beside the function that
// motivates them rather than growing the module root further.
//
// Why they exist: `encoding/asn1`'s `makeField` materialises a declared
// `asn1:"default:N"` value with
//     defaultValue := reflect.New(v.Type()).Elem()
//     defaultValue.SetInt(*params.defaultValue)
// and DeepEqual-compares it against the field. Without these, that branch
// of makeField — and therefore Marshal, and therefore crypto/x509 and
// crypto/tls behind it — cannot be written.
//
// `Set`, `SetBool` and `SetString` join them for the *decode* direction:
// asn1's `parseField` is one long dispatch that ends in `val.SetBool(b)`,
// `val.SetString(s)`, `val.Set(newSlice)`. Porting it without them would
// mean open-coding the assignment at every arm and losing the resemblance
// to the Go body.
//
// The addressability deviation is stated once, here, and applies to all
// four setters. Go's `Value` is a (type, pointer, flags) triple: `Set*`
// writes *through* the pointer, so a `Value` obtained from `v.Field(i)`
// mutates the struct it came from, and `CanSet()` reports whether that is
// allowed. goish's `Value` is an owned enum — a copy — so there is no
// pointer to write through and no addressability to check. `&mut self`
// is the whole permission model, and a caller that wants a nested write
// holds a `&mut` to the nested `Value` (see asn1's `parseField`, which
// recurses on `&mut fields[i]`). The consequence: the kind checks Go
// performs still apply and still panic, but `mustBeAssignable` has no
// counterpart, and `CanSet()` is absent rather than always-true.

#![allow(non_snake_case)]

extern crate alloc;

use super::{Value, Zero};
use crate::gostring::string;
use crate::types::int64;

// go: sdk 1.25.5 reflect/value.go:3085-3098 New
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
    // go: sdk 1.25.5 reflect/value.go:2124-2141 Value.Set
    /// Assign `x` to `v`.
    ///
    /// Go copies `x` through `v`'s pointer after an assignability check;
    /// goish owns its `Value`, so the assignment is the whole operation
    /// and `x` carries its own type with it. See the addressability note
    /// in this file's banner.
    pub fn Set(&mut self, x: Value) {
        *self = x;
    }

    // go: sdk 1.25.5 reflect/value.go:2145-2149 Value.SetBool
    /// Set the underlying value to `x`.
    ///
    /// Go panics if the Value is unaddressable or its Kind is not Bool;
    /// goish has no addressability, so only the kind check applies.
    pub fn SetBool(&mut self, x: bool) {
        match self {
            // A named boolean type is still settable through its name.
            Value::Named { inner, .. } => {
                inner.SetBool(x);
            }
            Value::Bool(v) => {
                *v = x;
            }
            _ => panic!("reflect: call of reflect.Value.SetBool on non-bool Value"),
        }
    }

    // go: sdk 1.25.5 reflect/value.go:2288-2292 Value.SetString
    /// Set the underlying value to `x`.
    ///
    /// Go panics if the Value is unaddressable or its Kind is not String;
    /// goish has no addressability, so only the kind check applies.
    pub fn SetString(&mut self, x: string) {
        match self {
            // A named string type is still settable through its name.
            Value::Named { inner, .. } => {
                inner.SetString(x);
            }
            Value::String(v) => {
                *v = x;
            }
            _ => panic!("reflect: call of reflect.Value.SetString on non-string Value"),
        }
    }

    // go: sdk 1.25.5 reflect/value.go:2208-2224 Value.SetInt
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
            // A named integer type is still settable through its name —
            // `asn1:"default:7"` on an Enumerated field lands here.
            Value::Named { inner, .. } => {
                inner.SetInt(x);
            }
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

    // go: sdk 1.25.5 reflect/value.go:2257-2276 Value.SetUint
    /// Set the underlying value to `x`.
    ///
    /// Go panics if the Value is unaddressable or not of an unsigned
    /// integer kind; goish has no addressability, so only the kind check
    /// applies. Like `SetInt`, a value too wide for the kind is truncated.
    /// `encoding/xml`'s `copyValue` is the caller that motivated it.
    pub fn SetUint(&mut self, x: crate::types::uint64) {
        match self {
            Value::Named { inner, .. } => {
                inner.SetUint(x);
            }
            Value::Uint(v) => {
                *v = x;
            }
            Value::Uint8(v) => {
                *v = crate::uint8(x);
            }
            Value::Uint16(v) => {
                *v = crate::uint16(x);
            }
            Value::Uint32(v) => {
                *v = crate::uint32(x);
            }
            _ => panic!("reflect: call of reflect.Value.SetUint on non-unsigned Value"),
        }
    }

    // go: sdk 1.25.5 reflect/value.go:2193-2203 Value.SetFloat
    /// Set the underlying value to `x`, rounding to float32 for a
    /// Float32 value.
    ///
    /// Go panics if the Value is unaddressable or its Kind is not Float32
    /// or Float64; goish has no addressability, so only the kind check
    /// applies.
    pub fn SetFloat(&mut self, x: crate::types::float64) {
        match self {
            Value::Named { inner, .. } => {
                inner.SetFloat(x);
            }
            Value::Float32(v) => {
                *v = crate::float32(x);
            }
            Value::Float64(v) => {
                *v = x;
            }
            _ => panic!("reflect: call of reflect.Value.SetFloat on non-float Value"),
        }
    }

    // go: sdk 1.25.5 reflect/value.go:2154-2161 Value.SetBytes
    /// Set the underlying value, which must be a slice of bytes, to `x`.
    ///
    /// goish's `Value::Slice` holds its elements as `Value`s, so the bytes
    /// are spread into `Uint8` elements; the element type is kept.
    pub fn SetBytes(&mut self, x: crate::goslice::slice<crate::types::byte>) {
        match self {
            Value::Named { inner, .. } => {
                inner.SetBytes(x);
            }
            Value::Slice { elem_type, items } => {
                if elem_type().Kind() != super::Kind::Uint8 {
                    panic!("reflect.Value.SetBytes of non-byte slice");
                }
                let mut out: alloc::vec::Vec<Value> = alloc::vec::Vec::with_capacity(x.len());
                for (_, b) in crate::range!(x) {
                    out.push(Value::Uint8(*b));
                }
                *items = out;
            }
            _ => panic!("reflect: call of reflect.Value.SetBytes on non-slice Value"),
        }
    }
}
