// convert — Go's typed conversions: string(x), []byte(s), []rune(s).
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   s := string(b)                       let s = string(b);            // []byte → string
//   s := string(r)                       let s = string(r);            // rune → 1..4-byte string
//   s := string(rs)                      let s = string(rs);           // []rune → string
//   s := "hi"                            let s = string("hi");         // literal sugar
//   b := []byte(s)                       let b = bytes(s);
//   rs := []rune(s)                      let rs = runes(s);
//
// Each builtin is a generic free function whose type parameter
// dispatches to the right conversion via a trait — same effect as
// Go's typed conversions selecting on argument type.

extern crate alloc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, rune};
use crate::unicode::utf8;

// ─── string(x) ────────────────────────────────────────────────────────

pub trait __StringConv {
    fn __to_string(self) -> string;
}

#[allow(non_snake_case)]
#[inline]
pub fn string<T: __StringConv>(x: T) -> string {
    x.__to_string()
}

impl __StringConv for string {
    #[inline]
    fn __to_string(self) -> string {
        self
    }
}

impl __StringConv for &'static str {
    #[inline]
    fn __to_string(self) -> string {
        string::from_static(self)
    }
}

impl __StringConv for rune {
    /// Go's `string(i rune)` — encode a single rune to UTF-8 (1..4 bytes).
    /// Note: this is the Go gotcha where `string(65)` == `"A"`, not `"65"`.
    fn __to_string(self) -> string {
        let mut buf = [0u8; 4];
        let n = utf8::EncodeRune(&mut buf, self);
        string::from_bytes(&buf[..n as usize])
    }
}

impl __StringConv for slice<byte> {
    /// Go's `string(b []byte)` — copy bytes into a fresh string.
    fn __to_string(self) -> string {
        string::from_bytes(&self)
    }
}

impl __StringConv for slice<rune> {
    /// Go's `string(rs []rune)` — encode each rune to UTF-8.
    fn __to_string(self) -> string {
        // Pre-size pessimistically (1 byte per rune → grows for non-ASCII).
        let mut v: Vec<byte> = Vec::with_capacity(self.Len() as usize);
        let mut buf = [0u8; 4];
        for r in self.__into_vec() {
            let n = utf8::EncodeRune(&mut buf, r);
            v.extend_from_slice(&buf[..n as usize]);
        }
        string::__from_vec(v)
    }
}

// ─── bytes(s) — []byte(s) ─────────────────────────────────────────────

pub trait __BytesConv {
    fn __to_bytes(self) -> slice<byte>;
}

#[allow(non_snake_case)]
#[inline]
pub fn bytes<T: __BytesConv>(x: T) -> slice<byte> {
    x.__to_bytes()
}

impl __BytesConv for string {
    fn __to_bytes(self) -> slice<byte> {
        slice::__from_vec(self.as_bytes().to_vec())
    }
}

impl __BytesConv for &'static str {
    fn __to_bytes(self) -> slice<byte> {
        slice::__from_vec(self.as_bytes().to_vec())
    }
}

// ─── runes(s) — []rune(s) ─────────────────────────────────────────────

pub trait __RunesConv {
    fn __to_runes(self) -> slice<rune>;
}

#[allow(non_snake_case)]
#[inline]
pub fn runes<T: __RunesConv>(x: T) -> slice<rune> {
    x.__to_runes()
}

// Borrow-friendly: `runes(&line)` where `line` is already `&string`
// (e.g. from a range-loop binding) needs `&string: __RunesConv`.
// Cloning is cheap (Arc bump) so we forward through `clone()`.
impl __RunesConv for &string {
    fn __to_runes(self) -> slice<rune> {
        self.clone().__to_runes()
    }
}

impl __RunesConv for string {
    fn __to_runes(self) -> slice<rune> {
        let bytes = self.as_bytes();
        let mut v: Vec<rune> = Vec::with_capacity(bytes.len()); // upper bound
        let mut i: usize = 0;
        while i < bytes.len() {
            let (r, sz) = utf8::DecodeRune(&bytes[i..]);
            v.push(r);
            // sz is always >= 1 for non-empty input (DecodeRune returns
            // (RuneError, 1) on invalid bytes), so no infinite loop.
            i += sz as usize;
        }
        slice::__from_vec(v)
    }
}

impl __RunesConv for &'static str {
    fn __to_runes(self) -> slice<rune> {
        runes(string::from_static(self))
    }
}

// ─── Go-style numeric conversions ────────────────────────────────────
//
// `int(x)`, `int64(x)`, `uint64(x)`, `float64(x)` — mirror Go's typed
// numeric conversion calls. Each accepts any numeric type and dispatches
// to a per-type trait so the call site reads exactly like Go:
//
//   let n = int(port);              // u16 → i64
//   let f = float64(REQ_COUNT.Load());   // u64 → f64
//   let u = uint64(n);              // i64 → u64
//
// Implemented for u8/i8/u16/i16/u32/i32/u64/i64/usize/isize/f32/f64
// and goish's `byte`/`rune`/`int`/`uint`. Truncation/widening matches
// Rust's `as` operator (which already mirrors Go's spec for numeric
// conversions).

use crate::types::{float32, float64, int, uint};

macro_rules! __num_conv {
    ($trait:ident, $fn_name:ident, $target:ty) => {
        pub trait $trait {
            #[doc(hidden)]
            fn __conv(self) -> $target;
        }
        #[allow(non_snake_case)]
        #[inline]
        pub fn $fn_name<T: $trait>(x: T) -> $target {
            x.__conv()
        }
        // Numeric source impls — `as` covers truncation/widening per Go.
        impl $trait for u8 {  #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for i8 {  #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for u16 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for i16 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for u32 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for i32 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for u64 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for i64 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for usize { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for isize { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for f32 { #[inline] fn __conv(self) -> $target { self as $target } }
        impl $trait for f64 { #[inline] fn __conv(self) -> $target { self as $target } }
    };
}

__num_conv!(__IntConv, int, int);
__num_conv!(__Int8Conv, int8, i8);
__num_conv!(__Int16Conv, int16, i16);
__num_conv!(__Int32Conv, int32, i32);
__num_conv!(__Int64Conv, int64, i64);
__num_conv!(__UintConv, uint, uint);
__num_conv!(__Uint8Conv, uint8, u8);
__num_conv!(__Uint16Conv, uint16, u16);
__num_conv!(__Uint32Conv, uint32, u32);
__num_conv!(__Uint64Conv, uint64, u64);
__num_conv!(__Float32Conv, float32, float32);
__num_conv!(__Float64Conv, float64, float64);
