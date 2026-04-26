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
        for r in self.into_vec() {
            let n = utf8::EncodeRune(&mut buf, r);
            v.extend_from_slice(&buf[..n as usize]);
        }
        string::from_vec(v)
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
        slice::from_vec(self.as_bytes().to_vec())
    }
}

impl __BytesConv for &'static str {
    fn __to_bytes(self) -> slice<byte> {
        slice::from_vec(self.as_bytes().to_vec())
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
        slice::from_vec(v)
    }
}

impl __RunesConv for &'static str {
    fn __to_runes(self) -> slice<rune> {
        runes(string::from_static(self))
    }
}
