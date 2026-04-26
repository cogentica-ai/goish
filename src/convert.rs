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

use crate::goslice::GoSlice;
use crate::gostring::GoString;
use crate::types::{byte, rune};
use crate::unicode::utf8;

// ─── string(x) ────────────────────────────────────────────────────────

pub trait ToGoString {
    fn __to_string(self) -> GoString;
}

#[allow(non_snake_case)]
#[inline]
pub fn string<T: ToGoString>(x: T) -> GoString {
    x.__to_string()
}

impl ToGoString for GoString {
    #[inline]
    fn __to_string(self) -> GoString {
        self
    }
}

impl ToGoString for &'static str {
    #[inline]
    fn __to_string(self) -> GoString {
        GoString::from_static(self)
    }
}

impl ToGoString for rune {
    /// Go's `string(i rune)` — encode a single rune to UTF-8 (1..4 bytes).
    /// Note: this is the Go gotcha where `string(65)` == `"A"`, not `"65"`.
    fn __to_string(self) -> GoString {
        let mut buf = [0u8; 4];
        let n = utf8::EncodeRune(&mut buf, self);
        GoString::from_bytes(&buf[..n as usize])
    }
}

impl ToGoString for GoSlice<byte> {
    /// Go's `string(b []byte)` — copy bytes into a fresh string.
    fn __to_string(self) -> GoString {
        GoString::from_bytes(&self)
    }
}

impl ToGoString for GoSlice<rune> {
    /// Go's `string(rs []rune)` — encode each rune to UTF-8.
    fn __to_string(self) -> GoString {
        // Pre-size pessimistically (1 byte per rune → grows for non-ASCII).
        let mut v: Vec<byte> = Vec::with_capacity(self.Len() as usize);
        let mut buf = [0u8; 4];
        for r in self.into_vec() {
            let n = utf8::EncodeRune(&mut buf, r);
            v.extend_from_slice(&buf[..n as usize]);
        }
        GoString::from_vec(v)
    }
}

// ─── bytes(s) — []byte(s) ─────────────────────────────────────────────

pub trait ToGoBytes {
    fn __to_bytes(self) -> GoSlice<byte>;
}

#[allow(non_snake_case)]
#[inline]
pub fn bytes<T: ToGoBytes>(x: T) -> GoSlice<byte> {
    x.__to_bytes()
}

impl ToGoBytes for GoString {
    fn __to_bytes(self) -> GoSlice<byte> {
        GoSlice::from_vec(self.as_bytes().to_vec())
    }
}

impl ToGoBytes for &'static str {
    fn __to_bytes(self) -> GoSlice<byte> {
        GoSlice::from_vec(self.as_bytes().to_vec())
    }
}

// ─── runes(s) — []rune(s) ─────────────────────────────────────────────

pub trait ToGoRunes {
    fn __to_runes(self) -> GoSlice<rune>;
}

#[allow(non_snake_case)]
#[inline]
pub fn runes<T: ToGoRunes>(x: T) -> GoSlice<rune> {
    x.__to_runes()
}

impl ToGoRunes for GoString {
    fn __to_runes(self) -> GoSlice<rune> {
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
        GoSlice::from_vec(v)
    }
}

impl ToGoRunes for &'static str {
    fn __to_runes(self) -> GoSlice<rune> {
        runes(GoString::from_static(self))
    }
}
