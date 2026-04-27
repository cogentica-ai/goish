// encoding/hex — Go's hex codec.
//
// Reference: /share/go/src/encoding/hex/hex.go.
//
// Public API:
//
//   hex::EncodeToString(&src) -> string
//   hex::DecodeString(&s) -> Result<Vec<u8>, error>
//   hex::Encode(&mut dst, &src) -> int   // bytes written = 2 * len(src)
//   hex::Decode(&mut dst, &src) -> (int, error)
//   hex::EncodedLen(n) -> int
//   hex::DecodedLen(n) -> int
//
// What v1 omits: NewEncoder/NewDecoder (io.Writer/Reader wrappers),
// AppendEncode/AppendDecode, Dump (canonical pretty-print). Easy to
// add later; not load-bearing for the typical use case.

#![allow(non_snake_case)]

use alloc::vec;
use alloc::vec::Vec;

use crate::errors::{error, ErrorTrait};
use crate::gostring::string;
use crate::types::int;

const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

/// `hex.EncodedLen(n)` — bytes needed to encode `n` source bytes.
/// Mirrors `EncodedLen` (hex.go:39).
pub fn EncodedLen(n: int) -> int {
    n * 2
}

/// `hex.DecodedLen(n)` — bytes produced by decoding `n` source
/// bytes. Mirrors `DecodedLen` (hex.go:78).
pub fn DecodedLen(n: int) -> int {
    n / 2
}

/// `hex.Encode(dst, src)` — write the hex encoding of `src` into
/// `dst`, returns the number of bytes written (always 2 * len(src)).
/// Mirrors `Encode` (hex.go:45).
pub fn Encode(dst: &mut [u8], src: &[u8]) -> int {
    let needed = src.len() * 2;
    assert!(dst.len() >= needed, "hex: Encode dst too short");
    let mut j = 0;
    for &b in src {
        dst[j] = HEX_TABLE[(b >> 4) as usize];
        dst[j + 1] = HEX_TABLE[(b & 0x0f) as usize];
        j += 2;
    }
    j as int
}

/// `hex.EncodeToString(src)` — return the hex encoding as a string.
/// Mirrors `EncodeToString` (hex.go:126).
pub fn EncodeToString(src: &[u8]) -> string {
    let mut dst = vec![0u8; src.len() * 2];
    Encode(&mut dst, src);
    string::from_bytes(&dst)
}

#[derive(Clone)]
struct InvalidByteError(u8);

impl ErrorTrait for InvalidByteError {
    fn Error(&self) -> string {
        // "encoding/hex: invalid byte: 0xNN"
        let prefix = b"encoding/hex: invalid byte: 0x";
        let mut buf: alloc::vec::Vec<u8> =
            alloc::vec::Vec::with_capacity(prefix.len() + 2);
        buf.extend_from_slice(prefix);
        buf.push(HEX_TABLE[(self.0 >> 4) as usize]);
        buf.push(HEX_TABLE[(self.0 & 0x0f) as usize]);
        string::from_bytes(&buf)
    }
}

#[derive(Clone)]
struct ErrLength;

impl ErrorTrait for ErrLength {
    fn Error(&self) -> string {
        string::from_static("encoding/hex: odd length hex string")
    }
}

#[inline]
fn from_hex_char(c: u8) -> (u8, bool) {
    match c {
        b'0'..=b'9' => (c - b'0', true),
        b'a'..=b'f' => (c - b'a' + 10, true),
        b'A'..=b'F' => (c - b'A' + 10, true),
        _ => (0, false),
    }
}

/// `hex.Decode(dst, src)` — decode `src` into `dst`, returns
/// (bytesWritten, err). Mirrors `Decode` (hex.go:87).
pub fn Decode(dst: &mut [u8], src: &[u8]) -> (int, error) {
    let mut i = 0;
    let mut j = 0;
    while j + 1 < src.len() {
        let (hi, ok1) = from_hex_char(src[j]);
        if !ok1 {
            return (i as int, crate::errors::Wrap(InvalidByteError(src[j])));
        }
        let (lo, ok2) = from_hex_char(src[j + 1]);
        if !ok2 {
            return (i as int, crate::errors::Wrap(InvalidByteError(src[j + 1])));
        }
        if i >= dst.len() {
            break;
        }
        dst[i] = (hi << 4) | lo;
        i += 1;
        j += 2;
    }
    if src.len() % 2 == 1 {
        // Check whether the trailing byte is a valid hex char before
        // reporting odd-length (Go's behavior).
        let (_, ok) = from_hex_char(src[src.len() - 1]);
        if !ok {
            return (i as int, crate::errors::Wrap(InvalidByteError(src[src.len() - 1])));
        }
        return (i as int, crate::errors::Wrap(ErrLength));
    }
    (i as int, crate::errors::nil)
}

/// `hex.DecodeString(s)` — decode a hex string into bytes. Mirrors
/// `DecodeString` (hex.go:138).
pub fn DecodeString(s: &str) -> (Vec<u8>, error) {
    let src = s.as_bytes();
    let mut dst = vec![0u8; src.len() / 2];
    let (n, err) = Decode(&mut dst, src);
    dst.truncate(n as usize);
    (dst, err)
}
