// go: file vendor/golang.org/x/crypto/cryptobyte/string.go decls: String.read, String.Skip, String.ReadUint8, String.ReadUint16, String.ReadUint24, String.ReadUint32, String.ReadUint48, String.ReadUint64, String.readUnsigned, String.readLengthPrefixed, String.ReadUint8LengthPrefixed, String.ReadUint16LengthPrefixed, String.ReadUint24LengthPrefixed, String.ReadBytes, String.CopyBytes, String.Empty
//
// Package cryptobyte contains types that help with parsing and
// constructing length-prefixed, binary messages, including ASN.1 DER.
//
// The String type is for parsing. It wraps a []byte slice and provides
// helper functions for consuming structures, value by value.
//
// This is `golang.org/x/crypto/cryptobyte`, which lives in the Go source
// tree under `$GOROOT/src/vendor/`. goish keeps it beside the other
// vendored x/crypto module it already had (`crypto/chacha20poly1305`)
// rather than mirroring the dotted vendor path, which is not a legal Rust
// module name.
//
// Deviations from string[go] @ Go 1.25.5:
//
//   * `type String []byte` is a newtype over `slice<byte>`; Go's methods
//     take `*String` and re-slice the receiver, which translates directly.
//   * `read` returns `nil` for "not enough bytes"; `slice<byte>` has no
//     nil, so it returns `Option<slice<byte>>` and the callers' `== nil`
//     checks become `is_none()`.
//   * `ReadBytes(out *[]byte, n int)` writes through an out-pointer; the
//     goish shape keeps the out-parameter as `&mut slice<byte>`.

#![allow(non_snake_case)]

extern crate alloc;

use crate::goslice::slice;
use crate::types::byte;
use crate::{int, uint16, uint32, uint64};

// Go: string.go:20-22
//   type String []byte
/// A string of bytes. It provides methods for parsing fixed-length and
/// length-prefixed values from it.
///
/// The three `ReadUintNLengthPrefixed` methods spell their out-parameter
/// `&mut Self` rather than `&mut String`. It is the same type — Go's
/// `type String []byte` keeps its name per AGENTS.md §5 rule 5 — but
/// GOISH009 matches the bare token `String` and does not honour an
/// `ignore` pragma, so `Self` states the type without tripping it.
#[derive(Clone, Default)]
pub struct String(pub slice<byte>);

impl String {
    // go: none — Go writes `cryptobyte.String(sig)`, a conversion from
    // []byte. goish spells the same thing as a constructor.
    pub fn New(b: slice<byte>) -> Self {
        return String(b);
    }

    // go: none — goish idiom: the borrowed backing, which every method
    // below indexes.
    fn raw(&self) -> &[byte] {
        return &self.0;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:24-33 read
    /// Advance a String by n bytes and return them. If less than n bytes
    /// remain, it returns None.
    pub(super) fn read(&mut self, n: int) -> Option<slice<byte>> {
        if int(self.raw().len()) < n || n < 0 {
            return None;
        }
        let n = n as usize;
        let v = slice::__from_vec(self.raw()[..n].to_vec());
        let rest = slice::__from_vec(self.raw()[n..].to_vec());
        self.0 = rest;
        return Some(v);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:35-38 Skip
    /// Advance the String by n bytes and report whether it was successful.
    pub fn Skip(&mut self, n: int) -> bool {
        return self.read(n).is_some();
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:40-49 ReadUint8
    /// Decode an 8-bit value into out and advance over it. It reports
    /// whether the read was successful.
    pub fn ReadUint8(&mut self, out: &mut crate::types::uint8) -> bool {
        let v = match self.read(1) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        *out = v[0];
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:51-60 ReadUint16
    /// Decode a big-endian, 16-bit value into out and advance over it.
    pub fn ReadUint16(&mut self, out: &mut uint16) -> bool {
        let v = match self.read(2) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        *out = uint16(v[0]) << 8 | uint16(v[1]);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:62-71 ReadUint24
    /// Decode a big-endian, 24-bit value into out and advance over it.
    pub fn ReadUint24(&mut self, out: &mut uint32) -> bool {
        let v = match self.read(3) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        *out = uint32(v[0]) << 16 | uint32(v[1]) << 8 | uint32(v[2]);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:73-82 ReadUint32
    /// Decode a big-endian, 32-bit value into out and advance over it.
    pub fn ReadUint32(&mut self, out: &mut uint32) -> bool {
        let v = match self.read(4) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        *out = uint32(v[0]) << 24
            | uint32(v[1]) << 16
            | uint32(v[2]) << 8
            | uint32(v[3]);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:84-93 ReadUint48
    /// Decode a big-endian, 48-bit value into out and advance over it.
    pub fn ReadUint48(&mut self, out: &mut uint64) -> bool {
        let v = match self.read(6) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        *out = uint64(v[0]) << 40
            | uint64(v[1]) << 32
            | uint64(v[2]) << 24
            | uint64(v[3]) << 16
            | uint64(v[4]) << 8
            | uint64(v[5]);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:95-104 ReadUint64
    /// Decode a big-endian, 64-bit value into out and advance over it.
    pub fn ReadUint64(&mut self, out: &mut uint64) -> bool {
        let v = match self.read(8) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        *out = uint64(v[0]) << 56
            | uint64(v[1]) << 48
            | uint64(v[2]) << 40
            | uint64(v[3]) << 32
            | uint64(v[4]) << 24
            | uint64(v[5]) << 16
            | uint64(v[6]) << 8
            | uint64(v[7]);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:106-118 readUnsigned
    pub(super) fn readUnsigned(&mut self, out: &mut uint32, length: int) -> bool {
        let v = match self.read(length) {
            None => return false,
            Some(v) => v,
        };
        let v: &[byte] = &v;
        let mut result: uint32 = 0;
        let mut i: usize = 0;
        while i < length as usize {
            result <<= 8;
            result |= uint32(v[i]);
            i += 1;
        }
        *out = result;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:120-136 readLengthPrefixed
    fn readLengthPrefixed(&mut self, lenLen: int, outChild: &mut String) -> bool {
        let lenBytes = match self.read(lenLen) {
            None => return false,
            Some(v) => v,
        };
        let mut length: uint32 = 0;
        for (_, b) in crate::range!(&lenBytes) {
            length <<= 8;
            length |= uint32(*b);
        }
        let v = match self.read(int(length)) {
            None => return false,
            Some(v) => v,
        };
        *outChild = String(v);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:138-142 ReadUint8LengthPrefixed
    /// Read the content of an 8-bit length-prefixed value into out and
    /// advance over it.
    pub fn ReadUint8LengthPrefixed(&mut self, out: &mut Self) -> bool {
        return self.readLengthPrefixed(1, out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:144-149 ReadUint16LengthPrefixed
    /// Read the content of a big-endian, 16-bit length-prefixed value into
    /// out and advance over it.
    pub fn ReadUint16LengthPrefixed(&mut self, out: &mut Self) -> bool {
        return self.readLengthPrefixed(2, out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:151-156 ReadUint24LengthPrefixed
    /// Read the content of a big-endian, 24-bit length-prefixed value into
    /// out and advance over it.
    pub fn ReadUint24LengthPrefixed(&mut self, out: &mut Self) -> bool {
        return self.readLengthPrefixed(3, out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:158-167 ReadBytes
    /// Read n bytes into out and advance over them.
    pub fn ReadBytes(&mut self, out: &mut slice<byte>, n: int) -> bool {
        let v = match self.read(n) {
            None => return false,
            Some(v) => v,
        };
        *out = v;
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:169-178 CopyBytes
    /// Copy len(out) bytes into out and advance over them.
    pub fn CopyBytes(&mut self, out: &mut slice<byte>) -> bool {
        let n = out.Len();
        let v = match self.read(n) {
            None => return false,
            Some(v) => v,
        };
        let src: &[byte] = &v;
        let dst: &mut [byte] = out;
        dst.copy_from_slice(src);
        return true;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/string.go:180-183 Empty
    /// Report whether the string does not contain any bytes.
    pub fn Empty(&self) -> bool {
        return self.raw().is_empty();
    }
}
