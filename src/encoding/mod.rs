// encoding — Go's `encoding` package tree.
//
// Reference: /share/go/src/encoding/encoding.go (interfaces) +
// subpackage source for each codec.
//
// v1 ships:
//   ascii85, asn1 (primitive parsers only), base32, base64, binary,
//   csv, hex, json, pem
//
// Other subpackages (`encoding/gob`, `encoding/xml`) land later —
// they require these interface traits as their dispatch surface.

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::error;
use crate::goslice::slice;
use crate::types::byte;

pub mod ascii85;
pub mod asn1;
pub mod base32;
pub mod base64;
pub mod binary;
pub mod csv;
pub mod hex;
pub mod json;
pub mod pem;

// ─── Marshaler / Unmarshaler interfaces ────────────────────────────────
//
// Direct port of /share/go/src/encoding/encoding.go (78 LOC, 6 ifaces).
// These are pure declarations — they pin the method signatures that
// goish types reach for when they want to be discoverable by
// future encoding/gob, encoding/json, encoding/xml dispatch.
//
// Existing goish types (`time.Time`, `net.IP`, `net/url.URL`) ship
// inherent methods with these exact signatures already — they don't
// `impl encoding::TextMarshaler for X` because we haven't yet wired
// runtime type-switch dispatch through these traits. The traits exist
// so user code can write trait-bound generics (`fn render<T:
// encoding::TextMarshaler>(t: T)`) and so future encoders can do
// trait-based fast paths. Both shapes coexist via blanket `impl
// encoding::TextMarshaler for T where T: HasMarshalText {}`-style
// adapters added when we ship the dispatching codecs.

// Go: encoding.go:24
//   type BinaryMarshaler interface {
//       MarshalBinary() (data []byte, err error)
//   }
/// `encoding.BinaryMarshaler` — types that can serialize themselves
/// into a binary byte slice.
pub trait BinaryMarshaler {
    fn MarshalBinary(&self) -> (slice<byte>, error);
}

// Go: encoding.go:34
//   type BinaryUnmarshaler interface {
//       UnmarshalBinary(data []byte) error
//   }
/// `encoding.BinaryUnmarshaler` — types that can read a binary
/// representation of themselves. Implementations must copy `data` if
/// they wish to retain it past the call.
pub trait BinaryUnmarshaler {
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error;
}

// Go: encoding.go:42
//   type BinaryAppender interface {
//       AppendBinary(b []byte) ([]byte, error)
//   }
/// `encoding.BinaryAppender` — append the binary representation of
/// `self` to the end of `b` (growing if needed) and return the
/// updated buffer. Implementations must not retain `b` nor mutate any
/// bytes within `b[:len(b)]`.
pub trait BinaryAppender {
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error);
}

// Go: encoding.go:54
//   type TextMarshaler interface {
//       MarshalText() (text []byte, err error)
//   }
/// `encoding.TextMarshaler` — types that can serialize themselves
/// into UTF-8-encoded text bytes.
pub trait TextMarshaler {
    fn MarshalText(&self) -> (slice<byte>, error);
}

// Go: encoding.go:64
//   type TextUnmarshaler interface {
//       UnmarshalText(text []byte) error
//   }
/// `encoding.TextUnmarshaler` — types that can read a textual
/// representation of themselves. Implementations must copy `text` if
/// they wish to retain it past the call.
pub trait TextUnmarshaler {
    fn UnmarshalText(&mut self, text: slice<byte>) -> error;
}

// Go: encoding.go:72
//   type TextAppender interface {
//       AppendText(b []byte) ([]byte, error)
//   }
/// `encoding.TextAppender` — append the textual representation of
/// `self` to the end of `b` (growing if needed) and return the
/// updated buffer. Implementations must not retain `b` nor mutate any
/// bytes within `b[:len(b)]`.
pub trait TextAppender {
    fn AppendText(&self, b: slice<byte>) -> (slice<byte>, error);
}
