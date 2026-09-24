// go: package encoding/xml
//
// encoding/xml — a simple XML 1.0 parser that understands XML name
// spaces, and the reflective Marshal/Unmarshal built on it.
//
// Line-by-line port of:
//   go1.25.5/src/
//     encoding/xml/xml.go       — tokenizer, Token types, escaping
//     encoding/xml/marshal.go   — Encoder, Marshal
//     encoding/xml/read.go      — Decoder.Decode, Unmarshal
//     encoding/xml/typeinfo.go  — the `xml:"…"` struct-tag grammar
//
// Using it from goish:
//
//   #[goish::reflect]
//   struct Person {
//       XMLName: xml::Name,                       // element name
//       #[tag(r#"xml:"id,attr""#)]   Id: int,
//       #[tag(r#"xml:"name>first""#)] First: string,
//       Email: slice<string>,
//   }
//   let (out, err) = xml::Marshal(&p);
//   let err = xml::Unmarshal(data, &mut p);
//
// The deviations, each stated in full in the file that owns it:
//
//   * Token is an enum (xml.rs), not `any`.
//   * Marshal/Unmarshal walk goish's owned reflect::Value tree, so
//     Marshaler / MarshalerAttr / Unmarshaler / UnmarshalerAttr and
//     encoding.TextMarshaler/TextUnmarshaler are NOT discovered on a
//     nested value; time.Time is the one type recognised (marshal.rs,
//     read.rs). The token-level API — Decoder.Token, Encoder.EncodeToken,
//     EncodeElement, DecodeElement, Skip — is complete, which is what a
//     hand-written marshaler uses.
//   * No embedded-struct flattening, because goish's reflect marks no
//     field Anonymous (typeinfo.rs).

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

// ─── one Rust file per Go file (GOISH015) ────────────────────────────
//
//   xml.rs        xml.go        - tokenizer, Token types, escaping
//   marshal.rs    marshal.go    - Encoder, Marshal
//   read.rs       read.go       - Unmarshal, Decode
//   typeinfo.rs   typeinfo.go   - struct-tag table

pub mod marshal;
pub mod read;
pub mod typeinfo;
pub mod xml;

pub use marshal::{
    Encoder, Header, Marshal, MarshalIndent, Marshaler, MarshalerAttr, NewEncoder,
    UnsupportedTypeError,
};
pub use read::{Unmarshal, UnmarshalError, Unmarshaler, UnmarshalerAttr};
pub use typeinfo::TagPathError;
pub use xml::{
    CopyToken, Escape, EscapeText, NewDecoder, NewTokenDecoder, Attr, CharData, Comment, Decoder,
    Directive, EndElement, Name, ProcInst, StartElement, SyntaxError, Token, TokenReader,
    HTMLAutoClose, HTMLEntity,
};
