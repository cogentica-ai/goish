// go: package encoding/xml
//
// encoding/xml — XML 1.0 parsing and generation.
//
// IN PROGRESS. Go's package is four files and 89 functions; this is the
// first slice. What is here is the part of xml.go that is PURE — the
// token types, the character and name-byte predicates, the text
// escaper, and the ProcInst attribute reader. None of it touches the
// Decoder's state machine, so each function is exhaustively testable
// against Go on its own, which is why it went first.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   xml.rs    xml.go    — the tokenizer. Partial: see its header for
//                         the list of what is and is not here.
//
// Not started: marshal.go, read.go, typeinfo.go.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod marshal;
pub mod typeinfo;
pub mod xml;

pub use xml::{
    Attr, CharData, Comment, CopyToken, Directive, EndElement, Escape, EscapeText, Name, ProcInst,
    StartElement, SyntaxError, Token,
};

pub use marshal::{Encoder, Header, NewEncoder};
pub use typeinfo::TagPathError;
