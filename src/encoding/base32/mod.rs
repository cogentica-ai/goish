// go: package encoding/base32
//
// encoding/base32 — base32 encoding as defined in RFC 4648.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   base32.rs    base32.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod base32;

pub use base32::{
    CorruptInputError, Decoder, Encoder, Encoding, HexEncoding, NewDecoder, NewEncoder,
    NewEncoding, NoPadding, StdEncoding, StdPadding,
};
