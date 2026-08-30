// go: package encoding/base64
//
// encoding/base64 — base64 encoding as defined in RFC 4648.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   base64.rs    base64.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod base64;

pub use base64::{
    Decoder, Encoder, Encoding, NewDecoder, NewEncoder, NewEncoding, NoPadding, RawStdEncoding,
    RawURLEncoding, StdEncoding, StdPadding, URLEncoding,
};
