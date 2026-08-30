// go: package unicode/utf16
//
// unicode/utf16 — UTF-16 encoding and decoding.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   utf16.rs     utf16.go     — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_upper_case_globals)]

pub mod utf16;

pub use utf16::{AppendRune, Decode, DecodeRune, Encode, EncodeRune, IsSurrogate, RuneLen};
