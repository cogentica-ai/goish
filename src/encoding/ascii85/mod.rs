// go: package encoding/ascii85
//
// encoding/ascii85 — the ascii85 data encoding as used in the btoa
// tool and in Adobe's PostScript and PDF document formats.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   ascii85.rs    ascii85.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod ascii85;

pub use ascii85::{CorruptInputError, Decode, Encode, MaxEncodedLen, NewDecoder, NewEncoder};
