// go: package hash/adler32
//
// hash/adler32 — the Adler-32 checksum, defined in RFC 1950.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   adler32.rs    adler32.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod adler32;

pub use adler32::{digest, register_adler32_impls, Checksum, New, Size};
