// go: package hash/crc64
//
// hash/crc64 — the 64-bit cyclic redundancy check, or CRC-64.
// See https://en.wikipedia.org/wiki/Cyclic_redundancy_check.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   crc64.rs    crc64.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod crc64;

pub use crc64::{
    digest, register_crc64_impls, Checksum, ECMATable, ISOTable, MakeTable, New, Size, Table,
    Update, ECMA, ISO,
};
