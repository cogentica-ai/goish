// go: package hash/crc32
//
// hash/crc32 — the 32-bit cyclic redundancy check, or CRC-32.
// See https://en.wikipedia.org/wiki/Cyclic_redundancy_check.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   crc32.rs             crc32.go             — tables, digest, dispatch
//   crc32_generic.rs     crc32_generic.go     — simple + slicing-by-8
//   crc32_otherarch.rs   crc32_otherarch.go   — "no hardware CRC-32"
//
// crc32_amd64.go is not ported: `castagnoliSSE42`, `castagnoliSSE42Triple`
// and `ieeeCLMUL` are assembly, and `castagnoliShift` exists only to
// feed them. goish ports the `!amd64` half of Go's own build instead,
// which is the truthful description of what this runtime can do.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod crc32;
pub mod crc32_generic;
pub mod crc32_otherarch;

pub use crc32::{
    digest, register_crc32_impls, Castagnoli, Checksum, ChecksumIEEE, IEEETable, Koopman,
    MakeTable, New, NewIEEE, Size, Table, Update, IEEE,
};
