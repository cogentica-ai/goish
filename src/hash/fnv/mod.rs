// go: package hash/fnv
//
// hash/fnv — FNV-1 and FNV-1a, non-cryptographic hash functions
// created by Glenn Fowler, Landon Curt Noll and Phong Vo. See
// https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   fnv.rs    fnv.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod fnv;

pub use fnv::{
    register_fnv_impls, sum128, sum128a, sum32, sum32a, sum64, sum64a, New128, New128a, New32,
    New32a, New64, New64a,
};
