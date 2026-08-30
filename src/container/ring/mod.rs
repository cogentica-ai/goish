// go: package container/ring
//
// container/ring — operations on circular lists.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   ring.rs    ring.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod ring;

pub use ring::{New, Ring};
