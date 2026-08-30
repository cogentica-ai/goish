// go: package container/list
//
// container/list — a doubly linked list.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   list.rs    list.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod list;

pub use list::{Element, List, New};
