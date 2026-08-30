// go: package container/heap
//
// container/heap — heap operations for any type implementing
// `heap.Interface`. A heap is a tree with the property that each node
// is the minimum-valued node in its subtree.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   heap.rs    heap.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod heap;

pub use heap::{Fix, Init, Interface, Pop, Push, Remove};
