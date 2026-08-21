// go: package compress/bzip2
//
// compress/bzip2 — bzip2 decompression.
//
// One Rust file per Go file, so each can carry its own provenance
// anchors (GOISH015 forbids two Go files in one Rust file, and an
// unanchored file is invisible to the fidelity tier):
//
//   bit_reader.rs     bit_reader.go      — MSB-first bit reader
//   bzip2.rs          bzip2.go           — the reader, RLE1, inverse BWT
//   huffman.rs        huffman.go         — canonical Huffman decoder
//   move_to_front.rs  move_to_front.go   — the MTF list
//
// Decompression only. Go's `compress/bzip2` has no compressor either,
// so this is the whole package, not a slice of it.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types)]

pub mod bit_reader;
pub mod bzip2;
pub mod huffman;
pub mod move_to_front;

pub use bzip2::{reader, NewReader, StructuralError};
