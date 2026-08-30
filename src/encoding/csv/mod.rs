// go: package encoding/csv
//
// encoding/csv — comma-separated values reader/writer.
//
// Line-by-line port of:
//   go1.25.5/src/
//     encoding/csv/reader.go
//     encoding/csv/writer.go
//
// Slim deviations:
//   * Reader returns `slice<string>` instead of `[]string`; goish lacks a
//     fixed-Vec field that can hold a Go-style `lastRecord` cache, so
//     `ReuseRecord` is accepted as a field but the optimization is a
//     no-op (each Read returns a fresh slice).
//   * `FieldPos` panics with goish-style panic.
//   * Empty-line + comment-line handling matches Go reader.go:305-319.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

// ─── one Rust file per Go file (GOISH015) ────────────────────────────
//
//   reader.rs    reader.go    - reading records
//   writer.rs    writer.go    - writing records

pub mod reader;
pub mod writer;

pub use reader::{NewReader, ParseError, Reader};
pub use writer::{NewWriter, Writer};
