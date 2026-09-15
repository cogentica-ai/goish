// go: package archive/zip
//
// archive/zip — Go's `archive/zip` package, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   struct.rs   archive/zip/struct.go  — FileHeader, the on-disk signatures
//                                        and lengths, the MS-DOS time codec
//                                        and the three file-mode mappings
//   reader.rs   archive/zip/reader.go  — the sentinel errors, readBuf, the
//                                        central-directory header parser and
//                                        the fs.FS name helpers
//   writer.rs   archive/zip/writer.go  — detectUTF8 only, because the READER
//                                        calls it
//
// The Reader and Writer themselves are not ported yet. Nothing about
// them is blocked — archive/zip touches no reflect and no recover, and
// every package it imports (bufio, compress/flate, encoding/binary,
// hash/crc32, io/fs, path, path/filepath, strings, sync, time) is here —
// they are simply next.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod reader;
pub mod r#struct;
pub mod writer;

pub use reader::{ErrAlgorithm, ErrChecksum, ErrFormat, ErrInsecurePath, File};
pub use r#struct::directoryEnd;
pub use r#struct::{Deflate, FileHeader, Store};
