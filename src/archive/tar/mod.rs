// go: package archive/tar
//
// archive/tar — Go's `archive/tar` package, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   common.rs   archive/tar/common.go  — Header, the type flags, the PAX
//                                        keywords, the sentinel errors,
//                                        sparse validation, FileInfoHeader
//   format.rs   archive/tar/format.go  — Format, the on-disk `block`
//   reader.rs   archive/tar/reader.go  — Reader
//   strconv.rs  archive/tar/strconv.go — the numeric/string codecs
//   writer.rs   archive/tar/writer.go  — Writer
//
// Sparse file reading is stubbed — sparse files return ErrHeader.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code
)]

extern crate alloc;

#[path = "common.rs"]
mod common;
pub use common::*;

#[path = "format.rs"]
mod format;
pub use format::*;

// strconv.go declares nothing exported — every codec in it is
// package-internal, shared by reader.rs and writer.rs. So this is a
// crate-visible re-export, not a `pub` one.
#[path = "strconv.rs"]
mod strconv_go;
pub(crate) use strconv_go::*;

#[path = "reader.rs"]
mod reader;
pub use reader::*;

#[path = "writer.rs"]
mod writer;
pub use writer::*;
