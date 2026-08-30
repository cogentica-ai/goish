// go: package mime/quotedprintable
//
// mime/quotedprintable — quoted-printable encoding as specified by
// RFC 2045.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   reader.rs    reader.go    — the decoder
//   writer.rs    writer.go    — the encoder
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_upper_case_globals)]

pub mod reader;
pub mod writer;

pub use reader::{NewReader, Reader};
pub use writer::{NewWriter, Writer};
