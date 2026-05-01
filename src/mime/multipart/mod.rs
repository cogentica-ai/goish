// mime/multipart — slim port of Go's mime/multipart package.
//
// Currently provides Writer (for assembling multipart/form-data
// uploads). The Reader port is deferred — its boundary scanner
// requires bufio.Reader.Peek streaming with proper rewind, which is
// substantial.
//
// Reference: src/mime/multipart/writer.go (Go 1.25, 202 LOC).

#![allow(non_snake_case)]

pub mod writer;

pub use writer::{FileContentDisposition, NewWriter, Writer};
