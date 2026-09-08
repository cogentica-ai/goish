// mime/multipart — slim port of Go's mime/multipart package.
//
// Provides Writer (for assembling multipart/form-data uploads) and
// Reader. This banner said "the Reader port is deferred — its boundary
// scanner requires bufio.Reader.Peek streaming with proper rewind";
// `reader.rs` has since landed, and what it deferred is narrower than
// that sentence: it scans a `slice<byte>` held whole rather than
// streaming through Peek/rewind, which is sound only while
// `Request.Body` is buffered up front. That coupling is ROADMAP §0 A,
// and reader.rs's own header states it.
//
// Reference: src/mime/multipart/{writer.go, multipart.go} (Go 1.25).

#![allow(non_snake_case)]

extern crate alloc;

pub mod reader;
pub mod writer;

pub use reader::{NewReader, Part, Reader};
pub use writer::{FileContentDisposition, NewWriter, Writer};

pub mod formdata;

pub use formdata::{FileHeader, Form};
