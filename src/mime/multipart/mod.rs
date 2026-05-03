// mime/multipart — slim port of Go's mime/multipart package.
//
// Currently provides Writer (for assembling multipart/form-data
// uploads). The Reader port is deferred — its boundary scanner
// requires bufio.Reader.Peek streaming with proper rewind, which is
// substantial.
//
// Reference: src/mime/multipart/writer.go (Go 1.25, 202 LOC).

#![allow(non_snake_case)]

extern crate alloc;

pub mod reader;
pub mod writer;

pub use reader::{NewReader, Part, Reader};
pub use writer::{FileContentDisposition, NewWriter, Writer};

// ─── File / FileHeader (Go 1.25 src/mime/multipart/formdata.go) ───────
//
// `File` is the interface a server-side handler receives for an
// uploaded part. Go composes it from io.{Reader, ReaderAt, Seeker,
// Closer}. Goish models it as a trait that requires the same four
// behaviours; concrete impls (e.g. an `os.File`-backed wrapper) must
// satisfy all four. The interface itself appears in user code mainly
// as a stored field type — `pub Data: File` lowers to `Box<dyn File +
// Send + Sync>` via the boxed-trait field convention.
pub trait File: crate::io::Reader + crate::io::ReaderAt + crate::io::Seeker + crate::io::Closer {}

// Blanket: any type that already implements all four io traits is a
// `File`. Lets call sites store concrete readers without explicit
// `impl File for MyT {}`.
impl<T> File for T where T: crate::io::Reader + crate::io::ReaderAt + crate::io::Seeker + crate::io::Closer {}

/// `multipart.FileHeader` (Go 1.25 src/mime/multipart/formdata.go:271)
/// — the metadata for an uploaded file part. Goish v1 carries the
/// public fields; the private `content`/`tmpfile`/etc. fields used by
/// Go's reader implementation are deferred until the Reader port lands.
#[derive(Clone, Default)]
pub struct FileHeader {
    /// Original filename as supplied by the client.
    pub Filename: crate::gostring::string,
    /// Headers attached to this part (Content-Type, Content-Disposition,
    /// etc.). `MIMEHeader` is `map<string, slice<string>>` per
    /// `net/textproto`.
    pub Header: crate::net::textproto::MIMEHeader,
    /// File size in bytes.
    pub Size: i64,
}
