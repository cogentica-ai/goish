// go: package bytes
//
// bytes — Go's `bytes` package, ported.
//
// Module root only: one `.rs` per Go `.go`, the `pub use` surface, and
// the interface-registry hook. Everything else lives in the file named
// for the Go file it came from.
//
//   bytes.rs   bytes/bytes.go    — the free functions
//   buffer.rs  bytes/buffer.go   — Buffer
//   reader.rs  bytes/reader.go   — Reader
//   iter.rs    bytes/iter.go     — the Seq family
//
// v1 deviations from Go:
//
//   * `Buffer::Bytes()` and `Buffer::String()` clone. Go returns a view
//     into the unread portion of the internal buffer; goish slices and
//     strings are owning, so we clone. Slightly more allocation, never
//     invalidated by the next Write/Read/Reset.
//   * `Index`/`LastIndex` use naive O(n*m) byte search — Go drops to
//     an assembly Rabin-Karp past a threshold.
//   * Each `Split` segment is a fresh `slice<byte>` (copy), where Go's
//     is a subslice aliasing the input.
//
// All `slice<byte>` inputs take `S: Into<slice<byte>>` so byte literals
// (`b","`) flow without wrapping (relies on the `From<&[u8]>` and
// `From<&[u8; N]>` impls on `slice<T>`).

#![allow(non_snake_case)]

extern crate alloc;

#[path = "reader.rs"]
mod reader;
pub use reader::{NewReader, Reader};

#[path = "buffer.rs"]
mod buffer;
pub use buffer::{Buffer, MinRead, NewBuffer, NewBufferString};

#[path = "bytes.rs"]
mod bytes_go;
#[allow(deprecated)]
pub use bytes_go::{
    Clone, Compare, Contains, ContainsAny, ContainsFunc, ContainsRune, Count, Cut, CutPrefix,
    CutSuffix, Equal, EqualFold, Fields, FieldsFunc, HasPrefix, HasSuffix, Index, IndexAny,
    IndexByte, IndexFunc, IndexRune, Join, LastIndex, LastIndexAny, LastIndexByte, LastIndexFunc,
    Map, Repeat, Replace, ReplaceAll, Runes, Split, SplitAfter, SplitAfterN, SplitN, Title,
    ToLower, ToLowerSpecial, ToTitle, ToTitleSpecial, ToUpper, ToUpperSpecial, ToValidUTF8, Trim,
    TrimFunc, TrimLeft, TrimLeftFunc, TrimPrefix, TrimRight, TrimRightFunc, TrimSpace, TrimSuffix,
};

#[path = "iter.rs"]
mod iter_go;
pub use iter_go::{FieldsFuncSeq, FieldsSeq, Lines, SplitAfterSeq, SplitSeq};

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b and
// the banner on `io::register_io_impls`.
/// Register `bytes`'s concrete types into the `io` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_bytes_impls() {
    use crate::io::{
        __goish_register_ByteReader_impl, __goish_register_ByteWriter_impl,
        __goish_register_ReaderAt_impl, __goish_register_ReaderFrom_impl,
        __goish_register_Reader_impl, __goish_register_Seeker_impl,
        __goish_register_StringWriter_impl, __goish_register_WriterTo_impl,
        __goish_register_Writer_impl,
    };
    __goish_register_Reader_impl::<Buffer>();
    __goish_register_Writer_impl::<Buffer>();
    __goish_register_ByteReader_impl::<Buffer>();
    __goish_register_ByteWriter_impl::<Buffer>();
    __goish_register_StringWriter_impl::<Buffer>();
    __goish_register_ReaderFrom_impl::<Buffer>();
    __goish_register_WriterTo_impl::<Buffer>();

    __goish_register_Reader_impl::<Reader>();
    __goish_register_ReaderAt_impl::<Reader>();
    __goish_register_ByteReader_impl::<Reader>();
    __goish_register_Seeker_impl::<Reader>();
    __goish_register_WriterTo_impl::<Reader>();
}
