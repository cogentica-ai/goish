// go: package io
//
// io — Go's `io` package, ported.
//
// Module root only: one `.rs` per Go `.go`, the `pub use` surface, and
// the interface-registry hook.
//
//   io.rs     io/io.go     — the interfaces, the sentinel errors, and
//                            the free functions built on them
//   multi.rs  io/multi.go  — MultiReader, MultiWriter
//   pipe.rs   io/pipe.go   — Pipe, PipeReader, PipeWriter
//   fs.rs     io/fs/*.go   — the io/fs subpackage
//   ioutil/   io/ioutil    — the Go 1.16-deprecated forwarders
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   type Reader interface {              pub trait Reader {
//       Read(p []byte) (n int, err error)    fn Read(&mut self, p: &mut slice<byte>) -> (int, error);
//   }                                     }
//
//   type Writer interface {              pub trait Writer {
//       Write(p []byte) (n int, err error)   fn Write(&mut self, p: slice<byte>) -> (int, error);
//   }                                     }
//
//   var EOF = errors.New("EOF")          pub fn EOF.into() -> error  // cached, ptr-stable
//   io.Copy(dst, src)                     io::Copy(dst, src) -> (int64, error)
//   io.WriteString(w, s)                  io::WriteString(w, s) -> (int, error)
//
// Method-receiver trait shape: `&mut self` mirrors Go's `*File` /
// pointer receiver — both express "needs exclusive access to the
// underlying resource (fd cursor, buffer position)".
//
// Buffer arguments:
//   - `Write` takes `slice<byte>` by value (consumed). Call sites read
//     as Go: `w.Write(buf)`. Trade: caller can't reuse `buf` after.
//   - `Read` takes `&mut slice<byte>` — unavoidable; the function must
//     mutate the caller's buffer in place to honor Go's pre-allocate
//     idiom.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

#[path = "io.rs"]
mod io_go;
pub use io_go::*;

#[path = "multi.rs"]
mod multi;
pub use multi::*;

// ─── Pipe (line-by-line port of pipe.go) ─────────────────────────────

pub mod pipe;
pub use pipe::{ErrClosedPipe, Pipe, PipeReader, PipeWriter};

// ─── io/fs subpackage ────────────────────────────────────────────────

pub mod fs;

// ─── io/ioutil — Go 1.16-deprecated forwarders ───────────────────────

pub mod ioutil;

// ─── Downcast-registry population ─────────────────────────────────────
//
// go: none — goish idiom. `#[goish::interface]` emits a per-trait
// downcast registry but nothing fills it; Go builds the equivalent
// itabs at link time. Every `impl Trait for Concrete` needs one entry,
// or a type assertion to that interface — `cast!` on a `dyn Trait`
// carrier, `.As::<dyn Trait>()` on an `Any` — misses even though the
// impl exists. See AGENTS.md §9b.
//
// Each package registers the types it declares, because unexported
// ones (`Empty`, `MultiReaderImpl`, …) are only nameable here.

// go: none — goish idiom: Go's linker builds the equivalent itabs.
/// Register `io`'s own concrete types into the `io` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_io_impls() {
    __goish_register_Reader_impl::<Empty>();
    __goish_register_Reader_impl::<MultiReaderImpl>();
    __goish_register_WriterTo_impl::<MultiReaderImpl>();
    __goish_register_Reader_impl::<SectionReader>();
    __goish_register_ReaderAt_impl::<SectionReader>();
    __goish_register_Seeker_impl::<SectionReader>();

    __goish_register_Writer_impl::<Discard>();
    __goish_register_ReaderFrom_impl::<Discard>();
    __goish_register_Writer_impl::<MultiWriterImpl>();
    __goish_register_StringWriter_impl::<MultiWriterImpl>();
    __goish_register_Writer_impl::<OffsetWriter>();
    __goish_register_WriterAt_impl::<OffsetWriter>();
    __goish_register_Seeker_impl::<OffsetWriter>();

    __goish_register_Closer_impl::<NullCloser>();

    __goish_register_Reader_impl::<pipe::PipeReader>();
    __goish_register_Closer_impl::<pipe::PipeReader>();
    __goish_register_Writer_impl::<pipe::PipeWriter>();
    __goish_register_Closer_impl::<pipe::PipeWriter>();
}
