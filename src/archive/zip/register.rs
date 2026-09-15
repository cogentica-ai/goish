// goishlint:ignore GOISH018 init — Go seeds the registry in a package `init()`; goish has no life-before-main, so the same two Store/Deflate entries are the initialiser of the `Lazy` that holds the map. Nothing can observe the difference: there is no point at which a caller sees the map unseeded.
// goishlint:ignore GOISH018 newFlateWriter, pooledFlateWriter.Write, pooledFlateWriter.Close, pooledFlateReader.Read, pooledFlateReader.Close, RegisterCompressor, compressor — the WRITE half of the registry, absent with writer.go. `pooledFlateReader` is additionally absent on the read side: it is a sync.Pool wrapper whose only job is to recycle flate readers between calls, and `newFlateReader` here returns the flate reader directly. That is an allocation difference, not a behavioural one — the pooled wrapper forwards Read and Close and adds a mutex around them — and it comes back when sync.Pool's Reset path is wired.
// goishlint:ignore GOISH021 Compressor, flateWriterPool, flateReaderPool, pooledFlateWriter, pooledFlateReader, compressors, nopCloser — the write half and the two pools, absent as above. `Compressor` is the function type the absent half is keyed on.
// go: file archive/zip/register.go decls: RegisterDecompressor, decompressor, newFlateReader
//
// archive/zip/register.go — the decompressor registry.
//
// Go's `Decompressor` is `func(io.Reader) io.ReadCloser` kept in a
// package-level `sync.Map`, seeded by `init()` with Store and Deflate.
// goish has no life-before-main, so the seeding happens on first use
// through a `Lazy`, which is the same observable thing: the map is
// never seen unseeded.
//
// The map's value type is `Option<Decompressor>` and not
// `Decompressor`. goish's `sync::Map<K, V>` requires `V: Default`, and
// a bare `fn` pointer has no default; `Option` supplies one and makes
// `Load`'s miss return `(None, false)` read exactly like Go's
// `di, ok := decompressors.Load(method)` followed by `return nil`.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use super::r#struct::{Deflate, Store};
use crate::io;
use crate::uint16;

// go: sdk 1.25.5 archive/zip/register.go:26-26 Decompressor
/// Go: "A Decompressor returns a new decompressing reader, reading from
/// r. The io.ReadCloser's Close method must be used to release
/// associated resources. The Decompressor itself must be safe to invoke
/// from multiple goroutines simultaneously, but each returned reader
/// will be used only by one goroutine at a time."
pub type Decompressor =
    fn(alloc::boxed::Box<dyn io::Reader>) -> alloc::boxed::Box<dyn io::ReadCloser>;

// go: sdk 1.25.5 archive/zip/register.go:68-76 newFlateReader
/// Go: takes a flate reader from `flateReaderPool` and `Reset`s it, or
/// makes one, and wraps it in a `pooledFlateReader` that returns it on
/// Close. goish makes one each time; see the GOISH018 waiver at the
/// head of this file for why the pool is not here yet.
pub fn newFlateReader(r: alloc::boxed::Box<dyn io::Reader>) -> alloc::boxed::Box<dyn io::ReadCloser> {
    return alloc::boxed::Box::new(crate::compress::flate::NewReader(r));
}

// go: none — goish idiom: Go's `init()` seeds the map before any
// caller can look; goish has no life-before-main, so the seeding is the
// `Lazy`'s initialiser and happens on first access instead. Nothing can
// observe the difference — there is no point at which a caller sees the
// map without Store and Deflate in it.
static decompressors: crate::lazy::Lazy<crate::sync::Map<uint16, Option<Decompressor>>> =
    crate::lazy::Lazy::new(|| {
        let m: crate::sync::Map<uint16, Option<Decompressor>> = crate::sync::Map::new();
        // Go: `decompressors.Store(Store, Decompressor(io.NopCloser))`
        m.Store(Store, Some(__store_decompressor as Decompressor));
        // Go: `decompressors.Store(Deflate, Decompressor(newFlateReader))`
        m.Store(Deflate, Some(newFlateReader as Decompressor));
        m
    });

// go: none — goish idiom: Go stores `io.NopCloser` itself, whose Go
// signature already IS a Decompressor. goish's `io::NopCloser` is
// generic and returns a concrete `NopCloserImpl<R>`, so it needs this
// one-line adaptor to have the function type the map holds.
fn __store_decompressor(
    r: alloc::boxed::Box<dyn io::Reader>,
) -> alloc::boxed::Box<dyn io::ReadCloser> {
    return alloc::boxed::Box::new(io::NopCloser(r));
}

// go: sdk 1.25.5 archive/zip/register.go:117-123 RegisterDecompressor
/// Go: "RegisterDecompressor allows custom decompressors for a
/// specified method ID. The common methods Store and Deflate are built
/// in." A duplicate PANICS — the registry is global and a second
/// registration would silently change another package's behaviour.
pub fn RegisterDecompressor(method: uint16, dcomp: Decompressor) {
    let (_, dup) = decompressors.LoadOrStore(method, Some(dcomp));
    if dup {
        panic!("decompressor already registered");
    }
}

// go: sdk 1.25.5 archive/zip/register.go:141-147 decompressor
/// Go: returns nil for an unregistered method, which is what turns into
/// `ErrAlgorithm` at the call site.
pub fn decompressor(method: uint16) -> Option<Decompressor> {
    let (di, ok) = decompressors.Load(method);
    if !ok {
        return None;
    }
    return di;
}
