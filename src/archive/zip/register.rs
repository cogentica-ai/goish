// goishlint:ignore GOISH018 init — Go seeds the registry in a package `init()`; goish has no life-before-main, so the same two Store/Deflate entries are the initialiser of the `Lazy` that holds the map. Nothing can observe the difference: there is no point at which a caller sees the map unseeded.
// goishlint:ignore GOISH018 pooledFlateWriter.Write, pooledFlateWriter.Close, pooledFlateReader.Read, pooledFlateReader.Close — the WRITE half of the registry, absent with writer.go. `pooledFlateReader` is additionally absent on the read side: it is a sync.Pool wrapper whose only job is to recycle flate readers between calls, and `newFlateReader` here returns the flate reader directly. That is an allocation difference, not a behavioural one — the pooled wrapper forwards Read and Close and adds a mutex around them — and it comes back when sync.Pool's Reset path is wired.
// goishlint:ignore GOISH021 flateWriterPool, flateReaderPool, pooledFlateWriter, pooledFlateReader, nopCloser — the two sync.Pools and their wrappers, absent as above; `nopCloser` is declared in writer.go and ported there, which is where GOISH015 wants it.
// go: file archive/zip/register.go decls: RegisterDecompressor, decompressor, newFlateReader, RegisterCompressor, compressor, newFlateWriter
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

// go: sdk 1.25.5 archive/zip/register.go:19-19 Compressor
/// Go: "A Compressor returns a new compressing writer, writing to w.
/// The WriteCloser's Close method must be used to flush pending data to
/// w. The Compressor itself must be safe to invoke from multiple
/// goroutines simultaneously, but each returned writer will be used
/// only by one goroutine at a time."
pub type Compressor = fn(
    alloc::boxed::Box<dyn io::Writer>,
) -> (alloc::boxed::Box<dyn io::WriteCloser>, crate::error);

// go: sdk 1.25.5 archive/zip/register.go:30-38 newFlateWriter
/// Go: takes a flate writer from `flateWriterPool` and `Reset`s it, or
/// makes one at `flate.BestSpeed`, and wraps it so Close returns it to
/// the pool. goish makes one each time; the pool is waived at the head
/// of this file.
pub fn newFlateWriter(
    w: alloc::boxed::Box<dyn io::Writer>,
) -> alloc::boxed::Box<dyn io::WriteCloser> {
    // Go: `flate.NewWriter(w, 5)` — BestSpeed is 1, DefaultCompression
    // -1; Go's zip uses 5.
    let (fw, _) = crate::compress::flate::NewWriter(w, 5);
    return alloc::boxed::Box::new(fw);
}

// go: none — goish idiom: see the note on `decompressors`.
static compressors: crate::lazy::Lazy<crate::sync::Map<uint16, Option<Compressor>>> =
    crate::lazy::Lazy::new(|| {
        let m: crate::sync::Map<uint16, Option<Compressor>> = crate::sync::Map::new();
        m.Store(Store, Some(__store_compressor as Compressor));
        m.Store(Deflate, Some(__deflate_compressor as Compressor));
        m
    });

// go: none — goish idiom: Go writes the two closures inline in `init()`;
// goish's `Lazy` initialiser is a fn pointer and the map holds fn
// pointers, so each is a named function.
fn __store_compressor(
    w: alloc::boxed::Box<dyn io::Writer>,
) -> (alloc::boxed::Box<dyn io::WriteCloser>, crate::error) {
    return (
        alloc::boxed::Box::new(super::writer::nopCloser { Writer: w }),
        crate::errors::nil,
    );
}

// go: none — see `__store_compressor`.
fn __deflate_compressor(
    w: alloc::boxed::Box<dyn io::Writer>,
) -> (alloc::boxed::Box<dyn io::WriteCloser>, crate::error) {
    return (newFlateWriter(w), crate::errors::nil);
}

// go: sdk 1.25.5 archive/zip/register.go:125-131 RegisterCompressor
/// Go: "RegisterCompressor registers custom compressors for a specified
/// method ID. The common methods Store and Deflate are built in." A
/// duplicate panics, as for RegisterDecompressor.
pub fn RegisterCompressor(method: uint16, comp: Compressor) {
    let (_, dup) = compressors.LoadOrStore(method, Some(comp));
    if dup {
        panic!("compressor already registered");
    }
}

// go: sdk 1.25.5 archive/zip/register.go:133-139 compressor
/// Go: returns nil for an unregistered method, which becomes
/// `ErrAlgorithm` at the call site.
pub fn compressor(method: uint16) -> Option<Compressor> {
    let (ci, ok) = compressors.Load(method);
    if !ok {
        return None;
    }
    return ci;
}
