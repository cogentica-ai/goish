// go: package compress/zlib
//
// compress/zlib — zlib compressed data format (RFC 1950).
//
// Line-by-line port of Go 1.25 `compress/zlib/`
// (`reader.go` + `writer.go`). zlib is a thin framing around
// `compress/flate`: a 2-byte header (CMF/FLG), an optional 4-byte
// preset-dictionary id, the raw DEFLATE payload, and a 4-byte
// big-endian Adler-32 checksum of the *uncompressed* data.
//
// Slim deviations from Go:
//   * Go's `NewReader`/`NewReaderDict` return `io.ReadCloser`; goish
//     has no trait-object ReadCloser, so they return the concrete
//     `Reader<R>` which implements `io::Reader` + `io::Closer` (and
//     carries `Reset`, mirroring Go's `Resetter` interface). The
//     `flate` port does the same.
//   * Go's `zlib.reader` keeps a `flate.Reader` handle (`z.r`) and
//     reads the Adler-32 trailer from it after the decompressor hits
//     EOF. goish's `flate::Decompressor<R>` owns its source, so the
//     zlib `Reader<R>` parses the header from a `bufio::Reader<R>`,
//     hands that to `flate::NewReader`, and reads the trailer back
//     through the decompressor's `reader_mut()` accessor — which is
//     positioned exactly at the first trailing byte once `Read` has
//     returned `io.EOF`.
//   * Go's `NewWriter` returns `*Writer` (level always valid);
//     `NewWriterLevel`/`NewWriterLevelDict` return `(*Writer, error)`.
//     goish returns `(Writer<W>, error)` by value throughout (the
//     `flate` precedent) and provides `into_writer` so callers can
//     recover the underlying writer after `Close`.
//   * Go's `Writer` is generic over an `io.Writer` interface field;
//     goish's `Writer<W>` is generic over `W: io::Writer` and wraps a
//     `flate::Writer<W>`. The optional preset dictionary makes the
//     compressed writer `flate::Writer<flate::dictWriter<W>>`, so a
//     dictless `Writer<W>` and a dict `Writer<W>` differ in their
//     inner compressor type; the public `Writer<W>` carries the
//     branch in an enum (`inner`).

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;

// ─── one Rust file per Go file (GOISH015) ────────────────────────────
//
//   reader.rs    reader.go    - the zlib reader
//   writer.rs    writer.go    - the zlib writer

pub mod reader;
pub mod writer;

pub use reader::{
    ErrChecksum, ErrDictionary, ErrHeader, NewReader, NewReaderByte, NewReaderByteDict,
    NewReaderDict, Reader,
};
pub use writer::{
    BestCompression, BestSpeed, DefaultCompression, HuffmanOnly, NewWriter, NewWriterLevel,
    NewWriterLevelDict, NoCompression, Writer,
};
