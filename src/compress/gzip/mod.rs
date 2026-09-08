// go: package compress/gzip
//
// compress/gzip — gzip file format (RFC 1952).
//
// Line-by-line port of Go 1.25 `compress/gzip/`
// (`gunzip.go` + `gzip.go`). gzip is a thin framing around
// `compress/flate`: a variable-length header (magic `1f 8b`, method,
// flags, mtime, XFL, OS, optional FEXTRA / FNAME / FCOMMENT / FHCRC
// fields), the raw DEFLATE payload, and an 8-byte little-endian
// trailer of CRC-32/IEEE + ISIZE (uncompressed length mod 2^32).
//
// Slim deviations from Go:
//   * Go's `NewReader` returns `*Reader`; goish has no trait-object
//     ReadCloser, so it returns the concrete `Reader<R>` which
//     implements `io::Reader` + `io::Closer` and carries `Reset`. The
//     `flate`/`zlib` ports do the same.
//   * Go's `gzip.Reader` keeps a `flate.Reader` handle (`z.r`) separate
//     from the `decompressor`, reading the header and the 8-byte
//     trailer directly from it. goish's `flate::Decompressor<R>` owns
//     its buffered source, so the gzip `Reader<R>` wraps the source in
//     a `bufio::Reader<R>`, hands it to `flate::NewReader`, and reaches
//     the trailer (and, for multistream, the next member's header)
//     through `reader_mut()` / `into_reader()` — the decompressor stops
//     on a byte boundary, so the source is positioned exactly at the
//     first trailing byte once `Read` has returned `io.EOF`.
//   * Go's `Writer` embeds `Header` and is generic over an `io.Writer`
//     interface field; goish's `Writer<W>` is generic over `W` and
//     names the embedded header field `Header` literally (AGENTS.md
//     §5), so `w.Header.Name = ...` mirrors Go's `w.Name = ...`.
//   * `into_writer` lets callers recover `W` after `Close`, matching
//     the `flate`/`zlib` ports.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;

// ─── one Rust file per Go file (GOISH015) ────────────────────────────
//
//   gunzip.rs    gunzip.go    - the gzip reader
//   gzip.rs      gzip.go      - the gzip writer

pub mod gunzip;
pub mod gzip;

pub use gunzip::{ErrChecksum, ErrHeader, Header, NewReader, Reader};
pub use gzip::{
    BestCompression, BestSpeed, DefaultCompression, HuffmanOnly, NewWriter, NewWriterLevel,
    NoCompression, Writer,
};
