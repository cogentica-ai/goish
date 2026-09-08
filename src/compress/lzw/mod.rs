// go: package compress/lzw
//
// compress/lzw — Lempel-Ziv-Welch (GIF/PDF flavor).
//
// Line-by-line port of Go 1.25 `compress/lzw/reader.go`.
// LZW with variable-width codes up to 12 bits; the first 1<<litWidth
// codes are literals, then a `clear` and `eof` code, then learned
// dictionary entries up to 4096 codes total.
//
// Slim deviations:
//   * Go's `*Reader` chooses readLSB / readMSB via a function-pointer
//     field (`r.read`). Goish dispatches via the `order` enum match
//     inside `read_code()` — functionally identical.
//   * Go embeds `suffix [4096]uint8`, `prefix [4096]uint16`, and
//     `output [8192]uint8` directly in the struct (~20 KiB stack
//     footprint). Goish boxes those tables (`Box<[T; N]>`) so the
//     Reader fits inside default-sized goroutine stacks (2 KiB) without
//     opt-up. The user-visible `Reader` type is otherwise byte-identical
//     to Go's.
//   * Go does `src.(io.ByteReader)` then falls back to bufio.NewReader.
//     Goish unconditionally wraps in `bufio::Reader` (the ByteReader
//     impl was added for that purpose). The cost is one extra buffer
//     on an already-buffered source; the bytes read are the same,
//     which lzw_smoke's Go-stream checks pin down.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

// Go: const ( LSB Order = iota; MSB )
//
// `Order` specifies the bit ordering in an LZW data stream.
// Go's `Order` is a typed `int`. We mirror as a tiny tuple struct that
// supports `==` against itself and the two constants.

/// `lzw.Order` — LSB or MSB ordering. (reader.go:29)
// ─── one Rust file per Go file (GOISH015) ────────────────────────────
//
//   reader.rs    reader.go    - the LZW decompressor
//   writer.rs    writer.go    - the LZW compressor
pub mod reader;
pub mod writer;

pub use reader::{NewReader, Order, Reader, LSB, MSB};
pub use writer::{NewWriter, Writer};
