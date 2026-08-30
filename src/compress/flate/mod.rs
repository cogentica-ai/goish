// go: package compress/flate
//
// compress/flate — the DEFLATE compressed data format (RFC 1951).
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015). All seven of Go's files are now split out:
//
//   inflate.rs             inflate.go             — the decompressor
//   dict_decoder.rs        dict_decoder.go        — the LZ77 window
//   token.rs               token.go               — the packed symbol
//   huffman_code.rs        huffman_code.go        — the code generator
//   huffman_bit_writer.rs  huffman_bit_writer.go  — the block writer
//   deflate.rs             deflate.go             — the compressor
//   deflatefast.rs         deflatefast.go         — the BestSpeed matcher
//
// What is left here is module wiring plus one goish-only piece: a
// round-trip shim that lets an example drive the encoder, since
// `huffmanBitWriter` and `token` are module-internal and an example
// crate cannot reach them.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::convert::{int as toint, uint32 as touint32};
use crate::goslice::slice;
use crate::types::{byte, int};

// ─── inflate.go lives in its own file ────────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. inflate.go's half has moved to `inflate.rs`.

pub mod inflate;

pub(crate) use inflate::new_decompressor_buffered;
pub use inflate::{
    CorruptInputError, Decompressor, InternalError, NewReader, NewReaderByte, NewReaderByteDict,
    NewReaderDict,
};

// ─── dict_decoder.go lives in its own file ───────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. dict_decoder.go's half has moved to
// `dict_decoder.rs` and is anchored; the other six Go files of this
// package are still here and still unanchored.

mod dict_decoder;

// ─── token.go lives in its own file ──────────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. token.go's half has moved to `token.rs`.

#[path = "token.rs"]
mod token_go;

use token_go::{literalToken, matchToken, token};

// ─── huffman_code.go lives in its own file ───────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. huffman_code.go's half has moved to
// `huffman_code.rs` and is anchored. `huffOffset` below stays here: it
// is huffman_bit_writer.go:600, not huffman_code.go.

mod huffman_code;

// ─── huffman_bit_writer.go lives in its own file ─────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. huffman_bit_writer.go's half has moved to
// `huffman_bit_writer.rs`.

mod huffman_bit_writer;

use huffman_bit_writer::newHuffmanBitWriter;

// ─── round-trip test shim ──────────────────────────────────────────────
//
// `huffmanBitWriter`, `token` etc. are module-internal (`pub(crate)`),
// so an example crate cannot drive them directly. This `#[doc(hidden)]`
// shim builds DEFLATE streams with the encoder above and decodes them
// back through the already-ported `NewReader` decompressor, returning a
// per-case status word so an example can assert the encoder is faithful.

// go: none — goish idiom: `huffmanBitWriter` and `token` are
//     module-internal, so an example crate cannot drive the encoder
//     directly. This shim does it and reports a per-case status word.
/// Drive the Huffman bit writer over three block kinds and inflate the
/// result back. Returns `(cases_passed, cases_total)`.
///
/// `#[doc(hidden)]` — for the `flate_huffman_smoke` example only; not a
/// stable API.
#[doc(hidden)]
pub fn __huffman_writer_roundtrip() -> (int, int) {
    use crate::bytes;

    let mut passed: int = 0;
    let total: int = 3;

    // go: none — goish idiom: the shim's own inflate helper.
    fn inflate(compressed: slice<byte>) -> Vec<byte> {
        let src = bytes::NewBuffer(compressed);
        let mut r = NewReader(src);
        let mut out: Vec<byte> = Vec::new();
        let mut buf: slice<byte> = {
            let mut v: Vec<byte> = Vec::with_capacity(512);
            v.resize(512, 0u8);
            slice::__from_vec(v)
        };
        loop {
            let (n, e) = r.Read(&mut buf);
            let mut k: int = 0;
            while k < n {
                out.push(buf[k]);
                k += 1;
            }
            if !e.IsNil() {
                break;
            }
        }
        return out;
    }

    // Case 1 — stored block (writeStoredHeader + writeBytes).
    {
        let payload: &[byte] = b"the quick brown fox stored verbatim";
        let mut w = newHuffmanBitWriter(bytes::NewBuffer(slice::new()));
        w.writeStoredHeader(toint(payload.len()), true);
        w.writeBytes(payload);
        w.flush();
        if w.err.IsNil() {
            let compressed = w.writer.Bytes();
            let got = inflate(compressed);
            if got.as_slice() == payload {
                passed += 1;
            }
        }
    }

    // Case 2 — literal-only Huffman block via writeBlock (input=None
    // forces Huffman; fixed or dynamic chosen by size).
    {
        let payload: &[byte] = b"aaaaaabbbbbbccccccddddddeeeeeeffffffhuffman literals";
        let mut toks: Vec<token> = Vec::with_capacity(payload.len());
        for &c in payload.iter() {
            toks.push(literalToken(touint32(c)));
        }
        let mut w = newHuffmanBitWriter(bytes::NewBuffer(slice::new()));
        w.writeBlock(&toks, true, None);
        w.flush();
        if w.err.IsNil() {
            let compressed = w.writer.Bytes();
            let got = inflate(compressed);
            if got.as_slice() == payload {
                passed += 1;
            }
        }
    }

    // Case 3 — a block with a back-reference match token via writeBlock.
    // Emit "abcabcabc": 6 literals then a match (length 3, offset 3).
    // matchToken xlength = length-3, xoffset = offset-1.
    {
        let expected: &[byte] = b"abcabc";
        let mut toks: Vec<token> = Vec::new();
        toks.push(literalToken(touint32(b'a')));
        toks.push(literalToken(touint32(b'b')));
        toks.push(literalToken(touint32(b'c')));
        // copy 3 bytes from 3 back -> "abc" again.
        toks.push(matchToken(0, 2));
        let mut w = newHuffmanBitWriter(bytes::NewBuffer(slice::new()));
        w.writeBlock(&toks, true, None);
        w.flush();
        if w.err.IsNil() {
            let compressed = w.writer.Bytes();
            let got = inflate(compressed);
            if got.as_slice() == expected {
                passed += 1;
            }
        }
    }

    return (passed, total);
}

// ═══════════════════════════════════════════════════════════════════════
// LZ77 compressor + Writer — port of Go 1.25 `deflate.go` + `deflatefast.go`.
//
// Both files are `package flate`; the types here (`compressor`,
// `deflateFast`, `dictWriter`) are Go-unexported and stay `pub(crate)` /
// private. The public surface is `Writer`, `NewWriter`, `NewWriterDict`,
// and the level constants.
//
// Slim deviations from Go:
//   * Go's `compressor.fill` (`func(*compressor,[]byte) int`) and
//     `compressor.step` (`func(*compressor)`) are function-pointer
//     fields. AGENTS.md §5 forbids fn-pointer struct fields, so goish
//     models each with an enum (`Fill`, `CStep`) dispatched by a method
//     — the same shape the decompressor's `Step` enum uses.
//   * Go's `compressor.bulkHasher` is also a `func` field; it always
//     holds `bulkHash4`, so goish drops the field and calls `bulkHash4`
//     directly.
//   * Go's `Writer` holds a `compressor` whose `huffmanBitWriter.writer`
//     is an `io.Writer` interface; `NewWriterDict` wraps the destination
//     in a `*dictWriter`. goish has no trait-object writer, so `Writer`
//     and `compressor` are generic over `W: io::Writer`. `NewWriter`
//     returns `Writer<W>`; `NewWriterDict` returns `Writer<dictWriter<W>>`.
//   * Go's `Writer.Reset` does a `dictWriter` type assertion to decide
//     whether to re-`fillWindow`. goish carries the `dict` bytes on the
//     `Writer` and re-fills the window iff `dict` is non-empty.
//   * Go's `NewWriter` returns `(*Writer, error)`; goish returns
//     `(Writer<W>, error)` by value.
// ═══════════════════════════════════════════════════════════════════════

// ─── deflate.go lives in its own file ────────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. deflate.go's half has moved to `deflate.rs`, and
// with it the last of this package's Go files: mod.rs is now only
// module wiring and the round-trip test shim.

mod deflate;

pub use deflate::{
    dictWriter, BestCompression, BestSpeed, DefaultCompression, HuffmanOnly, NewWriter,
    NewWriterDict, NoCompression, Writer,
};

// ─── deflatefast.go lives in its own file ────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. deflatefast.go's half has moved to
// `deflatefast.rs`.

mod deflatefast;
