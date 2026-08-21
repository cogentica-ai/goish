// go: file compress/bzip2/bit_reader.go decls: bitReader, newBitReader, bitReader.ReadBits64, bitReader.ReadBits, bitReader.ReadBit, bitReader.Err
//
// compress/bzip2/bit_reader.go — MSB-first bit reader over an
// `io.ByteReader`. bzip2 packs everything (magics, the 24-bit origPtr,
// the Huffman code lengths, the symbol stream) at bit granularity with
// no byte alignment between fields, so every other file in the package
// reads through this type.
//
// The Read* methods deliberately do NOT return an error — Go's comment
// says the error handling was too verbose — so a failed read yields 0
// and latches `br.err`, which callers check once via `Err()`.
//
// Slim deviation:
//   * Go's `newBitReader(r io.Reader)` does `r.(io.ByteReader)` and
//     only wraps in a `bufio.Reader` when the assertion misses. goish
//     has no runtime type assertion on a concrete generic (AGENTS.md
//     §9b), so it wraps unconditionally — the same choice `flate` and
//     `lzw` made. Behaviour is identical; an already-buffered source
//     just pays one extra layer of buffering. Go's `NewReader` doc
//     already warns that a non-ByteReader source "may read more data
//     than necessary", which is the only observable difference.

#![allow(non_snake_case, non_camel_case_types)]

use crate::bufio;
use crate::convert::{int as toint, uint64 as touint64};
use crate::errors::{error, nil};
use crate::io::{self, ByteReader};
use crate::types::{int, uint, uint64};

// go: sdk 1.25.5 compress/bzip2/bit_reader.go:12-20 bitReader
/// `bzip2.bitReader` — wraps an `io.ByteReader` and reads values
/// bit-by-bit from it. `n` holds the bits read so far but not yet
/// consumed, right-aligned; `bits` counts how many of them are valid.
pub struct bitReader<R: ByteReader> {
    // Go: r io.ByteReader
    pub(super) r: R,
    // Go: n uint64
    pub(super) n: uint64,
    // Go: bits uint
    pub(super) bits: uint,
    // Go: err error
    pub(super) err: error,
}

// go: sdk 1.25.5 compress/bzip2/bit_reader.go:23-30 newBitReader
/// `bzip2.newBitReader(r)` — a new bitReader reading from `r`. The
/// source is wrapped in a `bufio.Reader` to obtain `ReadByte` (see the
/// slim deviation in the file header).
pub fn newBitReader<R: io::Reader>(r: R) -> bitReader<bufio::Reader<R>> {
    // Go: byter, ok := r.(io.ByteReader); if !ok { byter = bufio.NewReader(r) }
    // Go: return bitReader{r: byter}
    return bitReader {
        r: bufio::NewReader(r),
        n: 0,
        bits: 0,
        err: nil,
    };
}

impl<R: ByteReader> bitReader<R> {
    // go: sdk 1.25.5 compress/bzip2/bit_reader.go:33-67 bitReader.ReadBits64
    /// `(br *bitReader).ReadBits64(bits)` — read `bits` bits and return
    /// them in the least-significant part of a `uint64`. On error it
    /// returns 0 and latches the error for [`bitReader::Err`].
    pub fn ReadBits64(&mut self, bits: uint) -> uint64 {
        // Go: for bits > br.bits
        while bits > self.bits {
            // Go: b, err := br.r.ReadByte()
            let (b, mut err) = self.r.ReadByte();
            // Go: if err == io.EOF { err = io.ErrUnexpectedEOF }
            if err == io::EOF {
                err = io::ErrUnexpectedEOF.into();
            }
            // Go: if err != nil { br.err = err; return 0 }
            if !err.IsNil() {
                self.err = err;
                return 0;
            }
            // Go: br.n <<= 8; br.n |= uint64(b); br.bits += 8
            self.n <<= 8;
            self.n |= touint64(b);
            self.bits += 8;
        }

        // br.n looks like this (assuming that br.bits = 14 and bits = 6):
        // Bit: 111111
        //      5432109876543210
        //
        //         (6 bits, the desired output)
        //        |-----|
        //        V     V
        //      0101101101001110
        //        ^            ^
        //        |------------|
        //           br.bits (num valid bits)
        //
        // The next line right shifts the desired bits into the
        // least-significant places and masks off anything above.
        //
        // Go: n = (br.n >> (br.bits - bits)) & ((1 << bits) - 1)
        //
        // Go's shift count is not masked and not a panic: `1 << 64` on
        // a uint64 is 0, so the mask becomes all-ones. Rust panics on a
        // shift that wide, so the saturating arm is spelled out. Every
        // in-tree caller passes bits <= 48, so the arm is defensive
        // only — it exists so a future caller cannot turn a Go
        // no-op into an abort.
        let mask: uint64 = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let n = (self.n >> (self.bits - bits)) & mask;
        // Go: br.bits -= bits
        self.bits -= bits;
        return n;
    }

    // go: sdk 1.25.5 compress/bzip2/bit_reader.go:70-72 bitReader.ReadBits
    /// `(br *bitReader).ReadBits(bits)` — [`ReadBits64`] narrowed to
    /// `int`. Every field bzip2 reads this way is at most 32 bits wide.
    ///
    /// [`ReadBits64`]: bitReader::ReadBits64
    pub fn ReadBits(&mut self, bits: uint) -> int {
        // Go: n64 := br.ReadBits64(bits); return int(n64)
        let n64 = self.ReadBits64(bits);
        return toint(n64);
    }

    // go: sdk 1.25.5 compress/bzip2/bit_reader.go:75-77 bitReader.ReadBit
    /// `(br *bitReader).ReadBit()` — one bit as a bool.
    pub fn ReadBit(&mut self) -> bool {
        // Go: n := br.ReadBits(1); return n != 0
        let n = self.ReadBits(1);
        return n != 0;
    }

    // go: sdk 1.25.5 compress/bzip2/bit_reader.go:80-81 bitReader.Err
    /// `(br *bitReader).Err()` — the latched error, nil if none.
    pub fn Err(&self) -> error {
        // Go: return br.err
        return self.err.clone();
    }
}
