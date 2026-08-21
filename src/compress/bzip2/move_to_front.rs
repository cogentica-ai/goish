// go: file compress/bzip2/move_to_front.go decls: moveToFrontDecoder, newMTFDecoder, newMTFDecoderWithRange, moveToFrontDecoder.Decode, moveToFrontDecoder.First
//
// compress/bzip2/move_to_front.go — the move-to-front list.
//
// bzip2 runs MTF twice per block: once over the symbol alphabet (so a
// repeated byte encodes as a run of zeros, which the RLE2 stage then
// collapses), and once over the Huffman tree selectors.
//
// Slim deviation:
//   * Go's `moveToFrontDecoder` is `[]byte`, so its methods take a
//     VALUE receiver and still mutate the caller's list — the slice
//     header is copied, the backing array is shared. goish's
//     `slice<byte>` copies on subslice (goslice.rs:17), so the
//     mutation has to be spelled as `&mut self`. The type stays a
//     newtype over `slice<byte>` to keep Go's shape.

#![allow(non_snake_case, non_camel_case_types)]

use crate::convert::byte as tobyte;
use crate::goslice::slice;
use crate::types::{byte, int};

// go: sdk 1.25.5 compress/bzip2/move_to_front.go:7-14 moveToFrontDecoder
/// `bzip2.moveToFrontDecoder` — a move-to-front list. Symbols are
/// referenced by their index into the list, and a referenced symbol
/// moves to the front, so a repeated symbol encodes as a run of zeros.
pub struct moveToFrontDecoder(pub(super) slice<byte>);

// go: sdk 1.25.5 compress/bzip2/move_to_front.go:16-22 newMTFDecoder
/// `bzip2.newMTFDecoder(symbols)` — a decoder with an explicit initial
/// list of symbols. Panics above 256 symbols, as Go does.
pub fn newMTFDecoder(symbols: slice<byte>) -> moveToFrontDecoder {
    // Go: if len(symbols) > 256 { panic("too many symbols") }
    if symbols.Len() > 256 {
        panic!("too many symbols");
    }
    // Go: return moveToFrontDecoder(symbols)
    return moveToFrontDecoder(symbols);
}

// go: sdk 1.25.5 compress/bzip2/move_to_front.go:25-36 newMTFDecoderWithRange
/// `bzip2.newMTFDecoderWithRange(n)` — a decoder whose initial list is
/// `0...n-1`. Used for the Huffman tree selectors.
pub fn newMTFDecoderWithRange(n: int) -> moveToFrontDecoder {
    // Go: if n > 256 { panic("newMTFDecoderWithRange: cannot have > 256 symbols") }
    if n > 256 {
        panic!("newMTFDecoderWithRange: cannot have > 256 symbols");
    }

    // Go: m := make([]byte, n); for i := 0; i < n; i++ { m[i] = byte(i) }
    let mut m = crate::make!([]byte, n);
    let mut i: int = 0;
    while i < n {
        m[i] = tobyte(i);
        i += 1;
    }
    // Go: return moveToFrontDecoder(m)
    return moveToFrontDecoder(m);
}

impl moveToFrontDecoder {
    // go: sdk 1.25.5 compress/bzip2/move_to_front.go:39-47 moveToFrontDecoder.Decode
    /// `(m moveToFrontDecoder).Decode(n)` — the symbol at index `n`,
    /// moved to the front of the list.
    pub fn Decode(&mut self, n: int) -> byte {
        // Implement move-to-front with a simple copy. This approach
        // beats more sophisticated approaches in benchmarking, probably
        // because it has high locality of reference inside of a
        // single cache line (most move-to-front operations have n < 64).
        //
        // Go: b = m[n]; copy(m[1:], m[:n]); m[0] = b
        //
        // Go's `copy` there is a memmove within ONE backing array;
        // `copy!(dst, src)` cannot express that (both handles would
        // have to borrow `self.0`), and goish's `slice()` copies, so
        // the shift is written out. Same element moves, same order.
        let b = self.0[n];
        let mut i = n;
        while i > 0 {
            self.0[i] = self.0[i - 1];
            i -= 1;
        }
        self.0[0] = b;
        return b;
    }

    // go: sdk 1.25.5 compress/bzip2/move_to_front.go:50-52 moveToFrontDecoder.First
    /// `(m moveToFrontDecoder).First()` — the symbol at the front of
    /// the list, without moving anything. The RLE2 stage replays it.
    pub fn First(&self) -> byte {
        // Go: return m[0]
        return self.0[0];
    }
}
