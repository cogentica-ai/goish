// go: file compress/bzip2/bzip2.go decls: StructuralError, StructuralError.Error, reader, NewReader, bzip2FileMagic, bzip2BlockMagic, bzip2FinalMagic, reader.setup, reader.Read, reader.readFromBlock, reader.read, reader.readBlock, inverseBWT, crctab, updateCRC
//
// compress/bzip2/bzip2.go — the decompressor proper.
//
// There's no RFC for bzip2. Go's port used the Wikipedia page for
// reference and a lot of guessing: https://en.wikipedia.org/wiki/Bzip2
//
// A bzip2 stream is a sequence of blocks. Each block is decoded whole
// (Huffman → move-to-front → inverse Burrows-Wheeler), leaving the
// still-run-length-encoded bytes in `tt`; the final RLE1 stage is then
// unwound lazily by `readFromBlock` so a 900 KB block doesn't need a
// worst-case expansion buffer.
//
// Slim deviations:
//   * Go's `NewReader` returns `io.Reader`; goish returns the concrete
//     `reader<R>`, which implements `io::Reader`. Same choice `flate`,
//     `gzip` and `lzw` made — goish has no trait-object ReadCloser and
//     a concrete return keeps the source generic without boxing.
//   * `bz2.preRLE = bz2.tt[:bufIndex]` aliases one backing array in Go;
//     goish's subslice copies (goslice.rs:17), so `preRLE` becomes an
//     independent buffer. That is observationally identical here: `tt`
//     is pure scratch, rewritten from index 0 by the next `readBlock`,
//     and nothing reads it between the two. The cost is one copy of the
//     decoded block per block.
//   * Go builds `crctab` in a package `init()`. goish has no package
//     init, so the table is a `const fn` evaluated at compile time —
//     no lock, no lazy slot, no startup work. The one `as` cast in it
//     is unavoidable: goish's `uint32(x)` conversion is not `const fn`.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::bufio;
use crate::convert::{byte as tobyte, int as toint, uint as touint, uint32 as touint32};
use crate::errors::{self, error, nil, ErrorTrait};
use crate::goarray::array;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, uint, uint32};

use super::bit_reader::{bitReader, newBitReader};
use super::huffman::{huffmanTree, newHuffmanTree};
use super::move_to_front::{newMTFDecoder, newMTFDecoderWithRange};

// go: sdk 1.25.5 compress/bzip2/bzip2.go:15-17 StructuralError
/// `bzip2.StructuralError` — returned when the bzip2 data is found to
/// be syntactically invalid. Go declares it as `type StructuralError
/// string`; goish spells that as a newtype over `string`, matching
/// `flate::InternalError`.
#[derive(Clone, Debug, Default)]
pub struct StructuralError(pub string);

// go: sdk 1.25.5 compress/bzip2/bzip2.go:19-20 StructuralError.Error
impl ErrorTrait for StructuralError {
    /// `(s StructuralError).Error()` — `"bzip2 data invalid: " + s`.
    fn Error(&self) -> string {
        // Go: return "bzip2 data invalid: " + string(s)
        return string::from("bzip2 data invalid: ") + self.0.clone();
    }
}

// go: none — goish idiom: Go writes `StructuralError("…")` at every use
// site, which is a TYPE CONVERSION of an untyped string constant, not a
// call. goish cannot spell a conversion into a newtype, and every site
// additionally has to lift the concrete type into `error`, so the pair
// gets one name.
/// Lift a `StructuralError` into the `error` interface.
pub(super) fn structuralError<S: Into<string>>(s: S) -> error {
    return errors::Wrap(StructuralError(s.into()));
}

// go: sdk 1.25.5 compress/bzip2/bzip2.go:23-40 reader
/// `bzip2.reader` — decompresses bzip2 compressed data. Public here
/// only because `NewReader` returns it (Go returns the `io.Reader`
/// interface instead); the Go name is kept per AGENTS.md §5.
pub struct reader<R: io::Reader> {
    // Go: br bitReader
    pub(super) br: bitReader<bufio::Reader<R>>,
    // Go: fileCRC uint32
    fileCRC: uint32,
    // Go: blockCRC uint32
    blockCRC: uint32,
    // Go: wantBlockCRC uint32
    wantBlockCRC: uint32,
    // Go: setupDone bool — true if we have parsed the bzip2 header.
    setupDone: bool,
    // Go: eof bool
    eof: bool,
    // Go: blockSize int — blockSize in bytes, i.e. 900 * 1000.
    blockSize: int,
    // Go: c [256]uint — the ``C'' array for the inverse BWT.
    c: array<uint, 256>,
    // Go: tt []uint32 — mirrors the ``tt'' array in the bzip2 source and
    // contains the P array in the upper 24 bits.
    tt: slice<uint32>,
    // Go: tPos uint32 — Index of the next output byte in tt.
    tPos: uint32,

    // Go: preRLE []uint32 — contains the RLE data still to be processed.
    preRLE: slice<uint32>,
    // Go: preRLEUsed int — number of entries of preRLE used.
    preRLEUsed: int,
    // Go: lastByte int — the last byte value seen.
    lastByte: int,
    // Go: byteRepeats uint — the number of repeats of lastByte seen.
    byteRepeats: uint,
    // Go: repeats uint — the number of copies of lastByte to output.
    repeats: uint,
}

// go: sdk 1.25.5 compress/bzip2/bzip2.go:43-49 NewReader
/// `bzip2.NewReader(r)` — a reader which decompresses bzip2 data from
/// `r`. The source is wrapped for byte-at-a-time reads, so the
/// decompressor may read more data than necessary from `r`.
pub fn NewReader<R: io::Reader>(r: R) -> reader<R> {
    // Go: bz2 := new(reader); bz2.br = newBitReader(r); return bz2
    //
    // goish cannot zero a `reader<R>` before its bitReader exists (the
    // field owns `r`), so the zero value is spelled at construction.
    return reader {
        br: newBitReader(r),
        fileCRC: 0,
        blockCRC: 0,
        wantBlockCRC: 0,
        setupDone: false,
        eof: false,
        blockSize: 0,
        c: array::default(),
        tt: slice::new(),
        tPos: 0,
        preRLE: slice::new(),
        preRLEUsed: 0,
        lastByte: 0,
        byteRepeats: 0,
        repeats: 0,
    };
}

// go: sdk 1.25.5 compress/bzip2/bzip2.go:52-52 bzip2FileMagic
/// `bzip2FileMagic` — "BZ".
const bzip2FileMagic: int = 0x425a;
// go: sdk 1.25.5 compress/bzip2/bzip2.go:53-53 bzip2BlockMagic
/// `bzip2BlockMagic` — the 48-bit magic that opens every block.
const bzip2BlockMagic: u64 = 0x314159265359;
// go: sdk 1.25.5 compress/bzip2/bzip2.go:54-54 bzip2FinalMagic
/// `bzip2FinalMagic` — the 48-bit magic that closes a stream.
const bzip2FinalMagic: u64 = 0x177245385090;

impl<R: io::Reader> reader<R> {
    // go: sdk 1.25.5 compress/bzip2/bzip2.go:56-82 reader.setup
    /// `(bz2 *reader).setup(needMagic)` — parse the bzip2 header.
    fn setup(&mut self, needMagic: bool) -> error {
        // Go: br := &bz2.br — spelled inline below; a live `&mut` on the
        // field would collide with the `bz2.tt` write at the end.

        // Go: if needMagic { magic := br.ReadBits(16); … }
        if needMagic {
            let magic = self.br.ReadBits(16);
            if magic != bzip2FileMagic {
                return structuralError("bad magic value");
            }
        }

        // Go: t := br.ReadBits(8); if t != 'h' { … }
        let t = self.br.ReadBits(8);
        if t != toint(b'h') {
            return structuralError("non-Huffman entropy encoding");
        }

        // Go: level := br.ReadBits(8); if level < '1' || level > '9' { … }
        let level = self.br.ReadBits(8);
        if level < toint(b'1') || level > toint(b'9') {
            return structuralError("invalid compression level");
        }

        // Go: bz2.fileCRC = 0
        self.fileCRC = 0;
        // Go: bz2.blockSize = 100 * 1000 * (level - '0')
        self.blockSize = 100 * 1000 * (level - toint(b'0'));
        // Go: if bz2.blockSize > len(bz2.tt) { bz2.tt = make([]uint32, bz2.blockSize) }
        if self.blockSize > self.tt.Len() {
            self.tt = crate::make!([]uint32, self.blockSize);
        }
        return nil;
    }

    // go: sdk 1.25.5 compress/bzip2/bzip2.go:85-107 reader.Read
    /// `(bz2 *reader).Read(buf)` — `io.Reader`. The bit reader's latched
    /// error wins over the decode error, so a truncated stream reports
    /// `io.ErrUnexpectedEOF` rather than a structural complaint about
    /// the zeros a failed read handed back.
    pub fn Read(&mut self, buf: &mut slice<byte>) -> (int, error) {
        // Go: if bz2.eof { return 0, io.EOF }
        if self.eof {
            return (0, io::EOF.into());
        }

        // Go: if !bz2.setupDone { … }
        if !self.setupDone {
            let mut err = self.setup(true);
            let brErr = self.br.Err();
            if !brErr.IsNil() {
                err = brErr;
            }
            if !err.IsNil() {
                return (0, err);
            }
            self.setupDone = true;
        }

        // Go: n, err = bz2.read(buf)
        let (n, mut err) = self.read(buf);
        let brErr = self.br.Err();
        if !brErr.IsNil() {
            err = brErr;
        }
        return (n, err);
    }

    // go: sdk 1.25.5 compress/bzip2/bzip2.go:110-160 reader.readFromBlock
    /// `(bz2 *reader).readFromBlock(buf)` — unwind the RLE1 stage of the
    /// current block into `buf`, returning how many bytes were produced.
    fn readFromBlock(&mut self, buf: &mut slice<byte>) -> int {
        // bzip2 is a block based compressor, except that it has a run-length
        // preprocessing step. The block based nature means that we can
        // preallocate fixed-size buffers and reuse them. However, the RLE
        // preprocessing would require allocating huge buffers to store the
        // maximum expansion. Thus we process blocks all at once, except for
        // the RLE which we decompress as required.
        // Go: n := 0
        let mut n: int = 0;
        // Go: for (bz2.repeats > 0 || bz2.preRLEUsed < len(bz2.preRLE)) && n < len(buf)
        while (self.repeats > 0 || self.preRLEUsed < self.preRLE.Len()) && n < buf.Len() {
            // We have RLE data pending.

            // The run-length encoding works like this:
            // Any sequence of four equal bytes is followed by a length
            // byte which contains the number of repeats of that byte to
            // include. (The number of repeats can be zero.) Because we are
            // decompressing on-demand our state is kept in the reader
            // object.

            // Go: if bz2.repeats > 0 { … continue }
            if self.repeats > 0 {
                buf[n] = tobyte(self.lastByte);
                n += 1;
                self.repeats -= 1;
                if self.repeats == 0 {
                    self.lastByte = -1;
                }
                continue;
            }

            // Go: bz2.tPos = bz2.preRLE[bz2.tPos]; b := byte(bz2.tPos)
            self.tPos = self.preRLE[self.tPos];
            let b = tobyte(self.tPos);
            self.tPos >>= 8;
            self.preRLEUsed += 1;

            // Go: if bz2.byteRepeats == 3 { … continue }
            if self.byteRepeats == 3 {
                self.repeats = touint(b);
                self.byteRepeats = 0;
                continue;
            }

            // Go: if bz2.lastByte == int(b) { bz2.byteRepeats++ } else { bz2.byteRepeats = 0 }
            if self.lastByte == toint(b) {
                self.byteRepeats += 1;
            } else {
                self.byteRepeats = 0;
            }
            self.lastByte = toint(b);

            buf[n] = b;
            n += 1;
        }

        return n;
    }

    // go: sdk 1.25.5 compress/bzip2/bzip2.go:163-232 reader.read
    /// `(bz2 *reader).read(buf)` — drain the current block, then walk
    /// the block/final magics, verifying CRCs and honouring a
    /// concatenated second file.
    fn read(&mut self, buf: &mut slice<byte>) -> (int, error) {
        loop {
            // Go: n := bz2.readFromBlock(buf)
            let n = self.readFromBlock(buf);
            // Go: if n > 0 || len(buf) == 0 { … }
            if n > 0 || buf.Len() == 0 {
                // Go: bz2.blockCRC = updateCRC(bz2.blockCRC, buf[:n])
                self.blockCRC = updateCRC(self.blockCRC, &buf.slice(0, n));
                return (n, nil);
            }

            // End of block. Check CRC.
            // Go: if bz2.blockCRC != bz2.wantBlockCRC { … }
            if self.blockCRC != self.wantBlockCRC {
                self.br.err = structuralError("block checksum mismatch");
                return (0, self.br.err.clone());
            }

            // Find next block.
            // Go: br := &bz2.br; switch br.ReadBits64(48) { … }
            let magic = self.br.ReadBits64(48);
            if magic == bzip2BlockMagic {
                // Start of block.
                // Go: err := bz2.readBlock(); if err != nil { return 0, err }
                let err = self.readBlock();
                if !err.IsNil() {
                    return (0, err);
                }
            } else if magic == bzip2FinalMagic {
                // Check end-of-file CRC.
                // Go: wantFileCRC := uint32(br.ReadBits64(32))
                let wantFileCRC = touint32(self.br.ReadBits64(32));
                if !self.br.err.IsNil() {
                    return (0, self.br.err.clone());
                }
                // Go: if bz2.fileCRC != wantFileCRC { … }
                if self.fileCRC != wantFileCRC {
                    self.br.err = structuralError("file checksum mismatch");
                    return (0, self.br.err.clone());
                }

                // Skip ahead to byte boundary.
                // Is there a file concatenated to this one?
                // It would start with BZ.
                // Go: if br.bits%8 != 0 { br.ReadBits(br.bits % 8) }
                if self.br.bits % 8 != 0 {
                    let odd = self.br.bits % 8;
                    self.br.ReadBits(odd);
                }
                // Go: b, err := br.r.ReadByte()
                let (b, err) = self.br.r.ReadByte();
                if err == io::EOF {
                    self.br.err = io::EOF.into();
                    self.eof = true;
                    return (0, io::EOF.into());
                }
                if !err.IsNil() {
                    self.br.err = err.clone();
                    return (0, err);
                }
                // Go: z, err := br.r.ReadByte()
                let (z, err) = self.br.r.ReadByte();
                if !err.IsNil() {
                    // Go: if err == io.EOF { err = io.ErrUnexpectedEOF }
                    let err = if err == io::EOF {
                        io::ErrUnexpectedEOF.into()
                    } else {
                        err
                    };
                    self.br.err = err.clone();
                    return (0, err);
                }
                // Go: if b != 'B' || z != 'Z' { … }
                if b != b'B' || z != b'Z' {
                    return (0, structuralError("bad magic value in continuation file"));
                }
                // Go: if err := bz2.setup(false); err != nil { return 0, err }
                let err = self.setup(false);
                if !err.IsNil() {
                    return (0, err);
                }
            } else {
                // Go: default: return 0, StructuralError("bad magic value found")
                return (0, structuralError("bad magic value found"));
            }
        }
    }

    // go: sdk 1.25.5 compress/bzip2/bzip2.go:235-443 reader.readBlock
    /// `(bz2 *reader).readBlock()` — read one bzip2 block. The magic
    /// number should already have been consumed.
    fn readBlock(&mut self) -> error {
        // Go: br := &bz2.br — spelled inline; the block body writes
        // `bz2.tt` and `bz2.c` while reading bits, so a live borrow of
        // the field cannot span the function.

        // Go: bz2.wantBlockCRC = uint32(br.ReadBits64(32))
        // (skip checksum. TODO: check it if we can figure out what it is.)
        self.wantBlockCRC = touint32(self.br.ReadBits64(32));
        self.blockCRC = 0;
        // Go: bz2.fileCRC = (bz2.fileCRC<<1 | bz2.fileCRC>>31) ^ bz2.wantBlockCRC
        self.fileCRC = ((self.fileCRC << 1) | (self.fileCRC >> 31)) ^ self.wantBlockCRC;
        // Go: randomized := br.ReadBits(1)
        let randomized = self.br.ReadBits(1);
        if randomized != 0 {
            return structuralError("deprecated randomized files");
        }
        // Go: origPtr := uint(br.ReadBits(24))
        let origPtr = touint(self.br.ReadBits(24));

        // If not every byte value is used in the block (i.e., it's text) then
        // the symbol set is reduced. The symbols used are stored as a
        // two-level, 16x16 bitmap.
        // Go: symbolRangeUsedBitmap := br.ReadBits(16)
        let symbolRangeUsedBitmap = self.br.ReadBits(16);
        // Go: symbolPresent := make([]bool, 256); numSymbols := 0
        let mut symbolPresent = crate::make!([]bool, 256);
        let mut numSymbols: int = 0;
        // Go: for symRange := uint(0); symRange < 16; symRange++
        let mut symRange: uint = 0;
        while symRange < 16 {
            if symbolRangeUsedBitmap & (1 << (15 - symRange)) != 0 {
                // Go: bits := br.ReadBits(16)
                let bits = self.br.ReadBits(16);
                // Go: for symbol := uint(0); symbol < 16; symbol++
                let mut symbol: uint = 0;
                while symbol < 16 {
                    if bits & (1 << (15 - symbol)) != 0 {
                        symbolPresent[16 * symRange + symbol] = true;
                        numSymbols += 1;
                    }
                    symbol += 1;
                }
            }
            symRange += 1;
        }

        // Go: if numSymbols == 0 { return StructuralError("no symbols in input") }
        if numSymbols == 0 {
            // There must be an EOF symbol.
            return structuralError("no symbols in input");
        }

        // A block uses between two and six different Huffman trees.
        // Go: numHuffmanTrees := br.ReadBits(3)
        let numHuffmanTrees = self.br.ReadBits(3);
        if numHuffmanTrees < 2 || numHuffmanTrees > 6 {
            return structuralError("invalid number of Huffman trees");
        }

        // The Huffman tree can switch every 50 symbols so there's a list of
        // tree indexes telling us which tree to use for each 50 symbol block.
        // Go: numSelectors := br.ReadBits(15); treeIndexes := make([]uint8, numSelectors)
        let numSelectors = self.br.ReadBits(15);
        let mut treeIndexes = crate::make!([]byte, numSelectors);

        // The tree indexes are move-to-front transformed and stored as unary
        // numbers.
        // Go: mtfTreeDecoder := newMTFDecoderWithRange(numHuffmanTrees)
        let mut mtfTreeDecoder = newMTFDecoderWithRange(numHuffmanTrees);
        // Go: for i := range treeIndexes
        for i in 0..treeIndexes.Len() {
            // Go: c := 0; for { inc := br.ReadBits(1); if inc == 0 { break }; c++ }
            let mut c: int = 0;
            loop {
                let inc = self.br.ReadBits(1);
                if inc == 0 {
                    break;
                }
                c += 1;
            }
            if c >= numHuffmanTrees {
                return structuralError("tree index too large");
            }
            treeIndexes[i] = mtfTreeDecoder.Decode(c);
        }

        // The list of symbols for the move-to-front transform is taken from
        // the previously decoded symbol bitmap.
        // Go: symbols := make([]byte, numSymbols); nextSymbol := 0
        let mut symbols = crate::make!([]byte, numSymbols);
        let mut nextSymbol: int = 0;
        // Go: for i := 0; i < 256; i++
        let mut i: int = 0;
        while i < 256 {
            if symbolPresent[i] {
                symbols[nextSymbol] = tobyte(i);
                nextSymbol += 1;
            }
            i += 1;
        }
        // Go: mtf := newMTFDecoder(symbols)
        let mut mtf = newMTFDecoder(symbols);

        // Go: numSymbols += 2 // to account for RUNA and RUNB symbols
        numSymbols += 2;
        // Go: huffmanTrees := make([]huffmanTree, numHuffmanTrees)
        let mut huffmanTrees = crate::make!([]huffmanTree, numHuffmanTrees);

        // Now we decode the arrays of code-lengths for each tree.
        // Go: lengths := make([]uint8, numSymbols)
        let mut lengths = crate::make!([]byte, numSymbols);
        // Go: for i := range huffmanTrees
        for i in 0..huffmanTrees.Len() {
            // The code lengths are delta encoded from a 5-bit base value.
            // Go: length := br.ReadBits(5)
            let mut length = self.br.ReadBits(5);
            // Go: for j := range lengths
            for j in 0..lengths.Len() {
                loop {
                    if length < 1 || length > 20 {
                        return structuralError("Huffman length out of range");
                    }
                    if !self.br.ReadBit() {
                        break;
                    }
                    if self.br.ReadBit() {
                        length -= 1;
                    } else {
                        length += 1;
                    }
                }
                lengths[j] = tobyte(length);
            }
            // Go: huffmanTrees[i], err = newHuffmanTree(lengths)
            let (tree, err) = newHuffmanTree(&lengths);
            huffmanTrees[i] = tree;
            if !err.IsNil() {
                return err;
            }
        }

        // Go: selectorIndex := 1 // the next tree index to use
        let mut selectorIndex: int = 1;
        if treeIndexes.Len() == 0 {
            return structuralError("no tree selectors given");
        }
        if toint(treeIndexes[0]) >= huffmanTrees.Len() {
            return structuralError("tree selector out of range");
        }
        // Go: currentHuffmanTree := huffmanTrees[treeIndexes[0]]
        //
        // Go copies the tree struct (two words sharing one node table);
        // goish holds the INDEX instead, because `slice<T>` clones its
        // backing on assignment and this runs every 50 symbols.
        let mut currentHuffmanTree: int = toint(treeIndexes[0]);
        // Go: bufIndex := 0 // indexes bz2.buf, the output buffer.
        let mut bufIndex: int = 0;
        // The output of the move-to-front transform is run-length encoded and
        // we merge the decoding into the Huffman parsing loop. These two
        // variables accumulate the repeat count. See the Wikipedia page for
        // details.
        let mut repeat: int = 0;
        let mut repeatPower: int = 0;

        // The `C' array (used by the inverse BWT) needs to be zero initialized.
        // Go: clear(bz2.c[:])
        let mut k: int = 0;
        while k < 256 {
            self.c[k] = 0;
            k += 1;
        }

        // Go: decoded := 0 // counts the number of symbols decoded by the current tree.
        let mut decoded: int = 0;
        loop {
            // Go: if decoded == 50 { … }
            if decoded == 50 {
                if selectorIndex >= numSelectors {
                    return structuralError("insufficient selector indices for number of symbols");
                }
                if toint(treeIndexes[selectorIndex]) >= huffmanTrees.Len() {
                    return structuralError("tree selector out of range");
                }
                currentHuffmanTree = toint(treeIndexes[selectorIndex]);
                selectorIndex += 1;
                decoded = 0;
            }

            // Go: v := currentHuffmanTree.Decode(br); decoded++
            let v = huffmanTrees[currentHuffmanTree].Decode(&mut self.br);
            decoded += 1;

            // Go: if v < 2 { … continue }
            if v < 2 {
                // This is either the RUNA or RUNB symbol.
                if repeat == 0 {
                    repeatPower = 1;
                }
                repeat += repeatPower << v;
                repeatPower <<= 1;

                // This limit of 2 million comes from the bzip2 source
                // code. It prevents repeat from overflowing.
                if repeat > 2 * 1024 * 1024 {
                    return structuralError("repeat count too large");
                }
                continue;
            }

            // Go: if repeat > 0 { … }
            if repeat > 0 {
                // We have decoded a complete run-length so we need to
                // replicate the last output symbol.
                if repeat > self.blockSize - bufIndex {
                    return structuralError("repeats past end of block");
                }
                // Go: for i := 0; i < repeat; i++
                let mut i: int = 0;
                while i < repeat {
                    let b = mtf.First();
                    self.tt[bufIndex] = touint32(b);
                    self.c[b] += 1;
                    bufIndex += 1;
                    i += 1;
                }
                repeat = 0;
            }

            // Go: if int(v) == numSymbols-1 { break }
            if toint(v) == numSymbols - 1 {
                // This is the EOF symbol. Because it's always at the
                // end of the move-to-front list, and never gets moved
                // to the front, it has this unique value.
                break;
            }

            // Since two metasymbols (RUNA and RUNB) have values 0 and 1,
            // one would expect |v-2| to be passed to the MTF decoder.
            // However, the front of the MTF list is never referenced as 0,
            // it's always referenced with a run-length of 1. Thus 0
            // doesn't need to be encoded and we have |v-1| in the next
            // line.
            // Go: b := mtf.Decode(int(v - 1))
            let b = mtf.Decode(toint(v - 1));
            if bufIndex >= self.blockSize {
                return structuralError("data exceeds block size");
            }
            self.tt[bufIndex] = touint32(b);
            self.c[b] += 1;
            bufIndex += 1;
        }

        // Go: if origPtr >= uint(bufIndex) { … }
        if origPtr >= touint(bufIndex) {
            return structuralError("origPtr out of bounds");
        }

        // We have completed the entropy decoding. Now we can perform the
        // inverse BWT and setup the RLE buffer.
        // Go: bz2.preRLE = bz2.tt[:bufIndex]  — see the aliasing note in
        // the file header; goish's subslice copies.
        self.preRLE = self.tt.slice(0, bufIndex);
        self.preRLEUsed = 0;
        // Go: bz2.tPos = inverseBWT(bz2.preRLE, origPtr, bz2.c[:])
        self.tPos = inverseBWT(&mut self.preRLE, origPtr, &mut self.c);
        self.lastByte = -1;
        self.byteRepeats = 0;
        self.repeats = 0;

        return nil;
    }
}

// go: sdk 1.25.5 compress/bzip2/bzip2.go:446-469 inverseBWT
/// `bzip2.inverseBWT(tt, origPtr, c)` — the inverse Burrows-Wheeler
/// transform as described in
/// <http://www.hpl.hp.com/techreports/Compaq-DEC/SRC-RR-124.pdf>,
/// section 4.2. In that document, `origPtr` is called "I" and `c` is
/// the "C" array after the first pass over the data. It's an argument
/// here because we merge the first pass with the Huffman decoding.
///
/// This also implements the "single array" method from the bzip2 source
/// code which leaves the output, still shuffled, in the bottom 8 bits of
/// `tt` with the index of the next byte in the top 24 bits. The index of
/// the first byte is returned.
///
/// `c` is `&mut array<uint, 256>`, not `slice<uint>`: Go passes
/// `bz2.c[:]`, a mutable VIEW of the reader's array field, and goish's
/// `to_slice()` would hand over a copy whose updates never landed. The
/// borrow of the array is the goish spelling of that view.
fn inverseBWT(tt: &mut slice<uint32>, origPtr: uint, c: &mut array<uint, 256>) -> uint32 {
    // Go: sum := uint(0); for i := 0; i < 256; i++ { sum += c[i]; c[i] = sum - c[i] }
    let mut sum: uint = 0;
    let mut i: int = 0;
    while i < 256 {
        sum += c[i];
        c[i] = sum - c[i];
        i += 1;
    }

    // Go: for i := range tt { b := tt[i] & 0xff; tt[c[b]] |= uint32(i) << 8; c[b]++ }
    for i in 0..tt.Len() {
        let b = tt[i] & 0xff;
        let cb = c[b];
        tt[cb] |= touint32(i) << 8;
        c[b] += 1;
    }

    // Go: return tt[origPtr] >> 8
    return tt[origPtr] >> 8;
}

// This is a standard CRC32 like in hash/crc32 except that all the shifts are reversed,
// causing the bits in the input to be processed in the reverse of the usual order.

// go: sdk 1.25.5 compress/bzip2/bzip2.go:475-475 crctab
/// `bzip2.crctab` — the reversed-CRC32 table. Go fills it from a
/// package `init()`; goish evaluates it at compile time (see the file
/// header).
static crctab: array<uint32, 256> = array::__from_arr(crctabInit());

// go: none — goish idiom: this is Go's package `init()` (bzip2.go:477),
// which goish has no equivalent of. `port_coverage` excludes `init`
// from the denominator, and an anchor named `init` would be ambiguous
// across a package, so the table it fills carries the anchor instead.
/// Go's package `init()` for [`crctab`], as a `const fn` so the table
/// costs nothing at run time.
const fn crctabInit() -> [uint32; 256] {
    // Go: const poly = 0x04C11DB7
    const poly: uint32 = 0x04C11DB7;
    let mut tab = [0u32; 256];
    // Go: for i := range crctab
    let mut i: usize = 0;
    while i < 256 {
        // Go: crc := uint32(i) << 24
        // (`as` is unavoidable here: goish's `uint32()` is not `const fn`.)
        let mut crc: uint32 = (i as uint32) << 24;
        // Go: for j := 0; j < 8; j++
        let mut j = 0;
        while j < 8 {
            if crc & 0x80000000 != 0 {
                crc = (crc << 1) ^ poly;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        // Go: crctab[i] = crc
        tab[i] = crc;
        i += 1;
    }
    tab
}

// go: sdk 1.25.5 compress/bzip2/bzip2.go:492-499 updateCRC
/// `bzip2.updateCRC(val, b)` — fold `b` into the running CRC. The
/// initial value is 0.
fn updateCRC(val: uint32, b: &slice<byte>) -> uint32 {
    // Go: crc := ^val
    let mut crc: uint32 = !val;
    // Go: for _, v := range b { crc = crctab[byte(crc>>24)^v] ^ (crc << 8) }
    for (_, v) in crate::range!(b) {
        crc = crctab[tobyte(crc >> 24) ^ *v] ^ (crc << 8);
    }
    // Go: return ^crc
    return !crc;
}

// ─── trait impls ───────────────────────────────────────────────────────

impl<R: io::Reader> io::Reader for reader<R> {
    // go: none — goish idiom: Go's `reader` satisfies `io.Reader`
    // structurally, by having the method. goish needs the `impl` block
    // written out; the port itself is the inherent `Read` above.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return reader::Read(self, p);
    }
}
