// bzip2_smoke — compress/bzip2 against Go's own test vectors.
//
// Every vector here is lifted from Go 1.25.5's
// /share/go/src/compress/bzip2/bzip2_test.go, and every expected value
// was re-confirmed by running that package on a live Go 1.26.5
// toolchain (AGENTS.md §10) rather than transcribed from the test's
// comments — including the three error STRINGS, which are the sharpest
// discriminator this port has.
//
// The vectors that need `testdata/` files are left out of this file —
// goish examples are self-contained — but they were run out of band
// against the Go tree before this landed, and all seven matched Go
// byte-for-byte (length + FNV-1a/64 of the output):
//
//   e.txt.bz2                     100003 B    pass-random1.bz2   1024 B
//   Isaac.Newton-Opticks.txt.bz2  567198 B    pass-random2.bz2     65 B
//   random.data.bz2                16384 B    pass-sawtooth.bz2  1 MiB
//   fail-issue5747.bz2 (RLE2 buffer overrun) rejected with Go's message
//
// Those cover what the hex vectors below cannot: 567 KB of English text
// is many blocks with the Huffman tree switching every 50 symbols
// across several selectors, and random.data is the full 256-symbol
// alphabet.
//
// What each assertion discriminates:
//
//   * "hello world" is the whole pipeline once — header, one block,
//     Huffman → MTF → inverse BWT → RLE1, block CRC, final CRC;
//   * "concatenated files" is the ONLY test of the continuation path:
//     after the final magic the reader must byte-align, read "BZ", and
//     re-run setup() without the file magic. A reader that stops at the
//     first stream passes everything else in this file;
//   * "32B zeros" and "1MiB zeros" are the RLE1/RUNA/RUNB run
//     machinery. 1MiB also forces a full 900k block and the
//     `repeat > blockSize-bufIndex` bound;
//   * "RLE1 stage" is Go's own random vector chosen to hit the
//     four-equal-bytes-plus-count encoding, which readFromBlock
//     unwinds lazily across Read calls;
//   * the three failure vectors each name a DIFFERENT rejection, and
//     the message is checked, not just the fact of an error: an
//     out-of-range selector must surface the bit reader's latched
//     io.ErrUnexpectedEOF (not a structural complaint about the zeros
//     a failed read handed back), a bad block size must be caught by
//     the repeat bound, and a bad Huffman delta by the 1..20 length
//     range. Collapsing any two of those into one error would still
//     "fail correctly" and be wrong;
//   * truncation mid-stream must be io.ErrUnexpectedEOF, never io.EOF
//     and never a hang;
//   * Read(nil) returns (0, nil) — Go's TestZeroRead. A reader that
//     decodes eagerly before checking len(buf) returns 0, io.EOF here;
//   * the bitReader and MTF vectors are Go's TestBitReader / TestMTF,
//     unit-testing the two pieces the block decoder is built on.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::bytes;
use goish::compress::bzip2;
use goish::compress::bzip2::bit_reader::newBitReader;
use goish::compress::bzip2::move_to_front::newMTFDecoderWithRange;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::string;
use goish::types::{byte, int, uint};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: string) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

/// Go's `mustDecodeHex` — panics on a malformed literal, as Go's does.
fn mustDecodeHex(s: &str) -> slice<byte> {
    let (b, err) = hex::DecodeString(s);
    if !err.IsNil() {
        panic!("bad hex vector in bzip2_smoke");
    }
    return b;
}

fn from_bytes(b: &[byte]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    v.extend_from_slice(b);
    return slice::__from_vec(v);
}

/// Decompress `input`, returning the bytes and the terminal error.
fn decompress(input: slice<byte>) -> (slice<byte>, goish::error) {
    let mut r = bzip2::NewReader(bytes::NewReader(input));
    return io::ReadAll(&mut r);
}

fn equal(got: &slice<byte>, want: &slice<byte>) -> bool {
    if got.Len() != want.Len() {
        return false;
    }
    for (i, v) in goish::range!(got) {
        if *v != want[i] {
            return false;
        }
    }
    return true;
}

/// A decode that must succeed and match `want` exactly.
fn wantBytes(name: &'static str, inputHex: &str, want: slice<byte>) {
    let (got, err) = decompress(mustDecodeHex(inputHex));
    if !err.IsNil() {
        check(name, false, fmt::Sprintf!("unexpected error: %v", err));
        return;
    }
    check(
        name,
        equal(&got, &want),
        fmt::Sprintf!("got %d bytes, want %d", got.Len(), want.Len()),
    );
}

/// A decode that must fail with exactly `wantErr` as its message.
fn wantError(name: &'static str, inputHex: &str, wantErr: &'static str) {
    let (_, err) = decompress(mustDecodeHex(inputHex));
    if err.IsNil() {
        check(name, false, string::from("unexpected success"));
        return;
    }
    let got = err.Error();
    let gv: &str = got.as_ref();
    check(name, gv == wantErr, fmt::Sprintf!("err = %q", got));
}

// ─── the vectors ───────────────────────────────────────────────────────

const helloWorld: &str = concat!(
    "425a68393141592653594eece83600000251800010400006449080200031064c",
    "4101a7a9a580bb9431f8bb9229c28482776741b0",
);

const concatenated: &str = concat!(
    "425a68393141592653594eece83600000251800010400006449080200031064c",
    "4101a7a9a580bb9431f8bb9229c28482776741b0425a68393141592653594eec",
    "e83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb92",
    "29c28482776741b0",
);

const zeros32: &str = concat!(
    "425a6839314159265359b5aa5098000000600040000004200021008283177245",
    "385090b5aa5098",
);

const zeros1MiB: &str = concat!(
    "425a683931415926535938571ce50008084000c0040008200030cc0529a60806",
    "c4201e2ee48a70a12070ae39ca",
);

const rle1Stage: &str = concat!(
    "425a6839314159265359d992d0f60000137dfe84020310091c1e280e100e0428",
    "01099210094806c0110002e70806402000546034000034000000f28300000320",
    "00d3403264049270eb7a9280d308ca06ad28f6981bee1bf8160727c7364510d7",
    "3a1e123083421b63f031f63993a0f40051fbf177245385090d992d0f60",
);

const rle1Output: &str = concat!(
    "92d5652616ac444a4a04af1a8a3964aca0450d43d6cf233bd03233f4ba92f871",
    "9e6c2a2bd4f5f88db07ecd0da3a33b263483db9b2c158786ad6363be35d17335",
    "ba",
);

/// Go issue 8363.
const outOfRangeSelector: &str = concat!(
    "425a68393141592653594eece83600000251800010400006449080200031064c",
    "4101a7a9a580bb943117724538509000000000",
);

/// Go issue 13941.
const badBlockSize: &str = concat!(
    "425a683131415926535936dc55330063ffc0006000200020a40830008b0008b8",
    "bb9229c28481b6e2a998",
);

const badHuffmanDelta: &str = concat!(
    "425a6836314159265359b1f7404b000000400040002000217d184682ee48a70a",
    "12163ee80960",
);

/// `helloWorld` cut off inside the first block.
const truncated: &str = "425a68393141592653594eece836000002518000104000064490";

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    goish::runtime::sched::schedule();
}

fn run() {
    // 1. the whole pipeline, once.
    wantBytes(
        "hello world",
        helloWorld,
        goish::convert::bytes("hello world\n"),
    );

    // 2. a second stream concatenated onto the first.
    wantBytes(
        "concatenated files",
        concatenated,
        goish::convert::bytes("hello world\nhello world\n"),
    );

    // 3-4. the RLE / RUNA / RUNB run machinery, small and full-block.
    wantBytes("32B zeros", zeros32, goish::make!([]byte, 32));
    wantBytes("1MiB zeros", zeros1MiB, goish::make!([]byte, 1 << 20));

    // 5. Go's random vector that exercises the RLE1 stage.
    wantBytes("random data — RLE1 stage", rle1Stage, mustDecodeHex(rle1Output));

    // 6-8. three distinct rejections, checked by message.
    wantError(
        "out-of-range selector (issue 8363)",
        outOfRangeSelector,
        "unexpected EOF",
    );
    wantError(
        "bad block size (issue 13941)",
        badBlockSize,
        "bzip2 data invalid: repeats past end of block",
    );
    wantError(
        "bad huffman delta",
        badHuffmanDelta,
        "bzip2 data invalid: Huffman length out of range",
    );

    // 9. truncation is ErrUnexpectedEOF, not EOF and not a hang.
    wantError("truncated stream", truncated, "unexpected EOF");

    // 10. Go's TestZeroRead: Read(nil) is (0, nil), not (0, io.EOF).
    test_zero_read();

    // 11-12. the two building blocks, on Go's unit vectors.
    test_bit_reader();
    test_mtf();

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("BZIP2_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("BZIP2_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}

/// Go's `TestZeroRead`.
fn test_zero_read() {
    let mut r = bzip2::NewReader(bytes::NewReader(mustDecodeHex(zeros32)));
    let mut empty = slice::<byte>::new();
    let (n, err) = r.Read(&mut empty);
    check(
        "Read(nil) = (0, nil)",
        n == 0 && err.IsNil(),
        fmt::Sprintf!("n = %d", n),
    );
}

/// Go's `TestBitReader` — nine reads over a fixed 8-byte source, the
/// last of which must run off the end and latch an error.
fn test_bit_reader() {
    // Go: rd := bytes.NewReader([]byte{0xab, 0x12, 0x34, 0x56, 0x78, 0x71, 0x3f, 0x8d})
    let src = from_bytes(&[0xab, 0x12, 0x34, 0x56, 0x78, 0x71, 0x3f, 0x8d]);
    let mut br = newBitReader(bytes::NewReader(src));

    // (nbits, value, fail)
    let vectors: [(uint, int, bool); 9] = [
        (1, 1, false),
        (1, 0, false),
        (1, 1, false),
        (5, 11, false),
        (32, 0x12345678, false),
        (15, 14495, false),
        (3, 6, false),
        (6, 13, false),
        (1, 0, true),
    ];

    let mut ok = true;
    let mut detail = string::from("");
    for i in 0..vectors.len() {
        let (nbits, want, wantFail) = vectors[i];
        let got = br.ReadBits(nbits);
        let failed = !br.Err().IsNil();
        if failed != wantFail {
            ok = false;
            detail = fmt::Sprintf!("vector %d: failure = %v, want %v", i as i64, failed, wantFail);
            break;
        }
        if !wantFail && got != want {
            ok = false;
            detail = fmt::Sprintf!("vector %d: ReadBits = %d, want %d", i as i64, got, want);
            break;
        }
    }
    check("bitReader: Go's TestBitReader vectors", ok, detail);
}

/// Go's `TestMTF` — five decodes over the 0..4 identity list. The
/// comments are Go's, and record the list state AFTER each decode.
fn test_mtf() {
    let mut mtf = newMTFDecoderWithRange(5);

    // (idx, sym)
    let vectors: [(int, byte); 5] = [
        (1, 1), // [1 0 2 3 4]
        (0, 1), // [1 0 2 3 4]
        (1, 0), // [0 1 2 3 4]
        (4, 4), // [4 0 1 2 3]
        (1, 0), // [0 4 1 2 3]
    ];

    let mut ok = true;
    let mut detail = string::from("");
    for i in 0..vectors.len() {
        let (idx, want) = vectors[i];
        let sym = mtf.Decode(idx);
        if sym != want {
            ok = false;
            detail = fmt::Sprintf!(
                "vector %d: Decode(%d) = %d, want %d",
                i as i64,
                idx,
                sym as i64,
                want as i64
            );
            break;
        }
    }
    // The list must also still read back its front symbol.
    if ok && mtf.First() != 0 {
        ok = false;
        detail = string::from("First() != 0 after the five decodes");
    }
    check("moveToFrontDecoder: Go's TestMTF vectors", ok, detail);
}
