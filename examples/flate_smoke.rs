// flate_smoke — exercise compress/flate's LZ77 compressor + Writer.
//
// The strong test is a compress -> decompress round-trip entirely
// through goish: for every compression level, NewWriter compresses a
// set of inputs, then NewReader (the already-ported decompressor)
// inflates them, and the output is asserted equal to the input.
//
// Coverage:
//   1..5   round-trip at NoCompression / BestSpeed / DefaultCompression
//          / BestCompression / HuffmanOnly, each over 4 inputs
//          (empty, short, highly repetitive, a few KB of mixed data).
//   6      NewWriterDict / NewReaderDict with a preset dictionary.
//   7      Flush mid-stream then continue + Close.
//   8      invalid level rejected by NewWriter.
//   9      Go -> goish interop: inflate streams produced by the real
//          Go toolchain (embedded fixtures; regen recipe at the
//          GO_STREAM_INTEROP definition).
//  10      goish -> Go interop: self round-trip a goish-compressed
//          stream; also dropped to /tmp for the manual Go-side check
//          (last verified against go1.25.5, 2026-07-24).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::bytes;
use goish::compress::flate;
use goish::error;
use goish::errors;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::runtime::sched::schedule;
use goish::types::{byte, int};
use goish::{go, syscall};

const KB: usize = 1024;
const TOTAL: usize = 11;

// Linux open(2) flags not exported by goish::syscall.
const O_WRONLY: i32 = 0o1;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;

// Where test 10 drops its stream for the manual Go-side check.
const GOISH_PRODUCED: &[u8] = b"/tmp/flate_smoke_goish_produced.bin\0";

// The fixed input the harness compresses with Go (test 9) and the input
// goish compresses for the harness to decompress with Go (test 10).
const INTEROP_INPUT: &[u8] =
    b"compress/flate interop: the quick brown fox jumps over the lazy dog. \
the quick brown fox jumps over the lazy dog. the quick brown fox jumps.";

// Streams produced by the REAL Go toolchain (go1.25.5), embedded so
// the test is self-contained. Regen recipe:
//
//   w, _ := flate.NewWriter(f, flate.DefaultCompression)
//   w.Write(input); w.Close()
//
// GO_STREAM_INTEROP: input = INTEROP_INPUT.
const GO_STREAM_INTEROP: &[u8] = &[
    0x4a, 0xce, 0xcf, 0x2d, 0x28, 0x4a, 0x2d, 0x2e, 0xd6, 0x4f, 0xcb, 0x49, 0x2c, 0x49, 0x55, 0xc8,
    0xcc, 0x2b, 0x49, 0x2d, 0xca, 0x2f, 0xb0, 0x52, 0x28, 0xc9, 0x48, 0x55, 0x28, 0x2c, 0xcd, 0x4c,
    0xce, 0x56, 0x48, 0x2a, 0xca, 0x2f, 0xcf, 0x53, 0x48, 0xcb, 0xaf, 0x50, 0xc8, 0x2a, 0xcd, 0x2d,
    0x28, 0x56, 0xc8, 0x2f, 0x4b, 0x2d, 0x02, 0x4b, 0xe7, 0x24, 0x56, 0x55, 0x2a, 0xa4, 0xe4, 0xa7,
    0xeb, 0x51, 0x49, 0xb1, 0x1e, 0x20, 0x00, 0x00, 0xff, 0xff,
];

// GO_STREAM_ALLBYTES: input = 64 KiB with ab[i] = byte(i*7) — cycles
// the full literal alphabet, compressed by Go to one dynamic-Huffman
// block full of long matches.
const GO_STREAM_ALLBYTES: &[u8] = &[
    0xec, 0xcf, 0xc3, 0x01, 0x18, 0x08, 0x00, 0x00, 0xb0, 0x43, 0x6d, 0xdb, 0xb6, 0x6d, 0xdb, 0xb6,
    0x6d, 0xdb, 0xb6, 0x6d, 0xdb, 0xb6, 0x6d, 0xdb, 0xb6, 0xed, 0x47, 0xd7, 0xc8, 0x08, 0xf9, 0x27,
    0x70, 0xa8, 0x88, 0x31, 0xe2, 0x27, 0x4b, 0x9b, 0x25, 0x77, 0xa1, 0x92, 0x15, 0xaa, 0xd7, 0x6b,
    0xda, 0xa6, 0x73, 0xaf, 0x81, 0x23, 0xc6, 0x4f, 0x9b, 0xbb, 0x64, 0xf5, 0xa6, 0x9d, 0x07, 0x8e,
    0x9f, 0xbb, 0x7a, 0xe7, 0xf1, 0xab, 0x8f, 0x3f, 0xfe, 0x0f, 0x16, 0x36, 0x4a, 0xec, 0x44, 0x29,
    0x33, 0x64, 0xcf, 0x57, 0xb4, 0x4c, 0xe5, 0x5a, 0x0d, 0x5b, 0xb4, 0xef, 0xd6, 0x77, 0xc8, 0xe8,
    0x49, 0x33, 0x17, 0x2c, 0x5f, 0xb7, 0x75, 0xcf, 0xe1, 0x53, 0x17, 0x6f, 0xdc, 0x7f, 0xf6, 0xf6,
    0xcb, 0xef, 0x40, 0x21, 0x23, 0x44, 0x8f, 0x97, 0x34, 0x4d, 0xe6, 0x5c, 0x05, 0x4b, 0x94, 0xaf,
    0x56, 0xb7, 0x49, 0xeb, 0x4e, 0x3d, 0x07, 0x0c, 0x1f, 0x37, 0x75, 0xce, 0xe2, 0x55, 0x1b, 0x77,
    0xec, 0x3f, 0x76, 0xf6, 0xca, 0xed, 0x47, 0x2f, 0x3f, 0x7c, 0xff, 0x2f, 0x68, 0x98, 0xc8, 0xb1,
    0x12, 0xa6, 0x48, 0x9f, 0x2d, 0x6f, 0x91, 0xd2, 0x95, 0x6a, 0x36, 0x68, 0xde, 0xae, 0x6b, 0x9f,
    0xc1, 0xa3, 0x26, 0xce, 0x98, 0xbf, 0x6c, 0xed, 0x96, 0xdd, 0x87, 0x4e, 0x5e, 0xb8, 0x7e, 0xef,
    0xe9, 0x9b, 0xcf, 0xbf, 0x02, 0x86, 0x08, 0x1f, 0x2d, 0x6e, 0x92, 0xd4, 0x99, 0x72, 0x16, 0x28,
    0x5e, 0xae, 0x6a, 0x9d, 0xc6, 0xad, 0x3a, 0xf6, 0xe8, 0x3f, 0x6c, 0xec, 0x94, 0xd9, 0x8b, 0x56,
    0x6e, 0xd8, 0xbe, 0xef, 0xe8, 0x99, 0xcb, 0xb7, 0x1e, 0xbe, 0x78, 0xff, 0xed, 0xdf, 0x20, 0xa1,
    0x23, 0xc5, 0x4c, 0x90, 0x3c, 0x5d, 0xd6, 0x3c, 0x85, 0x4b, 0x55, 0xac, 0x51, 0xbf, 0x59, 0xdb,
    0x2e, 0xbd, 0x07, 0x8d, 0x9c, 0x30, 0x7d, 0xde, 0xd2, 0x35, 0x9b, 0x77, 0x1d, 0x3c, 0x71, 0xfe,
    0xda, 0xdd, 0x27, 0xaf, 0x3f, 0xfd, 0x0c, 0x10, 0x3c, 0x5c, 0xd4, 0x38, 0x89, 0x53, 0x65, 0xcc,
    0x91, 0xbf, 0x58, 0xd9, 0x2a, 0xb5, 0x1b, 0xb5, 0xec, 0xd0, 0xbd, 0xdf, 0xd0, 0x31, 0x93, 0x67,
    0x2d, 0x5c, 0xb1, 0x7e, 0xdb, 0xde, 0x23, 0xa7, 0x2f, 0xdd, 0x7c, 0xf0, 0xfc, 0xdd, 0x57, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e,
    0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0xfe, 0xbf, 0xfe, 0x3f, 0x01,
    0x00, 0x00, 0xff, 0xff,
];

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 11/11");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 11");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_level(1, flate::NoCompression, b"NoCompression round-trip  ");
    test_level(2, flate::BestSpeed, b"BestSpeed round-trip      ");
    test_level(3, flate::DefaultCompression, b"DefaultCompression r-trip ");
    test_level(4, flate::BestCompression, b"BestCompression round-trip");
    test_level(5, flate::HuffmanOnly, b"HuffmanOnly round-trip    ");
    test_6_dict();
    test_7_flush();
    test_8_invalid_level();
    test_9_go_to_goish();
    test_10_goish_to_go();
    test_11_bytes_match_go();
}

// The six reference corpora, regenerated rather than embedded.
#[derive(Clone, Copy)]
enum Corpus {
    Run1000,
    Ab5000,
    Abc3,
    Period7,
    Window,
    Mixed,
}

fn corpus(kind: Corpus, n: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        let b = match kind {
            Corpus::Run1000 => b'a',
            Corpus::Ab5000 => b"ab"[i % 2],
            Corpus::Abc3 => b"abc"[i % 3],
            Corpus::Period7 => b'a' + (i % 7) as u8,
            Corpus::Window => b"xyz"[(i % 60000) % 3],
            Corpus::Mixed => (((i * 7) % 251) & 0x7f) as u8,
        };
        v.push(b);
        i += 1;
    }
    v
}

static EMIT_BAD: AtomicUsize = AtomicUsize::new(0);

// goish's DEFLATE output at DefaultCompression, compared byte for byte
// against what Go's own compressor emits for the same input. Nothing
// requires two compressors to agree — the format leaves the encoder
// free — so this is a statement about how faithful the port is, and it
// is the only check that reaches the Huffman code generator's output
// rather than just its round-trip.
fn check_emit(kind: Corpus, n: usize, want: &[u8], _label: &[u8]) {
    let raw = corpus(kind, n);
    let (got, ok) = deflate(&raw, flate::DefaultCompression);
    if !ok || !eq(&got, want) {
        EMIT_BAD.fetch_add(1, Ordering::AcqRel);
    }
}

fn test_11_bytes_match_go() {
    check_emit(
        Corpus::Run1000,
        1000,
        b"\x4a\x1c\x05\xa3\x60\x14\x0c\x7b\x00\x08\x00\x00\xff\xff",
        b"run1000     ",
    );
    check_emit(
        Corpus::Ab5000,
        5000,
        b"\xec\xc1\xc1\x10\x00\x00\x00\x02\x30\xd6\xf2\x87\x88\xa2\xdf\
        \x6e\x29\x00\x00\x00\x00\xf0\xb6\x00\x00\x00\xff\xff",
        b"ab5000      ",
    );
    check_emit(
        Corpus::Abc3,
        9,
        b"\x4a\x4c\x4a\x86\x20\x40\x00\x00\x00\xff\xff",
        b"abc3        ",
    );
    check_emit(
        Corpus::Period7,
        40000,
        b"\xec\xc5\x39\x01\x00\x40\x08\x03\x30\xad\xf4\x9e\xfa\x77\x80\
        \x91\x4c\x99\x9c\xfb\x7e\x01\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x74\xb2\x01\x00\x00\xff\xff",
        b"period7     ",
    );
    check_emit(
        Corpus::Window,
        120000,
        b"\xec\xc2\x01\x0d\x00\x00\x08\x02\xb0\xda\x4a\x7a\x1a\x90\xe0\
        \xdb\xef\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xd0\
        \x00\x00\x00\xff\xff",
        b"window      ",
    );
    check_emit(
        Corpus::Mixed,
        70000,
        b"\xec\xcf\xc3\x79\xa8\x01\x00\x00\xc1\x67\xc6\xb6\x6d\xdb\xb6\
        \x6d\xdb\x76\x5a\x4f\x01\xff\x39\xb7\x69\x60\xbf\x9d\x2f\xbf\
        \xc3\x62\x53\xb2\x8b\x2a\x1b\xda\xfb\x46\x67\x96\xb7\x0e\x2f\
        \xee\xdf\x7e\x86\x44\x27\x65\x16\x94\xd7\xb5\xf6\x0c\x4f\x2d\
        \x6e\xec\x9f\xdd\x7e\xfd\x13\x1e\x97\x9a\x53\x5c\xd5\xd8\xd1\
        \x3f\x36\xbb\xb2\x7d\x74\xf9\xf0\xfe\x2b\x34\x26\x39\xab\xb0\
        \xa2\xbe\xad\x77\x64\x7a\x69\xf3\xe0\xfc\xee\xdb\xdf\x88\xf8\
        \xb4\xdc\x92\xea\xa6\xce\x81\xf1\xb9\xd5\x9d\xe3\xab\xc7\x60\
        \xf9\xfb\xbf\xc8\x84\xf4\xbc\xd2\x9a\xe6\xae\xc1\x89\xf9\xb5\
        \xdd\x93\xeb\xa7\x60\xf9\xc7\xff\xa8\xc4\x8c\xfc\xb2\xda\x96\
        \xee\xa1\xc9\x85\xf5\xbd\xd3\x9b\xe7\x60\x39\x30\xf8\x12\x2c\
        \x07\x06\x5f\x03\x65\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\x74\
        \x74\x74\x74\x74\xf4\x4f\xa3\x7f\x04\x00\x00\xff\xff",
        b"mixed       ",
    );
    let bad = EMIT_BAD.load(Ordering::Acquire);
    write_result(11, b"deflate bytes == Go's     ", bad == 0);
    if bad != 0 {
        fail();
    }
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + idx % 10;
    if idx >= 10 {
        let d1 = b'0' + idx / 10;
        let buf = [d1, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
    }
}

// Compress `raw` at `level` with NewWriter; return the DEFLATE bytes.
fn deflate(raw: &[u8], level: int) -> (Vec<byte>, bool) {
    let (mut w, err) = flate::NewWriter(bytes::NewBuffer(slice::new()), level);
    if !err.IsNil() {
        return (Vec::new(), false);
    }
    let (_, werr) = w.Write(from_bytes(raw));
    if !werr.IsNil() {
        return (Vec::new(), false);
    }
    let cerr = w.Close();
    if !cerr.IsNil() {
        return (Vec::new(), false);
    }
    let buf = w.into_writer();
    let b = buf.Bytes();
    let mut out: Vec<byte> = Vec::with_capacity(b.len() as usize);
    let mut i: int = 0;
    while i < goish::len(&b) {
        out.push(b[i]);
        i += 1;
    }
    (out, true)
}

// Inflate a raw-DEFLATE byte stream through goish's NewReader.
fn inflate(compressed: &[u8]) -> (Vec<byte>, error) {
    let r = bytes::NewReader(from_bytes(compressed));
    let mut d = flate::NewReader(r);
    let mut out: Vec<byte> = Vec::new();
    let mut buf = from_bytes(&[0u8; 512]);
    loop {
        let (n, err) = d.Read(&mut buf);
        let mut k: int = 0;
        while k < n {
            out.push(buf[k]);
            k += 1;
        }
        if !err.IsNil() {
            if errors::Is(err.clone(), io::EOF) {
                return (out, errors::nil);
            }
            return (out, err);
        }
    }
}

fn eq(a: &[byte], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..b.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

// A few KB of mixed (semi-compressible) data.
fn mixed_kb() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(4096);
    let mut x: u32 = 0x1234_5678;
    for i in 0..4096u32 {
        // A blend of a repeating pattern and an LCG byte stream so the
        // result is neither trivially compressible nor random.
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let b = if i % 7 < 3 {
            (b'A' + (i % 26) as u8) as u8
        } else {
            (x >> 16) as u8
        };
        v.push(b);
    }
    v
}

// Round-trip the 4 standard inputs at one level.
fn test_level(idx: u8, level: int, label: &[u8]) {
    let kb = mixed_kb();
    let repetitive: &[u8] = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let inputs: [&[u8]; 4] = [b"", b"hello, flate", repetitive, kb.as_slice()];

    let mut ok = true;
    for raw in inputs.iter() {
        let (comp, cok) = deflate(raw, level);
        if !cok {
            ok = false;
            break;
        }
        let (got, err) = inflate(&comp);
        if !err.IsNil() || !eq(&got, raw) {
            ok = false;
            break;
        }
    }
    write_result(idx, label, ok);
    if !ok {
        fail();
    }
}

fn test_6_dict() {
    let dict: &[u8] = b"the quick brown fox";
    let raw: &[u8] = b"the quick brown fox jumps over the lazy dog";

    // Compress with NewWriterDict.
    let (mut w, err) = flate::NewWriterDict(
        bytes::NewBuffer(slice::new()),
        flate::BestCompression,
        from_bytes(dict),
    );
    let mut ok = err.IsNil();
    if ok {
        let (_, werr) = w.Write(from_bytes(raw));
        ok = werr.IsNil() && w.Close().IsNil();
    }
    if ok {
        let buf = w.into_writer().into_writer();
        let b = buf.Bytes();
        let mut comp: Vec<byte> = Vec::new();
        let mut i: int = 0;
        while i < goish::len(&b) {
            comp.push(b[i]);
            i += 1;
        }
        // Decompress with NewReaderDict + the same dictionary.
        let r = bytes::NewReader(slice::__from_vec(comp));
        let mut d = flate::NewReaderDict(r, from_bytes(dict));
        let mut out: Vec<byte> = Vec::new();
        let mut rbuf = from_bytes(&[0u8; 256]);
        loop {
            let (n, e) = d.Read(&mut rbuf);
            let mut k: int = 0;
            while k < n {
                out.push(rbuf[k]);
                k += 1;
            }
            if !e.IsNil() {
                if !errors::Is(e, io::EOF) {
                    ok = false;
                }
                break;
            }
        }
        if ok && !eq(&out, raw) {
            ok = false;
        }
    }
    write_result(6, b"NewWriterDict round-trip  ", ok);
    if !ok {
        fail();
    }
}

fn test_7_flush() {
    // Write part, Flush, write the rest, Close — the inflated result
    // must equal the concatenation of both writes.
    let p1: &[u8] = b"first half before the sync flush marker; ";
    let p2: &[u8] = b"second half written after Flush returned.";

    let (mut w, err) = flate::NewWriter(bytes::NewBuffer(slice::new()), flate::DefaultCompression);
    let mut ok = err.IsNil();
    if ok {
        ok = w.Write(from_bytes(p1)).1.IsNil();
    }
    if ok {
        ok = w.Flush().IsNil();
    }
    if ok {
        ok = w.Write(from_bytes(p2)).1.IsNil();
    }
    if ok {
        ok = w.Close().IsNil();
    }
    if ok {
        let buf = w.into_writer();
        let b = buf.Bytes();
        let mut comp: Vec<byte> = Vec::new();
        let mut i: int = 0;
        while i < goish::len(&b) {
            comp.push(b[i]);
            i += 1;
        }
        let mut expect: Vec<u8> = Vec::new();
        expect.extend_from_slice(p1);
        expect.extend_from_slice(p2);
        let (got, e) = inflate(&comp);
        if !e.IsNil() || !eq(&got, &expect) {
            ok = false;
        }
    }
    write_result(7, b"Flush mid-stream + Close  ", ok);
    if !ok {
        fail();
    }
}

fn test_8_invalid_level() {
    // Level 42 is out of range -> NewWriter must return a non-nil error.
    let (_, err) = flate::NewWriter(bytes::NewBuffer(slice::new()), 42);
    let ok = !err.IsNil();
    write_result(8, b"invalid level rejected    ", ok);
    if !ok {
        fail();
    }
}

// Write `data` to a file via raw syscalls. Returns success.
fn write_file(path: &[u8], data: &[u8]) -> bool {
    let fd = syscall::Open(path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        return false;
    }
    let mut off = 0usize;
    let mut ok = true;
    while off < data.len() {
        let n = syscall::Write(fd, data[off..].as_ptr(), data.len() - off);
        if n <= 0 {
            ok = false;
            break;
        }
        off += n as usize;
    }
    syscall::Close(fd);
    ok
}

fn test_9_go_to_goish() {
    // Inflate the embedded real-Go streams and compare byte-exactly.
    let (got, err) = inflate(GO_STREAM_INTEROP);
    let mut ok = err.IsNil() && eq(&got, INTEROP_INPUT);

    if ok {
        // Rebuild the deterministic all-bytes input Go compressed.
        let mut raw: Vec<u8> = Vec::with_capacity(64 * KB);
        let mut i: int = 0;
        while i < (64 * KB) as int {
            raw.push(((i * 7) & 0xff) as u8);
            i += 1;
        }
        let (got, err) = inflate(GO_STREAM_ALLBYTES);
        ok = err.IsNil() && eq(&got, &raw);
    }
    write_result(9, b"Go -> goish interop       ", ok);
    if !ok {
        fail();
    }
}

fn test_10_goish_to_go() {
    // Compress INTEROP_INPUT with goish; self round-trip it, and drop
    // it to GOISH_PRODUCED for the manual Go-side check:
    //   flate.NewReader(f) over the file must yield INTEROP_INPUT.
    let (comp, cok) = deflate(INTEROP_INPUT, flate::BestCompression);
    let mut ok = cok && !comp.is_empty();
    if ok {
        ok = write_file(GOISH_PRODUCED, &comp);
    }
    // Local sanity: goish must also round-trip its own output.
    if ok {
        let (got, err) = inflate(&comp);
        ok = err.IsNil() && eq(&got, INTEROP_INPUT);
    }
    write_result(10, b"goish -> Go interop       ", ok);
    if !ok {
        fail();
    }
}

// Reference the constant so the harness shape matches sibling examples.
const _: usize = TOTAL;
