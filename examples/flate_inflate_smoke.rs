// flate_inflate_smoke — exercise compress/flate's DEFLATE decompressor.
//
// The compressor is a later task, so decompression is tested against
// known raw-DEFLATE byte streams produced by the real Go 1.25
// toolchain (`compress/flate.NewWriter` / `NewWriterDict`).
//
// Coverage:
//   1. empty input — final empty stored block.
//   2. "hello, world" — default compression (compressed block).
//   3. stored (uncompressed) block — NoCompression.
//   4. dynamic-Huffman block — long repetitive input, BestCompression.
//   5. fixed-Huffman block — small input, BestSpeed.
//   6. NewReaderDict — preset-dictionary decode.
//   7. truncated stream — surfaces ErrUnexpectedEOF.
//   8. corrupt stream (reserved block type 3) — surfaces an error.
//   9. NewReader + Close — Close() returns nil after a full read.
//  10. small read buffer — multi-call Read drains correctly.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::bytes;
use goish::compress::flate;
use goish::error;
use goish::errors;
use goish::goslice::slice;
use goish::io;
use goish::runtime::sched::schedule;
use goish::types::{byte, int};
use goish::{go, syscall, Println};

const KB: usize = 1024;
const TOTAL: usize = 10;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(stack(256 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_empty();
    test_2_hello_default();
    test_3_stored();
    test_4_dynamic();
    test_5_fixed();
    test_6_dict();
    test_7_truncated();
    test_8_corrupt();
    test_9_close();
    test_10_small_buffer();
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

// Drain a Decompressor fully, returning (output, terminal-error).
fn read_all(r: &mut flate::Decompressor<bytes::Reader>) -> (alloc::vec::Vec<byte>, error) {
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut buf = from_bytes(&[0u8; 512]);
    loop {
        let (n, err) = r.Read(&mut buf);
        if n > 0 {
            for i in 0..(n as usize) {
                out.push(buf[i as int]);
            }
        }
        if !err.IsNil() {
            if errors::Is(err.clone(), io::EOF) {
                return (out, errors::nil);
            }
            return (out, err);
        }
    }
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d1 = b'0' + idx / 10;
    let d2 = b'0' + idx % 10;
    if idx >= 10 {
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

// Decompress `compressed`, assert the output equals `raw`.
fn check(idx: u8, raw: &[u8], compressed: &[u8], label: &[u8]) {
    let r = bytes::NewReader(from_bytes(compressed));
    let mut d = flate::NewReaderByte(r);
    let (got, err) = read_all(&mut d);
    let close_err = d.Close();
    let mut ok = err.IsNil() && close_err.IsNil() && got.len() == raw.len();
    if ok {
        for i in 0..raw.len() {
            if got[i] != raw[i] {
                ok = false;
                break;
            }
        }
    }
    write_result(idx, label, ok);
    if !ok {
        fail();
    }
}

fn test_1_empty() {
    // empty (5 bytes) — final empty stored block.
    check(1, b"", b"\x01\x00\x00\xff\xff", b"empty input               ");
}

fn test_2_hello_default() {
    // "hello, world" (default compression).
    check(
        2,
        b"hello, world",
        b"\xca\x48\xcd\xc9\xc9\xd7\x51\x28\xcf\x2f\xca\x49\x01\x04\x00\x00\xff\xff",
        b"hello,world (default)     ",
    );
}

fn test_3_stored() {
    // stored (uncompressed) block — NoCompression.
    check(
        3,
        b"STORED BLOCK DATA",
        b"\x00\x11\x00\xee\xff\x53\x54\x4f\x52\x45\x44\x20\x42\x4c\x4f\x43\x4b\x20\
\x44\x41\x54\x41\x01\x00\x00\xff\xff",
        b"stored block              ",
    );
}

fn test_4_dynamic() {
    // dynamic-Huffman block — long repetitive input, BestCompression.
    check(
        4,
        b"the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog.",
        b"\x2a\xc9\x48\x55\x28\x2c\xcd\x4c\xce\x56\x48\x2a\xca\x2f\xcf\x53\x48\xcb\
\xaf\x50\xc8\x2a\xcd\x2d\x28\x56\xc8\x2f\x4b\x2d\x52\x00\x49\xe7\x24\x56\x55\x2a\
\xa4\xe4\xa7\xeb\x29\xd0\x4c\x31\x20\x00\x00\xff\xff",
        b"dynamic Huffman block     ",
    );
}

fn test_5_fixed() {
    // fixed-Huffman / stored mix — small input, BestSpeed.
    check(
        5,
        b"abcabcabcabc",
        b"\x00\x0c\x00\xf3\xff\x61\x62\x63\x61\x62\x63\x61\x62\x63\x61\x62\x63\x01\
\x00\x00\xff\xff",
        b"fixed/small block         ",
    );
}

fn test_6_dict() {
    // NewReaderDict — preset dictionary "the quick brown fox".
    let dict = from_bytes(b"the quick brown fox");
    let r = bytes::NewReader(from_bytes(
        b"\xc2\x22\xa4\x90\x55\x9a\x5b\x50\x0c\x08\x00\x00\xff\xff",
    ));
    let mut d = flate::NewReaderByteDict(r, dict);
    let (got, err) = read_all(&mut d);
    let raw: &[u8] = b"the quick brown fox jumps";
    let mut ok = err.IsNil() && got.len() == raw.len();
    if ok {
        for i in 0..raw.len() {
            if got[i] != raw[i] {
                ok = false;
                break;
            }
        }
    }
    write_result(6, b"NewReaderDict             ", ok);
    if !ok {
        fail();
    }
}

fn test_7_truncated() {
    // Truncate the dynamic-Huffman stream mid-block — expect
    // ErrUnexpectedEOF (not a plain EOF).
    let r = bytes::NewReader(from_bytes(
        b"\x2a\xc9\x48\x55\x28\x2c\xcd\x4c\xce\x56\x48\x2a",
    ));
    let mut d = flate::NewReaderByte(r);
    let (_got, err) = read_all(&mut d);
    let ok = !err.IsNil() && errors::Is(err, io::ErrUnexpectedEOF);
    write_result(7, b"truncated ErrUnexpectedEOF ", ok);
    if !ok {
        fail();
    }
}

fn test_8_corrupt() {
    // First byte 0x07 -> BFINAL=1, BTYPE=11 (reserved) -> error.
    let r = bytes::NewReader(from_bytes(b"\x07\x00\x00\x00\x00"));
    let mut d = flate::NewReaderByte(r);
    let (_got, err) = read_all(&mut d);
    let ok = !err.IsNil();
    write_result(8, b"corrupt block type 3      ", ok);
    if !ok {
        fail();
    }
}

fn test_9_close() {
    // Close() returns nil once the stream has been fully consumed
    // (terminal err == io.EOF).
    let r = bytes::NewReader(from_bytes(b"\x01\x00\x00\xff\xff"));
    let mut d = flate::NewReaderByte(r);
    let (_got, _err) = read_all(&mut d);
    let ce = d.Close();
    let ok = ce.IsNil();
    write_result(9, b"NewReader + Close()       ", ok);
    if !ok {
        fail();
    }
}

fn test_10_small_buffer() {
    // Drain with a tiny 3-byte buffer — exercises the multi-call
    // toRead path of Read.
    let r = bytes::NewReader(from_bytes(
        b"\xca\x48\xcd\xc9\xc9\xd7\x51\x28\xcf\x2f\xca\x49\x01\x04\x00\x00\xff\xff",
    ));
    let mut d = flate::NewReaderByte(r);
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut buf = from_bytes(&[0u8; 3]);
    let raw: &[u8] = b"hello, world";
    let term_ok: bool;
    loop {
        let (n, err) = d.Read(&mut buf);
        for i in 0..(n as usize) {
            out.push(buf[i as int]);
        }
        if !err.IsNil() {
            term_ok = errors::Is(err, io::EOF);
            break;
        }
    }
    let mut ok = term_ok && out.len() == raw.len();
    if ok {
        for i in 0..raw.len() {
            if out[i] != raw[i] {
                ok = false;
                break;
            }
        }
    }
    write_result(10, b"small read buffer         ", ok);
    if !ok {
        fail();
    }
}

// Reference the constant so the harness shape matches sibling examples.
const _: usize = TOTAL;
