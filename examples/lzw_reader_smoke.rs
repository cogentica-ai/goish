// lzw_reader_smoke — exercise compress/lzw Reader.
//
// Test vectors lifted from /share/go/src/compress/lzw/reader_test.go
// (lzwTests slice). All eight vectors are decompressed and the output
// compared against the expected raw bytes.
//
// Coverage:
//   1. empty;LSB;8 — minimal stream, just clear+eof.
//   2. empty;MSB;8.
//   3. tobe;LSB;7 — 24-byte plaintext, 7-bit literals.
//   4. tobe;LSB;8 — 24-byte plaintext, 8-bit literals.
//   5. tobe;MSB;7.
//   6. tobe;MSB;8.
//   7. tobe-truncated;LSB;8 — early-EOF detection (ErrUnexpectedEOF).
//   8. gif;LSB;8 — GIF reference vector.
//   9. pdf;MSB;8 — PDF reference vector.
//  10. NewReader/Close — round-trip.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::bytes;
use goish::compress::lzw::{self, LSB, MSB};
use goish::errors;
use goish::goslice::slice;
use goish::io;
use goish::runtime::sched::schedule;
use goish::types::{byte, int};
use goish::{go, syscall, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(stack(128 * KB), || {
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
    test_1_empty_lsb();
    test_2_empty_msb();
    test_3_tobe_lsb_7();
    test_4_tobe_lsb_8();
    test_5_tobe_msb_7();
    test_6_tobe_msb_8();
    test_7_tobe_truncated();
    test_8_gif_lsb_8();
    test_9_pdf_msb_8();
    test_10_close_idempotent();
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn read_all(r: &mut lzw::Reader<bytes::Reader>) -> (alloc::vec::Vec<byte>, errors::error) {
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut buf = from_bytes(&[0u8; 256]);
    loop {
        let (n, err) = r.Read(&mut buf);
        if n > 0 {
            for i in 0..(n as usize) {
                out.push(buf[i as int]);
            }
        }
        if !err.IsNil() {
            if errors::Is(err.clone(), io::EOF()) {
                return (out, errors::nil);
            }
            return (out, err);
        }
    }
}

fn check(idx: u8, raw: &[u8], compressed: &[u8], order: lzw::Order, lit_width: int, label: &[u8]) {
    let r = bytes::NewReader(from_bytes(compressed));
    let mut rc = lzw::NewReader(r, order, lit_width);
    let (got, err) = read_all(&mut rc);
    let _ = rc.Close();
    let mut ok = err.IsNil() && got.len() == raw.len();
    if ok {
        for i in 0..raw.len() {
            if got[i] != raw[i] {
                ok = false;
                break;
            }
        }
    }
    if ok {
        write_result(idx, label, true);
    } else {
        write_result(idx, label, false);
        fail();
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

fn test_1_empty_lsb() {
    check(1, b"", b"\x01\x01", LSB, 8, b"empty;LSB;8                ");
}

fn test_2_empty_msb() {
    check(2, b"", b"\x80\x80", MSB, 8, b"empty;MSB;8                ");
}

fn test_3_tobe_lsb_7() {
    check(
        3,
        b"TOBEORNOTTOBEORTOBEORNOT",
        b"\x54\x4f\x42\x45\x4f\x52\x4e\x4f\x54\x82\x84\x86\x8b\x85\x87\x89\x81",
        LSB,
        7,
        b"tobe;LSB;7                 ",
    );
}

fn test_4_tobe_lsb_8() {
    check(
        4,
        b"TOBEORNOTTOBEORTOBEORNOT",
        b"\x54\x9e\x08\x29\xf2\x44\x8a\x93\x27\x54\x04\x12\x34\xb8\xb0\xe0\xc1\x84\x01\x01",
        LSB,
        8,
        b"tobe;LSB;8                 ",
    );
}

fn test_5_tobe_msb_7() {
    check(
        5,
        b"TOBEORNOTTOBEORTOBEORNOT",
        b"\x54\x4f\x42\x45\x4f\x52\x4e\x4f\x54\x82\x84\x86\x8b\x85\x87\x89\x81",
        MSB,
        7,
        b"tobe;MSB;7                 ",
    );
}

fn test_6_tobe_msb_8() {
    check(
        6,
        b"TOBEORNOTTOBEORTOBEORNOT",
        b"\x2a\x13\xc8\x44\x52\x79\x48\x9c\x4f\x2a\x40\xa0\x90\x68\x5c\x16\x0f\x09\x80\x80",
        MSB,
        8,
        b"tobe;MSB;8                 ",
    );
}

fn test_7_tobe_truncated() {
    let r = bytes::NewReader(from_bytes(
        b"\x54\x9e\x08\x29\xf2\x44\x8a\x93\x27\x54\x04",
    ));
    let mut rc = lzw::NewReader(r, LSB, 8);
    let (_got, err) = read_all(&mut rc);
    let _ = rc.Close();
    if !err.IsNil() && errors::Is(err, io::ErrUnexpectedEOF()) {
        write_result(7, b"tobe-truncated ErrUnexpectedEOF", true);
    } else {
        write_result(7, b"tobe-truncated ErrUnexpectedEOF", false);
        fail();
    }
}

fn test_8_gif_lsb_8() {
    check(
        8,
        b"\x28\xff\xff\xff\x28\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x00\x51\xfc\x1b\x28\x70\xa0\xc1\x83\x01\x01",
        LSB,
        8,
        b"gif;LSB;8                  ",
    );
}

fn test_9_pdf_msb_8() {
    check(
        9,
        b"-----A---B",
        b"\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01",
        MSB,
        8,
        b"pdf;MSB;8                  ",
    );
}

fn test_10_close_idempotent() {
    // Open + close, then verify subsequent Read returns the closed
    // sentinel (Go's "lzw: reader/writer is closed").
    let r = bytes::NewReader(from_bytes(b"\x01\x01"));
    let mut rc = lzw::NewReader(r, LSB, 8);
    let _ = rc.Close();
    let mut buf = from_bytes(&[0u8; 16]);
    let (n, err) = rc.Read(&mut buf);
    if n == 0 && !err.IsNil() {
        write_result(10, b"Close() then Read err      ", true);
    } else {
        write_result(10, b"Close() then Read err      ", false);
        fail();
    }
}
