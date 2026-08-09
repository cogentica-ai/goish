// lzw_writer_smoke — exercise compress/lzw Writer + round-trip with Reader.
//
// Coverage:
//
// All format checks use ROUND-TRIP (compress then decompress) since
// Go's reader_test.go vectors are minimal hand-crafted streams, not
// byte-exact writer output (e.g. an empty input through Go's writer
// emits clear+eof+flush, ~3 bytes, not the 2-byte hand vector).
//
//   1. empty input;LSB;8 — round-trip preserves length 0.
//   2. empty input;MSB;8.
//   3. tobe;LSB;8 — "TOBEORNOTTOBEORTOBEORNOT" round-trip.
//   4. tobe;MSB;8.
//   5. tobe;LSB;7 — 7-bit literals.
//   6. random ASCII string (LSB;8).
//   7. 1024-byte alternating pattern (MSB;8).
//   8. 4096 bytes triggers dictionary overflow (LSB;8).
//   9. Close() is idempotent (returns nil on second call).
//  10. Write of byte > maxLit returns "input byte too large" error.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::error;
use goish::bytes;
use goish::compress::lzw::{self, LSB, MSB};
use goish::errors;
use goish::goslice::slice;
use goish::io;
use goish::runtime::sched::schedule;
use goish::types::{byte, int};
use goish::{go, syscall};

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
            fmt::Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_empty_lsb_format();
    test_2_empty_msb_format();
    test_3_tobe_lsb_8_format();
    test_4_tobe_msb_8_format();
    test_5_tobe_lsb_7_format();
    test_6_random_ascii_roundtrip_lsb();
    test_7_alt_pattern_roundtrip_msb();
    test_8_4kb_dict_overflow_lsb();
    test_9_close_idempotent();
    test_10_byte_too_large_for_litwidth();
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn read_all(r: &mut lzw::Reader<bytes::Reader>) -> (alloc::vec::Vec<byte>, error) {
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

// ─── direct format checks ──────────────────────────────────────────────
//
// We write into a shared bytes::Buffer pointer then snapshot; goish's
// bytes::Buffer is itself an io::Writer. Use a Box with a pre-known
// life-of-test layout: take a Buffer, hand it to NewWriter (which moves
// it into bufio::Writer<Buffer>), then call Close which Flushes back.
// Recovery of the inner Buffer would need destructuring which the API
// doesn't expose. So instead, we route through a tiny custom writer
// that captures bytes into a static Vec<byte>.

use core::cell::UnsafeCell;

struct TapWriter {
    slot: usize,
}

const NUM_SLOTS: usize = 16;

struct Slots {
    bufs: [UnsafeCell<alloc::vec::Vec<byte>>; NUM_SLOTS],
}

unsafe impl Sync for Slots {}

static SLOTS: Slots = Slots {
    bufs: [
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
        UnsafeCell::new(alloc::vec::Vec::new()),
    ],
};

fn slot_get(i: usize) -> &'static mut alloc::vec::Vec<byte> {
    unsafe { &mut *SLOTS.bufs[i].get() }
}

impl io::Writer for TapWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let v = slot_get(self.slot);
        for i in 0..(p.Len() as usize) {
            v.push(p[i as int]);
        }
        (p.Len(), errors::nil)
    }
}

fn compress(slot: usize, input: &[u8], order: lzw::Order, lit_width: int) -> bool {
    slot_get(slot).clear();
    let mut w = lzw::NewWriter(TapWriter { slot }, order, lit_width);
    let (_n, err) = w.Write(from_bytes(input));
    if !err.IsNil() {
        return false;
    }
    let cerr = w.Close();
    cerr.IsNil()
}

fn test_1_empty_lsb_format() {
    let ok = roundtrip(1, b"", LSB, 8);
    write_result(1, b"empty roundtrip LSB;8      ", ok);
    if !ok {
        fail();
    }
}

fn test_2_empty_msb_format() {
    let ok = roundtrip(2, b"", MSB, 8);
    write_result(2, b"empty roundtrip MSB;8      ", ok);
    if !ok {
        fail();
    }
}

fn test_3_tobe_lsb_8_format() {
    let ok = roundtrip(3, b"TOBEORNOTTOBEORTOBEORNOT", LSB, 8);
    write_result(3, b"tobe roundtrip LSB;8       ", ok);
    if !ok {
        fail();
    }
}

fn test_4_tobe_msb_8_format() {
    let ok = roundtrip(4, b"TOBEORNOTTOBEORTOBEORNOT", MSB, 8);
    write_result(4, b"tobe roundtrip MSB;8       ", ok);
    if !ok {
        fail();
    }
}

fn test_5_tobe_lsb_7_format() {
    let ok = roundtrip(5, b"TOBEORNOTTOBEORTOBEORNOT", LSB, 7);
    write_result(5, b"tobe roundtrip LSB;7       ", ok);
    if !ok {
        fail();
    }
}

fn roundtrip(slot: usize, input: &[u8], order: lzw::Order, lit_width: int) -> bool {
    if !compress(slot, input, order, lit_width) {
        return false;
    }
    let compressed = slot_get(slot).clone();
    let r = bytes::NewReader(slice::__from_vec(compressed));
    let mut rc = lzw::NewReader(r, order, lit_width);
    let (got, err) = read_all(&mut rc);
    if !err.IsNil() {
        return false;
    }
    if got.len() != input.len() {
        return false;
    }
    for i in 0..input.len() {
        if got[i] != input[i] {
            return false;
        }
    }
    true
}

fn test_6_random_ascii_roundtrip_lsb() {
    // 256 bytes of ASCII ("the quick brown fox..." x N)
    let pat: &[u8] = b"the quick brown fox jumps over the lazy dog. ";
    let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    while buf.len() < 256 {
        for &c in pat {
            buf.push(c);
        }
    }
    buf.truncate(256);
    let ok = roundtrip(6, &buf, LSB, 8);
    if ok {
        write_result(6, b"random ASCII roundtrip LSB ", true);
    } else {
        write_result(6, b"random ASCII roundtrip LSB ", false);
        fail();
    }
}

fn test_7_alt_pattern_roundtrip_msb() {
    let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(1024);
    for i in 0..1024 {
        buf.push((i & 0xff) as byte);
    }
    let ok = roundtrip(7, &buf, MSB, 8);
    if ok {
        write_result(7, b"alt 1KiB roundtrip MSB     ", true);
    } else {
        write_result(7, b"alt 1KiB roundtrip MSB     ", false);
        fail();
    }
}

fn test_8_4kb_dict_overflow_lsb() {
    let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(4096);
    let mut state: u32 = 0xdead_beef;
    for _ in 0..4096 {
        // simple LCG to spread bytes
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        buf.push((state >> 16) as byte);
    }
    let ok = roundtrip(8, &buf, LSB, 8);
    if ok {
        write_result(8, b"4 KiB pseudo-random LSB    ", true);
    } else {
        write_result(8, b"4 KiB pseudo-random LSB    ", false);
        fail();
    }
}

fn test_9_close_idempotent() {
    let mut w = lzw::NewWriter(TapWriter { slot: 9 }, LSB, 8);
    let _ = w.Write(from_bytes(b"hi"));
    let e1 = w.Close();
    let e2 = w.Close();
    if e1.IsNil() && e2.IsNil() {
        write_result(9, b"Close() idempotent         ", true);
    } else {
        write_result(9, b"Close() idempotent         ", false);
        fail();
    }
}

fn test_10_byte_too_large_for_litwidth() {
    // litWidth=2 means valid bytes are 0..3.
    let mut w = lzw::NewWriter(TapWriter { slot: 10 }, LSB, 2);
    let (_n, err) = w.Write(from_bytes(b"\x00\x01\x02\x05"));
    let _ = w.Close();
    if !err.IsNil() {
        write_result(10, b"byte > maxLit -> error     ", true);
    } else {
        write_result(10, b"byte > maxLit -> error     ", false);
        fail();
    }
}
