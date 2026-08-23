// zlib_offset_smoke — proves goish zlib/flate consume EXACTLY the bytes of
// the zlib stream when given an io::ByteReader source (Go's flate.Reader
// fast-path), leaving the source positioned precisely at the trailer end.
//
// This is the semantic-equivalence guarantee that git packfile parsing
// relies on: after inflating object N, the reader is at the start of
// object N+1. A bufio-style over-read would advance the source past the
// stream and break sequential decoding.
//
// Method:
//   1. zlib-compress a known payload  → `comp`.
//   2. Build a buffer `comp || SENTINEL` (12 trailing bytes that are NOT
//      part of the stream).
//   3. Decompress via zlib::NewReaderByte over a bytes::Reader.
//   4. Assert: decompressed == payload, AND the bytes::Reader's remaining
//      length == SENTINEL.len() (i.e. consumed == comp.len(), no over-read),
//      AND the next SENTINEL bytes read back are intact.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::bytes as gbytes;
use goish::compress::zlib;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::types::byte;
use goish::{nil, syscall};

fn fail(msg: &str) -> ! {
    fmt::Println!(fmt::Sprintf!("[FAIL] %s", msg));
    syscall::Exit(1);
}

#[goish::main]
fn main() {
    fmt::Println!("=== zlib_offset_smoke ===");

    // Payload: a few hundred bytes with structure (so deflate actually
    // emits a non-trivial stream with back-references).
    let mut payload: Vec<byte> = Vec::new();
    let mut i = 0i64;
    while i < 600 {
        payload.push((b'A' + ((i % 26) as u8)) as byte);
        i += 1;
    }
    let payload_s = slice::<byte>::__from_vec(payload.clone());

    // 1. Compress with zlib::Writer.
    let mut buf = gbytes::NewBuffer(goish::make!([]byte, 0));
    let comp: Vec<byte> = {
        let mut zw = zlib::NewWriter(&mut buf);
        let (_, werr) = io::Writer::Write(&mut zw, payload_s.clone());
        if werr != nil {
            fail("zlib write");
        }
        let cerr = zlib::Writer::Close(&mut zw);
        if cerr != nil {
            fail("zlib writer close");
        }
        buf.Bytes().__into_vec()
    };
    let comp_len = comp.len() as i64;
    fmt::Println!(fmt::Sprintf!(
        "[OK] compressed %d bytes -> %d bytes",
        payload.len() as i64,
        comp_len
    ));

    // 2. Build comp || SENTINEL.
    const SENTINEL: &[u8] = &[
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    let mut combined: Vec<byte> = comp.clone();
    combined.extend_from_slice(SENTINEL);
    let combined_len = combined.len() as i64;
    let combined_s = slice::<byte>::__from_vec(combined);

    // 3. Decompress via the ByteReader-direct path.
    let mut br = gbytes::NewReader(combined_s);
    let mut out: Vec<byte> = Vec::new();
    {
        let (mut zr, err) = zlib::NewReaderByte(&mut br);
        if err != nil {
            fail("zlib NewReaderByte");
        }
        let mut rbuf = goish::make!([]byte, 256);
        loop {
            let (n, rerr) = zr.Read(&mut rbuf);
            let mut k = 0i64;
            while k < n {
                out.push(rbuf[k]);
                k += 1;
            }
            if rerr != nil {
                if rerr == io::EOF {
                    break;
                }
                fail("zlib read");
            }
        }
        let _ = zr.Close();
    }

    // 4a. Decompressed output must equal the original payload.
    if out.len() != payload.len() {
        let m = fmt::Sprintf!(
            "decompressed len %d != payload len %d",
            out.len() as i64,
            payload.len() as i64
        );
        fail(m.as_ref());
    }
    let mut j = 0usize;
    while j < out.len() {
        if out[j] != payload[j] {
            fail("decompressed content mismatch");
        }
        j += 1;
    }
    fmt::Println!("[OK] decompressed content matches payload");

    // 4b. THE KEY ASSERTION: the reader consumed EXACTLY comp_len bytes.
    // bytes::Reader.Len() = remaining = combined_len - position.
    let remaining = br.Len();
    let consumed = combined_len - remaining;
    fmt::Println!(fmt::Sprintf!(
        "[INFO] consumed=%d comp_len=%d remaining=%d sentinel=%d",
        consumed,
        comp_len,
        remaining,
        SENTINEL.len() as i64
    ));
    if consumed != comp_len {
        fail("OVER/UNDER-READ: bytes consumed != exact compressed stream length");
    }
    if remaining != SENTINEL.len() as i64 {
        fail("reader not positioned exactly at stream end");
    }
    fmt::Println!("[OK] consumed == exact compressed length (no over-read)");

    // 4c. The sentinel bytes must still be readable, intact, in order.
    let mut sbuf = goish::make!([]byte, SENTINEL.len() as i64);
    let (sn, _) = br.Read(&mut sbuf);
    if sn != SENTINEL.len() as i64 {
        fail("could not read back sentinel");
    }
    let mut s = 0usize;
    while s < SENTINEL.len() {
        if sbuf[s as i64] != SENTINEL[s] {
            fail("sentinel corrupted by over-read");
        }
        s += 1;
    }
    fmt::Println!("[OK] trailing sentinel intact — source position was exact");

    fmt::Println!("=== zlib_offset_smoke: PASS ===");
    syscall::Exit(0);
}
