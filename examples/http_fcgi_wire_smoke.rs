// net/http/fcgi record framing — the bytes that actually go on the wire.
//
// Every expected value is Go 1.25.5's, captured by calling the real
// unexported conn.writeRecord / writeEndRequest / writePairs inside
// net/http/fcgi (goref) and printing the buffer. Nothing is derived
// from reading the spec.
//
// The padding rule is what this pins: a record body is padded to a
// multiple of 8, so "a" (1 byte) gets 7 pad bytes and "12345678"
// (8 bytes) gets none.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::sync::Arc;
use goish::net::http::fcgi;
use goish::{errors, fmt, gomap::map, slice, string, syscall, types::int};

/// A transport that keeps whatever was written to it.
#[derive(Clone)]
#[allow(non_camel_case_types)]
struct capture(Arc<goish::sync::Mutex<alloc::vec::Vec<u8>>>);

impl goish::io::Writer for capture {
    fn Write(&mut self, p: slice<u8>) -> (int, goish::error) {
        let n = goish::len(&p);
        self.0.Lock().extend_from_slice(&*p);
        return (n, errors::nil);
    }
}
impl goish::io::Reader for capture {
    fn Read(&mut self, _p: &mut slice<u8>) -> (int, goish::error) {
        return (0, errors::nil);
    }
}
impl goish::io::Closer for capture {
    fn Close(&mut self) -> goish::error {
        return errors::nil;
    }
}

/// Render bytes as Go's "% x" does, so a mismatch is readable.
fn hex(b: &[u8]) -> string {
    const HEXD: &[u8; 16] = b"0123456789abcdef";
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            v.push(b' ');
        }
        v.push(HEXD[(x >> 4) as usize]);
        v.push(HEXD[(x & 15) as usize]);
    }
    return string::from_bytes(&v[..]);
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

fn newCap() -> (capture, Arc<fcgi::conn>) {
    let cap = capture(Arc::new(goish::sync::Mutex::new(alloc::vec::Vec::new())));
    let c = fcgi::newConn(Box::new(cap.clone()));
    return (cap, c);
}

fn wrote(cap: &capture) -> string {
    let g = cap.0.Lock();
    return hex(&g[..]);
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    // writeRecord — header framing plus the pad-to-8 rule.
    let cases: [(&str, &str); 4] = [
        ("", "01 06 00 01 00 00 00 00"),
        ("a", "01 06 00 01 00 01 07 00 61 00 00 00 00 00 00 00"),
        ("hello", "01 06 00 01 00 05 03 00 68 65 6c 6c 6f 00 00 00"),
        ("12345678", "01 06 00 01 00 08 00 00 31 32 33 34 35 36 37 38"),
    ];
    for (body, want) in cases.iter() {
        let (cap, c) = newCap();
        let err = c.writeRecord(
            fcgi::typeStdout,
            1,
            &slice::<u8>::__from_vec(body.as_bytes().to_vec()),
        );
        if err != errors::nil {
            fmt::Println!("FAIL writeRecord err ", err.Error());
            bad += 1;
            continue;
        }
        eq(wrote(&cap), want, "writeRecord", &mut bad);
    }

    // writeEndRequest — appStatus 200 big-endian, then protocolStatus.
    {
        let (cap, c) = newCap();
        let _ = c.writeEndRequest(7, 200, 0);
        eq(
            wrote(&cap),
            "01 03 00 07 00 08 00 00 00 00 00 c8 00 00 00 00",
            "writeEndRequest",
            &mut bad,
        );
    }

    // writePairs — one pair, then the empty record that ends the stream.
    {
        let (cap, c) = newCap();
        let mut m: map<string, string> = map::new();
        m.Set(string("KEY"), string("value"));
        let _ = fcgi::writePairs(&c, fcgi::typeParams, 3, &m);
        eq(
            wrote(&cap),
            "01 04 00 03 00 0a 06 00 03 05 4b 45 59 76 61 6c 75 65 00 00 00 00 00 00 01 04 00 03 00 00 00 00",
            "writePairs",
            &mut bad,
        );
    }

    // record.read round-trips what writeRecord produced.
    {
        let (cap, c) = newCap();
        let _ = c.writeRecord(
            fcgi::typeStdin,
            42,
            &slice::<u8>::__from_vec(b"payload".to_vec()),
        );
        let raw = { cap.0.Lock().clone() };
        let mut r = goish::bytes::NewReader(slice::<u8>::__from_vec(raw));
        let mut rec = fcgi::record::new();
        let err = rec.read(&mut r);
        if err != errors::nil {
            fmt::Println!("FAIL record.read ", err.Error());
            bad += 1;
        } else {
            if rec.h.Type != fcgi::typeStdin || rec.h.Id != 42 || rec.h.ContentLength != 7 {
                fmt::Println!("FAIL record.read header");
                bad += 1;
            }
            eq(
                string::from_bytes(&rec.content()),
                "payload",
                "record.content",
                &mut bad,
            );
        }
    }

    if bad == 0 {
        fmt::Println!("FCGI_WIRE_OK 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
