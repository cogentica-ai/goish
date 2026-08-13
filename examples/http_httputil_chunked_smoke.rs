// http_httputil_chunked_smoke — exercise httputil::NewChunkedReader/
// NewChunkedWriter/ErrLineTooLong + Request::ProtoAtLeast.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::convert::bytes;
use goish::io::{Closer, Reader, Writer};
use goish::net::http;
use goish::net::http::httputil;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Round-trip body via httputil::NewChunkedWriter →
    //    httputil::NewChunkedReader. The dechunked output must match
    //    the original body byte-for-byte.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        {
            let mut cw = httputil::NewChunkedWriter(&mut buf);
            let _ = cw.Write(bytes("hello "));
            let _ = cw.Write(bytes("world"));
            let _ = cw.Close();
        }
        // Close emits the terminating "0\r\n" but not the final "\r\n";
        // we must add it before handing the buffer to a reader.
        let _ = buf.Write(bytes("\r\n"));

        let on_wire = buf.Bytes();
        let mut wire_v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
        for i in 0..on_wire.Len() {
            wire_v.push(on_wire[i]);
        }
        let s = goish::string::from_bytes(&wire_v);
        let has_chunks = goish::strings::Contains(s.clone(), string("6\r\nhello \r\n"))
            && goish::strings::Contains(s.clone(), string("5\r\nworld\r\n"))
            && goish::strings::Contains(s.clone(), string("0\r\n"));
        if has_chunks {
            fmt::Println!("[ 1] httputil writer wire      PASS");
        } else {
            fmt::Println!("[ 1] httputil writer wire      FAIL");
            failed += 1;
        }

        let buf2 = goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(wire_v));
        let mut rdr = httputil::NewChunkedReader(buf2);
        let mut decoded: Vec<u8> = Vec::new();
        loop {
            let mut dst = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 32]);
            let (n, err) = rdr.Read(&mut dst);
            for i in 0..n {
                decoded.push(dst[i as i64]);
            }
            if !err.IsNil() {
                break;
            }
            if n == 0 {
                break;
            }
        }
        let got = goish::string::from_bytes(&decoded);
        if got == "hello world" {
            fmt::Println!("[ 2] httputil reader round-tr  PASS");
        } else {
            fmt::Println!("[ 2] httputil reader round-tr  FAIL got=", got);
            failed += 1;
        }
    }

    // 3. ErrLineTooLong carries GO's message, verbatim.
    //
    //    goish used to prefix every chunked error with "http: ". Go does
    //    not — internal/chunked.go:21 is
    //    `errors.New("header line too long")`. A caller comparing the
    //    text, which is the only thing an errors.New sentinel exposes
    //    across a package boundary, would not have matched.
    {
        let e: goish::error = httputil::ErrLineTooLong.into();
        if !e.IsNil() && e.Error() == "header line too long" {
            fmt::Println!("[ 3] ErrLineTooLong            PASS");
        } else {
            fmt::Println!("[ 3] ErrLineTooLong            FAIL msg=", e.Error());
            failed += 1;
        }
    }

    // 4. Request::ProtoAtLeast: HTTP/1.1 should be >= 1.0 and >= 1.1.
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), bytes(""));
        r.ProtoMajor = 1;
        r.ProtoMinor = 1;
        let ok10 = r.ProtoAtLeast(1, 0);
        let ok11 = r.ProtoAtLeast(1, 1);
        let not12 = !r.ProtoAtLeast(1, 2);
        let not2 = !r.ProtoAtLeast(2, 0);
        if ok10 && ok11 && not12 && not2 {
            fmt::Println!("[ 4] ProtoAtLeast HTTP/1.1     PASS");
        } else {
            fmt::Println!("[ 4] ProtoAtLeast HTTP/1.1     FAIL");
            failed += 1;
        }
    }

    // 5. Request::ProtoAtLeast on HTTP/2.0.
    {
        let (mut r, _) = http::NewRequest(string("GET"), string("http://example.com/"), bytes(""));
        r.ProtoMajor = 2;
        r.ProtoMinor = 0;
        let ok11 = r.ProtoAtLeast(1, 1);
        let ok20 = r.ProtoAtLeast(2, 0);
        let not21 = !r.ProtoAtLeast(2, 1);
        if ok11 && ok20 && not21 {
            fmt::Println!("[ 5] ProtoAtLeast HTTP/2.0     PASS");
        } else {
            fmt::Println!("[ 5] ProtoAtLeast HTTP/2.0     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
