// http_fcgi_smoke — net/http/fcgi/fcgi.go's wire codec: encodeSize
// (:219), readSize (:196), readString (:212), header.init (:92) and
// beginRequest.read (:79).
//
// This is a wire protocol, so the assertions are on BYTES, and every
// one is Go 1.25.5 output via scripts/goref.sh net/http/fcgi.
//
// The two rules that a plausible implementation gets wrong:
//
//   * The length prefix is variable width. 0..127 encodes in one byte;
//     anything larger takes four with bit 31 SET as the wide-form
//     marker — so 128 is "80 00 00 80", not "00 00 00 80". readSize
//     masks that bit off again, which is why the round trip is exact
//     up to 2^31-1.
//   * header.init pads the body to a multiple of 8 via `-len & 7`,
//     two's-complement negation on the byte. A 1-byte body pads SEVEN,
//     an 8-byte body pads zero, and 65535 pads one. Reading it as
//     `len % 8` gives the complement and desynchronises the stream.
//
// Both short-buffer paths return (0, 0) rather than an error: the
// caller distinguishes "nothing decoded" by the zero width.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::net::http::fcgi::fcgi::{
    beginRequest, encodeSize, header, readSize, readString, typeStdout,
};
use goish::{fmt, string, syscall};

fn buf(n: usize) -> slice<goish::types::byte> {
    return slice::__from_vec(alloc::vec![0u8; n]);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. encodeSize/readSize round trip, with the exact wire bytes.
    {
        let cases: &[(u32, i64, &[u8])] = &[
            (0, 1, &[0x00]),
            (1, 1, &[0x01]),
            (127, 1, &[0x7f]),
            (128, 4, &[0x80, 0x00, 0x00, 0x80]),
            (255, 4, &[0x80, 0x00, 0x00, 0xff]),
            (65535, 4, &[0x80, 0x00, 0xff, 0xff]),
            (1048576, 4, &[0x80, 0x10, 0x00, 0x00]),
            (2147483647, 4, &[0xff, 0xff, 0xff, 0xff]),
        ];
        let mut bad = 0;
        for (n, wantW, wantBytes) in cases {
            let mut b = buf(8);
            let w = encodeSize(&mut b, *n);
            if w != *wantW {
                fmt::Println!("     encodeSize(", *n as i64, ") width=", w);
                bad += 1;
                continue;
            }
            let enc = b.slice(0, w);
            for i in 0..(w as usize) {
                if enc[i as i64] != wantBytes[i] {
                    fmt::Println!("     encodeSize(", *n as i64, ") byte ", i as i64, " wrong");
                    bad += 1;
                }
            }
            let (got, rn) = readSize(enc);
            if got != *n || rn != *wantW {
                fmt::Println!("     readSize round trip ", *n as i64, " -> ", got as i64);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[1] encodeSize/readSize, 8 sizes vs Go bytes  PASS");
        } else {
            failed += 1;
        }
    }

    // 2. Short buffers decode to (0, 0), not an error.
    {
        let (a, an) = readSize(slice::new());
        let (b, bn) = readSize(slice::from([0x80u8, 0, 0].as_slice()));
        if a == 0 && an == 0 && b == 0 && bn == 0 {
            fmt::Println!("[2] readSize short buffers -> (0,0)  PASS");
        } else {
            fmt::Println!("[2] readSize short buffers  FAIL");
            failed += 1;
        }
    }

    // 3. readString truncates, and returns "" on overrun.
    {
        let s = readString(slice::from(b"abcdef".as_slice()), 3);
        let o = readString(slice::from(b"abc".as_slice()), 9);
        if s == "abc" && o == "" {
            fmt::Println!("[3] readString  PASS");
        } else {
            fmt::Println!("[3] readString  FAIL got=", s, " overrun=", o);
            failed += 1;
        }
    }

    // 4. header.init — padding is `-len & 7`, not `len % 8`.
    {
        let cases: &[(i64, u8)] = &[
            (0, 0), (1, 7), (7, 1), (8, 0), (9, 7), (15, 1), (16, 0), (65535, 1),
        ];
        let mut bad = 0;
        for (cl, wantPad) in cases {
            let mut h = header::default();
            h.init(typeStdout, 7, *cl);
            if h.Version != 1
                || h.Type != typeStdout
                || h.Id != 7
                || h.ContentLength != (*cl as u16)
                || h.PaddingLength != *wantPad
            {
                fmt::Println!("     header.init(cl=", *cl, ") pad=", h.PaddingLength as i64);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[4] header.init, 8 lengths vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 5. beginRequest.read requires exactly 8 bytes.
    {
        let mut br = beginRequest::default();
        let e = br.read(slice::from([0u8, 1, 1, 0, 0, 0, 0, 0].as_slice()));
        let ok1 = e == goish::nil && br.role == 1 && br.flags == 1;
        let mut br2 = beginRequest::default();
        let e2 = br2.read(slice::from([0u8, 1].as_slice()));
        let ok2 = e2 != goish::nil && e2.Error() == "fcgi: invalid begin request record";
        if ok1 && ok2 {
            fmt::Println!("[5] beginRequest.read  PASS");
        } else {
            fmt::Println!("[5] beginRequest.read  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 5");
        syscall::Exit(1);
    }
}
