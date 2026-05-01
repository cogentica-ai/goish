// http_protocols_smoke — exercise http.Protocols (Go 1.25) + http.NoBody.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::io;
use goish::net::http;
use goish::{make, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Zero value: all protocol bits cleared.
    {
        let p = http::Protocols::new();
        if !p.HTTP1() && !p.HTTP2() && !p.UnencryptedHTTP2() {
            Println!("[ 1] zero is empty             PASS");
        } else {
            Println!("[ 1] zero is empty             FAIL");
            failed += 1;
        }
    }

    // 2. SetHTTP1(true) flips only the HTTP1 bit.
    {
        let mut p = http::Protocols::new();
        p.SetHTTP1(true);
        if p.HTTP1() && !p.HTTP2() && !p.UnencryptedHTTP2() {
            Println!("[ 2] SetHTTP1(true) flips      PASS");
        } else {
            Println!("[ 2] SetHTTP1(true) flips      FAIL");
            failed += 1;
        }
    }

    // 3. SetHTTP1(false) clears the HTTP1 bit (idempotent on zero).
    {
        let mut p = http::Protocols::new();
        p.SetHTTP1(true);
        p.SetHTTP1(false);
        if !p.HTTP1() {
            Println!("[ 3] SetHTTP1(false) clears    PASS");
        } else {
            Println!("[ 3] SetHTTP1(false) clears    FAIL");
            failed += 1;
        }
    }

    // 4. HTTP2 + UnencryptedHTTP2 are independent bits.
    {
        let mut p = http::Protocols::new();
        p.SetHTTP2(true);
        p.SetUnencryptedHTTP2(true);
        if p.HTTP2() && p.UnencryptedHTTP2() && !p.HTTP1() {
            Println!("[ 4] HTTP2 bits independent    PASS");
        } else {
            Println!("[ 4] HTTP2 bits independent    FAIL");
            failed += 1;
        }
    }

    // 5. String format on empty set: "{}".
    {
        let p = http::Protocols::new();
        if p.String() == "{}" {
            Println!("[ 5] String() empty            PASS");
        } else {
            Println!("[ 5] String() empty            FAIL got={}", p.String());
            failed += 1;
        }
    }

    // 6. String format on full set: "{HTTP1,HTTP2,UnencryptedHTTP2}".
    {
        let mut p = http::Protocols::new();
        p.SetHTTP1(true);
        p.SetHTTP2(true);
        p.SetUnencryptedHTTP2(true);
        let s = p.String();
        if s == "{HTTP1,HTTP2,UnencryptedHTTP2}" {
            Println!("[ 6] String() full             PASS");
        } else {
            Println!("[ 6] String() full             FAIL got={}", s);
            failed += 1;
        }
    }

    // 7. String format on mixed: only HTTP1 + UnencryptedHTTP2 set.
    {
        let mut p = http::Protocols::new();
        p.SetHTTP1(true);
        p.SetUnencryptedHTTP2(true);
        let s = p.String();
        if s == "{HTTP1,UnencryptedHTTP2}" {
            Println!("[ 7] String() mixed            PASS");
        } else {
            Println!("[ 7] String() mixed            FAIL got={}", s);
            failed += 1;
        }
    }

    // 8. NoBody.Read returns (0, EOF).
    {
        let mut nb = http::NoBody();
        let mut buf = make!([]goish::byte, 16);
        let (n, err) = io::Reader::Read(&mut nb, &mut buf);
        if n == 0 && errors::Is(err, io::EOF()) {
            Println!("[ 8] NoBody.Read=(0,EOF)       PASS");
        } else {
            Println!("[ 8] NoBody.Read=(0,EOF)       FAIL n={}", n);
            failed += 1;
        }
    }

    // 9. NoBody.Close returns nil.
    {
        let mut nb = http::NoBody();
        let err = io::Closer::Close(&mut nb);
        if err.IsNil() {
            Println!("[ 9] NoBody.Close=nil          PASS");
        } else {
            Println!("[ 9] NoBody.Close=nil          FAIL");
            failed += 1;
        }
    }

    // 10. NoBody.WriteTo returns (0, nil) without touching the writer.
    {
        let mut nb = http::NoBody();
        let mut buf = goish::bytes::NewBuffer(make!([]goish::byte, 0));
        let (n, err) = io::WriterTo::WriteTo(&mut nb, &mut buf);
        if n == 0 && err.IsNil() && buf.Len() == 0 {
            Println!("[10] NoBody.WriteTo=(0,nil)    PASS");
        } else {
            Println!("[10] NoBody.WriteTo=(0,nil)    FAIL n={} buflen={}", n, buf.Len());
            failed += 1;
        }
    }

    // 11. Suppress unused-import warning for `string` in cargo lint pass.
    let _ = string("ok");

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
