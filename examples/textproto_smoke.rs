// textproto_smoke — exercise net/textproto.
// (net/textproto/header.go + writer.go + textproto.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bufio;
use goish::bytes;
use goish::errors;
use goish::net::textproto::{
    self, Add, CanonicalMIMEHeaderKey, Del, Error, Get, MIMEHeader, NewWriter, ProtocolError, Set,
    TrimBytes, TrimString, Values,
};
use goish::types::int;
use goish::{bytes as bytes_helper, errors as errors_helper, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. TrimString strips leading/trailing ASCII space.
    {
        let s = TrimString(string("  hello world\t\n\r"));
        if s == "hello world" {
            Println!("[ 1] TrimString               PASS");
        } else {
            Println!("[ 1] TrimString               FAIL got {}", s);
            failed += 1;
        }
    }

    // 2. TrimBytes equivalent.
    {
        let b = goish::convert::bytes("\t  abc \n");
        let trimmed = TrimBytes(b);
        let raw: &[goish::types::byte] = &trimmed;
        if raw == b"abc" {
            Println!("[ 2] TrimBytes                PASS");
        } else {
            Println!("[ 2] TrimBytes                FAIL");
            failed += 1;
        }
    }

    // 3. CanonicalMIMEHeaderKey lowercases except first letter and post-dash.
    {
        let k = CanonicalMIMEHeaderKey(string("content-type"));
        let k2 = CanonicalMIMEHeaderKey(string("ACCEPT-encoding"));
        if k == "Content-Type" && k2 == "Accept-Encoding" {
            Println!("[ 3] Canonical key            PASS");
        } else {
            Println!("[ 3] Canonical key            FAIL");
            failed += 1;
        }
    }

    // 4. MIMEHeader Add appends; Get returns first; Values returns all.
    {
        let mut h: MIMEHeader = goish::gomap::map::new();
        Add(&mut h, string("foo"), string("a"));
        Add(&mut h, string("FOO"), string("b"));
        let g = Get(&h, string("foo"));
        let vs = Values(&h, string("Foo"));
        if g == "a" && vs.Len() == 2 && vs[0] == "a" && vs[1] == "b" {
            Println!("[ 4] Add/Get/Values           PASS");
        } else {
            Println!("[ 4] Add/Get/Values           FAIL");
            failed += 1;
        }
    }

    // 5. MIMEHeader Set replaces.
    {
        let mut h: MIMEHeader = goish::gomap::map::new();
        Add(&mut h, string("X"), string("old"));
        Add(&mut h, string("X"), string("ignored"));
        Set(&mut h, string("x"), string("new"));
        let vs = Values(&h, string("X"));
        if vs.Len() == 1 && vs[0] == "new" {
            Println!("[ 5] Set replaces             PASS");
        } else {
            Println!("[ 5] Set replaces             FAIL n={}", vs.Len());
            failed += 1;
        }
    }

    // 6. MIMEHeader Del removes.
    {
        let mut h: MIMEHeader = goish::gomap::map::new();
        Add(&mut h, string("X"), string("v"));
        Del(&mut h, string("x"));
        if Get(&h, string("X")) == "" {
            Println!("[ 6] Del                      PASS");
        } else {
            Println!("[ 6] Del                      FAIL");
            failed += 1;
        }
    }

    // 7. Get on empty header returns "".
    {
        let h: MIMEHeader = goish::gomap::map::new();
        if Get(&h, string("missing")) == "" {
            Println!("[ 7] Get missing              PASS");
        } else {
            Println!("[ 7] Get missing              FAIL");
            failed += 1;
        }
    }

    // 8. Error.Error() uses %03d format.
    {
        let e = Error {
            Code: 42,
            Msg: string("not found"),
        };
        use goish::errors::ErrorTrait;
        let s = e.Error();
        if s == "042 not found" {
            Println!("[ 8] Error %03d format        PASS");
        } else {
            Println!("[ 8] Error %03d format        FAIL got {}", s);
            failed += 1;
        }
    }

    // 9. ProtocolError.Error() returns its string.
    {
        let p = ProtocolError(string("oops"));
        use goish::errors::ErrorTrait;
        let s = p.Error();
        if s == "oops" {
            Println!("[ 9] ProtocolError            PASS");
        } else {
            Println!("[ 9] ProtocolError            FAIL");
            failed += 1;
        }
    }

    // 10. Writer.PrintfLine writes with \r\n.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let bw = bufio::NewWriter(&mut buf);
        let mut w = NewWriter(bw);
        let _ = w.PrintfLine(string("HELLO 1"));
        let s = buf.String();
        if s == "HELLO 1\r\n" {
            Println!("[10] PrintfLine \\r\\n          PASS");
        } else {
            Println!("[10] PrintfLine \\r\\n          FAIL got {}", s);
            failed += 1;
        }
    }

    // 11. DotWriter emits dotcrnl after empty body.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let bw = bufio::NewWriter(&mut buf);
        let mut w = NewWriter(bw);
        {
            let dw = w.DotWriter();
            let _ = dw.Close();
        }
        let s = buf.String();
        if s == ".\r\n" {
            Println!("[11] DotWriter empty           PASS");
        } else {
            Println!("[11] DotWriter empty           FAIL got {:?}", s.Len());
            failed += 1;
        }
    }

    // 12. DotWriter escapes leading dot + emits trailer.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let bw = bufio::NewWriter(&mut buf);
        let mut w = NewWriter(bw);
        {
            let mut dw = w.DotWriter();
            let _ = dw.Write(goish::convert::bytes(".dotted\n"));
            let _ = dw.Close();
        }
        let s = buf.String();
        // Expected: "..dotted\r\n.\r\n" — leading dot doubled; \n→\r\n;
        // closer adds .\r\n on a fresh line.
        if s == "..dotted\r\n.\r\n" {
            Println!("[12] DotWriter dot escape      PASS");
        } else {
            Println!("[12] DotWriter dot escape      FAIL got len={}", s.Len());
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
