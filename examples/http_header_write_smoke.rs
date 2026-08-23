// http_header_write_smoke — Header.Write / WriteSubset / get,
// net/http/header.go:85, :186 and :62.
//
// Expected bytes are Go 1.25.5 output, captured by writing the same
// Header inside a writable GOROOT (scripts/goref.sh net/http).
//
// The case that matters is the INVALID NAME. Go guards the write loop
// with httpguts.ValidHeaderFieldName and silently drops any key that
// is not a token — its comment says there is no way to report the
// error back to a handler, so dropping is the behaviour. goish was
// missing that guard, so a key like "Bad Name", or one containing a
// newline, was written to the wire verbatim. That is header
// injection: a value-controlled key ending in CRLF can open a second
// header or a response body.
//
// The rest pins the transformations Go applies per value: newlines and
// carriage returns become spaces (headerNewlineToSpace), the result is
// trimmed (textproto.TrimString), a key with several values emits one
// line each, a key with zero values emits nothing, and keys are
// written in sorted order.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::gomap::map;
use goish::net::http::header::Header;
use goish::{fmt, string, syscall};

fn build() -> Header {
    let mut h = Header::new();
    h.Set(string("Content-Type"), string("text/plain"));
    h.Set(string("X-Zebra"), string("z"));
    h.Set(string("Accept"), string("*/*"));
    h.Set(string("Bad Name"), string("dropped"));
    h.Set(string("Bad\nName2"), string("dropped"));
    h.Set(string("Multi"), string("a"));
    h.Add(string("Multi"), string("b"));
    h.Set(string("Newline-Value"), string("a\nb\rc"));
    h.Set(string("Padded-Value"), string("  spaced  "));
    return h;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Write — sorted, invalid names dropped, values sanitized.
    {
        let want = "Accept: */*\r\n\
                    Content-Type: text/plain\r\n\
                    Multi: a\r\n\
                    Multi: b\r\n\
                    Newline-Value: a b c\r\n\
                    Padded-Value: spaced\r\n\
                    X-Zebra: z\r\n";
        let h = build();
        let mut buf = bytes::Buffer::new();
        let err = h.Write(&mut buf);
        let got = string::from_bytes(&buf.Bytes());
        if err.IsNil() && got == want {
            fmt::Println!("[1] Header.Write matches Go  PASS");
        } else {
            fmt::Println!("[1] Header.Write  FAIL got:\n", got);
            failed += 1;
        }
    }

    // 2. The two invalid names must not appear at all.
    {
        let h = build();
        let mut buf = bytes::Buffer::new();
        let _ = h.Write(&mut buf);
        let got = string::from_bytes(&buf.Bytes());
        if !goish::strings::Contains(got.clone(), string("Bad"))
            && !goish::strings::Contains(got.clone(), string("dropped"))
        {
            fmt::Println!("[2] invalid header names are dropped  PASS");
        } else {
            fmt::Println!("[2] invalid header names LEAKED  FAIL:\n", got);
            failed += 1;
        }
    }

    // 3. WriteSubset excludes by exact key.
    {
        let want = "Content-Type: text/plain\r\n\
                    Multi: a\r\n\
                    Multi: b\r\n\
                    Newline-Value: a b c\r\n\
                    Padded-Value: spaced\r\n";
        let h = build();
        let mut ex: map<string, bool> = map::new();
        ex.Set(string("X-Zebra"), true);
        ex.Set(string("Accept"), true);
        let mut buf = bytes::Buffer::new();
        let err = h.WriteSubset(&mut buf, &ex);
        let got = string::from_bytes(&buf.Bytes());
        if err.IsNil() && got == want {
            fmt::Println!("[3] Header.WriteSubset matches Go  PASS");
        } else {
            fmt::Println!("[3] Header.WriteSubset  FAIL got:\n", got);
            failed += 1;
        }
    }

    // 4. get is a RAW lookup — case-sensitive, unlike Get.
    {
        let h = build();
        if h.get(string("Content-Type")) == "text/plain"
            && h.get(string("content-type")) == ""
            && h.get(string("Nope")) == ""
            && h.Get(string("content-type")) == "text/plain"
        {
            fmt::Println!("[4] Header.get is case-sensitive, Get is not  PASS");
        } else {
            fmt::Println!("[4] Header.get  FAIL");
            failed += 1;
        }
    }

    // 5. CanonicalHeaderKey returns a key with invalid bytes UNCHANGED.
    //    Go: "If s contains a space or invalid header field bytes, it
    //    is returned without modifications." goish used to canonicalize
    //    regardless, turning "Bad Name" into "Bad name" — silently
    //    rewriting the caller's key, and since Set/Get/Add/Del all
    //    canonicalize, storing it under a name never used.
    {
        let cases: &[(&str, &str)] = &[
            ("accept-encoding", "Accept-Encoding"),
            ("ACCEPT-ENCODING", "Accept-Encoding"),
            ("a-b-c", "A-B-C"),
            ("Bad Name", "Bad Name"),
            ("x", "X"),
            ("", ""),
            ("a--b", "A--B"),
            ("-a", "-A"),
            ("a_b", "A_b"),
        ];
        let mut bad = 0;
        for (input, want) in cases {
            let got = goish::net::http::header::CanonicalHeaderKey(string(*input));
            if got != *want {
                fmt::Println!(
                    "     CanonicalHeaderKey(",
                    *input,
                    ") = ",
                    got,
                    " want ",
                    *want
                );
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[5] CanonicalHeaderKey, 9 cases vs Go  PASS");
        } else {
            fmt::Println!("[5] CanonicalHeaderKey  FAIL");
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
