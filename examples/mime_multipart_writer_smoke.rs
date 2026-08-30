// mime_multipart_writer_smoke — exercise mime/multipart::Writer.
// (mime/multipart/writer.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_multipart_writer_ref.go` run inside
// mime/multipart by `scripts/goref.sh`. The writer's output is fully
// determined once `SetBoundary` fixes the boundary, so the whole
// message is compared byte-for-byte.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string as gostring;
use goish::mime::multipart;
use goish::net::http::Header;
use goish::string;
use goish::syscall;
use goish::types::byte;

fn newbuf() -> goish::bytes::Buffer {
    return goish::bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
}

fn gbytes(s: &gostring) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

fn errtext(e: &goish::errors::error) -> Vec<byte> {
    if e.IsNil() {
        return Vec::new();
    }
    return gbytes(&e.Error());
}

// Go's SetBoundary accept/reject table: (boundary, error text).
const BOUNDARIES: [(&str, &str); 12] = [
    ("", "mime: invalid boundary length"),
    ("x", ""),
    ("abcDEF012", ""),
    ("'()+_,-./:=?", ""),
    ("has space", ""),
    ("trailing ", "mime: invalid boundary character"),
    (" leading", ""),
    ("has\ttab", "mime: invalid boundary character"),
    ("has\"quote", "mime: invalid boundary character"),
    ("has@at", "mime: invalid boundary character"),
    (
        "0123456789012345678901234567890123456789012345678901234567890123456789",
        "",
    ),
    (
        "01234567890123456789012345678901234567890123456789012345678901234567890",
        "mime: invalid boundary length",
    ),
];

// Go's FormDataContentType quoting table.
const CONTENT_TYPES: [(&str, &str); 5] = [
    ("simple", "multipart/form-data; boundary=simple"),
    ("has space", "multipart/form-data; boundary=\"has space\""),
    ("has=eq", "multipart/form-data; boundary=\"has=eq\""),
    ("has(paren", "multipart/form-data; boundary=\"has(paren\""),
    ("abcDEF012", "multipart/form-data; boundary=abcDEF012"),
];

// The whole message Go writes for the four parts assembled in check 5.
const WANT_MESSAGE: &[u8] = b"--BOUNDARY\r\n\
Content-Disposition: form-data; name=\"alpha\"\r\n\
\r\n\
one\r\n\
--BOUNDARY\r\n\
Content-Disposition: form-data; name=\"we\\\"ird\\\\name\"\r\n\
\r\n\
two\r\n\
--BOUNDARY\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"my\\\"file\\\\.txt\"\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
FILE BODY\r\n\
--BOUNDARY\r\n\
A-First: a\r\n\
A-First: a2\r\n\
M-Middle: m\r\n\
Z-Last: z\r\n\
\r\n\
raw body\r\n\
--BOUNDARY--\r\n";

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. NewWriter's boundary is 30 random bytes as 60 hex digits, and
    //    two writers do not share one.
    {
        let mut b1 = newbuf();
        let mut b2 = newbuf();
        let a = multipart::NewWriter(&mut b1).Boundary();
        let b = multipart::NewWriter(&mut b2).Boundary();
        let a_raw = gbytes(&a);
        let mut hexonly = true;
        for c in a_raw.iter() {
            if !((*c >= b'0' && *c <= b'9') || (*c >= b'a' && *c <= b'f')) {
                hexonly = false;
            }
        }
        if a.Len() == 60 && b.Len() == 60 && hexonly && a_raw != gbytes(&b) {
            fmt::Println!("[ 1] randomBoundary shape     PASS");
        } else {
            fmt::Println!("[ 1] randomBoundary shape     FAIL");
            failed += 1;
        }
    }

    // 2. SetBoundary's RFC 2046 §5.1.1 rules, against Go. A space is
    //    legal anywhere but at the end, which is the case a rewrite of
    //    the loop usually gets backwards.
    {
        let mut ok = true;
        let mut i = 0;
        while i < BOUNDARIES.len() {
            let (b, want) = BOUNDARIES[i];
            let mut buf = newbuf();
            let mut w = multipart::NewWriter(&mut buf);
            let err = w.SetBoundary(string(b));
            if errtext(&err) != want.as_bytes().to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] SetBoundary 12 vectors   PASS");
        } else {
            fmt::Println!("[ 2] SetBoundary 12 vectors   FAIL");
            failed += 1;
        }
    }

    // 3. SetBoundary after a part exists is refused.
    {
        let mut buf = newbuf();
        let mut w = multipart::NewWriter(&mut buf);
        let _ = w.SetBoundary(string("B"));
        {
            let (_p, _e) = w.CreateFormField(string("f"));
        }
        let err = w.SetBoundary(string("C"));
        if errtext(&err) == b"mime: SetBoundary called after write".to_vec() {
            fmt::Println!("[ 3] SetBoundary after write  PASS");
        } else {
            fmt::Println!("[ 3] SetBoundary after write  FAIL");
            failed += 1;
        }
    }

    // 4. FormDataContentType quotes the boundary only when it holds one
    //    of RFC 2045's tspecials, or a space.
    {
        let mut ok = true;
        let mut i = 0;
        while i < CONTENT_TYPES.len() {
            let (b, want) = CONTENT_TYPES[i];
            let mut buf = newbuf();
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string(b));
            if gbytes(&w.FormDataContentType()) != want.as_bytes().to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] FormDataContentType      PASS");
        } else {
            fmt::Println!("[ 4] FormDataContentType      FAIL");
            failed += 1;
        }
    }

    // 5. A whole message, byte-for-byte against Go: two fields (the
    //    second with a quote and a backslash in its name), a file part,
    //    and a raw part whose headers were set out of order — Go emits
    //    them in sorted key order, with repeated values kept in
    //    insertion order.
    {
        let mut buf = newbuf();
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("BOUNDARY"));
            let _ = w.WriteField(string("alpha"), string("one"));
            let _ = w.WriteField(string("we\"ird\\name"), string("two"));
            {
                let (mut fw, _) = w.CreateFormFile(string("upload"), string("my\"file\\.txt"));
                let _ = fw.Write(to_bytes("FILE BODY"));
            }
            {
                let mut h = Header::new();
                h.Set(string("Z-Last"), string("z"));
                h.Set(string("A-First"), string("a"));
                h.Add(string("A-First"), string("a2"));
                h.Set(string("M-Middle"), string("m"));
                let (mut pw, _) = w.CreatePart(h);
                let _ = pw.Write(to_bytes("raw body"));
            }
            let _ = w.Close();
        }
        if gbytes(&buf.String()) == WANT_MESSAGE.to_vec() {
            fmt::Println!("[ 5] full message vs Go       PASS");
        } else {
            fmt::Println!("[ 5] full message vs Go       FAIL");
            failed += 1;
        }
    }

    // 6. Close with no parts still writes the terminating line — and it
    //    starts with CRLF, which is what makes an empty body legal.
    {
        let mut buf = newbuf();
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("B"));
            let _ = w.Close();
        }
        if gbytes(&buf.String()) == b"\r\n--B--\r\n".to_vec() {
            fmt::Println!("[ 6] Close with no parts      PASS");
        } else {
            fmt::Println!("[ 6] Close with no parts      FAIL");
            failed += 1;
        }
    }

    // 7. FileContentDisposition, including the escaping.
    {
        let a = multipart::FileContentDisposition(string("field"), string("name.txt"));
        let b = multipart::FileContentDisposition(string("a\"b"), string("c\\d"));
        if gbytes(&a) == b"form-data; name=\"field\"; filename=\"name.txt\"".to_vec()
            && gbytes(&b) == b"form-data; name=\"a\\\"b\"; filename=\"c\\\\d\"".to_vec()
        {
            fmt::Println!("[ 7] FileContentDisposition   PASS");
        } else {
            fmt::Println!("[ 7] FileContentDisposition   FAIL");
            failed += 1;
        }
    }

    // 8. Only the first part omits the leading CRLF; the boundary line
    //    of every later one carries it.
    {
        let mut buf = newbuf();
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("B"));
            let _ = w.WriteField(string("a"), string("1"));
            let _ = w.WriteField(string("b"), string("2"));
            let _ = w.Close();
        }
        let want: &[u8] = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\
\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--B--\r\n";
        if gbytes(&buf.String()) == want.to_vec() {
            fmt::Println!("[ 8] CRLF before later parts  PASS");
        } else {
            fmt::Println!("[ 8] CRLF before later parts  FAIL");
            failed += 1;
        }
    }

    // 9. A part is written to through the handle CreatePart returns, in
    //    as many Writes as the caller likes.
    //
    //    Go's "multipart: can't write to finished part" has no test
    //    here because goish cannot reach it: the handle borrows the
    //    Writer, so holding an old part across the next CreatePart is a
    //    compile error rather than a runtime one.
    {
        let mut buf = newbuf();
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("B"));
            let mut h = Header::new();
            h.Set(string("X"), string("y"));
            let (mut p, err) = w.CreatePart(h);
            let (n1, _) = p.Write(to_bytes("abc"));
            let (n2, _) = p.Write(to_bytes("def"));
            let ok = err.IsNil() && n1 == 3 && n2 == 3;
            drop(p);
            let _ = w.Close();
            if !ok {
                failed += 1;
                fmt::Println!("[ 9] CreatePart multi-Write   FAIL");
            } else if gbytes(&buf.String()) == b"--B\r\nX: y\r\n\r\nabcdef\r\n--B--\r\n".to_vec() {
                fmt::Println!("[ 9] CreatePart multi-Write   PASS");
            } else {
                fmt::Println!("[ 9] CreatePart multi-Write   FAIL");
                failed += 1;
            }
        }
    }

    // 10. WriteFile is goish's CreateFormFile + one Write; its output
    //     must match the equivalent CreateFormFile pair exactly.
    {
        let mut b1 = newbuf();
        {
            let mut w = multipart::NewWriter(&mut b1);
            let _ = w.SetBoundary(string("B"));
            let _ = w.WriteFile(string("f"), string("n.txt"), to_bytes("BODY"));
            let _ = w.Close();
        }
        let mut b2 = newbuf();
        {
            let mut w = multipart::NewWriter(&mut b2);
            let _ = w.SetBoundary(string("B"));
            {
                let (mut p, _) = w.CreateFormFile(string("f"), string("n.txt"));
                let _ = p.Write(to_bytes("BODY"));
            }
            let _ = w.Close();
        }
        if gbytes(&b1.String()) == gbytes(&b2.String()) {
            fmt::Println!("[10] WriteFile == CreateForm  PASS");
        } else {
            fmt::Println!("[10] WriteFile == CreateForm  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
