// http_multipart_request_smoke — exercise Request.MultipartReader.
// Builds an in-memory multipart/form-data body via the writer, hands
// it to a Request, then walks the parts via MultipartReader.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::convert::bytes;
use goish::errors;
use goish::io;
use goish::mime::multipart;
use goish::net::http;
use goish::types::byte;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Construct a multipart body and hand it to a Request via the
    //    Body field; MultipartReader should parse out the parts.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let ct;
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("ABCBOUND"));
            ct = w.FormDataContentType();
            let _ = w.WriteField(string("name"), string("alice"));
            let _ = w.WriteFile(string("file"), string("hello.bin"), bytes("PNGBYTES"));
            let _ = w.Close();
        }
        let on_wire = buf.Bytes();
        let mut body_v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
        for i in 0..on_wire.Len() {
            body_v.push(on_wire[i]);
        }
        let body = goish::goslice::slice::<u8>::__from_vec(body_v);

        // Build a Request manually with the assembled body.
        let (mut req, _) =
            http::NewRequest(string("POST"), string("http://x/upload"), bytes(""));
        req.Header.Set(string("Content-Type"), ct);
        req.Body = http::Body::from_bytes(body);

        let (mut mr, err) = req.MultipartReader();
        if !err.IsNil() {
            fmt::Println!("[ 1] MultipartReader err       FAIL");
            failed += 1;
        } else {
            let (p1, e1) = mr.NextPart();
            let (p2, e2) = mr.NextPart();
            let (_, e3) = mr.NextPart();
            let ok = e1.IsNil()
                && p1.FormName() == "name"
                && body_str(&p1.Body) == "alice"
                && e2.IsNil()
                && p2.FormName() == "file"
                && p2.FileName() == "hello.bin"
                && body_str(&p2.Body) == "PNGBYTES"
                && errors::Is(e3, io::EOF);
            if ok {
                fmt::Println!("[ 1] MultipartReader 2 parts   PASS");
            } else {
                fmt::Println!("[ 1] MultipartReader 2 parts   FAIL");
                failed += 1;
            }
        }
    }

    // 2. Non-multipart Content-Type → ErrNotMultipart.
    {
        let (mut req, _) =
            http::NewRequest(string("POST"), string("http://x/u"), bytes("hello"));
        req.Header.Set(string("Content-Type"), string("text/plain"));
        let (_mr, err) = req.MultipartReader();
        if errors::Is(err, http::ErrNotMultipart) {
            fmt::Println!("[ 2] non-multipart err         PASS");
        } else {
            fmt::Println!("[ 2] non-multipart err         FAIL");
            failed += 1;
        }
    }

    // 3. multipart/form-data without boundary → ErrMissingBoundary.
    {
        let (mut req, _) =
            http::NewRequest(string("POST"), string("http://x/u"), bytes("body"));
        req.Header
            .Set(string("Content-Type"), string("multipart/form-data"));
        let (_mr, err) = req.MultipartReader();
        if errors::Is(err, http::ErrMissingBoundary) {
            fmt::Println!("[ 3] missing boundary err      PASS");
        } else {
            fmt::Println!("[ 3] missing boundary err      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 3", failed);
        syscall::Exit(1);
    }
}

fn body_str(body: &goish::slice<byte>) -> goish::string {
    let mut v: Vec<u8> = Vec::with_capacity(body.Len() as usize);
    for i in 0..body.Len() {
        v.push(body[i]);
    }
    goish::string::from_bytes(&v)
}
