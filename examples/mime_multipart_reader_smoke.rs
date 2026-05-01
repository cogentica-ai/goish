// mime_multipart_reader_smoke — round-trip Writer → Reader and exercise
// boundary parsing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::convert::bytes;
use goish::errors;
use goish::io;
use goish::mime::multipart;
use goish::types::byte;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Round-trip: Writer assembles two fields + one file, Reader
    //    reproduces them.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let boundary;
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("MYBOUNDARY"));
            boundary = w.Boundary();
            let _ = w.WriteField(string("name"), string("alice"));
            let _ = w.WriteField(string("age"), string("30"));
            let _ = w.WriteFile(string("avatar"), string("a.png"), bytes("PNGBYTES"));
            let _ = w.Close();
        }
        let on_wire = buf.Bytes();
        // Copy out as a fresh slice<byte> for the Reader.
        let mut body_v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
        for i in 0..on_wire.Len() {
            body_v.push(on_wire[i]);
        }
        let body = goish::goslice::slice::<u8>::__from_vec(body_v);

        let mut r = multipart::NewReader(body, boundary);
        let mut parts: Vec<multipart::Part> = Vec::new();
        loop {
            let (p, err) = r.NextPart();
            if !err.IsNil() {
                if errors::Is(err.clone(), io::EOF()) {
                    break;
                }
                Println!("[ 1] reader err {}", err.Error());
                failed += 1;
                break;
            }
            parts.push(p);
        }

        let names_ok = parts.len() == 3
            && parts[0].FormName() == "name"
            && parts[1].FormName() == "age"
            && parts[2].FormName() == "avatar"
            && parts[2].FileName() == "a.png";
        let bodies_ok = parts.len() == 3
            && body_str(&parts[0].Body) == "alice"
            && body_str(&parts[1].Body) == "30"
            && body_str(&parts[2].Body) == "PNGBYTES";

        if names_ok && bodies_ok {
            Println!("[ 1] round-trip 3 parts        PASS");
        } else {
            Println!(
                "[ 1] round-trip 3 parts        FAIL n={} names_ok={} bodies_ok={}",
                parts.len(),
                names_ok,
                bodies_ok
            );
            failed += 1;
        }
    }

    // 2. Hand-built body: two simple parts, no preamble.
    {
        let raw =
            "--B\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nhello\r\n--B\r\nContent-Disposition: form-data; name=\"y\"\r\n\r\nworld\r\n--B--\r\n";
        let body = bytes(string(raw));
        let mut r = multipart::NewReader(body, string("B"));
        let (p1, e1) = r.NextPart();
        let (p2, e2) = r.NextPart();
        let (_, e3) = r.NextPart();
        let ok = e1.IsNil() && e2.IsNil()
            && p1.FormName() == "x" && body_str(&p1.Body) == "hello"
            && p2.FormName() == "y" && body_str(&p2.Body) == "world"
            && errors::Is(e3, io::EOF());
        if ok {
            Println!("[ 2] hand-built body           PASS");
        } else {
            Println!("[ 2] hand-built body           FAIL");
            failed += 1;
        }
    }

    // 3. Preamble before first boundary is skipped.
    {
        let raw =
            "preamble text--B\r\n--B\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nvee\r\n--B--\r\n";
        let body = bytes(string(raw));
        let mut r = multipart::NewReader(body, string("B"));
        let (p, err) = r.NextPart();
        if err.IsNil() && p.FormName() == "k" && body_str(&p.Body) == "vee" {
            Println!("[ 3] preamble skipped          PASS");
        } else {
            Println!("[ 3] preamble skipped          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 3", failed);
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
