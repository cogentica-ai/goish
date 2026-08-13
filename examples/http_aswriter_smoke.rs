// http_aswriter_smoke — a ResponseWriter used where an io.Writer is wanted.
//
// In Go this needs no adapter and no test: `http.ResponseWriter`'s
// method set contains `Write([]byte) (int, error)`, so it satisfies
// `io.Writer` structurally, and fs.go's serveContent hands `w` straight
// to `io.CopyN`.
//
// goish's ResponseWriter::Write takes `&self` — a response writer is
// shared and interior-mutable — while io::Writer::Write takes
// `&mut self`, so the two do not unify and a blanket impl would overlap
// the existing Box/Arc<Mutex> impls. `http::AsWriter(w)` carries one to
// the other, and this checks that bytes written through the io::Writer
// view actually reach the response body.
//
// Both directions are exercised: a direct `Write` through the adapter,
// and `io::Copy` from a reader, which is the shape serveContent needs.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::io;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::response::ResponseWriter;
use goish::strings;
use goish::{fmt, slice, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Bytes written through the io::Writer view reach the body.
    {
        let rec = httptest::NewRecorder();
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
            let mut aw = http::AsWriter(w);
            let (n, err) = io::Writer::Write(&mut aw, slice::from(b"hello ".as_slice()));
            if err != goish::nil || n != 6 {
                fmt::Println!("[1] direct Write  FAIL n=", n);
                failed += 1;
            }
        }
        if string::from_bytes(&rec.Body()) == "hello " {
            fmt::Println!("[1] direct Write through AsWriter  PASS");
        } else {
            fmt::Println!("[1] direct Write through AsWriter  FAIL got: ", string::from_bytes(&rec.Body()));
            failed += 1;
        }
    }

    // 2. io::Copy into it — the shape serveContent needs, where the
    //    destination is a ResponseWriter and the source is the file.
    {
        let rec = httptest::NewRecorder();
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
            let mut aw = http::AsWriter(w);
            let mut src = strings::NewReader(string("copied body"));
            let (n, err) = io::Copy(&mut aw, &mut src);
            if err != goish::nil || n != 11 {
                fmt::Println!("[2] io::Copy  FAIL n=", n);
                failed += 1;
            }
        }
        if string::from_bytes(&rec.Body()) == "copied body" {
            fmt::Println!("[2] io::Copy into a ResponseWriter  PASS");
        } else {
            fmt::Println!("[2] io::Copy into a ResponseWriter  FAIL got: ", string::from_bytes(&rec.Body()));
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 2");
        syscall::Exit(1);
    }
}
