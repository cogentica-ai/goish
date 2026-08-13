// net/http/cgi child-side `response` writer.
//
// Expected bytes are Go 1.25.5's, captured by driving the real
// unexported `response` struct over a bytes.Buffer inside
// net/http/cgi (goref), exactly as Serve drives it over stdout.
//
// The interesting case is "no body at all": Serve calls Write(nil)
// after the handler returns, which is what forces a Status line and a
// sniffed Content-Type even when the handler wrote nothing.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::sync::Arc;
use goish::net::http;
use goish::net::http::cgi;
use goish::net::http::response::ResponseWriter;
use goish::{fmt, slice, string, syscall};

/// A writer that keeps what was written, so the CGI bytes can be
/// compared instead of going to stdout.
#[derive(Clone)]
#[allow(non_camel_case_types)]
struct capture(Arc<goish::sync::Mutex<alloc::vec::Vec<u8>>>);

impl goish::io::Writer for capture {
    fn Write(&mut self, p: slice<u8>) -> (goish::types::int, goish::error) {
        let n = goish::len(&p);
        self.0.Lock().extend_from_slice(&*p);
        return (n, goish::errors::nil);
    }
}

fn bytesOf(s: &str) -> slice<u8> {
    return slice::<u8>::__from_vec(s.as_bytes().to_vec());
}

/// Drive `response` the way Serve does, and return what it wrote.
fn run(h: &dyn Fn(&cgi::response)) -> string {
    let buf = capture(Arc::new(goish::sync::Mutex::new(alloc::vec::Vec::new())));
    let (req, _) = http::NewRequest(string("GET"), string("http://x/p"), goish::nil);
    let rw = cgi::response::new(&req, Box::new(buf.clone()));
    h(&rw);
    // Serve's "make sure a response is sent".
    let _ = rw.Write(slice::<u8>::new());
    rw.Flush();
    let g = buf.0.Lock();
    return string::from_bytes(&g[..]);
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    eq(
        run(&|w| {
            let _ = w.Write(bytesOf("hello world"));
        }),
        "Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello world",
        "plain body",
        &mut bad,
    );

    eq(
        run(&|w| {
            w.Header()
                .Set(string("Content-Type"), string("application/json"));
            w.WriteHeader(201);
            let _ = w.Write(bytesOf("{\"a\":1}"));
        }),
        "Status: 201 Created\r\nContent-Type: application/json\r\n\r\n{\"a\":1}",
        "explicit type+status",
        &mut bad,
    );

    eq(
        run(&|_w| {}),
        "Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        "no body at all",
        &mut bad,
    );

    eq(
        run(&|w| {
            let _ = w.Write(bytesOf("<html><body>hi</body></html>"));
        }),
        "Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>hi</body></html>",
        "html sniffed",
        &mut bad,
    );

    if bad == 0 {
        fmt::Println!("CGI_CHILD_OK 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
