// The response status line, byte-for-byte against Go 1.25.5.
//
// Expected values from a goref run of the unexported writeStatusLine.
//
// The case that matters is a NON-STANDARD status code. Go falls back
// to `fmt.Fprintf(bw, "%03d status code %d\r\n", code, code)`:
//
//   Go:    "HTTP/1.1 599 status code 599\r\n"
//   goish: "HTTP/1.1 599 Status\r\n"          (before this port)
//
// goish substituted the literal word "Status", so every response with
// a vendor-specific code went onto the wire with a status line Go
// would never produce. This reads the RAW SOCKET rather than going
// through a client, because a client parses the reason phrase away.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::{errors, fmt, io, net, slice, string, syscall};

fn firstLine(port: string, path: &'static str) -> string {
    let (mut c, err) = net::Dial(string("tcp"), port);
    if err != errors::nil {
        return string("dial error: ") + err.Error();
    }
    let req = string("GET ") + string(path) + string(" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let _ = io::Writer::Write(&mut c, slice::<u8>::__from_vec(req.as_bytes().to_vec()));
    let mut all: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    loop {
        let mut buf = goish::make!([]goish::types::byte, 512);
        let (n, e) = io::Reader::Read(&mut c, &mut buf);
        if n > 0 {
            all.extend_from_slice(&(&*buf)[..n as usize]);
        }
        if n <= 0 || e != errors::nil {
            break;
        }
    }
    let _ = io::Closer::Close(&mut c);
    // First line, without the CRLF.
    let mut end = all.len();
    for i in 0..all.len() {
        if all[i] == b'\r' {
            end = i;
            break;
        }
    }
    return string::from_bytes(&all[..end]);
}

#[goish::main]
fn main() {
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/ok"), |w, _r| {
        w.WriteHeader(200);
    });
    mux.HandleFunc(string("/notfound"), |w, _r| {
        w.WriteHeader(404);
    });
    mux.HandleFunc(string("/odd"), |w, _r| {
        w.WriteHeader(599);
    });
    mux.HandleFunc(string("/odd2"), |w, _r| {
        w.WriteHeader(299);
    });
    let mux: Arc<dyn http::Handler> = Arc::new(mux);

    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if err != errors::nil {
        fmt::Println!("listen failed: ", err.Error());
        syscall::Exit(1);
    }
    let addr = ln.Addr().String();
    goish::go!(stack(256 * 1024), move || {
        let _ = http::Serve(ln, mux);
    });

    goish::go!(stack(256 * 1024), move || {
        let mut bad = 0i32;
        let cases: [(&str, &str); 4] = [
            ("/ok", "HTTP/1.1 200 OK"),
            ("/notfound", "HTTP/1.1 404 Not Found"),
            ("/odd", "HTTP/1.1 599 status code 599"),
            ("/odd2", "HTTP/1.1 299 status code 299"),
        ];
        for (path, want) in cases.iter() {
            let got = firstLine(addr.clone(), path);
            if got != *want {
                fmt::Println!("FAIL ", *path, ": got ", got, " want ", *want);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("STATUSLINE_OK 4/4");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAILED ", bad);
            syscall::Exit(1);
        }
    });

    loop {
        goish::runtime::sched::Gosched();
    }
}
