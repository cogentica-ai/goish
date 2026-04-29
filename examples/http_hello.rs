// http_hello — minimal HTTP server demo on top of M27d's net/http.
//
// Listens on 127.0.0.1:0, picks a kernel-assigned port, prints it
// to stdout so a driver script can curl it. Tests two routes plus
// the default 404 path.
//
// In a separate process / shell:
//   $ ./target/.../examples/http_hello &
//   PID 12345 PORT 41234
//   $ curl -i http://127.0.0.1:41234/
//   HTTP/1.1 200 OK
//   Content-Type: text/plain; charset=utf-8
//   Connection: close
//
//   hello world

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net;
use goish::net::http;
use goish::runtime::sched::schedule;
use goish::{bytes, go, string, syscall, KB};

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn print_dec(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    print(&buf[i..]);
}

#[goish::main]
fn main() {
    // Build a mux with two routes.
    let mux = http::ServeMux::new();
    // Go convention: `/` is the catch-all because patterns ending in
    // `/` match-as-prefix. Handlers gate on `r.URL.Path == "/"` to
    // distinguish the homepage from any-unmatched-path.
    mux.HandleFunc(string("/"), |w, r| {
        if r.URL.Path == "/" {
            let _ = w.Write(bytes("hello world\n"));
        } else {
            w.WriteHeader(404);
            let _ = w.Write(bytes("404 page not found\n"));
        }
    });
    mux.HandleFunc(string("/healthz"), |w, _r| {
        let _ = w.Write(bytes("ok\n"));
    });
    let mux: Arc<dyn http::Handler> = Arc::new(mux);

    // Bind on 127.0.0.1:0 so the kernel picks a free port, discover
    // it via Listener.Addr, print it, then hand the listener to
    // `http::Serve` which runs the keep-alive accept loop.
    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !err.IsNil() {
        print(b"listen failed\n");
        syscall::Exit(1);
    }
    let port = ln.Addr().Port as u32;
    print(b"PID ");
    print_dec(syscall::Getpid() as u32);
    print(b" PORT ");
    print_dec(port);
    print(b"\n");

    let mux_for_listen = mux.clone();
    go!(stack(64 * KB), move || {
        let _ = http::Serve(ln, mux_for_listen);
    });

    schedule();
}
