// http_writeheader_code_ref_smoke — WriteHeader's status-code guard,
// against Go 1.25.5.
//
// Go's response.WriteHeader calls checkWriteHeaderCode (server.go:1195)
// and PANICS for anything outside [100, 999]. That is deliberate, and
// the reason is in Go's own comment: "there's no equivalent bogus
// thing we can realistically send in HTTP/2, so we'll consistently
// panic instead and help people find their bugs early."
//
// goish had checkWriteHeaderCode ported and anchored, called only from
// httptest's ResponseRecorder — so the real server wrote whatever it
// was handed onto the wire:
//
//     WriteHeader(-1)    -> HTTP/1.1 00-1 status code -1
//     WriteHeader(42)    -> HTTP/1.1 042 status code 42
//     WriteHeader(1000)  -> HTTP/1.1 1000 status code 1000
//
// The -1 row is the bad one: `00-1` is not a wrong status, it is a
// syntactically invalid status line, and every client and proxy
// downstream has to decide what to do with it.
//
// 600 and 999 are in the table deliberately: they are NOT valid HTTP
// status codes, and Go passes them anyway. The guard is three digits,
// not a registry check, and a port that "fixed" that would diverge.
// 100 and 599 pin the boundaries.
//
// A panicking handler closes the conn with no response on both sides,
// which is what the closed rows assert. goish prints its own panic
// diagnostics to stderr; only stdout is compared.
//
// Reference: scripts/goref.sh net/http.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net::http;
use goish::types::byte;
use goish::{fmt, net, strings, time};

const GO: [&str; 10] = [
    "code=42    <connection closed, no response>",
    "code=99    <connection closed, no response>",
    "code=100   HTTP/1.1 100 Continue",
    "code=200   HTTP/1.1 200 OK",
    "code=599   HTTP/1.1 599 status code 599",
    "code=600   HTTP/1.1 600 status code 600",
    "code=999   HTTP/1.1 999 status code 999",
    "code=1000  <connection closed, no response>",
    "code=-1    <connection closed, no response>",
    "code=0     <connection closed, no response>",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let mut ln: usize = 0;
    for code in [42 as goish::int, 99, 100, 200, 599, 600, 999, 1000, -1, 0].iter() {
        let c = *code;
        let mux = http::ServeMux::new();
        mux.HandleFunc(string::from("/"), move |w, _r| {
            w.WriteHeader(c);
            let _ = w.Write(goish::convert::bytes(string::from("body")));
        });
        let mut srv = http::Server::default();
        srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
        let srv = Arc::new(srv);
        let (l, _) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
        let addr = l.Addr().String();
        let s2 = srv.clone();
        goish::go!(stack(512 * 1024), move || { let _ = s2.Serve(l); });
        time::Sleep(time::Millisecond * 40);
        let (mut cn, de) = net::Dial(string::from("tcp"), addr);
        if !de.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("code=%-5d dial-error", c));
            let _ = srv.Close();
            continue;
        }
        let _ = cn.SetReadDeadline(time::Now().Add(time::Millisecond * 1500));
        let _ = cn.Write(goish::convert::bytes(string::from(
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")));
        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 256]);
        loop {
            let (n, e) = cn.Read(&mut buf);
            if n > 0 { raw.extend_from_slice(&buf.as_ref()[..n as usize]); }
            if n <= 0 || !e.IsNil() { break; }
        }
        let _ = cn.Close();
        let _ = srv.Close();
        let txt = string::from_bytes(&raw);
        let line = if txt.Len() == 0 {
            string::from("<connection closed, no response>")
        } else {
            strings::Split(txt, string::from("\r\n"))[0].clone()
        };
        chk(&mut ln, &fmt::Sprintf!("code=%-5d %s", c, line));
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
    goish::os::Exit(0);
}
