// http_fileserver_range_smoke — exercise Range / If-Modified-Since
// end-to-end through the goish HTTP server.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::convert::bytes;
use goish::net;
use goish::net::http;
use goish::os;
use goish::time;
use goish::{go, string, syscall, Println, KB};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Set up: write a fixed test file in /tmp.
    let path = string("/tmp/goish-range-smoke.bin");
    let payload = bytes("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"); // 36 bytes
    let _ = os::WriteFile(path.clone(), payload.clone(), 0o644);

    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/file"), |w, r| {
        http::ServeFile(w, r, string("/tmp/goish-range-smoke.bin"));
    });
    let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
    let mut srv = http::Server::default();
    srv.Handler = mux_arc;
    let (ln, _e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(stack(64 * KB), move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    // 1. Whole file: 200 + full body.
    {
        let url = build_url(&addr, "/file");
        let (resp, _) = http::Get(url);
        if resp.StatusCode == 200 && resp.Body.Len() == 36 {
            Println!("[ 1] full body 200             PASS");
        } else {
            Println!(
                "[ 1] full body 200             FAIL status={} len={}",
                resp.StatusCode, resp.Body.Len()
            );
            failed += 1;
        }
    }

    // 2. Range bytes=0-9 → 206 + first 10 bytes.
    {
        let mut req = make_req(&addr, "/file");
        req.Header.Set(string("Range"), string("bytes=0-9"));
        let cli = http::Client::default();
        let (resp, _) = cli.Do(&req);
        let cr = resp.Header.Get(string("Content-Range"));
        if resp.StatusCode == 206 && resp.Body.Len() == 10 && cr == "bytes 0-9/36" {
            Println!("[ 2] Range 0-9 → 206           PASS");
        } else {
            Println!(
                "[ 2] Range 0-9 → 206           FAIL status={} len={} cr={}",
                resp.StatusCode, resp.Body.Len(), cr
            );
            failed += 1;
        }
    }

    // 3. Suffix Range bytes=-5 → last 5 bytes.
    {
        let mut req = make_req(&addr, "/file");
        req.Header.Set(string("Range"), string("bytes=-5"));
        let cli = http::Client::default();
        let (resp, _) = cli.Do(&req);
        if resp.StatusCode == 206 && resp.Body.Len() == 5 {
            // Last 5 bytes are "VWXYZ".
            let last5 = body_as_bytes(&resp.Body);
            if &last5[..] == b"VWXYZ" {
                Println!("[ 3] suffix Range → 206        PASS");
            } else {
                Println!("[ 3] suffix Range → 206        FAIL bytes");
                failed += 1;
            }
        } else {
            Println!("[ 3] suffix Range → 206        FAIL");
            failed += 1;
        }
    }

    // 4. Out-of-bounds Range → 416.
    {
        let mut req = make_req(&addr, "/file");
        req.Header.Set(string("Range"), string("bytes=100-200"));
        let cli = http::Client::default();
        let (resp, _) = cli.Do(&req);
        if resp.StatusCode == 416 {
            Println!("[ 4] OOB Range → 416           PASS");
        } else {
            Println!("[ 4] OOB Range → 416           FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 5. If-Modified-Since with future date → 304.
    {
        let mut req = make_req(&addr, "/file");
        // 2099-01-01 — definitely after the file's mtime.
        req.Header
            .Set(string("If-Modified-Since"), string("Thu, 01 Jan 2099 00:00:00 GMT"));
        let cli = http::Client::default();
        let (resp, _) = cli.Do(&req);
        if resp.StatusCode == 304 {
            Println!("[ 5] If-Modified-Since → 304   PASS");
        } else {
            Println!("[ 5] If-Modified-Since → 304   FAIL status={}", resp.StatusCode);
            failed += 1;
        }
    }

    // 6. Last-Modified header is set on a normal 200.
    {
        let url = build_url(&addr, "/file");
        let (resp, _) = http::Get(url);
        let lm = resp.Header.Get(string("Last-Modified"));
        if resp.StatusCode == 200 && lm.Len() > 0 {
            Println!("[ 6] Last-Modified header      PASS");
        } else {
            Println!("[ 6] Last-Modified header      FAIL");
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 6", failed);
        syscall::Exit(1);
    }
}

fn build_url(addr: &goish::string, path: &str) -> goish::string {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"http://");
    let ab = bytes(addr.clone());
    for i in 0..ab.Len() {
        buf.push(ab[i]);
    }
    buf.extend_from_slice(path.as_bytes());
    goish::string::from_bytes(&buf)
}

fn make_req(addr: &goish::string, path: &str) -> http::Request {
    let url = build_url(addr, path);
    let (req, _) = http::NewRequest(string("GET"), url, bytes(""));
    req
}

fn body_as_bytes(body: &goish::slice<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.Len() as usize);
    for i in 0..body.Len() {
        out.push(body[i]);
    }
    out
}
