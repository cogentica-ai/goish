// http_fileserver_dir_smoke — exercise FileServer directory listings
// via the dirList port (fs.go:139). Spins up a server rooted at a
// tmp dir with two files, requests "/", and asserts the HTML index.

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

    // Set up a tmp dir layout (mkdir is best-effort: ignore EEXIST).
    let dir = string("/tmp/goish-fs-dir-smoke");
    let _ = os::Remove(string("/tmp/goish-fs-dir-smoke/a.txt"));
    let _ = os::Remove(string("/tmp/goish-fs-dir-smoke/b.txt"));
    let _ = os::Remove(dir.clone());
    let _ = os::Mkdir(dir.clone(), 0o755);
    let _ = os::WriteFile(string("/tmp/goish-fs-dir-smoke/a.txt"), bytes("aa"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-fs-dir-smoke/b.txt"), bytes("bb"), 0o644);

    let fs_handler: Arc<dyn http::Handler> = http::FileServer(http::NewDir(dir.clone()));
    let mut srv = http::Server::default();
    srv.Handler = fs_handler;
    let (ln, _e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_for_serve = srv_arc.clone();
    go!(stack(64 * KB), move || {
        let _ = srv_for_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 30);

    // 1. GET / → 200 + HTML body containing both file links.
    {
        let url = build_url(&addr, "/");
        let (resp, _) = http::Get(url);
        let body = body_str(&resp.Body);
        let ct = resp.Header.Get(string("Content-Type"));
        let has_a = goish::strings::Contains(body.clone(), string(">a.txt</a>"));
        let has_b = goish::strings::Contains(body.clone(), string(">b.txt</a>"));
        let has_pre = goish::strings::Contains(body.clone(), string("<pre>"));
        if resp.StatusCode == 200 && ct == "text/html; charset=utf-8" && has_a && has_b && has_pre {
            Println!("[ 1] dir index 200             PASS");
        } else {
            Println!(
                "[ 1] dir index 200             FAIL status={} ct={} a={} b={}",
                resp.StatusCode, ct, has_a, has_b
            );
            failed += 1;
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed == 0 {
        Println!("ok 1/1");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 1", failed);
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

fn body_str(body: &goish::slice<u8>) -> goish::string {
    let mut buf: Vec<u8> = Vec::with_capacity(body.Len() as usize);
    for i in 0..body.Len() {
        buf.push(body[i]);
    }
    goish::string::from_bytes(&buf)
}
