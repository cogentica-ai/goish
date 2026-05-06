// http_limits_smoke — exercise Server.MaxHeaderBytes plumb-through and
// Server.MaxConcurrentConns backpressure.
//
// Coverage:
//   1. MaxHeaderBytes=200 — a request line longer than 200 bytes is
//      rejected by ReadRequest; the conn closes; client sees no 200.
//
//   2. MaxConcurrentConns=2 — fire 4 concurrent slow handlers; assert
//      at most 2 are in-flight at any time (peak observed ≤ 2).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string, syscall, Println, KB};

#[goish::main]
fn main() {
    let mut failed = 0;

    // ─── Test 1: MaxHeaderBytes ───────────────────────────────────────
    {
        let mux = http::ServeMux::new();
        mux.HandleFunc(string("/"), |w, _r| {
            let _ = w.Write(bytes("ok\n"));
        });
        let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
        let mut srv = http::Server::default();
        srv.Handler = mux_arc;
        srv.MaxHeaderBytes = 200;

        let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !err.IsNil() {
            Println!("[ 1] Listen FAIL");
            failed += 1;
        } else {
            let addr = ln.Addr().String();
            let srv_arc = Arc::new(srv);
            let srv_for_serve = srv_arc.clone();
            go!(stack(64 * KB), move || {
                let _ = srv_for_serve.Serve(ln);
            });
            time::Sleep(time::Millisecond * 20);

            // Send a request line that exceeds 200 bytes.
            let (mut conn, derr) = net::Dial(string("tcp"), addr);
            if !derr.IsNil() {
                Println!("[ 1] Dial FAIL");
                failed += 1;
            } else {
                // Build "GET /<300 chars> HTTP/1.1\r\nHost: x\r\n\r\n".
                let mut req: Vec<u8> = Vec::new();
                req.extend_from_slice(b"GET /");
                for _ in 0..300 {
                    req.push(b'x');
                }
                req.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                let _ = conn.Write(goish::goslice::slice::<u8>::__from_vec(req));

                // Slurp response. With MaxHeaderBytes=200 and a 300+ byte
                // request line, the server must reject — either close
                // immediately (empty read) or send 4xx + close.
                let mut total: usize = 0;
                let mut whole: Vec<u8> = Vec::new();
                loop {
                    let mut dst = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 256]);
                    let (n, e) = conn.Read(&mut dst);
                    for i in 0..(n as usize) {
                        whole.push(dst[i as i64]);
                    }
                    total += n as usize;
                    if n == 0 || !e.IsNil() {
                        break;
                    }
                }
                let _ = conn.Close();

                // Expect: NO "200 OK" anywhere in the response stream.
                let has_200 = find_marker(&whole, b"200 OK").is_some();
                let _ = total;
                if !has_200 {
                    Println!("[ 1] MaxHeaderBytes reject     PASS");
                } else {
                    Println!("[ 1] MaxHeaderBytes reject     FAIL got 200 OK");
                    failed += 1;
                }
            }
            let _ = srv_arc.Shutdown(time::Second);
        }
    }

    // ─── Test 2: MaxConcurrentConns backpressure ──────────────────────
    {
        let in_flight = Arc::new(AtomicI32::new(0));
        let peak = Arc::new(AtomicI32::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        let mux = http::ServeMux::new();
        let in_flight_h = in_flight.clone();
        let peak_h = peak.clone();
        let completed_h = completed.clone();
        mux.HandleFunc(string("/slow"), move |w, _r| {
            let cur = in_flight_h.fetch_add(1, Ordering::SeqCst) + 1;
            // Update peak (CAS loop).
            loop {
                let p = peak_h.load(Ordering::SeqCst);
                if cur <= p || peak_h.compare_exchange(p, cur, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    break;
                }
            }
            time::Sleep(time::Millisecond * 80);
            in_flight_h.fetch_sub(1, Ordering::SeqCst);
            completed_h.fetch_add(1, Ordering::SeqCst);
            let _ = w.Write(bytes("done\n"));
        });
        let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
        let mut srv = http::Server::default();
        srv.Handler = mux_arc;
        srv.MaxConcurrentConns = 2;

        let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !err.IsNil() {
            Println!("[ 2] Listen FAIL");
            failed += 1;
        } else {
            let addr = ln.Addr().String();
            let srv_arc = Arc::new(srv);
            let srv_for_serve = srv_arc.clone();
            go!(stack(64 * KB), move || {
                let _ = srv_for_serve.Serve(ln);
            });
            time::Sleep(time::Millisecond * 20);

            let client_done = Arc::new(AtomicUsize::new(0));
            for _ in 0..4 {
                let addr_c = addr.clone();
                let cd = client_done.clone();
                go!(stack(64 * KB), move || {
                    let url = make_url(&addr_c, "/slow");
                    let (_resp, _e) = http::Get(url);
                    cd.fetch_add(1, Ordering::SeqCst);
                });
            }
            while client_done.load(Ordering::SeqCst) < 4 {
                time::Sleep(time::Millisecond * 20);
            }

            let p = peak.load(Ordering::SeqCst);
            let done = completed.load(Ordering::SeqCst);
            if done == 4 && p <= 2 {
                Println!("[ 2] MaxConcurrentConns peak<=2 PASS done={}", done);
            } else {
                Println!("[ 2] MaxConcurrentConns peak<=2 FAIL peak={} done={}", p, done);
                failed += 1;
            }
            let _ = srv_arc.Shutdown(time::Second);
        }
    }

    if failed == 0 {
        Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 2", failed);
        syscall::Exit(1);
    }
}

fn make_url(addr: &goish::string, path: &str) -> goish::string {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"http://");
    let ab = bytes(addr.clone());
    for i in 0..ab.Len() {
        buf.push(ab[i]);
    }
    buf.extend_from_slice(path.as_bytes());
    goish::string::from_bytes(&buf)
}

fn find_marker(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    for i in 0..=hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}
