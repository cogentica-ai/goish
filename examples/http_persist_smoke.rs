// http_persist_smoke — httputil's deprecated ClientConn/ServerConn.
//
// The property worth pinning is OWNERSHIP: Hijack DETACHES the
// connection, so the ServerConn keeps no reference and a later Close
// cannot close a socket the caller now owns. Returning a clone instead
// would double-close it.
//
// The ServerConn Read/Pending/Write half below is pinned against Go
// 1.25.5, same program shape, `go run` on the SDK this tree targets:
//
//     read err=<nil> method="GET" path="/sc"
//     pending after read=1
//     write foreign err=pipeline error
//     pending after foreign=1
//     write real err=<nil>
//     pending after write=0
//     second write err=pipeline error
//
// The two that are easy to get wrong are the ones in the middle: a
// Write for a request this conn never read must NOT consume the real
// request's slot, and a second Write for the same request must fail —
// Go deletes the pipeline id on the first, so the second finds none.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net;
use goish::net::http::httputil::persist::{
    ErrPipeline, NewClientConn, NewProxyClientConn, NewServerConn,
};
use goish::{go, string, time};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let (ln, e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !e.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", e));
        finish();
    }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        loop {
            let (c, e) = ln.Accept();
            if !e.IsNil() {
                return;
            }
            let _ = c;
            time::Sleep(time::Duration(50 * 1_000_000));
        }
    });
    time::Sleep(time::Duration(100 * 1_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);

    // Hijack detaches: the ServerConn no longer holds the conn.
    {
        let (c, _) = net::Dial(string("tcp"), addr.clone());
        let sc = NewServerConn(c, None);
        let taken = sc.Hijack();
        check(
            "ServerConn.Hijack yields the connection",
            taken.is_some(),
            string(""),
        );
        check(
            "and a second Hijack yields nothing — it was detached, not cloned",
            sc.Hijack().is_none(),
            string(""),
        );
        // Close after Hijack must be a no-op, not a double close.
        check(
            "Close after Hijack is a no-op",
            sc.Close().IsNil(),
            string(""),
        );
    }
    // Close without Hijack closes the conn.
    {
        let (c, _) = net::Dial(string("tcp"), addr.clone());
        let sc = NewServerConn(c, None);
        let err = sc.Close();
        check(
            "Close without Hijack closes the connection",
            err.IsNil() && sc.Hijack().is_none(),
            fmt::Sprintf!("%v", err),
        );
    }
    // ClientConn mirrors it, and the proxy form differs only in flag.
    {
        let (c1, _) = net::Dial(string("tcp"), addr.clone());
        let cc = NewClientConn(c1, None);
        let (c2, _) = net::Dial(string("tcp"), addr.clone());
        let pc = NewProxyClientConn(c2, None);
        check(
            "NewProxyClientConn differs from NewClientConn only in request form",
            !cc.proxy && pc.proxy,
            string(""),
        );
        check(
            "ClientConn.Pending starts at 0",
            cc.Pending() == 0,
            string(""),
        );
        check(
            "ClientConn.Hijack detaches the same way",
            cc.Hijack().is_some() && cc.Hijack().is_none(),
            string(""),
        );
        let _ = pc.Close();
    }

    // ── Do against a real HTTP server ──
    //
    // ClientConn.Do is Write + Read, and the pipeline id minted by the
    // first is what lets the second know which response is its own.
    {
        let srvmux = goish::net::http::ServeMux::new();
        srvmux.HandleFunc("/hi", |w, r| {
            w.Header().Set(string("X-Echo"), r.URL.Path.clone());
            let _ = w.Write(goish::bytes("persist-ok"));
        });
        let srv = alloc::sync::Arc::new(goish::net::http::Server {
            Handler: alloc::sync::Arc::new(srvmux),
            ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
            ..Default::default()
        });
        let (sln, se) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !se.IsNil() {
            check("listen 2", false, fmt::Sprintf!("%v", se));
            finish();
        }
        let sport = sln.Addr().Port;
        {
            let s2 = srv.clone();
            go!(stack(1024 * 1024), move || {
                let _ = s2.Serve(sln);
            });
        }
        time::Sleep(time::Duration(150 * 1_000_000));

        let saddr = fmt::Sprintf!("127.0.0.1:%d", sport as i64);
        let (c3, _) = net::Dial(string("tcp"), saddr.clone());
        let cc2 = NewClientConn(c3, None);
        let (req, _) = goish::net::http::NewRequest(
            string("GET"),
            fmt::Sprintf!("http://%s/hi", saddr),
            goish::goslice::slice::new(),
        );
        let (resp, derr) = cc2.Do(&req);
        let body = goish::string::from_bytes(&{
            let (b, _) = goish::io::ReadAll(&mut resp.Body.clone());
            b
        });
        check(
            "ClientConn.Do writes the request and reads its response",
            derr.IsNil()
                && resp.StatusCode == 200
                && resp.Header.Get(string("X-Echo")) == "/hi"
                && body == "persist-ok",
            fmt::Sprintf!("err=%v code=%d body=%q", derr, resp.StatusCode, body),
        );
        check(
            "the pipeline slot is consumed: Pending is back to zero",
            cc2.Pending() == 0,
            fmt::Sprintf!("pending=%d", cc2.Pending()),
        );

        // Read without a matching Write has no pipeline slot, and must
        // say so rather than steal someone else's response.
        let (req2, _) = goish::net::http::NewRequest(
            string("GET"),
            fmt::Sprintf!("http://%s/hi", saddr),
            goish::goslice::slice::new(),
        );
        let (_, perr) = cc2.Read(&req2);
        check(
            "Read with no prior Write is ErrPipeline",
            goish::errors::Is(perr.clone(), ErrPipeline),
            fmt::Sprintf!("%v", perr),
        );
        let _ = cc2.Close();
        let _ = srv.clone().Close();
    }

    // ── ServerConn.Read / Pending / Write ──
    //
    // The server half runs the pipeline the other way round: Read
    // ALLOCATES the request and records its pipeline id, and Write
    // finds that id by the identity Read handed back. Go keys that by
    // *http.Request; goish hands out an Arc<Request> and keys by its
    // pointer, so a request this conn never read cannot claim a slot.
    {
        let (sln2, e2) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !e2.IsNil() {
            check("listen 3", false, fmt::Sprintf!("%v", e2));
            finish();
        }
        let p2 = sln2.Addr().Port;
        let a2 = fmt::Sprintf!("127.0.0.1:%d", p2 as i64);

        // A raw client: send one request, then read to EOF.
        let got = alloc::sync::Arc::new(goish::sync::Mutex::new(string::new()));
        {
            let got2 = got.clone();
            let a3 = a2.clone();
            go!(stack(512 * 1024), move || {
                let (mut c, de) = net::Dial(string("tcp"), a3);
                if !de.IsNil() {
                    return;
                }
                let _ = goish::io::Writer::Write(
                    &mut c,
                    goish::bytes("GET /sc HTTP/1.1\r\nHost: x\r\n\r\n"),
                );
                let (b, _) = goish::io::ReadAll(&mut c);
                *got2.Lock() = goish::string::from_bytes(&b);
            });
        }

        let (sc_conn, ae) = sln2.Accept();
        if !ae.IsNil() {
            check("accept", false, fmt::Sprintf!("%v", ae));
            finish();
        }
        let sc = NewServerConn(sc_conn, None);
        let (req, rerr) = sc.Read();
        check(
            "ServerConn.Read returns the request off the wire",
            rerr.IsNil() && req.Method == "GET" && req.URL.Path == "/sc",
            fmt::Sprintf!("err=%v method=%q path=%q", rerr, req.Method, req.URL.Path),
        );
        check(
            "Pending counts the request that has not been answered",
            sc.Pending() == 1,
            fmt::Sprintf!("pending=%d", sc.Pending()),
        );

        // A request this ServerConn never read has no pipeline slot.
        // Go's answer is ErrPipeline, not a guess at whose slot it is.
        let foreign = alloc::sync::Arc::new(goish::net::http::Request::default());
        let mut hh = goish::net::http::Header::new();
        hh.Set(string("X-Sc"), string("1"));
        let resp = goish::net::http::Response {
            StatusCode: 200,
            ProtoMajor: 1,
            ProtoMinor: 1,
            Header: hh,
            Body: goish::net::http::Body::from_bytes(goish::bytes("sc-ok")),
            ContentLength: 5,
            ..Default::default()
        };
        let ferr = sc.Write(&foreign, &resp);
        check(
            "Write for a request this conn never read is ErrPipeline",
            goish::errors::Is(ferr.clone(), ErrPipeline),
            fmt::Sprintf!("%v", ferr),
        );
        check(
            "and the rejected Write did not consume the real slot",
            sc.Pending() == 1,
            fmt::Sprintf!("pending=%d", sc.Pending()),
        );

        let werr = sc.Write(&req, &resp);
        check(
            "Write answers the request Read handed back",
            werr.IsNil(),
            fmt::Sprintf!("%v", werr),
        );
        check(
            "Pending returns to zero once written",
            sc.Pending() == 0,
            fmt::Sprintf!("pending=%d", sc.Pending()),
        );
        // Go: a second Write for the same request finds no slot, since
        // the id was deleted on the first.
        let derr2 = sc.Write(&req, &resp);
        check(
            "a second Write for the same request is ErrPipeline",
            goish::errors::Is(derr2.clone(), ErrPipeline),
            fmt::Sprintf!("%v", derr2),
        );

        let _ = sc.Close();
        time::Sleep(time::Duration(250 * 1_000_000));
        let seen = got.Lock().clone();
        check(
            "the response reaches the client",
            goish::strings::Contains(seen.clone(), string("200 OK"))
                && goish::strings::Contains(seen.clone(), string("X-Sc: 1"))
                && goish::strings::Contains(seen.clone(), string("sc-ok")),
            fmt::Sprintf!("%q", seen),
        );
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_PERSIST_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PERSIST_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
