// deploy_rest_api — the blessed production-deployment pattern (M31).
//
// A REST API service shaped for real infrastructure behind a load
// balancer / ingress: env-var config, health + readiness endpoints,
// hardened Server config (timeouts, MaxHeaderBytes, ErrorLog,
// BaseContext/ConnContext), access logging, and SIGTERM-triggered
// graceful shutdown via `signal::NotifyContext` + `Server::Shutdown`.
//
// Runs as a self-test under `make e2e`: main drives a client against
// the live server, sends SIGTERM to itself mid-flight, and asserts
// the drain semantics an orchestrator (k8s, systemd) relies on:
//
//    1. GET  /healthz → 200                 (liveness probe)
//    2. HEAD /healthz → 200, headers only   (HEAD body suppression;
//       keep-alive conn stays parseable afterwards)
//    3. GET  /readyz  → 200 before shutdown (readiness probe)
//    4. CRUD round-trip on /api/notes
//    5. BaseContext / ConnContext values visible via r.Context()
//    6. POST with `Expect: 100-continue` → interim 100, then 201
//    7. Unknown `Expect:` value → 417
//    8. IdleTimeout closes an idle keep-alive conn
//    9. Handler panic → 500-ish conn close + `ErrorLog` line
//   10. SIGTERM → readyz flips 503 (LB stops routing), in-flight
//       slow request COMPLETES, Shutdown returns nil, Serve returns
//       ErrServerClosed, new connections are refused.
//
// Marker on success: DEPLOY_REST_API_OK <n>/<n>

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use goish::context;
use goish::io::{Closer, Writer};
use goish::net;
use goish::net::http;
use goish::os;
use goish::os::signal;
use goish::sync::Mutex;
use goish::{bytes, go, string, syscall, time, Sprintf};

// ─── test harness ────────────────────────────────────────────────────

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn pass(name: &'static str) {
    PASSED.fetch_add(1, Ordering::Relaxed);
    goish::Printf!("PASS: %s\n", name);
}

fn fail(msg: goish::string) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    goish::Printf!("FAIL: %s\n", msg);
}

// ─── service state ───────────────────────────────────────────────────

static READY: AtomicBool = AtomicBool::new(true);
static NOTE_SEQ: AtomicI64 = AtomicI64::new(0);
static SLOW_DONE: AtomicUsize = AtomicUsize::new(0);

/// Shared capture buffer for ErrorLog assertions.
struct LogCapture(Arc<Mutex<Vec<u8>>>);
impl goish::io::Writer for LogCapture {
    fn Write(&mut self, p: goish::slice<goish::byte>) -> (goish::int, goish::error) {
        self.0.Lock().extend_from_slice(&p);
        (p.len() as goish::int, goish::errors::nil)
    }
}

// ─── tiny raw-socket client helpers (keep-alive aware) ──────────────

/// One request on a fresh conn; returns the full raw response bytes.
fn raw_roundtrip(port: i64, req: &[u8]) -> Vec<u8> {
    let (mut conn, err) = net::Dial(string("tcp"), Sprintf!("127.0.0.1:%d", port));
    if !err.IsNil() {
        return Vec::new();
    }
    let _ = conn.Write(goish::slice::<goish::byte>::__from_vec(req.to_vec()));
    read_response_bytes(&mut conn)
}

/// Read until conn close or a short read-deadline lapse.
fn read_response_bytes(conn: &mut net::TCPConn) -> Vec<u8> {
    let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));
    let mut out: Vec<u8> = Vec::new();
    loop {
        let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 4096]);
        let (n, err) = goish::io::Reader::Read(conn, &mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !err.IsNil() || n == 0 {
            return out;
        }
        // Heuristic: headers + short body fit one segment; stop once
        // we have a complete header block and the declared body.
        if response_complete(&out) {
            return out;
        }
    }
}

fn response_complete(buf: &[u8]) -> bool {
    if let Some(hdr_end) = find(buf, b"\r\n\r\n") {
        let head = &buf[..hdr_end];
        if let Some(cl_pos) = find_ci(head, b"content-length:") {
            let mut n: usize = 0;
            for &b in &head[cl_pos + 15..] {
                if b == b'\r' {
                    break;
                }
                if b.is_ascii_digit() {
                    n = n * 10 + (b - b'0') as usize;
                }
            }
            return buf.len() >= hdr_end + 4 + n;
        }
        return true;
    }
    false
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn status_of(resp: &[u8]) -> i64 {
    // "HTTP/1.1 NNN ..."
    if resp.len() < 12 {
        return -1;
    }
    let mut code: i64 = 0;
    for &b in &resp[9..12] {
        if !b.is_ascii_digit() {
            return -1;
        }
        code = code * 10 + (b - b'0') as i64;
    }
    code
}

// ─── main ────────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    // ── config from the environment (12-factor style) ──
    // PORT is honored when set (real deployment); the self-test binds
    // 127.0.0.1:0 and reads back the kernel-assigned port.
    let env_port = os::Getenv("PORT");
    let bind_addr = if env_port.Len() > 0 {
        Sprintf!("0.0.0.0:%s", env_port)
    } else {
        string("127.0.0.1:0")
    };

    // ── ErrorLog captured into a shared buffer for assertion 9 ──
    let log_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let error_log = Arc::new(goish::log::New(
        alloc::boxed::Box::new(LogCapture(log_buf.clone())),
        "taskd ",
        0,
    ));

    // ── routes ──
    let mux = http::ServeMux::new();

    // Liveness: always 200 while the process runs.
    mux.HandleFunc("GET /healthz", |w, _r| {
        let _ = w.Write(bytes("ok\n"));
    });
    // Readiness: 503 once shutdown begins so the LB drains us.
    mux.HandleFunc("GET /readyz", |w, _r| {
        if READY.load(Ordering::Acquire) {
            let _ = w.Write(bytes("ready\n"));
        } else {
            w.WriteHeader(503);
            let _ = w.Write(bytes("draining\n"));
        }
    });
    // Context hooks probe: reads values planted by BaseContext /
    // ConnContext below.
    mux.HandleFunc("GET /api/whoami", |w, r| {
        let ctx = r.Context();
        let svc = ctx
            .Value("service")
            .and_then(|v| v.downcast_ref::<&'static str>().copied())
            .unwrap_or("?");
        let conn_tagged = ctx.Value("conn-tag").is_some();
        let _ = w.Write(goish::convert::bytes(Sprintf!(
            "service=%s conn-tag=%t\n",
            string(svc),
            conn_tagged
        )));
    });
    // Minimal REST resource.
    mux.HandleFunc("POST /api/notes", |w, r| {
        if r.Body.len() == 0 {
            w.WriteHeader(422);
            return;
        }
        let id = NOTE_SEQ.fetch_add(1, Ordering::AcqRel) + 1;
        w.Header().Set("Location", Sprintf!("/api/notes/%d", id));
        w.WriteHeader(201);
        let _ = w.Write(goish::convert::bytes(Sprintf!("{\"id\":%d}", id)));
    });
    // Slow endpoint for the drain test.
    mux.HandleFunc("GET /api/slow", |w, _r| {
        time::Sleep(time::Millisecond * 500);
        SLOW_DONE.fetch_add(1, Ordering::AcqRel);
        let _ = w.Write(bytes("slow done\n"));
    });
    // Panic endpoint for the ErrorLog test.
    mux.HandleFunc("GET /api/boom", |_w, _r| {
        panic!("kaboom");
    });

    // ── hardened server config (the deployment template) ──
    let mut srv = http::Server::default();
    srv.Addr = bind_addr.clone();
    srv.Handler = Arc::new(mux);
    srv.ReadHeaderTimeout = time::Second * 5;
    srv.ReadTimeout = time::Second * 30;
    srv.WriteTimeout = time::Second * 30;
    srv.IdleTimeout = time::Millisecond * 400; // short for the self-test; 60-120s in production
    srv.MaxHeaderBytes = 16 * 1024;
    srv.ErrorLog = Some(error_log);
    srv.BaseContext = Some(Arc::new(|_ln: &net::Listener| {
        context::WithValue(context::Background(), "service", "taskd")
    }));
    srv.ConnContext = Some(Arc::new(
        |ctx: Arc<dyn context::Context>, _c: &net::TCPConn| {
            context::WithValue(ctx, "conn-tag", true)
        },
    ));
    let srv = Arc::new(srv);

    // ── bind + serve ──
    let (ln, err) = net::Listen(string("tcp"), bind_addr);
    if !err.IsNil() {
        fail(Sprintf!("Listen: %v", err));
        goish::Printf!("DEPLOY_REST_API_FAIL\n");
        os::Exit(1);
    }
    let port = ln.Addr().Port as i64;

    static SERVE_CLOSED_OK: AtomicUsize = AtomicUsize::new(0);
    let srv_run = srv.clone();
    go!(move || {
        let err = srv_run.Serve(ln);
        if goish::errors::Is(err, http::ErrServerClosed) {
            SERVE_CLOSED_OK.store(1, Ordering::Release);
        }
    });

    // ── SIGTERM → graceful shutdown (the orchestrator contract) ──
    static SHUTDOWN_NIL: AtomicUsize = AtomicUsize::new(0);
    static SHUTDOWN_DONE: AtomicUsize = AtomicUsize::new(0);
    let (sig_ctx, sig_stop) = signal::NotifyContext(
        context::Background(),
        &[syscall::SIGTERM, syscall::SIGINT],
    );
    let srv_shutdown = srv.clone();
    go!(move || {
        // Park until SIGTERM/SIGINT.
        let _ = (sig_ctx.Done()).Recv();
        // 1. Flip readiness so the LB stops sending new work.
        READY.store(false, Ordering::Release);
        // 2. Small grace so in-flight probes observe the 503.
        time::Sleep(time::Millisecond * 100);
        // 3. Drain with a budget an orchestrator would allow.
        let err = srv_shutdown.Shutdown(time::Second * 10);
        if err.IsNil() {
            SHUTDOWN_NIL.store(1, Ordering::Release);
        }
        SHUTDOWN_DONE.store(1, Ordering::Release);
    });

    // give the accept loop a beat
    time::Sleep(time::Millisecond * 50);

    // ─── the self-test client ────────────────────────────────────────

    // 1. liveness
    let resp = raw_roundtrip(port, b"GET /healthz HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    if status_of(&resp) == 200 {
        pass("GET /healthz -> 200");
    } else {
        fail(Sprintf!("healthz status %d", status_of(&resp)));
    }

    // 2. HEAD suppression on a keep-alive conn: HEAD then GET must
    //    both parse; HEAD must carry Content-Length but no body.
    {
        let (mut conn, err) = net::Dial(string("tcp"), Sprintf!("127.0.0.1:%d", port));
        if err.IsNil() {
            let _ = conn.Write(goish::slice::<goish::byte>::__from_vec(
                b"HEAD /healthz HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
            ));
            let head_resp = read_response_bytes_headers_only(&mut conn);
            let ok_status = status_of(&head_resp) == 200;
            let has_cl = find_ci(&head_resp, b"content-length: 3").is_some();
            // The next request on the SAME conn must parse cleanly —
            // a leaked HEAD body would corrupt it.
            let _ = conn.Write(goish::slice::<goish::byte>::__from_vec(
                b"GET /healthz HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            let get_resp = read_response_bytes(&mut conn);
            let get_ok = status_of(&get_resp) == 200 && find(&get_resp, b"ok\n").is_some();
            if ok_status && has_cl && get_ok {
                pass("HEAD suppresses body, keep-alive intact");
            } else {
                fail(Sprintf!(
                    "HEAD test: status=%t cl=%t get=%t",
                    ok_status,
                    has_cl,
                    get_ok
                ));
            }
            let _ = conn.Close();
        } else {
            fail(string("HEAD test: dial failed"));
        }
    }

    // 3. readiness (pre-shutdown)
    let resp = raw_roundtrip(port, b"GET /readyz HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    if status_of(&resp) == 200 {
        pass("GET /readyz -> 200 before shutdown");
    } else {
        fail(Sprintf!("readyz status %d", status_of(&resp)));
    }

    // 4. REST create
    let resp = raw_roundtrip(
        port,
        b"POST /api/notes HTTP/1.1\r\nHost: t\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"title\":\"n1\"}x",
    );
    if status_of(&resp) == 201 && find_ci(&resp, b"location: /api/notes/1").is_some() {
        pass("POST /api/notes -> 201 + Location");
    } else {
        fail(Sprintf!("create status %d", status_of(&resp)));
    }

    // 5. context hooks
    let resp = raw_roundtrip(port, b"GET /api/whoami HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    if find(&resp, b"service=taskd conn-tag=true").is_some() {
        pass("BaseContext + ConnContext values reach r.Context()");
    } else {
        fail(Sprintf!(
            "whoami: hook values missing; got %s",
            goish::string::from_bytes(&resp)
        ));
    }

    // 6. Expect: 100-continue — two-phase send.
    {
        let (mut conn, err) = net::Dial(string("tcp"), Sprintf!("127.0.0.1:%d", port));
        if err.IsNil() {
            let _ = conn.Write(goish::slice::<goish::byte>::__from_vec(
                b"POST /api/notes HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            // Interim must arrive BEFORE we send the body.
            let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));
            let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 64]);
            let (n, _e) = goish::io::Reader::Read(&mut conn, &mut buf);
            let mut interim: Vec<u8> = Vec::new();
            for i in 0..n {
                interim.push(buf[i]);
            }
            let got_100 = find(&interim, b"HTTP/1.1 100 Continue").is_some();
            let _ = conn.Write(goish::slice::<goish::byte>::__from_vec(b"body".to_vec()));
            let final_resp = read_response_bytes(&mut conn);
            if got_100 && status_of(&final_resp) == 201 {
                pass("Expect: 100-continue -> interim then 201");
            } else {
                fail(Sprintf!(
                    "100-continue: interim=%t final=%d",
                    got_100,
                    status_of(&final_resp)
                ));
            }
            let _ = conn.Close();
        } else {
            fail(string("100-continue: dial failed"));
        }
    }

    // 7. unknown Expect -> 417
    let resp = raw_roundtrip(
        port,
        b"POST /api/notes HTTP/1.1\r\nHost: t\r\nExpect: teleport\r\nContent-Length: 1\r\n\r\nx",
    );
    if status_of(&resp) == 417 {
        pass("unknown Expect -> 417");
    } else {
        fail(Sprintf!("Expect: teleport -> %d, want 417", status_of(&resp)));
    }

    // 8. IdleTimeout closes idle keep-alive conns (configured 400ms).
    {
        let (mut conn, err) = net::Dial(string("tcp"), Sprintf!("127.0.0.1:%d", port));
        if err.IsNil() {
            let _ = conn.Write(goish::slice::<goish::byte>::__from_vec(
                b"GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
            ));
            let first = read_response_bytes_headers_and_body(&mut conn, 3);
            let first_ok = status_of(&first) == 200;
            // Sit idle past IdleTimeout; the server must close.
            time::Sleep(time::Millisecond * 900);
            let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));
            let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 16]);
            let (n, rerr) = goish::io::Reader::Read(&mut conn, &mut buf);
            // EOF (n==0 with error) proves the server closed the idle conn.
            if first_ok && n == 0 && !rerr.IsNil() {
                pass("IdleTimeout closes idle keep-alive conn");
            } else {
                fail(Sprintf!("idle test: first=%t n=%d", first_ok, n));
            }
            let _ = conn.Close();
        } else {
            fail(string("idle test: dial failed"));
        }
    }

    // 9. handler panic → conn closed + ErrorLog line
    let _ = raw_roundtrip(port, b"GET /api/boom HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    time::Sleep(time::Millisecond * 100);
    {
        let logged = {
            let buf = log_buf.Lock();
            find(&buf, b"http: panic serving").is_some() && find(&buf, b"kaboom").is_some()
        };
        if logged {
            pass("handler panic reaches ErrorLog");
        } else {
            fail(string("panic not found in ErrorLog"));
        }
    }

    // 10. SIGTERM drain: launch a slow request, then signal ourselves.
    static SLOW_STATUS: AtomicI64 = AtomicI64::new(-1);
    let slow_port = port;
    go!(move || {
        let resp = raw_roundtrip(
            slow_port,
            b"GET /api/slow HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        );
        SLOW_STATUS.store(status_of(&resp), Ordering::Release);
    });
    time::Sleep(time::Millisecond * 100); // slow request is in flight
    syscall::Kill(syscall::Getpid(), syscall::SIGTERM);

    // readyz must flip 503 while the listener still accepts (the
    // 100ms grace window in the shutdown goroutine).
    let resp = raw_roundtrip(port, b"GET /readyz HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    if status_of(&resp) == 503 {
        pass("readyz -> 503 after SIGTERM (LB drain signal)");
    } else {
        fail(Sprintf!("readyz after SIGTERM: %d, want 503", status_of(&resp)));
    }

    // Wait for the drain to finish.
    let mut waited = 0i64;
    while SHUTDOWN_DONE.load(Ordering::Acquire) == 0 && waited < 15_000 {
        time::Sleep(time::Millisecond * 10);
        waited += 10;
    }
    if SHUTDOWN_NIL.load(Ordering::Acquire) == 1 {
        pass("Shutdown drained within budget");
    } else {
        fail(string("Shutdown timed out or errored"));
    }
    if SLOW_DONE.load(Ordering::Acquire) == 1 && SLOW_STATUS.load(Ordering::Acquire) == 200 {
        pass("in-flight request completed during drain");
    } else {
        fail(Sprintf!(
            "slow request: done=%d status=%d",
            SLOW_DONE.load(Ordering::Acquire) as i64,
            SLOW_STATUS.load(Ordering::Acquire)
        ));
    }
    if SERVE_CLOSED_OK.load(Ordering::Acquire) == 1 {
        pass("Serve returned ErrServerClosed");
    } else {
        fail(string("Serve error != ErrServerClosed"));
    }

    // 11. post-shutdown: connections refused.
    let (mut c2, derr) = net::Dial(string("tcp"), Sprintf!("127.0.0.1:%d", port));
    if !derr.IsNil() {
        pass("post-shutdown connect refused");
    } else {
        fail(string("post-shutdown dial unexpectedly succeeded"));
        let _ = c2.Close();
    }

    sig_stop();

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        goish::Printf!("DEPLOY_REST_API_OK %d/%d\n", p as i64, p as i64);
        os::Exit(0);
    } else {
        goish::Printf!("DEPLOY_REST_API_FAIL %d failures\n", f as i64);
        os::Exit(1);
    }
}

/// Read just the header block (for HEAD: no body follows).
fn read_response_bytes_headers_only(conn: &mut net::TCPConn) -> Vec<u8> {
    let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));
    let mut out: Vec<u8> = Vec::new();
    loop {
        let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 1024]);
        let (n, err) = goish::io::Reader::Read(conn, &mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if find(&out, b"\r\n\r\n").is_some() || !err.IsNil() || n == 0 {
            return out;
        }
    }
}

/// Read headers plus exactly `body_len` body bytes (keep-alive safe).
fn read_response_bytes_headers_and_body(conn: &mut net::TCPConn, body_len: usize) -> Vec<u8> {
    let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));
    let mut out: Vec<u8> = Vec::new();
    loop {
        let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 1024]);
        let (n, err) = goish::io::Reader::Read(conn, &mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if let Some(he) = find(&out, b"\r\n\r\n") {
            if out.len() >= he + 4 + body_len {
                return out;
            }
        }
        if !err.IsNil() || n == 0 {
            return out;
        }
    }
}
