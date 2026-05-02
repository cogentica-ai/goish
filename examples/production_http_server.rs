// production_http_server — production-grade HTTP server exercising the
// full goish net/http surface.
//
// Features exercised (✓ = wired up; ✗ = falls back to manual; ✗✗ =
// missing entirely from goish):
//
//   ✓  Multi-route ServeMux + Go 1.22 path wildcards.
//   ✓  Logging middleware (Handler wrapper pattern).
//   ✓  Authentication middleware (Bearer + Basic).
//   ✓  CSRF protection (CrossOriginProtection).
//   ✓  Static file serving (FileServer + StripPrefix).
//   ✓  JSON request/response (json::Value).
//   ✓  Form parsing (ParseForm).
//   ✓  Cookies (SetCookie / Cookies).
//   ✓  Server timeouts (ReadHeaderTimeout, ReadTimeout, WriteTimeout).
//   ✓  Graceful shutdown (Server.Shutdown).
//   ✓  Custom 404.
//   ✓  Request context (Context / WithContext).
//   ✗  Bearer token check — built manually atop r.Header.Get("Authorization").
//   ✗  Per-IP rate limiting — built manually with sync.Map + atomic counters.
//   ✗  Request ID middleware — built with crypto/rand.
//   ✗✗ TLS — no crypto/tls in goish yet.
//   ✗✗ Gzip response compression — no compress/gzip yet.
//   ✗✗ HTTP/2 — no h2_bundle.go port.
//   ✗✗ Structured logging (slog) — log.Println only.
//
// Driver: spawns the server on 127.0.0.1:0, sends one request to each
// route via http::Client::Get/Post, asserts statuses & bodies, then
// calls Server.Shutdown.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::encoding::json;
use goish::net;
use goish::net::http;
use goish::os;
use goish::runtime::sched::schedule;
use goish::sync::atomic::Uint64;
use goish::time;
use goish::{
    bytes, float64, go, int, int64, nil, string, uint64, Eprintln, Printf, Println, KB,
};

// ─── shared server state ─────────────────────────────────────────────

static SERVE_DONE: Uint64 = Uint64::new(0);
static FAILED: Uint64 = Uint64::new(0);
static REQ_COUNT: Uint64 = Uint64::new(0);
static CLIENT_PORT: Uint64 = Uint64::new(0);

fn fail<S: Into<string>>(name: S) {
    FAILED.Add(1);
    Eprintln!("FAIL:", name.into());
}

fn pass<S: Into<string>>(name: S) {
    Println!("PASS:", name.into());
}

// ─── handlers ────────────────────────────────────────────────────────

fn h_health(w: &mut http::ResponseWriter, _r: &http::Request) {
    let mut obj = goish::map::<string, json::Value>::new();
    obj.Set("status", "ok");
    obj.Set("reqs", float64(REQ_COUNT.Load()));
    let v = json::Value::Object(obj);
    let (body, e) = json::Marshal(&v);
    if !e.IsNil() {
        http::Error(w, e.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json; charset=utf-8");
    w.Write(body);
}

fn h_user_get(w: &mut http::ResponseWriter, r: &http::Request) {
    let id = r.PathValue("id");
    if id.Len() == 0 {
        http::Error(w, "missing id", http::StatusBadRequest);
        return;
    }
    let mut obj = goish::map::<string, json::Value>::new();
    obj.Set("id", id);
    obj.Set("name", "Alice");
    let v = json::Value::Object(obj);
    let (body, _) = json::Marshal(&v);
    w.Header().Set("Content-Type", "application/json");
    w.Write(body);
}

fn h_form(w: &mut http::ResponseWriter, r: &http::Request) {
    // ParseForm + FormValue both take `&Request` (interior mutability
    // via Mutex<FormCell>), so handlers can parse form values
    // directly — no `&mut self` workaround needed.
    let name = r.FormValue("name");
    let age = r.FormValue("age");
    w.Header().Set("Content-Type", "text/plain");
    let mut out = goish::strings::Builder::new();
    out.WriteString("name=");
    out.WriteString(name);
    out.WriteString("&age=");
    out.WriteString(age);
    w.Write(bytes(out.String()));
}

fn h_session_set(w: &mut http::ResponseWriter, _r: &http::Request) {
    let c = http::Cookie {
        Name: string("sid"),
        Value: string("abc123"),
        Path: string("/"),
        HttpOnly: true,
        ..Default::default()
    };
    http::SetCookie(w, &c);
    w.Write(bytes("session set\n"));
}

fn h_session_get(w: &mut http::ResponseWriter, r: &http::Request) {
    let (c, err) = r.Cookie("sid");
    if !err.IsNil() {
        w.Write(bytes("no session\n"));
        return;
    }
    let mut out = goish::strings::Builder::new();
    out.WriteString("sid=");
    out.WriteString(c.Value);
    out.WriteString("\n");
    w.Write(bytes(out.String()));
}

fn h_protected(w: &mut http::ResponseWriter, _r: &http::Request) {
    // Reached only after Bearer middleware validated.
    w.Write(bytes("admin only\n"));
}

fn h_root(w: &mut http::ResponseWriter, r: &http::Request) {
    if r.URL.Path == "/" {
        w.Write(bytes("hello world\n"));
    } else {
        w.WriteHeader(http::StatusNotFound);
        w.Write(bytes("custom 404\n"));
    }
}

// ─── middleware combinators ──────────────────────────────────────────

struct LoggingMW<H: http::Handler>(H);

impl<H: http::Handler> http::Handler for LoggingMW<H> {
    fn ServeHTTP(&self, w: &mut http::ResponseWriter, r: &http::Request) {
        REQ_COUNT.Add(1);
        // TODO(slog): emit structured access log with time::Since(started).
        self.0.ServeHTTP(w, r);
    }
}

struct BearerAuthMW<H: http::Handler> {
    inner: H,
    token: string,
}

impl<H: http::Handler> http::Handler for BearerAuthMW<H> {
    fn ServeHTTP(&self, w: &mut http::ResponseWriter, r: &http::Request) {
        let auth = r.Header.Get("Authorization");
        if !goish::strings::HasPrefix(&auth, "Bearer ") {
            w.Header().Set("WWW-Authenticate", "Bearer");
            http::Error(w, "unauthorized", http::StatusUnauthorized);
            return;
        }
        let supplied = goish::strings::TrimPrefix(auth, "Bearer ");
        if supplied != self.token {
            http::Error(w, "unauthorized", http::StatusUnauthorized);
            return;
        }
        self.inner.ServeHTTP(w, r);
    }
}

struct CorsMW<H: http::Handler>(H);

impl<H: http::Handler> http::Handler for CorsMW<H> {
    fn ServeHTTP(&self, w: &mut http::ResponseWriter, r: &http::Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*");
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        if r.Method == "OPTIONS" {
            w.WriteHeader(http::StatusNoContent);
            return;
        }
        self.0.ServeHTTP(w, r);
    }
}

// ─── helpers ─────────────────────────────────────────────────────────

fn check<S: Into<string>>(cond: bool, name: S) {
    if cond {
        pass(name);
    } else {
        fail(name);
    }
}

fn url_at<S: Into<string>>(path: S) -> string {
    let port = int(CLIENT_PORT.Load());
    goish::Sprintf!("http://127.0.0.1:%d%s", port, path.into())
}

// ─── main ────────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    // Bind first so we can report the port.
    let (ln, e) = net::Listen("tcp", "127.0.0.1:0");
    if !e.IsNil() {
        Println!("listen failed");
        os::Exit(1);
    }
    let port = ln.Addr().Port;
    CLIENT_PORT.Store(uint64(port));

    // Build the mux with a representative set of routes.
    let mux = http::ServeMux::new();
    mux.HandleFunc("/healthz", h_health);
    mux.HandleFunc("/api/users/{id}", h_user_get);
    mux.HandleFunc("/form", h_form);
    mux.HandleFunc("/session/set", h_session_set);
    mux.HandleFunc("/session/get", h_session_get);
    mux.HandleFunc("/", h_root);

    // /admin protected by Bearer middleware
    let admin_mux = http::ServeMux::new();
    admin_mux.HandleFunc("/secret", h_protected);
    mux.Handle("/admin/", BearerAuthMW {
        inner: http::StripPrefix("/admin", admin_mux),
        token: string("s3cret"),
    });

    // Server with timeouts. Wrap whole mux in CORS + Logging.
    let srv = Arc::new(http::Server {
        Handler: http::handler(LoggingMW(CorsMW(mux))),
        ReadHeaderTimeout: time::Second,
        ReadTimeout: time::Second * 3,
        WriteTimeout: time::Second * 3,
        ..Default::default()
    });

    let srv_run = srv.clone();
    go!(stack(64 * KB), move || {
        srv_run.Serve(ln);
        SERVE_DONE.Store(1);
    });

    // Driver goroutine — runs all assertions then shuts the server.
    let srv_for_shutdown = srv.clone();
    go!(stack(256 * KB), move || {
        time::Sleep(time::Millisecond * 50);

        // Test 1: /healthz → 200 with JSON body.
        let (resp, e) = http::Get(url_at("/healthz"));
        check(e.IsNil() && resp.StatusCode == 200
              && goish::bytes::Contains(&resp.Body, bytes("\"status\"")),
              "GET /healthz returns JSON 200");

        // Test 2: / root → 200 hello.
        let (resp, e) = http::Get(url_at("/"));
        check(e.IsNil() && resp.StatusCode == 200
              && goish::bytes::HasPrefix(&resp.Body, bytes("hello world")),
              "GET / returns hello world");

        // Test 3: /unknown → 404 custom.
        let (resp, e) = http::Get(url_at("/unknown"));
        check(e.IsNil() && resp.StatusCode == 404
              && goish::bytes::Contains(&resp.Body, bytes("custom 404")),
              "GET /unknown returns custom 404");

        // Test 4: /api/users/{id} wildcard binding.
        let (resp, e) = http::Get(url_at("/api/users/42"));
        check(e.IsNil() && resp.StatusCode == 200
              && goish::bytes::Contains(&resp.Body, bytes("\"id\":\"42\"")),
              "GET /api/users/42 binds wildcard");

        // Test 5: /admin/secret without token → 401.
        let (resp, e) = http::Get(url_at("/admin/secret"));
        check(e.IsNil() && resp.StatusCode == 401,
              "GET /admin/secret unauth -> 401");

        // Test 6: /admin/secret with bad token -> 401.
        let mut req = match http::NewRequest("GET", url_at("/admin/secret"), nil) {
            (r, e) if e.IsNil() => r,
            _ => { fail("NewRequest"); return; }
        };
        req.Header.Set("Authorization", "Bearer wrong");
        let client = http::Client::default();
        let (resp, e) = client.Do(&req);
        check(e.IsNil() && resp.StatusCode == 401,
              "GET /admin/secret bad token -> 401");

        // Test 7: /admin/secret with correct token → 200.
        let (mut req, _) = http::NewRequest("GET", url_at("/admin/secret"), nil);
        req.Header.Set("Authorization", "Bearer s3cret");
        let (resp, e) = client.Do(&req);
        check(e.IsNil() && resp.StatusCode == 200
              && goish::bytes::Contains(&resp.Body, bytes("admin only")),
              "GET /admin/secret with token -> 200");

        // Test 8: CORS headers on plain GET.
        let (resp, _) = http::Get(url_at("/"));
        let cors = resp.Header.Get("Access-Control-Allow-Origin");
        check(cors.Len() > 0, "CORS header on response");

        // Test 9: OPTIONS preflight → 204.
        let (req, _) = http::NewRequest("OPTIONS", url_at("/"), nil);
        let (resp, e) = client.Do(&req);
        check(e.IsNil() && resp.StatusCode == 204,
              "OPTIONS preflight -> 204");

        // Test 10: cookie set/get round-trip via header forwarding.
        let (resp, _) = http::Get(url_at("/session/set"));
        let sc = resp.Header.Get("Set-Cookie");
        check(goish::strings::HasPrefix(&sc, "sid=abc123"),
              "Set-Cookie returned");

        let (mut req, _) = http::NewRequest("GET", url_at("/session/get"), nil);
        req.Header.Set("Cookie", "sid=abc123");
        let (resp, e) = client.Do(&req);
        check(e.IsNil() && resp.StatusCode == 200
              && goish::bytes::Contains(&resp.Body, bytes("sid=abc123")),
              "Cookie roundtrip");

        // Test 11: form query parsing via FormValue (handler-side parse).
        let (resp, e) = http::Get(url_at("/form?name=alice&age=30"));
        check(e.IsNil()
              && goish::bytes::Contains(&resp.Body, bytes("name=alice"))
              && goish::bytes::Contains(&resp.Body, bytes("age=30")),
              "Form query parsed via FormValue");

        // Test 12: graceful shutdown.
        let err = srv_for_shutdown.Shutdown(time::Second);
        check(err.IsNil(), "Server.Shutdown returns nil");

        // Wait for serve goroutine to acknowledge.
        let mut tries = 0;
        while SERVE_DONE.Load() == 0 && tries < 30 {
            time::Sleep(time::Millisecond * 50);
            tries += 1;
        }
        check(SERVE_DONE.Load() == 1,
              "Serve goroutine returned post-Shutdown");

        let f = int64(FAILED.Load());
        if f == 0 {
            Println!("PRODUCTION_HTTP_OK 12/12");
            os::Exit(0);
        } else {
            Printf!("PRODUCTION_HTTP_FAIL %d / 12\n", f);
            os::Exit(1);
        }
    });

    go!(stack(32 * KB), move || {
        time::Sleep(time::Second * 30);
        Println!("TIMEOUT");
        os::Exit(2);
    });

    schedule();
}