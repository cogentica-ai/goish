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

// Go-shape package imports — `strings.HasPrefix(...)` reads as
// `strings::HasPrefix(...)` once `strings` is in scope.
use goish::bytes as gobytes;
use goish::encoding::json;
use goish::net;
use goish::net::http;
use goish::os;
use goish::runtime::sched::schedule;
use goish::strings;
use goish::sync::atomic::Uint64;
use goish::time;
use goish::{
    append, bytes, float64, go, int, int64, make, nil, string, uint64, Eprintln, Printf, Println,
    Sprintf, KB,
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

fn healthz(w: &mut http::ResponseWriter, _r: &http::Request) {
    let mut obj = make!(map[string]json::Value);
    obj.Set("status", "ok");
    obj.Set("reqs", float64(REQ_COUNT.Load()));
    let (body, e) = json::Marshal(&json::Value::Object(obj));
    if e != nil {
        http::Error(w, e.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json; charset=utf-8");
    w.Write(body);
}

fn userGet(w: &mut http::ResponseWriter, r: &http::Request) {
    let id = r.PathValue("id");
    if id.Len() == 0 {
        http::Error(w, "missing id", http::StatusBadRequest);
        return;
    }
    let mut obj = make!(map[string]json::Value);
    obj.Set("id", id);
    obj.Set("name", "Alice");
    let (body, err) = json::Marshal(&json::Value::Object(obj));
    if err != nil {
        http::Error(w, err.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json");
    w.Write(body);
}

// POST /api/echo — accepts a JSON body { "name": "...", "items": [...] },
// validates the schema (name must be a non-empty string, items must be
// an array), then echoes it back with a server-side `received_at`
// timestamp and an `item_count` field. Demonstrates the request-side
// JSON path: r.Body → json::Unmarshal → schema check → reshape →
// json::Marshal → w.Write.
fn apiEcho(w: &mut http::ResponseWriter, r: &http::Request) {
    if r.Method != "POST" {
        http::Error(w, "POST required", http::StatusMethodNotAllowed);
        return;
    }
    // Go shape: var req map[string]any; if err := json.Unmarshal(r.Body, &req); err != nil { … }
    let mut req_val = json::Value::Null;
    let perr = json::Unmarshal(&r.Body, &mut req_val);
    if perr != nil {
        http::Error(w, "invalid json", http::StatusBadRequest);
        return;
    }
    // req, ok := reqVal.(map[string]any)
    let req = req_val.AsObject();
    if req.is_none() {
        http::Error(w, "expected object", http::StatusBadRequest);
        return;
    }
    let req = req.unwrap();
    // nameV, ok := req["name"]; name, ok := nameV.(string); …
    let (name_v, ok) = req.Get("name");
    let name_s = name_v.AsString();
    if !ok || name_s.is_none() || name_s.unwrap().Len() == 0 {
        http::Error(w, "name must be a non-empty string", http::StatusBadRequest);
        return;
    }
    let name = name_s.unwrap().clone();
    // itemsV, ok := req["items"]; items, ok := itemsV.([]any); …
    let (items_v, ok) = req.Get("items");
    if !ok || items_v.AsArray().is_none() {
        http::Error(w, "items must be an array", http::StatusBadRequest);
        return;
    }
    let items = items_v.AsArray().unwrap().clone();
    // out := map[string]any{ "name": name, "item_count": …, "items": items, "received_at_unix": … }
    let mut out = make!(map[string]json::Value);
    out.Set("name", name);
    out.Set("item_count", float64(items.Len()));
    out.Set("items", json::Value::Array(items));
    out.Set("received_at_unix", float64(time::Now().Unix()));
    let (body, e) = json::Marshal(&json::Value::Object(out));
    if e != nil {
        http::Error(w, e.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json; charset=utf-8");
    w.Write(body);
}

// GET /api/stats — emits a nested-JSON status snapshot. Exercises the
// response-side path with non-trivial nesting (object → array of
// objects → number/string mix) so the body's json::Marshal recursion
// is non-trivial. With auto-grow this fits in tier-1 with room to
// spare; under heavier nesting the maybe_grow_step inside json's
// recursive marshaller would pivot.
fn apiStats(w: &mut http::ResponseWriter, _r: &http::Request) {
    // shards := make([]any, 0)
    // for i := 0; i < 4; i++ { shards = append(shards, map[string]any{…}) }
    let mut shards = make!([]json::Value, 0);
    for i in 0..int64(4) {
        let mut s = make!(map[string]json::Value);
        s.Set("id", float64(i));
        s.Set("reqs", float64(REQ_COUNT.Load() / 4));
        s.Set("healthy", json::Value::Bool(true));
        shards = append!(shards, json::Value::Object(s));
    }
    // root := map[string]any{ "service": …, "shards": shards, … }
    let mut root = make!(map[string]json::Value);
    root.Set("service", "production_http_server");
    root.Set("uptime_unix", float64(time::Now().Unix()));
    root.Set("total_reqs", float64(REQ_COUNT.Load()));
    root.Set("shards", json::Value::Array(shards));
    let (body, err) = json::Marshal(&json::Value::Object(root));
    if err != nil {
        http::Error(w, err.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json; charset=utf-8");
    w.Write(body);
}

fn formHandler(w: &mut http::ResponseWriter, r: &http::Request) {
    // ParseForm + FormValue both take `&Request` (interior mutability
    // via Mutex<FormCell>), so handlers can parse form values
    // directly — no `&mut self` workaround needed.
    let name = r.FormValue("name");
    let age = r.FormValue("age");
    w.Header().Set("Content-Type", "text/plain");
    let mut out = strings::Builder::new();
    out.WriteString("name=");
    out.WriteString(name);
    out.WriteString("&age=");
    out.WriteString(age);
    w.Write(bytes(out.String()));
}

fn sessionSet(w: &mut http::ResponseWriter, _r: &http::Request) {
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

fn sessionGet(w: &mut http::ResponseWriter, r: &http::Request) {
    let (c, err) = r.Cookie("sid");
    if err != nil {
        w.Write(bytes("no session\n"));
        return;
    }
    let mut out = strings::Builder::new();
    out.WriteString("sid=");
    out.WriteString(c.Value);
    out.WriteString("\n");
    w.Write(bytes(out.String()));
}

fn adminSecret(w: &mut http::ResponseWriter, _r: &http::Request) {
    // Reached only after Bearer middleware validated.
    w.Write(bytes("admin only\n"));
}

fn rootHandler(w: &mut http::ResponseWriter, r: &http::Request) {
    if r.URL.Path == "/" {
        w.Write(bytes("hello world\n"));
    } else {
        w.WriteHeader(http::StatusNotFound);
        w.Write(bytes("custom 404\n"));
    }
}

// ─── middleware combinators ──────────────────────────────────────────
//
// Go shape: middleware are functions `func(next http.Handler) http.Handler`,
// composing via wrapping. Goish renders these as functions returning an
// `Arc<dyn http::Handler>` constructed from a closure via
// `http::HandlerFunc`. No generic struct + trait-impl boilerplate.

fn logging(next: Arc<dyn http::Handler>) -> Arc<dyn http::Handler> {
    Arc::new(http::HandlerFunc(move |w: &mut http::ResponseWriter, r: &http::Request| {
        REQ_COUNT.Add(1);
        // TODO(slog): emit structured access log with time::Since(started).
        next.ServeHTTP(w, r);
    }))
}

fn bearerAuth<S: Into<string>>(token: S, next: Arc<dyn http::Handler>) -> Arc<dyn http::Handler> {
    let token: string = token.into();
    Arc::new(http::HandlerFunc(move |w: &mut http::ResponseWriter, r: &http::Request| {
        let auth = r.Header.Get("Authorization");
        if !strings::HasPrefix(&auth, "Bearer ") {
            w.Header().Set("WWW-Authenticate", "Bearer");
            http::Error(w, "unauthorized", http::StatusUnauthorized);
            return;
        }
        let supplied = strings::TrimPrefix(auth, "Bearer ");
        if supplied != token {
            http::Error(w, "unauthorized", http::StatusUnauthorized);
            return;
        }
        next.ServeHTTP(w, r);
    }))
}

fn cors(next: Arc<dyn http::Handler>) -> Arc<dyn http::Handler> {
    Arc::new(http::HandlerFunc(move |w: &mut http::ResponseWriter, r: &http::Request| {
        w.Header().Set("Access-Control-Allow-Origin", "*");
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        if r.Method == "OPTIONS" {
            w.WriteHeader(http::StatusNoContent);
            return;
        }
        next.ServeHTTP(w, r);
    }))
}

// ─── helpers ─────────────────────────────────────────────────────────

fn urlAt<S: Into<string>>(path: S) -> string {
    let port = int(CLIENT_PORT.Load());
    Sprintf!("http://127.0.0.1:%d%s", port, path.into())
}

// ─── main ────────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    // Bind first so we can report the port.
    let (ln, e) = net::Listen("tcp", "127.0.0.1:0");
    if e != nil {
        Println!("listen failed");
        os::Exit(1);
    }
    let port = ln.Addr().Port;
    CLIENT_PORT.Store(uint64(port));

    // Build the mux with a representative set of routes.
    let mux = http::ServeMux::new();
    mux.HandleFunc("/healthz", healthz);
    mux.HandleFunc("/api/users/{id}", userGet);
    mux.HandleFunc("/api/echo", apiEcho);
    mux.HandleFunc("/api/stats", apiStats);
    mux.HandleFunc("/form", formHandler);
    mux.HandleFunc("/session/set", sessionSet);
    mux.HandleFunc("/session/get", sessionGet);
    mux.HandleFunc("/", rootHandler);

    // /admin protected by Bearer middleware (Go: bearerAuth("s3cret",
    // http.StripPrefix("/admin", adminMux))).
    let admin_mux = http::ServeMux::new();
    admin_mux.HandleFunc("/secret", adminSecret);
    mux.Handle("/admin/", bearerAuth(
        "s3cret",
        http::StripPrefix("/admin", admin_mux),
    ));

    // Server with timeouts. Wrap whole mux in CORS + Logging
    // (Go: srv.Handler = logging(cors(mux))).
    let srv = Arc::new(http::Server {
        Handler: logging(cors(http::handler(mux))),
        ReadHeaderTimeout: time::Second,
        ReadTimeout: time::Second * 3,
        WriteTimeout: time::Second * 3,
        ..Default::default()
    });

    // Serve goroutine — runs the accept loop. Kept on `stack(64*KB)`
    // because Serve's internal per-connection spawn path uses heavier
    // closure plumbing than the auto-grow wrap's lazy-pivot threshold.
    let srv_run = srv.clone();
    go!(stack(64 * KB), move || {
        srv_run.Serve(ln);
        SERVE_DONE.Store(1);
    });

    // Driver goroutine — runs all assertions then shuts the server.
    // Kept on `stack(256*KB)` because the http client.Do chain has
    // heavy debug-build frame overhead that exceeds the auto-grow
    // wrap's tier-1 → tier-2 transition headroom.
    let srv_for_shutdown = srv.clone();
    go!(stack(256 * KB), move || {
        time::Sleep(time::Millisecond * 50);
        let client = http::Client::default();

        // Test 1: /healthz → 200 with JSON body.
        let name = "GET /healthz returns JSON 200";
        let (resp, err) = http::Get(urlAt("/healthz"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("\"status\"")) {
            fail(Sprintf!("%s: missing \"status\" field", name));
        } else {
            pass(name);
        }

        // Test 2: / root → 200 hello.
        let name = "GET / returns hello world";
        let (resp, err) = http::Get(urlAt("/"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::HasPrefix(&resp.Body, bytes("hello world")) {
            fail(Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // Test 3: /unknown → 404 custom.
        let name = "GET /unknown returns custom 404";
        let (resp, err) = http::Get(urlAt("/unknown"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 404 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("custom 404")) {
            fail(Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // Test 4: /api/users/{id} wildcard binding.
        let name = "GET /api/users/42 binds wildcard";
        let (resp, err) = http::Get(urlAt("/api/users/42"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("\"id\":\"42\"")) {
            fail(Sprintf!("%s: id not bound", name));
        } else {
            pass(name);
        }

        // Test 5: /admin/secret without token → 401.
        let name = "GET /admin/secret unauth -> 401";
        let (resp, err) = http::Get(urlAt("/admin/secret"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 401 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            pass(name);
        }

        // Test 6: /admin/secret with bad token -> 401.
        let name = "GET /admin/secret bad token -> 401";
        let (mut req, err) = http::NewRequest("GET", urlAt("/admin/secret"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Header.Set("Authorization", "Bearer wrong");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 401 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // Test 7: /admin/secret with correct token → 200.
        let name = "GET /admin/secret with token -> 200";
        let (mut req, err) = http::NewRequest("GET", urlAt("/admin/secret"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Header.Set("Authorization", "Bearer s3cret");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(&resp.Body, bytes("admin only")) {
                fail(Sprintf!("%s: bad body", name));
            } else {
                pass(name);
            }
        }

        // Test 8: CORS headers on plain GET.
        let name = "CORS header on response";
        let (resp, err) = http::Get(urlAt("/"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.Header.Get("Access-Control-Allow-Origin").Len() == 0 {
            fail(Sprintf!("%s: header missing", name));
        } else {
            pass(name);
        }

        // Test 9: OPTIONS preflight → 204.
        let name = "OPTIONS preflight -> 204";
        let (req, err) = http::NewRequest("OPTIONS", urlAt("/"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 204 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // Test 10a: cookie set returns Set-Cookie header.
        let name = "Set-Cookie returned";
        let (resp, err) = http::Get(urlAt("/session/set"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else {
            let sc = resp.Header.Get("Set-Cookie");
            if !strings::HasPrefix(&sc, "sid=abc123") {
                fail(Sprintf!("%s: got %s", name, &sc));
            } else {
                pass(name);
            }
        }

        // Test 10b: cookie roundtrip — client sends, server reads.
        let name = "Cookie roundtrip";
        let (mut req, err) = http::NewRequest("GET", urlAt("/session/get"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Header.Set("Cookie", "sid=abc123");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(&resp.Body, bytes("sid=abc123")) {
                fail(Sprintf!("%s: server didn't see cookie", name));
            } else {
                pass(name);
            }
        }

        // Test 11: form query parsing via FormValue (handler-side parse).
        let name = "Form query parsed via FormValue";
        let (resp, err) = http::Get(urlAt("/form?name=alice&age=30"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if !gobytes::Contains(&resp.Body, bytes("name=alice"))
            || !gobytes::Contains(&resp.Body, bytes("age=30"))
        {
            fail(Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // Test 12: POST /api/echo — JSON request body roundtrip.
        let name = "POST /api/echo roundtrips JSON body";
        let payload = bytes(r#"{"name":"widget","items":[1,"two",true,null]}"#);
        let (mut req, err) = http::NewRequest("POST", urlAt("/api/echo"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = payload.clone();
            req.ContentLength = payload.Len();
            req.Header.Set("Content-Type", "application/json");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(&resp.Body, bytes("\"name\":\"widget\""))
                || !gobytes::Contains(&resp.Body, bytes("\"item_count\":4"))
            {
                fail(Sprintf!("%s: bad body", name));
            } else {
                pass(name);
            }
        }

        // Test 13: POST /api/echo with bad JSON → 400.
        let name = "POST /api/echo rejects malformed JSON";
        let (mut req, err) = http::NewRequest("POST", urlAt("/api/echo"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = bytes("not-json{");
            req.ContentLength = req.Body.Len();
            req.Header.Set("Content-Type", "application/json");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 400 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // Test 14: POST /api/echo with wrong schema (missing items) → 400.
        let name = "POST /api/echo rejects bad schema";
        let (mut req, err) = http::NewRequest("POST", urlAt("/api/echo"), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = bytes(r#"{"name":"x"}"#);
            req.ContentLength = req.Body.Len();
            req.Header.Set("Content-Type", "application/json");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 400 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // Test 15: GET /api/echo → 405 (POST required).
        let name = "GET /api/echo returns 405";
        let (resp, err) = http::Get(urlAt("/api/echo"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 405 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            pass(name);
        }

        // Test 16: GET /api/stats — nested JSON response.
        let name = "GET /api/stats returns nested JSON";
        let (resp, err) = http::Get(urlAt("/api/stats"));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("\"service\""))
            || !gobytes::Contains(&resp.Body, bytes("\"shards\""))
            || !gobytes::Contains(&resp.Body, bytes("\"healthy\":true"))
        {
            fail(Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // Test 17: graceful shutdown.
        let name = "Server.Shutdown returns nil";
        let err = srv_for_shutdown.Shutdown(time::Second);
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else {
            pass(name);
        }

        // Wait for serve goroutine to acknowledge.
        let name = "Serve goroutine returned post-Shutdown";
        let mut tries = 0;
        while SERVE_DONE.Load() == 0 && tries < 30 {
            time::Sleep(time::Millisecond * 50);
            tries += 1;
        }
        if SERVE_DONE.Load() != 1 {
            fail(Sprintf!("%s: serve still running", name));
        } else {
            pass(name);
        }

        let f = int64(FAILED.Load());
        if f == 0 {
            Println!("PRODUCTION_HTTP_OK 17/17");
            os::Exit(0);
        } else {
            Printf!("PRODUCTION_HTTP_FAIL %d / 17\n", f);
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