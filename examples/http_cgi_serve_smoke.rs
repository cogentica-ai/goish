// http_cgi_serve_smoke — net/http/cgi's host side: Handler.ServeHTTP
// runs a real child process and turns its stdout into an HTTP
// response.
//
// The script under test is /bin/sh -c, which is exactly the shape Go
// uses: `cmd.Args = append([]string{h.Path}, h.Args...)`, so argv[0]
// is Path and Args follow.
//
// What is worth asserting, beyond "it runs":
//
//   * the `Proxy` request header must NOT become HTTP_PROXY. That is
//     CVE-2016-5385 (httpoxy): a client-supplied `Proxy:` header
//     arriving as the script's HTTP_PROXY redirects the script's own
//     outbound requests through an attacker's host. Go drops it
//     explicitly (issue 16405).
//   * Cookie is joined with "; " while every other repeated header is
//     joined with ", ". Getting that wrong corrupts every multi-cookie
//     request.
//   * a chunked request body is refused with 400 rather than passed
//     along, because CGI has no way to say "length unknown" to the
//     child.
//   * a script that writes no headers, or a Content-Type-less response
//     with no Status, is a 500 — not a 200 with a blank body.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::goslice::slice;
use goish::net::http;
use goish::net::http::cgi;
use goish::net::http::httptest;
use goish::net::http::responsewriter::ResponseWriter;
use goish::net::http::server::Handler as HTTPHandler;
use goish::string;

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);
static REDIRECTED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

/// The handler a local `Location: /…` is redirected into.
struct localHandler;

impl HTTPHandler for localHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        REDIRECTED.fetch_add(1, Ordering::Relaxed);
        let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
            "internal:%s:%s",
            r.Method,
            r.URL.Path
        )));
    }
}

/// Echoes just the two variables the Root table is about.
const SCRIPT_ROOT: &str = concat!(
    "printf 'Content-Type: text/plain\\r\\n\\r\\n'; ",
    "printf 'SN=[%s] PI=[%s]' \"$SCRIPT_NAME\" \"$PATH_INFO\"",
);

fn sh(script: &'static str) -> cgi::host::Handler {
    let mut args: slice<goish::string> = slice::new();
    args = goish::append!(args, string("-c"));
    args = goish::append!(args, string(script));
    return cgi::host::Handler {
        Path: string("/bin/sh"),
        Args: args,
        ..Default::default()
    };
}

fn req(path: &'static str) -> http::Request {
    let mut r = http::Request::default();
    r.Method = string("GET");
    r.Proto = string("HTTP/1.1");
    r.ProtoMajor = 1;
    r.ProtoMinor = 1;
    r.Host = string("example.com:8080");
    r.RemoteAddr = string("192.0.2.7:1234");
    let (u, _) = http::url::Parse(string(path));
    r.URL = u;
    r.RequestURI = string(path);
    return r;
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    goish::net::http::server::register_http_impls();
    goish::net::http::server::__goish_register_Handler_impl::<localHandler>();

    // ── the ordinary case ──
    {
        let h = sh("printf 'Content-Type: text/plain\\r\\n\\r\\nhello from cgi'");
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/x"));
        let body = goish::string::from_bytes(&w.Body());
        check(
            "a CGI script's head and body become the response",
            w.Code() == 200
                && body == "hello from cgi"
                && w.HeaderMap().Get(string("Content-Type")) == "text/plain",
            fmt::Sprintf!("code=%d body=%q", w.Code(), body),
        );
    }

    // ── Status: overrides the code and is not echoed as a header ──
    {
        let h =
            sh("printf 'Status: 418 I am a teapot\\r\\nContent-Type: text/plain\\r\\n\\r\\nnope'");
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/x"));
        check(
            "a Status: line sets the code and does not leak into the headers",
            w.Code() == 418 && w.HeaderMap().Get(string("Status")).Len() == 0,
            fmt::Sprintf!("code=%d", w.Code()),
        );
    }

    // ── the CGI environment ──
    {
        let h = sh("printf 'Content-Type: text/plain\\r\\n\\r\\n'; \
             printf 'M=%s Q=%s P=%s SN=%s PI=%s SP=%s RA=%s' \
             \"$REQUEST_METHOD\" \"$QUERY_STRING\" \"$SCRIPT_FILENAME\" \
             \"$SERVER_NAME\" \"$PATH_INFO\" \"$SERVER_PORT\" \"$REMOTE_ADDR\"");
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/a/b?q=1&r=2"));
        let body = goish::string::from_bytes(&w.Body());
        let b: &str = body.as_ref();
        check(
            "RFC 3875 variables carry the request",
            b.contains("M=GET")
                && b.contains("Q=q=1&r=2")
                && b.contains("P=/bin/sh")
                && b.contains("SN=example.com")
                && b.contains("PI=/a/b")
                && b.contains("SP=8080")
                && b.contains("RA=192.0.2.7"),
            body,
        );
    }

    // ── Root trims a trailing slash, and PATH_INFO is what is left ──
    //
    // Table from scripts/goref.sh against Go 1.25.5 for the SAME
    // request (GET /cgi/a/b?q=1&r=2):
    //
    //   Root ""      -> SCRIPT_NAME=[]     PATH_INFO=[/cgi/a/b]
    //   Root "/cgi"  -> SCRIPT_NAME=[/cgi] PATH_INFO=[/a/b]
    //   Root "/cgi/" -> SCRIPT_NAME=[/cgi] PATH_INFO=[/a/b]
    {
        let cases: &[(&'static str, &'static str)] = &[
            ("", "SN=[] PI=[/cgi/a/b]"),
            ("/cgi", "SN=[/cgi] PI=[/a/b]"),
            ("/cgi/", "SN=[/cgi] PI=[/a/b]"),
        ];
        let mut bad = string("");
        for (root, want) in cases {
            let mut h = sh(SCRIPT_ROOT);
            h.Root = string(*root);
            let w = httptest::NewRecorder();
            h.ServeHTTP(&w, &req("/cgi/a/b?q=1&r=2"));
            let body = goish::string::from_bytes(&w.Body());
            if body != *want {
                bad = fmt::Sprintf!(
                    "Root=%q gave %q want %q",
                    string(*root),
                    body,
                    string(*want)
                );
            }
        }
        check(
            "Root trims one trailing slash and PATH_INFO is the remainder",
            bad.Len() == 0,
            bad,
        );
    }

    // ── httpoxy: Proxy must not reach the child ──
    {
        let h = sh("printf 'Content-Type: text/plain\\r\\n\\r\\n'; \
             printf 'proxy=[%s] foo=[%s]' \"$HTTP_PROXY\" \"$HTTP_X_FOO\"");
        let w = httptest::NewRecorder();
        let mut r = req("/x");
        r.Header
            .Set(string("Proxy"), string("http://evil.example/"));
        r.Header.Set(string("X-Foo"), string("kept"));
        h.ServeHTTP(&w, &r);
        let body = goish::string::from_bytes(&w.Body());
        let b: &str = body.as_ref();
        check(
            "the Proxy header is dropped (httpoxy) while others pass through",
            b.contains("proxy=[]") && b.contains("foo=[kept]"),
            body,
        );
    }

    // ── Cookie joins with "; ", everything else with ", " ──
    {
        let h = sh("printf 'Content-Type: text/plain\\r\\n\\r\\n'; \
             printf 'c=[%s] a=[%s]' \"$HTTP_COOKIE\" \"$HTTP_X_MULTI\"");
        let w = httptest::NewRecorder();
        let mut r = req("/x");
        r.Header.Add(string("Cookie"), string("a=1"));
        r.Header.Add(string("Cookie"), string("b=2"));
        r.Header.Add(string("X-Multi"), string("one"));
        r.Header.Add(string("X-Multi"), string("two"));
        h.ServeHTTP(&w, &r);
        let body = goish::string::from_bytes(&w.Body());
        let b: &str = body.as_ref();
        check(
            "Cookie joins with '; ' and other repeated headers with ', '",
            b.contains("c=[a=1; b=2]") && b.contains("a=[one, two]"),
            body,
        );
    }

    // ── a chunked request body is refused ──
    {
        let h = sh("printf 'Content-Type: text/plain\\r\\n\\r\\nshould not run'");
        let w = httptest::NewRecorder();
        let mut r = req("/x");
        r.Header.Add(string("Transfer-Encoding"), string("chunked"));
        h.ServeHTTP(&w, &r);
        let body = goish::string::from_bytes(&w.Body());
        check(
            "a chunked request body is refused with 400, and the script never runs",
            w.Code() == 400 && !(body.as_ref() as &str).contains("should not run"),
            fmt::Sprintf!("code=%d body=%q", w.Code(), body),
        );
    }

    // ── a script with no headers at all ──
    {
        let h = sh("printf 'no head, just body'");
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/x"));
        check(
            "a script that writes no header block is a 500",
            w.Code() == 500,
            fmt::Sprintf!("code=%d", w.Code()),
        );
    }

    // ── no Content-Type and no Status ──
    {
        let h = sh("printf 'X-Thing: 1\\r\\n\\r\\nbody'");
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/x"));
        check(
            "a response with neither Content-Type nor Status is a 500",
            w.Code() == 500,
            fmt::Sprintf!("code=%d", w.Code()),
        );
    }

    // ── a local Location goes through PathLocationHandler ──
    {
        let mut h = sh("printf 'Location: /elsewhere\\r\\n\\r\\n'");
        h.PathLocationHandler = Some(Arc::new(localHandler));
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/x"));
        let body = goish::string::from_bytes(&w.Body());
        check(
            "a local Location is served internally, as GET, by PathLocationHandler",
            REDIRECTED.load(Ordering::Relaxed) == 1
                && (body.as_ref() as &str).contains("internal:GET:/elsewhere"),
            fmt::Sprintf!("code=%d body=%q", w.Code(), body),
        );
    }

    // ── an absolute Location is a 302 to the client ──
    {
        let h = sh("printf 'Location: http://other.example/p\\r\\n\\r\\n'");
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, &req("/x"));
        check(
            "an absolute Location becomes a 302 the client follows",
            w.Code() == 302
                && w.HeaderMap().Get(string("Location")) == "http://other.example/p"
                && REDIRECTED.load(Ordering::Relaxed) == 1,
            fmt::Sprintf!("code=%d", w.Code()),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CGI_SERVE_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CGI_SERVE_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
