// http_mux_allow_ref_smoke — the Allow header on a 405, against Go.
//
// ServeMux.matchingMethods (server.go:2831) builds that header, and it
// runs the tree match TWICE: once for the path as given, and again
// with a trailing slash appended, "because matchOrRedirect will try
// appending a trailing slash if there is no match". goish ran it once.
//
// The visible effect: a mux carrying only "POST /x/" answered GET /x
// with 404, where Go answers 405 and names POST in Allow. A 404 says
// the route does not exist; a 405 says it exists under another method.
// A client cannot tell the difference from the outside, so the wrong
// one sends it looking for a bug that is not there.
//
// The last line is the guard the fix needs. When the METHOD matches,
// the path must still redirect — GET /z against a registered
// "GET /z/" is a 301 to /z/, not a 405 — so the second match must not
// swallow the redirect path.
//
// GO[] is the verbatim output of tools/gen_mux_allow_ref.go under
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http;
use goish::net::http::httptest;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 5] = [
    "GET    /x   status=405 allow=\"POST\" loc=\"\"",
    "GET    /x/  status=405 allow=\"POST\" loc=\"\"",
    "DELETE /y   status=405 allow=\"GET, HEAD, PUT\" loc=\"\"",
    "POST   /y/  status=404 allow=\"\" loc=\"\"",
    "GET    /z   status=301 allow=\"\" loc=\"/z/\"",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s
", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d
  got:  %s
  want: %s
",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
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

fn run() {
    let mux = http::ServeMux::new();
    mux.HandleFunc("POST /x/", |_w, _r| {});
    mux.HandleFunc("GET /y", |_w, _r| {});
    mux.HandleFunc("PUT /y", |_w, _r| {});
    mux.HandleFunc("GET /z/", |_w, _r| {});

    let cases: [(&str, &str); 5] = [
        ("GET", "/x"),
        ("GET", "/x/"),
        ("DELETE", "/y"),
        ("POST", "/y/"),
        ("GET", "/z"),
    ];
    let mut i = 0;
    while i < cases.len() {
        let (m, p) = cases[i];
        let req = httptest::NewRequest(m, p, goish::nil);
        let w = httptest::NewRecorder();
        http::Handler::ServeHTTP(&mux, &w, &req);
        chk(fmt::Sprintf!(
            "%-6s %-4s status=%d allow=%q loc=%q",
            string(m),
            string(p),
            w.Code() as i64,
            w.HeaderMap().Get(string("Allow")),
            w.HeaderMap().Get(string("Location"))
        ));
        i += 1;
    }

    let f = FAILED.load(Ordering::Relaxed);
    let n = SEEN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("
ok %d/%d
", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("
FAILED %d of %d
", f as i64, GO.len() as i64);
    goish::os::Exit(1);
}
