//! Pinned against Go 1.25.5: `http.Response.Body`'s close contract.
//!
//! The third layer in the error-discipline sweep that started with
//! crypto/tls latching a read deadline (da96552) and bufio choosing
//! oppositely in each half (551e2df). A response body is where a
//! caller most often gets the lifecycle wrong, and where the answers
//! are least guessable:
//!
//!   * Reading past the end is `io.EOF`, and reading AGAIN is io.EOF
//!     — not a closed-body error. The body is exhausted, not shut.
//!   * `Close` twice is nil BOTH times. Unlike os.File and net.Conn,
//!     which report "already closed", a response body is idempotent —
//!     `defer resp.Body.Close()` after an explicit Close is the
//!     documented idiom, so it cannot be an error.
//!   * Reading after Close is `http: read on closed response body`,
//!     a distinct message from EOF. That difference is the whole
//!     point: it separates "the server finished" from "you closed it".
//!   * Closing BEFORE reading gives the same error, not the body.
//!   * `io.NopCloser`'s Close is a no-op, so a read after it still
//!     returns EOF. Wrapping does not add a lifecycle.
//!
//! goish matches Go on all eleven lines — no defects. The smoke exists
//! so the four different answers stay four.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net/http <body_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::io::{Closer, Reader};
use goish::net::http::{self, httptest, Handler, Request, ResponseWriter};
use goish::types::byte;
use goish::{bytes, fmt, io, make, string};

struct Backend;
impl Handler for Backend {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
        let _ = w.Write(goish::convert::bytes(string("hello body")));
    }
}
fn es(e: goish::error) -> string {
    if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    }
}
/// Go's output, verbatim.
const GO: [&str; 11] = [
    "read-partial             [4 \"hell\" \"<nil>\"]",
    "read-rest                [\"o body\" \"<nil>\"]",
    "read-after-eof           [0 \"EOF\"]",
    "close                    [\"<nil>\"]",
    "close-twice              [\"<nil>\"]",
    "read-after-close         [0 \"http: read on closed response body\"]",
    "early-close              [\"<nil>\"]",
    "read-after-early-close   [0 \"http: read on closed response body\"]",
    "nopcloser-read           [3 \"abc\" \"<nil>\"]",
    "nopcloser-close          [\"<nil>\"]",
    "nopcloser-after-close    [0 \"EOF\"]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

fn line(tag: &'static str, parts: alloc::vec::Vec<string>) {
    let mut out = string("");
    for (i, x) in parts.iter().enumerate() {
        if i > 0 {
            out = out + string(" ");
        }
        out = out + x.clone();
    }
    chk(fmt::Sprintf!("%-24s [%s]", string::from_static(tag), out));
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
fn q(s: string) -> string {
    fmt::Sprintf!("%q", s)
}
fn n(v: i64) -> string {
    fmt::Sprintf!("%d", v)
}

#[goish::main]
fn main() {
    goish::go!(stack(2 * 1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let srv = httptest::NewServer(Arc::new(Backend) as Arc<dyn Handler>);
    let url = srv.URL();

    let (mut resp, _) = http::Get(url.clone());
    let mut b = make!([]byte, 4);
    let (rn, re) = resp.Body.Read(&mut b);
    line(
        "read-partial",
        alloc::vec![
            n(rn as i64),
            q(string::from_bytes(&b.slice(0, rn as i64).to_vec())),
            q(es(re))
        ],
    );
    let (all, ae) = io::ReadAll(&mut resp.Body);
    line(
        "read-rest",
        alloc::vec![q(string::from_bytes(&all.to_vec())), q(es(ae))],
    );
    let (rn, re) = resp.Body.Read(&mut b);
    line("read-after-eof", alloc::vec![n(rn as i64), q(es(re))]);
    line("close", alloc::vec![q(es(resp.Body.Close()))]);
    line("close-twice", alloc::vec![q(es(resp.Body.Close()))]);
    let (rn, re) = resp.Body.Read(&mut b);
    line("read-after-close", alloc::vec![n(rn as i64), q(es(re))]);

    let (mut resp2, _) = http::Get(url.clone());
    line("early-close", alloc::vec![q(es(resp2.Body.Close()))]);
    let (rn, re) = resp2.Body.Read(&mut b);
    line(
        "read-after-early-close",
        alloc::vec![n(rn as i64), q(es(re))],
    );

    let mut rc = io::NopCloser(bytes::NewReader(goish::convert::bytes(string("abc"))));
    let (rn, re) = rc.Read(&mut b);
    line(
        "nopcloser-read",
        alloc::vec![
            n(rn as i64),
            q(string::from_bytes(&b.slice(0, rn as i64).to_vec())),
            q(es(re))
        ],
    );
    line("nopcloser-close", alloc::vec![q(es(rc.Close()))]);
    let (rn, re) = rc.Read(&mut b);
    line(
        "nopcloser-after-close",
        alloc::vec![n(rn as i64), q(es(re))],
    );

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("http body close: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
