// http_body_sticky_ref_smoke — a failed body read keeps failing.
//
// Go's bodyEOFSignal (transport.go:2989) stores `rerr`, the first read
// error, and returns it from every later Read. A truncated response —
// Content-Length promises 100, the server sends 10 and closes — must
// report the SAME failure each time rather than decaying into EOF,
// which would read as "body ended cleanly" to anything that retries
// after an error.
//
// goish has no explicit rerr for the conn-backed framings and does not
// need one: each read hits the same dead connection and reports the
// same unexpected EOF. That is a behaviour worth PINNING rather than
// arguing about, because the body read path is where a sticky-error
// defect has already been found once — the transport's gzip reader
// decayed to EOF on its second read, and every fix in that function
// since (did_read, chunk_drained) touches the same code.
//
// After Close the closed-check wins, ahead of the read error: Go tests
// `closed` before `rerr`, so the answer is the closed-body error and
// not the truncation that preceded it.
//
// GO[] is the verbatim output of tools/gen_body_sticky_ref.go under
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::io::Reader as _;
use goish::types::byte;
use goish::fmt;
use goish::net;
use goish::net::http;
use goish::{go, string, time};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 5] = [
    "read0 n=8 err=<nil>",
    "read1 n=2 err=<nil>",
    "read2 n=0 err=unexpected EOF",
    "read3 n=0 err=unexpected EOF",
    "after close n=0 err=http: read on closed response body",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
}
#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() { fmt::Printf!("listen: %v\n", le); goish::os::Exit(1); }
    let port = ln.Addr().Port;
    go!(stack(512 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if !e.IsNil() { return; }
        let mut br = goish::bufio::NewReader(&mut c);
        let _ = http::ReadRequest(&mut br);
        drop(br);
        let _ = goish::io::Writer::Write(&mut c,
            goish::bytes("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789"));
        let _ = goish::io::Closer::Close(&mut c);
    });
    time::Sleep(time::Duration(150_000_000));

    let (mut resp, e) = http::Get(fmt::Sprintf!("http://127.0.0.1:%d/", port as i64));
    if !e.IsNil() { fmt::Printf!("get err=%v\n", e); goish::os::Exit(1); }
    let mut buf = goish::make!([]byte, 8);
    let mut i = 0;
    while i < 4 {
        let (n, err) = resp.Body.Read(&mut buf);
        chk(fmt::Sprintf!("read%d n=%d err=%v", i as i64, n as i64, err));
        i += 1;
    }
    let _ = goish::io::Closer::Close(&mut resp.Body.clone());
    let (n, err) = resp.Body.Read(&mut buf);
    chk(fmt::Sprintf!("after close n=%d err=%v", n as i64, err));

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 5/5\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 5\n", f as i64);
    goish::os::Exit(1);
}
