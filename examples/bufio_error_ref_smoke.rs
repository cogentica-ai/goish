//! Pinned against Go 1.25.5: bufio's ERROR DISCIPLINE — which half
//! latches and which does not.
//!
//! Written because of da96552, where crypto/tls latched a read timeout
//! that Go deliberately does not, and the first timeout killed the
//! connection. bufio sits under every buffered reader and writer in
//! the tree, and it makes the OPPOSITE choice in each half:
//!
//!   * **Writer LATCHES.** Once a write fails, every later Write and
//!     Flush reports the stored error and the underlying writer is
//!     never called again — `underlying-calls=1` after three
//!     operations. That is deliberate: a partially written stream
//!     cannot be recovered by writing more, so Go removes the
//!     caller's ability to try.
//!   * **Reader does NOT latch.** `readErr` returns the stored error
//!     and CLEARS it, so a transient failure is reported once and the
//!     next Read proceeds — the same call that failed returns "ok" on
//!     the retry here.
//!
//! Getting either backwards is invisible in ordinary use and wrong
//! under failure: a latching Reader turns one hiccup into a dead
//! stream, and a non-latching Writer silently produces a corrupt one.
//!
//! goish matches Go on all eight lines — no defects. The smoke exists
//! so that stays true.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh bufio <bufio_err_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::io::{Reader, Writer};
use goish::types::byte;
use goish::{bufio, errors, fmt, io, make, slice, string, sync};

struct FailWriter(Arc<sync::Mutex<i64>>);
impl Writer for FailWriter {
    fn Write(&mut self, _p: slice<byte>) -> (goish::int, goish::error) {
        *self.0.Lock() += 1;
        return (0, errors::New(string("boom")));
    }
}
struct FailReader(Arc<sync::Mutex<i64>>);
impl Reader for FailReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (goish::int, goish::error) {
        let mut g = self.0.Lock();
        *g += 1;
        if *g == 1 {
            return (0, errors::New(string("transient")));
        }
        drop(g);
        let src = b"ok";
        for (i, b) in src.iter().enumerate() {
            if i < p.len() {
                p[i] = *b;
            }
        }
        return (2, errors::nil);
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
const GO: [&str; 8] = [
    "write-fails            n=0 err=\"boom\"",
    "write-again            n=0 err=\"boom\"",
    "flush-after-fail       err=\"boom\"",
    "underlying-calls       calls=1",
    "read-fails             n=0 err=\"transient\"",
    "read-again             n=2 got=\"ok\" err=\"<nil>\"",
    "limit-read             n=2 got=\"ok\" err=\"<nil>\"",
    "limit-read-eof         n=0 err=\"EOF\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

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

#[goish::main]
fn main() {
    let calls = Arc::new(sync::Mutex::new(0i64));
    let mut w = bufio::NewWriterSize(FailWriter(calls.clone()), 8 as goish::int);
    let (n, err) = w.Write(goish::convert::bytes(string("0123456789")));
    chk(fmt::Sprintf!(
        "%-22s n=%d err=%q",
        string("write-fails"),
        n as i64,
        es(err)
    ));
    let (n, err) = w.Write(goish::convert::bytes(string("more")));
    chk(fmt::Sprintf!(
        "%-22s n=%d err=%q",
        string("write-again"),
        n as i64,
        es(err)
    ));
    chk(fmt::Sprintf!(
        "%-22s err=%q",
        string("flush-after-fail"),
        es(w.Flush())
    ));
    chk(fmt::Sprintf!(
        "%-22s calls=%d",
        string("underlying-calls"),
        *calls.Lock()
    ));

    let rc = Arc::new(sync::Mutex::new(0i64));
    let mut r = bufio::NewReaderSize(FailReader(rc.clone()), 8 as goish::int);
    let mut buf = make!([]byte, 4);
    let (n, err) = r.Read(&mut buf);
    chk(fmt::Sprintf!(
        "%-22s n=%d err=%q",
        string("read-fails"),
        n as i64,
        es(err)
    ));
    let (n, err) = r.Read(&mut buf);
    chk(fmt::Sprintf!(
        "%-22s n=%d got=%q err=%q",
        string("read-again"),
        n as i64,
        string::from_bytes(&buf.slice(0, n as i64).to_vec()),
        es(err)
    ));

    let rc2 = Arc::new(sync::Mutex::new(1i64));
    let mut r2 = bufio::NewReaderSize(io::LimitReader(FailReader(rc2), 2), 8 as goish::int);
    let (n, err) = r2.Read(&mut buf);
    chk(fmt::Sprintf!(
        "%-22s n=%d got=%q err=%q",
        string("limit-read"),
        n as i64,
        string::from_bytes(&buf.slice(0, n as i64).to_vec()),
        es(err)
    ));
    let (n, err) = r2.Read(&mut buf);
    chk(fmt::Sprintf!(
        "%-22s n=%d err=%q",
        string("limit-read-eof"),
        n as i64,
        es(err)
    ));
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("bufio errors: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
