// http_transport_opts_smoke — transport.go's option defaults and the
// two request-validation helpers. Values from scripts/goref.sh.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{is408Message, validateHeaders, DefaultMaxIdleConnsPerHost};
use goish::net::http::{Header, Transport};
use goish::{slice, string};

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
    // The asymmetry: a NEGATIVE buffer size falls back to 4 KiB, but a
    // negative MaxIdleConnsPerHost passes through — Go tests `!= 0`
    // there, because negative means "no pool for this host".
    {
        let cases: &[(i64, i64, i64)] =
            &[(0, 4096, 2), (-1, 4096, -1), (1, 1, 1), (8192, 8192, 8192)];
        let mut bad = string("");
        for (v, want_buf, want_idle) in cases {
            let mut t = Transport::default();
            t.WriteBufferSize = *v as goish::int;
            t.ReadBufferSize = *v as goish::int;
            t.MaxIdleConnsPerHost = *v as goish::int;
            if t.writeBufferSize() != *want_buf as goish::int
                || t.readBufferSize() != *want_buf as goish::int
                || t.maxIdleConnsPerHost() != *want_idle as goish::int
            {
                bad = fmt::Sprintf!(
                    "v=%d -> w=%d r=%d idle=%d",
                    *v,
                    t.writeBufferSize(),
                    t.readBufferSize(),
                    t.maxIdleConnsPerHost()
                );
            }
        }
        check(
            "buffer sizes fall back at <=0, MaxIdleConnsPerHost only at ==0",
            bad.Len() == 0,
            bad,
        );
    }
    check(
        "DefaultMaxIdleConnsPerHost is 2",
        DefaultMaxIdleConnsPerHost == 2,
        string(""),
    );

    // is408Message: byte 7 (the minor version) is skipped entirely.
    {
        let cases: &[(&str, bool)] = &[
            ("HTTP/1.1 408", true),
            ("HTTP/1.0 408", true),
            ("HTTP/1.x 408 Request Timeout", true),
            ("HTTP/1.1 200", false),
            ("HTTP/2.0 408", false),
            ("HTTP/1.1 40", false),
            ("", false),
            ("HTTP/1.1408", false),
        ];
        let mut bad = string("");
        for (s, want) in cases {
            let b = slice::<goish::byte>::__from_vec(s.as_bytes().to_vec());
            if is408Message(&b) != *want {
                bad = fmt::Sprintf!("%q -> %v", string(*s), is408Message(&b));
            }
        }
        check(
            "is408Message over 8 inputs (minor version ignored)",
            bad.Len() == 0,
            bad,
        );
    }

    // validateHeaders: a TAB in a value is legal; CR and LF are not.
    {
        let mk = |k: &'static str, v: &'static str| -> Header {
            let mut h = Header::new();
            h.Add(string(k), string(v));
            h
        };
        let ok = validateHeaders(&mk("X-Ok", "fine")).Len() == 0
            && validateHeaders(&mk("X-Ok", "tab\there")).Len() == 0
            && validateHeaders(&mk("X-Ok", "bad\rvalue")) == "field value for \"X-Ok\""
            && validateHeaders(&mk("X-Ok", "bad\nvalue")) == "field value for \"X-Ok\"";
        check(
            "validateHeaders allows TAB, rejects CR/LF, and hides the value",
            ok,
            validateHeaders(&mk("X-Ok", "bad\rvalue")),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_TRANSPORT_OPTS_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_TRANSPORT_OPTS_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
