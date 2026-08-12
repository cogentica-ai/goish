// Pins the `#[goish::interface]` downcast registries: an assertion to an
// interface must find a concrete type that implements it.
//
// Go's linker builds itabs, so `if c, ok := w.(io.Closer)` just works.
// goish fills a per-trait registry at init instead, and until
// 2026-08-12 nothing filled it: 25 traits had implementors and zero
// entries, so every one of these assertions reported `false` while the
// impl sat right there. A comma-ok assertion cannot fail loudly — it
// reports "no" — so only a test like this one can tell the difference.
//
// See AGENTS.md §9b for the two ways an assertion silently misses.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::fmt;
use goish::goany::AsExt;
use goish::io;
use goish::math::big;

static mut PASS: goish::types::int = 0;
static mut FAIL: goish::types::int = 0;

fn check(name: &str, ok: bool) {
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL: %s\n", name);
        }
    }
}

#[goish::main]
fn main() {
    // `bytes.Buffer` is Go's canonical multi-interface value.
    let buf = bytes::NewBufferString("hello");
    check(
        "bytes.Buffer -> io.Writer",
        buf.As::<dyn io::Writer + Send + Sync>().is_some(),
    );
    check(
        "bytes.Buffer -> io.Reader",
        buf.As::<dyn io::Reader + Send + Sync>().is_some(),
    );
    check(
        "bytes.Buffer -> io.WriterTo",
        buf.As::<dyn io::WriterTo + Send + Sync>().is_some(),
    );

    // A type that does NOT implement the interface must still say no —
    // registration must not make every assertion succeed.
    check(
        "bytes.Buffer -/> io.Seeker (negative)",
        buf.As::<dyn io::Seeker + Send + Sync>().is_none(),
    );

    // bytes.Reader does implement Seeker, so the negative above is
    // discriminating rather than vacuous.
    let rd = bytes::NewReader(bytes::NewBufferString("hello").Bytes());
    check(
        "bytes.Reader -> io.Seeker",
        rd.As::<dyn io::Seeker + Send + Sync>().is_some(),
    );

    // fmt.Stringer off a big.Int — the shape `fmt` uses to print any
    // value, and the one most Go code asserts.
    let n = big::NewInt(42);
    check(
        "big.Int -> fmt.Stringer",
        n.As::<dyn fmt::Stringer + Send + Sync>().is_some(),
    );

    unsafe {
        // See tls_common_smoke: copy before formatting so we never take
        // a shared reference to a `static mut`.
        let (pass, fail) = (PASS, FAIL);
        fmt::Printf!("iface_registry_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
