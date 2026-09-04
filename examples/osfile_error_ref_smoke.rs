//! Pinned against Go 1.25.5: what os.File reports when a write or
//! read FAILS — through the method and through the interface.
//!
//! Three defects, found by asking where else the class of bug fixed in
//! 7b051a3 lived:
//!
//!   * **The io::Writer and io::Reader impls were a SECOND
//!     implementation.** They called write(2)/read(2) themselves and
//!     reported `errors.New("write failed")` — no path, no errno, no
//!     closed-file detection — while the inherent `f.Write` on the
//!     same file reported "write /path: no space left on device".
//!     Everything generic goes through the trait: io::Copy,
//!     fmt::Fprintf, any `dyn io::Writer`. So `io.Copy(f, r)` onto a
//!     full disk said "write failed". They forward now, and there is
//!     one implementation again.
//!   * **`Write` did a single write(2).** Go's poll.FD.Write loops
//!     until every byte is written, which is what lets os.File
//!     satisfy io.Writer's "must return a non-nil error if it returns
//!     n < len(p)". A pipe or socket-backed File takes what fits and
//!     reports success; the caller loses the rest silently. The 1 MiB
//!     case is here for that.
//!   * **ENOSPC rendered as "errno 28".** The errno table covered the
//!     socket set; a full disk, a read-only filesystem, a too-long
//!     filename and forty-six others fell through to the number.
//!     Measured against Go and filled in.
//!
//! /dev/full is the portable way to make a real ENOSPC: it accepts
//! every open and fails every write.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh os <oswrite_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::string::String;
use goish::io::{Closer, Reader, Writer};
use goish::types::byte;
use goish::{bytes, fmt, io, make, os, string};
fn es(e: goish::error) -> string {
    if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    }
}
static mut P: Option<String> = None;
fn q(s: string) -> string {
    let p = unsafe { P.clone().unwrap_or_default() };
    let raw: &str = s.as_ref();
    return fmt::Sprintf!(
        "%q",
        string::from_bytes(raw.replace(p.as_str(), "PATH").as_bytes())
    );
}
fn n(v: i64) -> string {
    fmt::Sprintf!("%d", v)
}
/// Go's output, verbatim.
const GO: [&str; 9] = [
    "write-readonly             [0 \"write PATH: bad file descriptor\"]",
    "write-readonly-iface       [0 \"write PATH: bad file descriptor\"]",
    "copy-readonly              [0 \"write PATH: bad file descriptor\"]",
    "read-writeonly             [0 \"read PATH: bad file descriptor\"]",
    "read-writeonly-iface       [0 \"read PATH: bad file descriptor\"]",
    "write-devfull              [0 \"write /dev/full: no space left on device\"]",
    "write-devfull-iface        [0 \"write /dev/full: no space left on device\"]",
    "write-1MiB-iface           [true \"<nil>\"]",
    "size-1MiB                  [1048576]",
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
    chk(fmt::Sprintf!("%-26s [%s]", string::from_static(tag), out));
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
#[goish::main]
fn main() {
    let dir = string("/tmp/goish-oswrite-probe");
    let _ = os::MkdirAll(dir.clone(), os::FileMode(0o755));
    let p = dir.clone() + string("/f");
    unsafe { P = Some(String::from(<goish::string as AsRef<str>>::as_ref(&p))) };
    let _ = os::WriteFile(
        p.clone(),
        goish::convert::bytes(string("seed")),
        os::FileMode(0o644),
    );

    let (roo, _) = os::Open(p.clone());
    let mut ro = roo.MustTake();
    let (wn, we) = ro.Write(goish::convert::bytes(string("nope")));
    line("write-readonly", alloc::vec![n(wn as i64), q(es(we))]);
    let (wn, we) = Writer::Write(&mut ro, goish::convert::bytes(string("nope")));
    line("write-readonly-iface", alloc::vec![n(wn as i64), q(es(we))]);
    let mut src = bytes::NewReader(goish::convert::bytes(string("nope")));
    let (cn, ce) = io::Copy(&mut ro, &mut src);
    line("copy-readonly", alloc::vec![n(cn as i64), q(es(ce))]);
    let _ = ro.Close();

    let (woo, _) = os::OpenFile(p.clone(), os::O_WRONLY, os::FileMode(0));
    let mut wo = woo.MustTake();
    let mut buf = make!([]byte, 4);
    let (rn, re) = wo.Read(&mut buf);
    line("read-writeonly", alloc::vec![n(rn as i64), q(es(re))]);
    let (rn, re) = Reader::Read(&mut wo, &mut buf);
    line("read-writeonly-iface", alloc::vec![n(rn as i64), q(es(re))]);
    let _ = wo.Close();

    let (fullo, fe) = os::OpenFile(string("/dev/full"), os::O_WRONLY, os::FileMode(0));
    if fe.IsNil() {
        let mut full = fullo.MustTake();
        let (wn, we) = full.Write(goish::convert::bytes(string("x")));
        line("write-devfull", alloc::vec![n(wn as i64), q(es(we))]);
        let (wn, we) = Writer::Write(&mut full, goish::convert::bytes(string("x")));
        line("write-devfull-iface", alloc::vec![n(wn as i64), q(es(we))]);
        let _ = full.Close();
    }

    let big = make!([]byte, 1 << 20);
    let (fo, _) = os::Create(p.clone());
    let mut f = fo.MustTake();
    let (wn, we) = Writer::Write(&mut f, big.clone());
    line(
        "write-1MiB-iface",
        alloc::vec![
            fmt::Sprintf!("%v", wn as i64 == big.Len() as i64),
            q(es(we))
        ],
    );
    let _ = f.Close();
    let (st, _) = os::Stat(p.clone());
    line("size-1MiB", alloc::vec![n(st.Size() as i64)]);
    let _ = os::Remove(p);

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("os.File errors: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
