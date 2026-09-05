//! Pinned against Go 1.25.5: `ListenTCP`, `DialTCP` and `AcceptTCP`.
//!
//! goish had none of the three. What the reference settles:
//!
//!   * A nil `laddr` to ListenTCP is the WILDCARD, not an error — Go
//!     writes `laddr = &TCPAddr{}` before listening.
//!   * A nil `raddr` to DialTCP is "dial tcp: missing address", and an
//!     unknown network fails before anything is dialled.
//!   * An unknown network produces an OpError whose Net field AND
//!     wrapped error both name it: "listen udp: unknown network udp".
//!     It reads redundant and it is what Go prints.
//!   * AcceptTCP on a closed listener reports the listener's own
//!     address: "accept tcp ADDR: use of closed network connection".
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net <tcpsock_ctor_ref_test.go>
//! Ports are ephemeral and rewritten to PORT before comparing.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String;
use goish::net::tcpsock::{DialTCP, ListenTCP, ResolveTCPAddr};
use goish::{fmt, nilable, string};

/// Go's output, verbatim.
const GO: [&str; 7] = [
    "listen-nil-laddr       addr=\"[::]:PORT\"          err=\"<nil>\"",
    "listen-bad-network     addr=\"<nil>\"              err=\"listen udp: unknown network udp\"",
    "listen-explicit        addr=\"127.0.0.1:PORT\"     err=\"<nil>\"",
    "dial-ok                addr=\"127.0.0.1:PORT\"     err=\"<nil>\"",
    "dial-nil-raddr         addr=\"<nil>\"              err=\"dial tcp: missing address\"",
    "dial-bad-network       addr=\"<nil>\"              err=\"dial udp 127.0.0.1:PORT: unknown network udp\"",
    "accept-closed          addr=\"<nil>\"              err=\"accept tcp [::]:PORT: use of closed network connection\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

/// KNOWN DIVERGENCE, pinned so a change trips this test.
///
/// Go listens on the IPv6 dual-stack wildcard and renders it "[::]";
/// goish's net is IPv4-only, so its wildcard is "0.0.0.0". That is a
/// property of the whole package, not of these three functions, and
/// the two lines below are the only place it shows here. Everything
/// else on both sides is identical, ephemeral port included.
const DIVERGENT: [(usize, &str); 2] = [
    (0, "listen-nil-laddr       addr=\"0.0.0.0:PORT\"       err=\"<nil>\""),
    (
        6,
        "accept-closed          addr=\"<nil>\"              err=\"accept tcp 0.0.0.0:PORT: use of closed network connection\"",
    ),
];

#[goish::main]
fn main() {
    // 1. Nil laddr is the wildcard.
    let (ln, e) = ListenTCP(string("tcp"), nilable::nil());
    let a = if ln.IsNil() {
        string("<nil>")
    } else {
        ln.Must().Addr().String()
    };
    let port = port_of(&a);
    show("listen-nil-laddr", a.clone(), e, &port);

    // 2. An unknown network, before anything is bound.
    let (ln2, e2) = ListenTCP(string("udp"), nilable::nil());
    show(
        "listen-bad-network",
        if ln2.IsNil() {
            string("<nil>")
        } else {
            ln2.Must().Addr().String()
        },
        e2,
        "",
    );

    // 3. An explicit laddr is honoured.
    let (la, _) = ResolveTCPAddr(string("tcp"), string("127.0.0.1:0"));
    let (ln3, e3) = ListenTCP(string("tcp"), la);
    let a3 = if ln3.IsNil() {
        string("<nil>")
    } else {
        ln3.Must().Addr().String()
    };
    let p3 = port_of(&a3);
    show("listen-explicit", a3.clone(), e3, &p3);

    // 4. DialTCP reaches it.
    let (ra, _) = ResolveTCPAddr(string("tcp"), a3.clone());
    let (c, e4) = DialTCP(string("tcp"), nilable::nil(), ra.clone());
    show(
        "dial-ok",
        if c.IsNil() {
            string("<nil>")
        } else {
            c.Must().RemoteAddr().String()
        },
        e4,
        &p3,
    );

    // 5. A nil raddr is errMissingAddress.
    let (c2, e5) = DialTCP(string("tcp"), nilable::nil(), nilable::nil());
    show(
        "dial-nil-raddr",
        if c2.IsNil() {
            string("<nil>")
        } else {
            string("?")
        },
        e5,
        "",
    );

    // 6. An unknown network names the target it did not dial.
    let (c3, e6) = DialTCP(string("udp"), nilable::nil(), ra.clone());
    show(
        "dial-bad-network",
        if c3.IsNil() {
            string("<nil>")
        } else {
            string("?")
        },
        e6,
        &p3,
    );

    // 7. AcceptTCP on a closed listener names the listener.
    let (ln4, _) = ListenTCP(string("tcp"), nilable::nil());
    let a4 = ln4.Must().Addr().String();
    let p4 = port_of(&a4);
    let _ = ln4.Must().Close();
    let (c4, e7) = ln4.Must().AcceptTCP();
    show(
        "accept-closed",
        if c4.IsNil() {
            string("<nil>")
        } else {
            string("?")
        },
        e7,
        &p4,
    );

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!(
            "tcpsock constructors: %d/%d match Go, %d pinned divergences\n",
            n - 2,
            n - 2,
            2i64
        );
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d line(s) unexpected\n", failed);
    goish::os::Exit(1);
}

/// The ephemeral port of an "ip:port" rendering, for normalisation.
fn port_of(addr: &string) -> String {
    let s: &str = addr.as_ref();
    return String::from(s.rsplit(':').next().unwrap_or(""));
}

/// Render one case the way the Go reference renders it and compare.
fn show(tag: &'static str, got: string, err: goish::error, norm: &str) {
    let g: &str = got.as_ref();
    let g2 = if norm.is_empty() {
        String::from(g)
    } else {
        g.replace(norm, "PORT")
    };
    let es = if err.IsNil() {
        string("<nil>")
    } else {
        err.Error()
    };
    let e: &str = es.as_ref();
    let e2 = if norm.is_empty() {
        String::from(e)
    } else {
        e.replace(norm, "PORT")
    };
    chk(fmt::Sprintf!(
        "%-22s addr=%-20q err=%q",
        string::from_static(tag),
        string::from_bytes(g2.as_bytes()),
        string::from_bytes(e2.as_bytes())
    ));
}

/// Compare one rendered line, in order, against Go — or against the
/// pinned goish answer where a divergence is recorded.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    for (idx, expect) in DIVERGENT.iter() {
        if *idx == i {
            let want = string::from_static(expect);
            if got == want {
                return;
            }
            if got == string::from_static(GO[i]) {
                fmt::Printf!(
                    "KNOWN DIVERGENCE CHANGED at %d - goish now matches Go. Update this note.\n",
                    i as i64
                );
            } else {
                fmt::Printf!("DIFF pinned: %s\n", want);
                fmt::Printf!("     goish : %s\n", got);
            }
            unsafe { FAILED += 1 };
            return;
        }
    }
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
