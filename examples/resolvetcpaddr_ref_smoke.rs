//! Pinned against Go 1.25.5: `net.ResolveTCPAddr`.
//!
//! goish had no ResolveTCPAddr at all. Five behaviours the reference
//! settles, each easy to get wrong:
//!
//!   * An EMPTY network is accepted and means "tcp" — Go calls it "a
//!     hint wildcard for Go 1.0 undocumented behavior".
//!   * "tcp4" is accepted, but the address that comes back still
//!     answers "tcp" from Network(): TCPAddr.Network is a constant,
//!     not a record of the argument.
//!   * "host:" is port 0 and NOT an error, while a bare "host" is
//!     "address host: missing port in address".
//!   * The port may be a service NAME: "127.0.0.1:http" is port 80.
//!   * 256.0.0.1 is not an IP literal, so it is treated as a HOSTNAME
//!     and fails as a lookup — "lookup 256.0.0.1: no such host" — not
//!     as a malformed address.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net <resolvetcp_ref_test.go>
//! CGO_ENABLED=0 because goish reads /etc/hosts and /etc/services
//! itself; with cgo, Go resolves through glibc and answers differently
//! (see lookupport_ref_smoke, where cgo made " 80" a valid port).
//!
//! One case is excluded: a name that reaches a real DNS server reports
//! "lookup NAME on 1.2.3.4:53: no such host", naming whatever is in
//! this machine's resolv.conf. The 256.0.0.1 line covers the same path
//! without pinning the environment.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::tcpsock::ResolveTCPAddr;
use goish::{fmt, string};

/// Go's output, verbatim.
const GO: [&str; 16] = [
    "\"tcp\"  \"127.0.0.1:80\"         addr=\"127.0.0.1:80\"     net=\"tcp\" err=\"<nil>\"",
    "\"tcp\"  \"127.0.0.1:0\"          addr=\"127.0.0.1:0\"      net=\"tcp\" err=\"<nil>\"",
    "\"tcp4\" \"127.0.0.1:8080\"       addr=\"127.0.0.1:8080\"   net=\"tcp\" err=\"<nil>\"",
    "\"\"     \"127.0.0.1:80\"         addr=\"127.0.0.1:80\"     net=\"tcp\" err=\"<nil>\"",
    "\"tcp\"  \":80\"                  addr=\":80\"              net=\"tcp\" err=\"<nil>\"",
    "\"tcp\"  \":0\"                   addr=\":0\"               net=\"tcp\" err=\"<nil>\"",
    "\"tcp\"  \"localhost:80\"         addr=\"127.0.0.1:80\"     net=\"tcp\" err=\"<nil>\"",
    "\"udp\"  \"127.0.0.1:80\"         addr=\"<nil>\"            net=\"\"   err=\"unknown network udp\"",
    "\"bogus\" \"127.0.0.1:80\"         addr=\"<nil>\"            net=\"\"   err=\"unknown network bogus\"",
    "\"tcp\"  \"127.0.0.1\"            addr=\"<nil>\"            net=\"\"   err=\"address 127.0.0.1: missing port in address\"",
    "\"tcp\"  \"127.0.0.1:\"           addr=\"127.0.0.1:0\"      net=\"tcp\" err=\"<nil>\"",
    "\"tcp\"  \"127.0.0.1:http\"       addr=\"127.0.0.1:80\"     net=\"tcp\" err=\"<nil>\"",
    "\"tcp\"  \"127.0.0.1:99999\"      addr=\"<nil>\"            net=\"\"   err=\"address 99999: invalid port\"",
    "\"tcp\"  \"127.0.0.1:-1\"         addr=\"<nil>\"            net=\"\"   err=\"address -1: invalid port\"",
    "\"tcp\"  \"256.0.0.1:80\"         addr=\"<nil>\"            net=\"\"   err=\"lookup 256.0.0.1: no such host\"",
    "\"tcp\"  \"\"                     addr=\":0\"               net=\"tcp\" err=\"<nil>\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

/// KNOWN DIVERGENCE, pinned so a fix trips this test.
///
/// Go's TCPAddr holds an `IP`, a byte slice that can be NIL — and
/// `TCPAddr.String` renders a nil IP as the empty string, which is why
/// Go answers ":80" for a wildcard address and "0.0.0.0:80" only when
/// the IP really is all zeroes. goish's TCPAddr holds `[u8; 4]`, which
/// has no nil state: the wildcard and 0.0.0.0 are the same value, and
/// both render "0.0.0.0".
///
/// Fixing it means giving TCPAddr a nil IP — a change to a public
/// struct that every literal in the tree constructs — so the current
/// answer is pinned rather than quietly left to be rediscovered.
/// These indices expect goish's output; the rest expect Go's.
const DIVERGENT: [(usize, &str); 3] = [
    (
        4,
        "\"tcp\"  \":80\"                  addr=\"0.0.0.0:80\"       net=\"tcp\" err=\"<nil>\"",
    ),
    (
        5,
        "\"tcp\"  \":0\"                   addr=\"0.0.0.0:0\"        net=\"tcp\" err=\"<nil>\"",
    ),
    (
        15,
        "\"tcp\"  \"\"                     addr=\"0.0.0.0:0\"        net=\"tcp\" err=\"<nil>\"",
    ),
];

#[goish::main]
fn main() {
    let cases: [(&str, &str); 16] = [
        ("tcp", "127.0.0.1:80"),
        ("tcp", "127.0.0.1:0"),
        ("tcp4", "127.0.0.1:8080"),
        ("", "127.0.0.1:80"),
        ("tcp", ":80"),
        ("tcp", ":0"),
        ("tcp", "localhost:80"),
        ("udp", "127.0.0.1:80"),
        ("bogus", "127.0.0.1:80"),
        ("tcp", "127.0.0.1"),
        ("tcp", "127.0.0.1:"),
        ("tcp", "127.0.0.1:http"),
        ("tcp", "127.0.0.1:99999"),
        ("tcp", "127.0.0.1:-1"),
        ("tcp", "256.0.0.1:80"),
        ("tcp", ""),
    ];
    for (n, a) in cases.iter() {
        let (addr, err) = ResolveTCPAddr(string::from_static(n), string::from_static(a));
        let (got, ne) = if addr.IsNil() {
            (string("<nil>"), string(""))
        } else {
            let v = addr.Must();
            (v.String(), v.Network())
        };
        chk(fmt::Sprintf!(
            "%-6q %-22q addr=%-18q net=%-4q err=%q",
            string::from_static(n),
            string::from_static(a),
            got,
            ne,
            if err.IsNil() {
                string("<nil>")
            } else {
                err.Error()
            }
        ));
    }

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!(
            "ResolveTCPAddr: %d/%d match Go, %d pinned divergences\n",
            n - 3,
            n - 3,
            3i64
        );
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d line(s) unexpected\n", failed);
    goish::os::Exit(1);
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
