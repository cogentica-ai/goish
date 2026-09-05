//! Pinned against Go 1.25.5: `net.LookupPort`.
//!
//! goish had no LookupPort, no /etc/services reading and no
//! `parsePort`. `ResolveTCPAddr` needs all three — "127.0.0.1:http"
//! is a valid address — so this is the half that had to land first.
//!
//! Six behaviours the reference settles:
//!
//!   * An EMPTY service is port 0 and NOT an error. Go calls this the
//!     legacy behaviour (golang.org/issue/13610).
//!   * The network is validated only when a lookup is actually
//!     NEEDED: LookupPort("bogus", "80") answers 80, because a numeric
//!     service never reaches the switch. "bogus"+"http" is an error.
//!   * "" as the network means "ip", which tries tcp and then udp.
//!   * Service names are matched case-insensitively — "HTTP" is 80 —
//!     because Go lowercases into a fixed buffer before the lookup.
//!   * "+80" is 80 and "080" is 80, but " 80" is a service NAME: the
//!     parser consumes a leading sign and nothing else, so a leading
//!     space makes the whole thing non-numeric.
//!   * Out-of-range numbers are not parse errors. They saturate and
//!     the caller rejects them: "address 65536: invalid port".
//!
//! Two exclusions, both deliberate:
//!
//!   * `("tcp", "domain")` answers 53 on this machine, but from
//!     /etc/services rather than Go's built-in map, which carries
//!     "domain" only under udp. Pinning it would pin this box's
//!     /etc/services. The `("udp", "domain")` line covers the same
//!     path from the built-in table.
//!   * maxPortBufSize (25 characters) is not reachable through this
//!     API: a name too long to match is indistinguishable from a name
//!     that simply is not a service, so a case for it would not
//!     discriminate.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net <lookupport_ref_test.go>
//! The CGO_ENABLED=0 matters. With cgo, Go resolves ports through
//! glibc's getaddrinfo, whose strtoul SKIPS LEADING WHITESPACE — and
//! the first version of this reference, taken with cgo on, said
//! " 80" was port 80. goish reads the files itself, so the pure-Go
//! resolver is the one to diff against; scripts/goref.sh says so in
//! its own header.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::lookup;
use goish::{fmt, string};

/// Go's output, verbatim.
const GO: [&str; 24] = [
    "\"tcp\"  \"80\"             port=80     err=\"<nil>\"",
    "\"tcp\"  \"0\"              port=0      err=\"<nil>\"",
    "\"tcp\"  \"65535\"          port=65535  err=\"<nil>\"",
    "\"tcp\"  \"65536\"          port=0      err=\"address 65536: invalid port\"",
    "\"tcp\"  \"-1\"             port=0      err=\"address -1: invalid port\"",
    "\"tcp\"  \"\"               port=0      err=\"<nil>\"",
    "\"tcp\"  \"http\"           port=80     err=\"<nil>\"",
    "\"tcp\"  \"https\"          port=443    err=\"<nil>\"",
    "\"tcp\"  \"ssh\"            port=22     err=\"<nil>\"",
    "\"tcp\"  \"smtp\"           port=25     err=\"<nil>\"",
    "\"tcp\"  \"gopher\"         port=70     err=\"<nil>\"",
    "\"tcp\"  \"submissions\"    port=465    err=\"<nil>\"",
    "\"udp\"  \"domain\"         port=53     err=\"<nil>\"",
    "\"udp\"  \"http\"           port=0      err=\"lookup udp/http: unknown port\"",
    "\"\"     \"http\"           port=80     err=\"<nil>\"",
    "\"ip\"   \"http\"           port=80     err=\"<nil>\"",
    "\"tcp4\" \"http\"           port=80     err=\"<nil>\"",
    "\"bogus\" \"http\"           port=0      err=\"address bogus: unknown network\"",
    "\"bogus\" \"80\"             port=80     err=\"<nil>\"",
    "\"tcp\"  \"nosuchservice\"  port=0      err=\"lookup tcp/nosuchservice: unknown port\"",
    "\"tcp\"  \"HTTP\"           port=80     err=\"<nil>\"",
    "\"tcp\"  \"+80\"            port=80     err=\"<nil>\"",
    "\"tcp\"  \" 80\"            port=0      err=\"lookup tcp/ 80: unknown port\"",
    "\"tcp\"  \"080\"            port=80     err=\"<nil>\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

#[goish::main]
fn main() {
    let cases: [(&str, &str); 24] = [
        ("tcp", "80"),
        ("tcp", "0"),
        ("tcp", "65535"),
        ("tcp", "65536"),
        ("tcp", "-1"),
        ("tcp", ""),
        ("tcp", "http"),
        ("tcp", "https"),
        ("tcp", "ssh"),
        ("tcp", "smtp"),
        ("tcp", "gopher"),
        ("tcp", "submissions"),
        ("udp", "domain"),
        ("udp", "http"),
        ("", "http"),
        ("ip", "http"),
        ("tcp4", "http"),
        ("bogus", "http"),
        ("bogus", "80"),
        ("tcp", "nosuchservice"),
        ("tcp", "HTTP"),
        ("tcp", "+80"),
        ("tcp", " 80"),
        ("tcp", "080"),
    ];
    for (network, service) in cases.iter() {
        let (p, err) =
            lookup::LookupPort(string::from_static(network), string::from_static(service));
        let es = if err.IsNil() {
            string("<nil>")
        } else {
            err.Error()
        };
        chk(fmt::Sprintf!(
            "%-6q %-16q port=%-6d err=%q",
            string::from_static(network),
            string::from_static(service),
            p as i64,
            es
        ));
    }

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("LookupPort: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
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
