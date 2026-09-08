// url_iplit_ref_smoke — only a real IPv6 address belongs in brackets.
//
// RFC 3986, and Go's url.go:674: "only a host identified by a valid
// IPv6 address can be enclosed by square brackets. This excludes any
// IPv4, but notably not IPv4-mapped addresses." Go validates with
// netip.ParseAddr and then rejects Is4.
//
// goish tested "the hostname contains a colon", because when that was
// written goish had no net/netip. It has one now — and the weaker test
// meant `[not:an:address]`, `[zz::1]` and `[:::]` all PARSED here and
// all fail in Go. A URL parser that accepts more than Go's is the
// wrong direction for anything that validates one.
//
// The error strings match too, because goish's netip::ParseAddr is a
// faithful port carrying Go's messages.
//
// GO[] is the verbatim output of tools/gen_url_iplit_ref.go under
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::url;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 9] = [
    "http://[::1]/p               host=\"[::1]\" hostname=\"::1\"",
    "http://[fe80::1%25eth0]/p    host=\"[fe80::1%eth0]\" hostname=\"fe80::1%eth0\"",
    "http://[::ffff:1.2.3.4]/p    host=\"[::ffff:1.2.3.4]\" hostname=\"::ffff:1.2.3.4\"",
    "http://[1.2.3.4]/p           err=parse \"http://[1.2.3.4]/p\": invalid IP-literal",
    "http://[not:an:address]/p    err=parse \"http://[not:an:address]/p\": invalid host: ParseAddr(\"not:an:address\"): each colon-separated field must have at least one digit (at \"not:an:address\")",
    "http://[::1]:8080/p          host=\"[::1]:8080\" hostname=\"::1\"",
    "http://[zz::1]/p             err=parse \"http://[zz::1]/p\": invalid host: ParseAddr(\"zz::1\"): each colon-separated field must have at least one digit (at \"zz::1\")",
    "http://[:::]/p               err=parse \"http://[:::]/p\": invalid host: ParseAddr(\":::\"): each colon-separated field must have at least one digit (at \":\")",
    "http://[]/p                  err=parse \"http://[]/p\": invalid host: ParseAddr(\"\"): unable to parse IP",
];

static RAW: [&str; 9] = [
    "http://[::1]/p",
    "http://[fe80::1%25eth0]/p",
    "http://[::ffff:1.2.3.4]/p",
    "http://[1.2.3.4]/p",
    "http://[not:an:address]/p",
    "http://[::1]:8080/p",
    "http://[zz::1]/p",
    "http://[:::]/p",
    "http://[]/p",
];

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
    // Driven by RAW: a GO row with no RAW row would never run.
    if RAW.len() != GO.len() {
        fmt::Printf!("rows: RAW=%d GO=%d\n", RAW.len() as i64, GO.len() as i64);
        goish::os::Exit(1);
    }
    let mut i = 0usize;
    while i < RAW.len() {
        let (u, e) = url::Parse(string(RAW[i]));
        let got = if !e.IsNil() {
            fmt::Sprintf!("%-28s err=%v", string(RAW[i]), e)
        } else {
            fmt::Sprintf!("%-28s host=%q hostname=%q", string(RAW[i]), u.Host, u.Hostname())
        };
        if got == string(GO[i]) {
            fmt::Printf!("ok   %s
", got);
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            fmt::Printf!("[!!]
  got:  %s
  want: %s
", got, string(GO[i]));
        }
        i += 1;
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("
ok 9/9
");
        goish::os::Exit(0);
    }
    fmt::Printf!("
FAILED %d of 9
", f as i64);
    goish::os::Exit(1);
}
