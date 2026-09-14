// net: Resolver.StrictErrors was a field nothing read.
//
// Go's doc for it: "For a query composed of multiple sub-queries (such
// as an A+AAAA address lookup, or walking the name server suffix list
// when AbsDomain is not fully qualified), strict errors mean that the
// query as a whole fails when any sub-query fails." goish declared the
// field, let callers set it, and never looked at it, so a caller who
// asked for strict semantics silently got lenient ones — a dual-stack
// host whose A query hit SERVFAIL came back v6-only, with no error,
// which is the exact downgrade Go's comment at dnsclient_unix.go:783
// says the feature exists to prevent.
//
// The whole of the decision is `nerr.Temporary() && r.strictErrors()`,
// one line of Go. Testing it where it lives would mean a DNS server
// that fails the way a flaky one does, so it is extracted as
// `strict_abort` and driven here instead.
//
// EVERY expected value below came out of Go 1.25.5 itself: a
// `TestGoishRef` inside a writable GOROOT copy (scripts/goref.sh net),
// which can name the unexported sentinels, running Go's own predicate
// over the same eight errors. Transcribed programmatically, not by
// hand.
//
// What the table is really for is the NEGATIVE rows. Aborting on a
// temporary error is the easy half; the half that breaks a resolver is
// aborting on errNoSuchHost, because NXDOMAIN is the ordinary answer
// while walking a search list, and a strict resolver that treated it as
// a flake would fail every unqualified lookup. Five of the eight
// sentinels must NOT abort, and they are here by name.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::dnsclient::__strict_abort;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn ab(what: &'static str, which: int, strict: bool, want: bool) {
    let got = __strict_abort(which, strict);
    unsafe {
        if got == want {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL %s: got %v want %v\n", what, got, want);
        }
    }
}

#[goish::main]
fn main() {
    ab("errServerTemporarilyMisbehaving under StrictErrors", 0, true, true);
    ab("errServerTemporarilyMisbehaving without StrictErrors", 0, false, false);
    ab("errNoSuchHost under StrictErrors", 1, true, false);
    ab("errNoSuchHost without StrictErrors", 1, false, false);
    ab("errServerMisbehaving under StrictErrors", 2, true, false);
    ab("errServerMisbehaving without StrictErrors", 2, false, false);
    ab("errLameReferral under StrictErrors", 3, true, false);
    ab("errLameReferral without StrictErrors", 3, false, false);
    ab("errCannotUnmarshalDNSMessage under StrictErrors", 4, true, false);
    ab("errCannotUnmarshalDNSMessage without StrictErrors", 4, false, false);
    ab("DNSError{IsTimeout} under StrictErrors", 5, true, true);
    ab("DNSError{IsTimeout} without StrictErrors", 5, false, false);
    ab("DNSError{IsTemporary} under StrictErrors", 6, true, true);
    ab("DNSError{IsTemporary} without StrictErrors", 6, false, false);
    ab("plain errors.New under StrictErrors", 7, true, false);
    ab("plain errors.New without StrictErrors", 7, false, false);

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        fmt::Printf!(
            "dns_strict_errors_smoke: %v checks, %v failed\n",
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
