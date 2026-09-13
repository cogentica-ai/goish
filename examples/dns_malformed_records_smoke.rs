// dns_malformed_records_smoke — a response carrying invalid names must
// be REPORTED, not silently trimmed.
//
// Go filters records whose names are not valid domain names and returns
// an error ALONGSIDE the survivors, at five sites — LookupCNAME,
// LookupSRV, LookupMX, LookupNS and LookupAddr. Its own doc is explicit
// that a caller must be able to tell: "If the response contains invalid
// names, those records are filtered out and an error will be returned
// alongside the remaining results, if any."
//
// goish filtered — every `is_domain_name` check was there — and then
// returned nil, so a partly-malformed response looked clean. That is a
// signal about the resolver, and swallowing it makes a broken or
// hostile one indistinguishable from a good one. `LookupCNAME` did
// report, but with "invalid CNAME", which is not Go's text.
//
// The evidence it was intended and abandoned: the constant holding
// Go's exact string was declared in lookup.rs and never used. It
// surfaced when `#![allow(dead_code)]` came off the file.
//
// Measured against Go 1.25.5:
//
//   errMalformedDNSRecordsDetail
//     Err field  "DNS response contained records which contain invalid names"
//     rendered   lookup 192.0.2.42: DNS response contained records ...
//     IsTimeout=false IsTemporary=false IsNotFound=false
//     survivors ARE returned alongside it
//
//   isDomainName("ok.example.com.")   true
//   isDomainName("bad name")          false
//   isDomainName("")                  false
//   isDomainName("a..b")              false
//   isDomainName("-x.example.")       false
//
// WHAT THIS DOES NOT COVER, stated rather than implied: the five call
// sites are not exercised end to end. Every `Resolver` method reads
// `get_system_dns_config()` directly, so there is no way to point one
// at a fake nameserver without adding an injection point, which is a
// design change and not this fix. What is pinned here is the predicate
// the sites filter on and the error they now report.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::net::lookup as lk;
use goish::{fmt, int, string};

static mut FAILED: int = 0;

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        unsafe { FAILED += 1 };
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    // ── the predicate the five filter sites depend on ───────────────
    //
    // Pinned against Go's own `isDomainName`, run under goref. A
    // predicate can be right in the abstract and wrong for the values
    // it actually receives, so these are the values Go was asked about.
    let cases: [(&'static str, bool); 5] = [
        ("ok.example.com.", true),
        ("bad name", false),
        ("", false),
        ("a..b", false),
        ("-x.example.", false),
    ];
    let mut bad = string("");
    for (s, want) in cases.iter() {
        let got = lk::__is_domain_name(s);
        if got != *want {
            bad = fmt::Sprintf!("%s: got %v want %v", string::from_static(s), got, *want);
        }
    }
    check(
        "is_domain_name agrees with Go on all five measured inputs",
        bad.Len() == 0,
        bad,
    );

    // ── the error the sites now report ──────────────────────────────
    let e = lk::__malformed_records_error("192.0.2.42");
    check(
        "a dropped record produces a non-nil error",
        !e.IsNil(),
        string("nil — the filtering is silent again"),
    );

    match goish::errors::AsConcrete::<goish::net::net::DNSError>(&e) {
        Some(d) => {
            check(
                "it is a DNSError carrying Go's exact detail string",
                d.Err == "DNS response contained records which contain invalid names",
                d.Err.clone(),
            );
            check(
                "with Go's flags: not a timeout, not temporary, not not-found",
                !d.IsTimeout && !d.IsTemporary && !d.IsNotFound,
                fmt::Sprintf!(
                    "IsTimeout=%v IsTemporary=%v IsNotFound=%v",
                    d.IsTimeout,
                    d.IsTemporary,
                    d.IsNotFound
                ),
            );
            check(
                "and the queried name, so the caller knows which lookup",
                d.Name == "192.0.2.42",
                d.Name.clone(),
            );
        }
        None => {
            check("it is a DNSError", false, e.Error());
            check("with Go's flags", false, string("not a DNSError"));
            check("and the queried name", false, string("not a DNSError"));
        }
    }

    check(
        "it renders the way Go renders it",
        e.Error() == "lookup 192.0.2.42: DNS response contained records which contain invalid names",
        e.Error(),
    );

    let f = unsafe { FAILED };
    if f == 0 {
        fmt::Printf!("\nok 6/6\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
