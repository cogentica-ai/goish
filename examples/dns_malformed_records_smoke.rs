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
//   isDomainName over 39 inputs, dumped as hex from Go's own
//   `isDomainName` under goref — the five it used to carry plus the
//   label- and total-length boundaries, the hyphen/underscore rules,
//   the all-numeric cases, and eight inputs that are NOT valid UTF-8.
//
// WHY HEX, AND WHY THE INVALID-UTF-8 ROWS. The table used to be
// `&'static str` and the predicate used to take `&str`. Go's
// `isDomainName` has a `default: return false` arm that rejects any
// byte outside [A-Za-z0-9_.-], and a byte that is not valid UTF-8 is
// squarely in it — but goish's `string: AsRef<str>` TRUNCATES at the
// first invalid byte, so the five filter sites, which call
// `is_domain_name(cname.as_ref())` on names that came off the wire,
// were judging a PREFIX. Measured: "www.example.com\xff\xff" was
// ACCEPTED here and is rejected by Go. A `&str` table cannot express
// the failing input, which is why nobody wrote the failing test.
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

fn unhex(h: &str) -> alloc::vec::Vec<u8> {
    let b = h.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        fn nib(c: u8) -> u8 {
            if c >= b'0' && c <= b'9' {
                return c - b'0';
            }
            return c - b'a' + 10;
        }
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return out;
}

#[goish::main]
fn main() {
    // ── the predicate the five filter sites depend on ───────────────
    //
    // Pinned against Go's own `isDomainName`, run under goref. A
    // predicate can be right in the abstract and wrong for the values
    // it actually receives, so these are the values Go was asked about.
    // Hex because the inputs include bytes a Rust &str cannot hold.
    let cases: [(&'static str, bool); 39] = [
        ("6f6b2e6578616d706c652e636f6d2e", true),
        ("626164206e616d65", false),
        ("", false),
        ("612e2e62", false),
        ("2d782e6578616d706c652e", false),
        ("2e", true),
        ("2e2e", false),
        ("7777772e6578616d706c652e636f6dffff", false),
        ("61ff62", false),
        ("ff", false),
        ("ff2e6578616d706c652e636f6d", false),
        ("6578616d706c652e636f6d80", false),
        ("6578c3616d706c652e636f6d", false),
        ("eda0802e636f6d", false),
        ("6f6b2e6578616d706c652e636f6d2eff", false),
        ("6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612e636f6d", true),
        ("616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612e636f6d", false),
        ("612e616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", true),
        ("612e61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", false),
        ("612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e6162", false),
        ("612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e616263", false),
        ("612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e", true),
        ("612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e612e61", false),
        ("2d612e636f6d", false),
        ("612d2e636f6d", false),
        ("612d622e636f6d", true),
        ("5f612e636f6d", true),
        ("615f622e636f6d", true),
        ("312e322e332e34", false),
        ("312e322e332e342e", false),
        ("313233", false),
        ("3132332e", false),
        ("612e", true),
        ("2e61", false),
        ("612e2e", false),
        ("612e622e", true),
        ("61c3a92e636f6d", false),
        ("6109622e636f6d", false),
        ("6120622e636f6d", false),
    ];
    let mut bad = string("");
    let mut ran: int = 0;
    let mut wrong: int = 0;
    for (h, want) in cases.iter() {
        let input = unhex(h);
        let got = lk::__is_domain_name(goish::gostring::string::from_bytes(&input));
        ran += 1;
        if got != *want {
            wrong += 1;
            if bad.Len() == 0 {
                bad = fmt::Sprintf!("%s: got %v want %v", string::from_static(h), got, *want);
            }
        }
    }
    // The mismatch COUNT is in the detail on purpose: one red row out of
    // 39 means the table is too thin for the defect, and only the count
    // says so.
    check(
        "is_domain_name agrees with Go on all 39 measured inputs",
        wrong == 0 && ran == 39,
        fmt::Sprintf!("%v of %v rows disagree; first: %s", wrong, ran, bad),
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
