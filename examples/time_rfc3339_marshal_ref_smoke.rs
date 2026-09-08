// time_rfc3339_marshal_ref_smoke — Time's RFC 3339 marshallers against
// Go 1.25.5.
//
// Go marshals a Time as RFC3339**Nano** — "the time is a quoted string
// in the RFC 3339 format with sub-second precision" — and reports an
// ERROR when the value cannot be represented as valid RFC 3339. Both
// halves were missing here.
//
// goish emitted plain RFC3339, so every marshal silently truncated the
// fractional second: a Time carrying 123456789ns came back as
// `...T12:34:56Z` and did not survive a round trip through text or
// JSON. The stated reason in the code was that "the slim Format helper
// doesn't recognise RFC3339Nano", which had stopped being true — the
// nanos/millis/trailing-zero/offset rows below are exactly the cases
// that claim covered, and Format handles all of them.
//
// goish also returned a nil error for years outside [0,9999], so
// `"10000-01-01T00:00:00Z"` and `"-0001-01-01T00:00:00Z"` reached the
// output as JSON strings no RFC 3339 parser accepts. Go's
// appendStrictRFC3339 (format_rfc3339.go:62) exists precisely because
// the ordinary layout walk renders those without complaint.
//
// AppendText is checked with a non-empty prefix ("X:") because the
// year check indexes from the buffer's length on entry, not from zero.
//
// Reference: scripts/goref.sh time, MarshalJSON/MarshalText/AppendText.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::{fmt, time};

const GO: [&str; 30] = [
    "nanos          json=\"\\\"2024-03-01T12:34:56.123456789Z\\\"\" err=<nil>",
    "nanos          text=\"2024-03-01T12:34:56.123456789Z\"   err=<nil>",
    "nanos          appd=\"X:2024-03-01T12:34:56.123456789Z\" err=<nil>",
    "millis         json=\"\\\"2024-03-01T12:34:56.123Z\\\"\"     err=<nil>",
    "millis         text=\"2024-03-01T12:34:56.123Z\"         err=<nil>",
    "millis         appd=\"X:2024-03-01T12:34:56.123Z\"       err=<nil>",
    "whole-sec      json=\"\\\"2024-03-01T12:34:56Z\\\"\"         err=<nil>",
    "whole-sec      text=\"2024-03-01T12:34:56Z\"             err=<nil>",
    "whole-sec      appd=\"X:2024-03-01T12:34:56Z\"           err=<nil>",
    "trailing-zero  json=\"\\\"2024-03-01T12:34:56.12Z\\\"\"      err=<nil>",
    "trailing-zero  text=\"2024-03-01T12:34:56.12Z\"          err=<nil>",
    "trailing-zero  appd=\"X:2024-03-01T12:34:56.12Z\"        err=<nil>",
    "offset         json=\"\\\"2024-03-01T12:34:56.5-07:00\\\"\"  err=<nil>",
    "offset         text=\"2024-03-01T12:34:56.5-07:00\"      err=<nil>",
    "offset         appd=\"X:2024-03-01T12:34:56.5-07:00\"    err=<nil>",
    "offset-pos     json=\"\\\"2024-03-01T12:34:56+05:30\\\"\"    err=<nil>",
    "offset-pos     text=\"2024-03-01T12:34:56+05:30\"        err=<nil>",
    "offset-pos     appd=\"X:2024-03-01T12:34:56+05:30\"      err=<nil>",
    "year-0         json=\"\\\"0000-01-01T00:00:00Z\\\"\"         err=<nil>",
    "year-0         text=\"0000-01-01T00:00:00Z\"             err=<nil>",
    "year-0         appd=\"X:0000-01-01T00:00:00Z\"           err=<nil>",
    "year-9999      json=\"\\\"9999-12-31T23:59:59Z\\\"\"         err=<nil>",
    "year-9999      text=\"9999-12-31T23:59:59Z\"             err=<nil>",
    "year-9999      appd=\"X:9999-12-31T23:59:59Z\"           err=<nil>",
    "year-10000     json=\"\"                                 err=Time.MarshalJSON: year outside of range [0,9999]",
    "year-10000     text=\"\"                                 err=Time.MarshalText: year outside of range [0,9999]",
    "year-10000     appd=\"\"                                 err=Time.AppendText: year outside of range [0,9999]",
    "year-negative  json=\"\"                                 err=Time.MarshalJSON: year outside of range [0,9999]",
    "year-negative  text=\"\"                                 err=Time.MarshalText: year outside of range [0,9999]",
    "year-negative  appd=\"\"                                 err=Time.AppendText: year outside of range [0,9999]",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let utc = time::UTC;
    let cases: [(&str, time::Time); 10] = [
        ("nanos", time::Date(2024, time::March, 1, 12, 34, 56, 123456789, utc)),
        ("millis", time::Date(2024, time::March, 1, 12, 34, 56, 123000000, utc)),
        ("whole-sec", time::Date(2024, time::March, 1, 12, 34, 56, 0, utc)),
        ("trailing-zero", time::Date(2024, time::March, 1, 12, 34, 56, 120000000, utc)),
        ("offset", time::Date(2024, time::March, 1, 12, 34, 56, 500000000,
            time::FixedZone(string::from(""), -7 * 3600))),
        ("offset-pos", time::Date(2024, time::March, 1, 12, 34, 56, 0,
            time::FixedZone(string::from(""), 5 * 3600 + 30 * 60))),
        ("year-0", time::Date(0, time::January, 1, 0, 0, 0, 0, utc)),
        ("year-9999", time::Date(9999, time::December, 31, 23, 59, 59, 0, utc)),
        ("year-10000", time::Date(10000, time::January, 1, 0, 0, 0, 0, utc)),
        ("year-negative", time::Date(-1, time::January, 1, 0, 0, 0, 0, utc)),
    ];
    for (n, t) in cases.iter() {
        let nm = string::from(*n);
        let (j, je) = t.MarshalJSON();
        chk(&mut ln, &fmt::Sprintf!("%-14s json=%-34q err=%v", nm.clone(),
            string::from_bytes(&j), je));
        let (m, me) = t.MarshalText();
        chk(&mut ln, &fmt::Sprintf!("%-14s text=%-34q err=%v", nm.clone(),
            string::from_bytes(&m), me));
        let (a, ae) = t.AppendText(goish::convert::bytes(string::from("X:")));
        chk(&mut ln, &fmt::Sprintf!("%-14s appd=%-34q err=%v", nm.clone(),
            string::from_bytes(&a), ae));
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
    goish::os::Exit(0);
}
