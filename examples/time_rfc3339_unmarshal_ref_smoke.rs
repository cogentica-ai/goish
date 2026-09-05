// time_rfc3339_unmarshal_ref_smoke — Time's RFC 3339 parsers against
// Go 1.25.5.
//
// The companion to time_rfc3339_marshal_ref_smoke. That one found two
// defects; this one found none, and the reason is worth pinning.
//
// Go's `parseStrictRFC3339` (format_rfc3339.go:155) looks like it
// enforces rules Go's own `Parse` cannot express — a two-digit hour, a
// period rather than a comma before the sub-second, a zone hour under
// 24, a zone minute under 60. Every one of those checks is behind
// `case true: return t, nil`, disabled pending go.dev/issue/54580. So
// Go's real contract for UnmarshalText/UnmarshalJSON is plain
// `Parse(RFC3339, …)`, which is what goish already does — and the four
// inputs that dead code names are ACCEPTED by both.
//
// The rows below carry those four deliberately. If Go ever lands that
// TODO, or if someone here reads parseStrictRFC3339 and "fixes" goish
// to match code that does not run, these rows go red.
//
// UnmarshalJSON's own quoting check is live in Go and is checked too:
// unquoted input, a lone quote, and empty input must all report
// "input is not a JSON string" rather than a parse error.
//
// Reference: scripts/goref.sh time, UnmarshalText/UnmarshalJSON.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::gostring::string;
use goish::{fmt, time};

const GO: [&str; 21] = [
    "text \"2024-03-01T12:34:56Z\"     err=<nil>",
    "text \"2024-03-01T12:34:56.5Z\"   err=<nil>",
    "text \"2024-03-01T12:34:56-07:00\" err=<nil>",
    "text \"2024-03-01T12:34:56,5Z\"   err=<nil>",
    "text \"2024-03-01T1:34:56Z\"      err=<nil>",
    "text \"2024-03-01T12:34:56+24:00\" err=<nil>",
    "text \"2024-03-01T12:34:56+00:60\" err=<nil>",
    "text \"2024-03-01t12:34:56z\"     err=parsing time \"2024-03-01t12:34:56z\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"t12:34:56z\" as \"T\"",
    "text \"2024-03-01 12:34:56Z\"     err=parsing time \"2024-03-01 12:34:56Z\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \" 12:34:56Z\" as \"T\"",
    "text \"2024-03-01T12:34:56\"      err=parsing time \"2024-03-01T12:34:56\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\" as \"Z07:00\"",
    "text \"2024-03-01T12:34:56Zjunk\" err=parsing time \"2024-03-01T12:34:56Zjunk\": extra text: \"junk\"",
    "text \"\"                         err=parsing time \"\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\" as \"2006\"",
    "text \"2024-13-01T12:34:56Z\"     err=parsing time \"2024-13-01T12:34:56Z\": month out of range",
    "json \"\\\"2024-03-01T12:34:56.5Z\\\"\" err=<nil>",
    "json \"null\"                     err=<nil>",
    "json \"\\\"2024-03-01T12:34:56Z\\\"\" err=<nil>",
    "json \"2024-03-01T12:34:56Z\"     err=Time.UnmarshalJSON: input is not a JSON string",
    "json \"\\\"\\\"\"                     err=parsing time \"\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"\" as \"2006\"",
    "json \"\\\"\"                       err=Time.UnmarshalJSON: input is not a JSON string",
    "json \"\"                         err=Time.UnmarshalJSON: input is not a JSON string",
    "json \"\\\"2024-03-01T12:34:56+24:00\\\"\" err=<nil>",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    for s in [
        "2024-03-01T12:34:56Z", "2024-03-01T12:34:56.5Z", "2024-03-01T12:34:56-07:00",
        "2024-03-01T12:34:56,5Z", "2024-03-01T1:34:56Z", "2024-03-01T12:34:56+24:00",
        "2024-03-01T12:34:56+00:60", "2024-03-01t12:34:56z", "2024-03-01 12:34:56Z",
        "2024-03-01T12:34:56", "2024-03-01T12:34:56Zjunk", "", "2024-13-01T12:34:56Z",
    ].iter() {
        let mut tt = time::Time::default();
        let e = tt.UnmarshalText(goish::convert::bytes(string::from(*s)));
        chk(&mut ln, &fmt::Sprintf!("text %-26q err=%v", string::from(*s), e));
    }
    for s in [
        "\"2024-03-01T12:34:56.5Z\"", "null", "\"2024-03-01T12:34:56Z\"",
        "2024-03-01T12:34:56Z", "\"\"", "\"", "", "\"2024-03-01T12:34:56+24:00\"",
    ].iter() {
        let mut tt = time::Time::default();
        let e = tt.UnmarshalJSON(goish::convert::bytes(string::from(*s)));
        chk(&mut ln, &fmt::Sprintf!("json %-26q err=%v", string::from(*s), e));
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
    }
    goish::os::Exit(0);
}
