// json_null_error_ref_smoke — a rejected null must not touch the
// destination (issue #19).
//
// `nul`, `nulx` and `n` all begin with 'n', so the generated
// `UnmarshalerFrom` enters its null branch and only then finds the
// token does not parse. The generated code used to zero `*self` before
// looking at that error, so a malformed byte or two wiped a populated
// struct — silently, because the error returned says "syntax" and says
// nothing about the destination.
//
// That is data loss in the ordinary use of Unmarshal: decoding into a
// value that already holds something. The `{"value":3}` row is the
// same point from the other side — Go leaves `name` alone rather than
// zeroing the fields the document did not mention.
//
// A VALID null DOES zero the destination, and shares the branch, so
// both are pinned here: neither can be "fixed" into the other without
// a row going red.
//
// GO[] is the verbatim output of tools/gen_json_null_ref.go under
//   GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::v2 as json;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 5] = [
    "\"nul\"        err=true  value=9 name=\"kept\"",
    "\"nulx\"       err=true  value=9 name=\"kept\"",
    "\"null\"       err=false value=0 name=\"\"",
    "\"n\"          err=true  value=9 name=\"kept\"",
    "\"{\\\"value\\\":3}\" err=false value=3 name=\"kept\"",
];

#[goish::reflect]
#[derive(Default)]
struct Probe {
    #[tag(r#"json:"value""#)]
    Value: int,
    #[tag(r#"json:"name""#)]
    Name: string,
}

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    for input in [&b"nul"[..], &b"nulx"[..], &b"null"[..], &b"n"[..], &b"{\"value\":3}"[..]] {
        let mut got = Probe {
            Value: int::from(9),
            Name: string::from_static("kept"),
        };
        let err = json::Unmarshal(input, &mut got, []);
        chk(
            &mut ln,
            &fmt::Sprintf!(
                "%-12q err=%-5v value=%d name=%q",
                string::from_bytes(input),
                !err.IsNil(),
                got.Value,
                got.Name
            ),
        );
    }

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
