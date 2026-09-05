//! Pinned against Go 1.25.5: `textproto.ReadCodeLine` and
//! `ReadResponse`.
//!
//! goish had neither, nor `parseCodeLine` under them. They are how
//! every line-oriented server protocol reads its status line, and
//! net/smtp — 0% ported — cannot start without them.
//!
//! Four rules the reference settles, all load-bearing:
//!
//!   * The line must be at least four bytes and its FOURTH byte must
//!     be a space or a hyphen. The check is positional, not "starts
//!     with three digits": "220\r\n" is short, and so is
//!     "220x no space".
//!   * A hyphen in that position means the response continues.
//!     ReadCodeLine refuses a continued response and reports the
//!     FIRST line's message; ReadResponse joins the lines with '\n'.
//!   * A code below 100 is invalid even when it parses.
//!   * `expectCode` is matched by WIDTH — 1..9 checks the leading
//!     digit, 10..99 the leading two, 100..999 the whole code — and a
//!     mismatch does NOT clear the code or the message. Go returns
//!     both beside an `Error{code, message}`, so a caller that
//!     ignores the error still sees what the server said. A port that
//!     zeroed them on mismatch would pass a test that only checked
//!     the error.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net/textproto <textproto_code_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::textproto;
use goish::{bufio, bytes, fmt, string};

/// Go's output, verbatim.
const GO: [&str; 16] = [
    "ReadCodeLine \"220 hello\\r\\n\"            expect=0    code=220  msg=\"hello\"        err=\"<nil>\"",
    "ReadCodeLine \"220 hello\\r\\n\"            expect=2    code=220  msg=\"hello\"        err=\"<nil>\"",
    "ReadCodeLine \"220 hello\\r\\n\"            expect=22   code=220  msg=\"hello\"        err=\"<nil>\"",
    "ReadCodeLine \"220 hello\\r\\n\"            expect=220  code=220  msg=\"hello\"        err=\"<nil>\"",
    "ReadCodeLine \"220 hello\\r\\n\"            expect=5    code=220  msg=\"hello\"        err=\"220 hello\"",
    "ReadCodeLine \"220 hello\\r\\n\"            expect=25   code=220  msg=\"hello\"        err=\"220 hello\"",
    "ReadCodeLine \"220 hello\\r\\n\"            expect=221  code=220  msg=\"hello\"        err=\"220 hello\"",
    "ReadCodeLine \"220-first\\r\\n220 second\\r\\n\" expect=0    code=220  msg=\"first\"        err=\"unexpected multi-line response: first\"",
    "ReadResponse \"220-first\\r\\n220 second\\r\\n\" expect=0    code=220  msg=\"first\\nsecond\" err=\"<nil>\"",
    "ReadResponse \"250-a\\r\\n250-b\\r\\n250 c\\r\\n\" expect=25   code=250  msg=\"a\\nb\\nc\"      err=\"<nil>\"",
    "ReadCodeLine \"99 too small\\r\\n\"         expect=0    code=0    msg=\"\"             err=\"short response: 99 too small\"",
    "ReadCodeLine \"abc bad\\r\\n\"              expect=0    code=0    msg=\"\"             err=\"invalid response code: abc bad\"",
    "ReadCodeLine \"22\\r\\n\"                   expect=0    code=0    msg=\"\"             err=\"short response: 22\"",
    "ReadCodeLine \"220x no space\\r\\n\"        expect=0    code=0    msg=\"\"             err=\"short response: 220x no space\"",
    "ReadCodeLine \"220\\r\\n\"                  expect=0    code=0    msg=\"\"             err=\"short response: 220\"",
    "ReadCodeLine \"500 boom\\r\\n\"             expect=2    code=500  msg=\"boom\"         err=\"500 boom\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

#[goish::main]
fn main() {
    let cases: [(&str, i64, bool); 16] = [
        ("220 hello\r\n", 0, false),
        ("220 hello\r\n", 2, false),
        ("220 hello\r\n", 22, false),
        ("220 hello\r\n", 220, false),
        ("220 hello\r\n", 5, false),
        ("220 hello\r\n", 25, false),
        ("220 hello\r\n", 221, false),
        ("220-first\r\n220 second\r\n", 0, false),
        ("220-first\r\n220 second\r\n", 0, true),
        ("250-a\r\n250-b\r\n250 c\r\n", 25, true),
        ("99 too small\r\n", 0, false),
        ("abc bad\r\n", 0, false),
        ("22\r\n", 0, false),
        ("220x no space\r\n", 0, false),
        ("220\r\n", 0, false),
        ("500 boom\r\n", 2, false),
    ];
    for (input, expect, multi) in cases.iter() {
        let src = bytes::NewReader(goish::convert::bytes(string::from_static(input)));
        let mut r = textproto::NewReader(bufio::NewReader(src));
        let (code, msg, err) = if *multi {
            r.ReadResponse(*expect as goish::int)
        } else {
            r.ReadCodeLine(*expect as goish::int)
        };
        let tag = if *multi {
            "ReadResponse"
        } else {
            "ReadCodeLine"
        };
        chk(fmt::Sprintf!(
            "%-12s %-26q expect=%-4d code=%-4d msg=%-14q err=%q",
            string::from_static(tag),
            string::from_static(input),
            *expect,
            code as i64,
            msg,
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
        fmt::Printf!("textproto code lines: %d/%d match Go\n", n, n);
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
