//! Pinned against Go 1.25.5: `textproto.Writer` — PrintfLine and
//! DotWriter, the write half of the dot-encoding whose reader landed
//! in de2007d.
//!
//! goish had no textproto/writer.go port at all. What the reference
//! settles, and two of these are traps:
//!
//!   * PrintfLine appends \r\n UNCONDITIONALLY. It does not check
//!     whether the text already ends in one, so `PrintfLine("already\r\n")`
//!     writes "already\r\n\r\n". A port that "helpfully" suppressed the
//!     second pair would break every protocol that sends a deliberate
//!     blank line.
//!   * An EMPTY body still emits a CRLF before the terminator:
//!     `DotWriter().Close()` with nothing written produces
//!     "\r\n.\r\n", because the initial state falls through Close's
//!     default arm. A port that treated "nothing written" as "nothing
//!     to terminate" would send a body the peer reads as
//!     unterminated.
//!   * A `.` at the START of a line is doubled; a dot anywhere else
//!     is untouched, which is why "mid.dot" is unchanged.
//!   * A bare \n becomes \r\n; a lone \r not followed by \n passes
//!     through as data.
//!   * The count Write returns is of INPUT bytes consumed, not bytes
//!     written — "line one\nline two\n" reports 18 while writing 20.
//!     That is checked here for the same reason: a port that returned
//!     the written count would satisfy io.Writer and corrupt every
//!     caller that loops on the remainder.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net/textproto <textproto_writer_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::bytes;
use goish::io::{Closer, Writer as _};
use goish::net::textproto::writer;
use goish::{bufio, fmt, string};

/// Go's output, verbatim.
const GO: [&str; 13] = [
    "PrintfLine     \"NOOP\"                 out=\"NOOP\\r\\n\"                 err=\"<nil>\"",
    "PrintfLine     \"MAIL FROM:<%s>\"       out=\"MAIL FROM:<a@b.c>\\r\\n\"    err=\"<nil>\"",
    "PrintfLine     \"%d %s\"                out=\"250 OK\\r\\n\"               err=\"<nil>\"",
    "PrintfLine     \"already\\r\\n\"          out=\"already\\r\\n\\r\\n\"          err=\"<nil>\"",
    "DotWriter      \"line one\\nline two\\n\" n=18  out=\"line one\\r\\nline two\\r\\n.\\r\\n\"    err=\"<nil>\"",
    "DotWriter      \".leading\\n\"           n=9   out=\"..leading\\r\\n.\\r\\n\"               err=\"<nil>\"",
    "DotWriter      \"..two dots\\n\"         n=11  out=\"...two dots\\r\\n.\\r\\n\"             err=\"<nil>\"",
    "DotWriter      \"no trailing newline\"  n=19  out=\"no trailing newline\\r\\n.\\r\\n\"     err=\"<nil>\"",
    "DotWriter      \"\"                     n=0   out=\"\\r\\n.\\r\\n\"                        err=\"<nil>\"",
    "DotWriter      \"a\\r\\nb\\r\\n\"           n=6   out=\"a\\r\\nb\\r\\n.\\r\\n\"                  err=\"<nil>\"",
    "DotWriter      \"mid.dot\\n\"            n=8   out=\"mid.dot\\r\\n.\\r\\n\"                 err=\"<nil>\"",
    "DotWriter      \"\\n\"                   n=1   out=\"\\r\\n.\\r\\n\"                        err=\"<nil>\"",
    "DotWriter      \"a\\rb\\n\"               n=4   out=\"a\\rb\\r\\n.\\r\\n\"                    err=\"<nil>\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
#[goish::main]
fn main() {
    let cases: [&str; 4] = ["NOOP", "MAIL FROM:<a@b.c>", "250 OK", "already\r\n"];
    let fmts: [&str; 4] = ["NOOP", "MAIL FROM:<%s>", "%d %s", "already\r\n"];
    for (i, s) in cases.iter().enumerate() {
        let buf = bytes::NewBuffer(goish::convert::bytes(string("")));
        let mut w = writer::NewWriter(bufio::NewWriter(buf));
        let err = w.PrintfLine(string::from_static(s));
        let _ = w.W.Flush();
        let out = w.W.__wr_mut().String();
        chk(fmt::Sprintf!(
            "%-14s %-22q out=%-26q err=%q",
            string("PrintfLine"),
            string::from_static(fmts[i]),
            out,
            if err.IsNil() {
                string("<nil>")
            } else {
                err.Error()
            }
        ));
    }
    let ins: [&str; 9] = [
        "line one\nline two\n",
        ".leading\n",
        "..two dots\n",
        "no trailing newline",
        "",
        "a\r\nb\r\n",
        "mid.dot\n",
        "\n",
        "a\rb\n",
    ];
    for s in ins.iter() {
        let buf = bytes::NewBuffer(goish::convert::bytes(string("")));
        let mut w = writer::NewWriter(bufio::NewWriter(buf));
        let (n, werr) = {
            let mut d = w.DotWriter();
            let r = d.Write(goish::convert::bytes(string::from_static(s)));
            let c = d.Close();
            (r.0, if r.1.IsNil() { c } else { r.1 })
        };
        let _ = w.W.Flush();
        let out = w.W.__wr_mut().String();
        chk(fmt::Sprintf!(
            "%-14s %-22q n=%-3d out=%-34q err=%q",
            string("DotWriter"),
            string::from_static(s),
            n as i64,
            out,
            if werr.IsNil() {
                string("<nil>")
            } else {
                werr.Error()
            }
        ));
    }
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("textproto writer: %d/%d match Go\n", n, n);
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
