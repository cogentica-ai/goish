//! Pinned against Go 1.25.5: `textproto.DotReader`, `ReadDotBytes`
//! and `ReadDotLines` — the dot-encoding SMTP and NNTP bodies use.
//!
//! goish had none of the three. Five rules the reference settles:
//!
//!   * CRLF becomes LF in the decoded output. The block terminator is
//!     a line containing only ".".
//!   * A line beginning "." that is NOT the terminator has exactly ONE
//!     dot removed: "..stuffed" decodes to ".stuffed", and — the case
//!     a port written from the RFC would miss — ".leading" decodes to
//!     "leading". Go strips the dot whatever follows it.
//!   * A lone `\r` NOT followed by `\n` is data. The state machine
//!     unreads and emits the saved `\r`, which is the only reason it
//!     is a state machine and not a line loop.
//!   * Running out of input before the terminator is
//!     io.ErrUnexpectedEOF, NOT io.EOF — and whatever decoded so far
//!     still comes back beside the error.
//!   * Everything after the terminator is left in the stream.
//!
//! All three entry points are checked on all ten inputs because they
//! decode by different means — ReadDotLines reads a line at a time
//! (Go's own comment: it "avoids needing a large contiguous block of
//! memory"), while ReadDotBytes runs io.ReadAll over the state
//! machine. A port could get one right and the other wrong.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh net/textproto <textproto_dot_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::net::textproto;
use goish::{bufio, bytes, fmt, io, string};

/// Go's output, verbatim.
const GO: [&str; 30] = [
    "ReadDotLines             \"line one\\r\\nline two\\r\\n.\\r\\n\" lines=[\"line one\"                     \"line two\"                    ] err=\"<nil>\"",
    "ReadDotBytes             \"line one\\r\\nline two\\r\\n.\\r\\n\" bytes=\"line one\\nline two\\n\"         err=\"<nil>\"",
    "DotReader                \"line one\\r\\nline two\\r\\n.\\r\\n\" out=\"line one\\nline two\\n\"           err=\"<nil>\"",
    "ReadDotLines             \".\\r\\n\"                    lines=[] err=\"<nil>\"",
    "ReadDotBytes             \".\\r\\n\"                    bytes=\"\"                             err=\"<nil>\"",
    "DotReader                \".\\r\\n\"                    out=\"\"                               err=\"<nil>\"",
    "ReadDotLines             \"..stuffed\\r\\n.\\r\\n\"       lines=[\".stuffed\"                    ] err=\"<nil>\"",
    "ReadDotBytes             \"..stuffed\\r\\n.\\r\\n\"       bytes=\".stuffed\\n\"                   err=\"<nil>\"",
    "DotReader                \"..stuffed\\r\\n.\\r\\n\"       out=\".stuffed\\n\"                     err=\"<nil>\"",
    "ReadDotLines             \"a\\r\\n..\\r\\n b\\r\\n.\\r\\n\"   lines=[\"a\"                            \".\"                            \" b\"                          ] err=\"<nil>\"",
    "ReadDotBytes             \"a\\r\\n..\\r\\n b\\r\\n.\\r\\n\"   bytes=\"a\\n.\\n b\\n\"                   err=\"<nil>\"",
    "DotReader                \"a\\r\\n..\\r\\n b\\r\\n.\\r\\n\"   out=\"a\\n.\\n b\\n\"                     err=\"<nil>\"",
    "ReadDotLines             \"no terminator\\r\\n\"        lines=[\"no terminator\"               ] err=\"unexpected EOF\"",
    "ReadDotBytes             \"no terminator\\r\\n\"        bytes=\"no terminator\\n\"              err=\"unexpected EOF\"",
    "DotReader                \"no terminator\\r\\n\"        out=\"no terminator\\n\"                err=\"unexpected EOF\"",
    "ReadDotLines             \"\"                         lines=[] err=\"unexpected EOF\"",
    "ReadDotBytes             \"\"                         bytes=\"\"                             err=\"unexpected EOF\"",
    "DotReader                \"\"                         out=\"\"                               err=\"unexpected EOF\"",
    "ReadDotLines             \"a\\r\\n.\\r\\nafter\\r\\n\"      lines=[\"a\"                           ] err=\"<nil>\"",
    "ReadDotBytes             \"a\\r\\n.\\r\\nafter\\r\\n\"      bytes=\"a\\n\"                          err=\"<nil>\"",
    "DotReader                \"a\\r\\n.\\r\\nafter\\r\\n\"      out=\"a\\n\"                            err=\"<nil>\"",
    "ReadDotLines             \".leading\\r\\n.\\r\\n\"        lines=[\"leading\"                     ] err=\"<nil>\"",
    "ReadDotBytes             \".leading\\r\\n.\\r\\n\"        bytes=\"leading\\n\"                    err=\"<nil>\"",
    "DotReader                \".leading\\r\\n.\\r\\n\"        out=\"leading\\n\"                      err=\"<nil>\"",
    "ReadDotLines             \"trailing dot.\\r\\n.\\r\\n\"   lines=[\"trailing dot.\"               ] err=\"<nil>\"",
    "ReadDotBytes             \"trailing dot.\\r\\n.\\r\\n\"   bytes=\"trailing dot.\\n\"              err=\"<nil>\"",
    "DotReader                \"trailing dot.\\r\\n.\\r\\n\"   out=\"trailing dot.\\n\"                err=\"<nil>\"",
    "ReadDotLines             \"\\r\\n.\\r\\n\"                lines=[\"\"                            ] err=\"<nil>\"",
    "ReadDotBytes             \"\\r\\n.\\r\\n\"                bytes=\"\\n\"                           err=\"<nil>\"",
    "DotReader                \"\\r\\n.\\r\\n\"                out=\"\\n\"                             err=\"<nil>\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
#[goish::main]
fn main() {
    let inputs: [&str; 10] = [
        "line one\r\nline two\r\n.\r\n",
        ".\r\n",
        "..stuffed\r\n.\r\n",
        "a\r\n..\r\n b\r\n.\r\n",
        "no terminator\r\n",
        "",
        "a\r\n.\r\nafter\r\n",
        ".leading\r\n.\r\n",
        "trailing dot.\r\n.\r\n",
        "\r\n.\r\n",
    ];
    for input in inputs.iter() {
        let s = string::from_static(input);
        let mut r = textproto::NewReader(bufio::NewReader(bytes::NewReader(
            goish::convert::bytes(s.clone()),
        )));
        let (lines, err) = r.ReadDotLines();
        let mut joined = string("[");
        for i in 0..lines.len() {
            if i > 0 {
                joined = joined + string(" ");
            }
            joined = joined + fmt::Sprintf!("%-30q", lines.get(i).cloned().unwrap_or(string("")));
        }
        joined = joined + string("]");
        chk(fmt::Sprintf!(
            "%-24s %-26q lines=%s err=%q",
            string("ReadDotLines"),
            s.clone(),
            joined,
            if err.IsNil() {
                string("<nil>")
            } else {
                err.Error()
            }
        ));

        let mut r2 = textproto::NewReader(bufio::NewReader(bytes::NewReader(
            goish::convert::bytes(s.clone()),
        )));
        let (b, e2) = r2.ReadDotBytes();
        chk(fmt::Sprintf!(
            "%-24s %-26q bytes=%-30q err=%q",
            string("ReadDotBytes"),
            s.clone(),
            string::from_bytes(&b.to_vec()),
            if e2.IsNil() {
                string("<nil>")
            } else {
                e2.Error()
            }
        ));

        let mut r3 = textproto::NewReader(bufio::NewReader(bytes::NewReader(
            goish::convert::bytes(s.clone()),
        )));
        let mut d = r3.DotReader();
        let (out, e3) = io::ReadAll(&mut d);
        chk(fmt::Sprintf!(
            "%-24s %-26q out=%-32q err=%q",
            string("DotReader"),
            s.clone(),
            string::from_bytes(&out.to_vec()),
            if e3.IsNil() {
                string("<nil>")
            } else {
                e3.Error()
            }
        ));
    }
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("textproto dot encoding: %d/%d match Go\n", n, n);
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
