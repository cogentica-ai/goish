// multipart_headers_ref_smoke — a part's headers are CONTINUED lines.
//
// Go reads them with textproto.ReadMIMEHeader, which is not a CRLF
// split: a line starting with space or tab continues the header before
// it (RFC 5322 obsolete folding), duplicates accumulate under one key,
// and the block ends at the first empty line.
//
// goish split on CRLF, so every folded header was "malformed" and the
// WHOLE part failed — a legal message rejected outright, not merely a
// header dropped.
//
// The last four rows encode the joining rule, which is easy to get
// almost right: one space, then the continuation with its own leading
// whitespace removed, and the final value left-trimmed. So a wide fold
// collapses to one space, `X: a\r\n ` KEEPS its trailing space, and
// `X: \r\n b` is "b" rather than " b".
//
// GO[] is the verbatim output of tools/gen_multipart_headers_ref.go
// under scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::mime::multipart;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 10] = [
    "plain       x=\"a\" vals=[a] y=\"\" body=\"data\"",
    "folded      x=\"a b\" vals=[a b] y=\"\" body=\"data\"",
    "folded-tab  x=\"a b\" vals=[a b] y=\"\" body=\"data\"",
    "duplicate   x=\"a\" vals=[a b] y=\"\" body=\"data\"",
    "no-space    x=\"a\" vals=[a] y=\"\" body=\"data\"",
    "mixed-case  x=\"\" vals=[] y=\"a\" body=\"data\"",
    "fold-wide   x=\"a b\" vals=[a b] y=\"\" body=\"data\"",
    "fold-twice  x=\"a b c\" vals=[a b c] y=\"\" body=\"data\"",
    "fold-empty  x=\"a \" vals=[a ] y=\"\" body=\"data\"",
    "fold-first  x=\"b\" vals=[b] y=\"\" body=\"data\"",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let cases: [(&str, &str); 10] = [
        ("plain", "X: a"),
        ("folded", "X: a\r\n b"),
        ("folded-tab", "X: a\r\n\tb"),
        ("duplicate", "X: a\r\nX: b"),
        ("no-space", "X:a"),
        ("mixed-case", "x-Y: a"),
        ("fold-wide", "X: a\r\n     b"),
        ("fold-twice", "X: a\r\n b\r\n c"),
        ("fold-empty", "X: a\r\n "),
        ("fold-first", "X: \r\n b"),
    ];
    let mut i = 0;
    while i < cases.len() {
        let (name, hdrs) = cases[i];
        let body = string("--B\r\n") + string(hdrs) + string("\r\n\r\ndata\r\n--B--\r\n");
        let mut r = multipart::NewReader(goish::bytes(body), string("B"));
        let (p, e) = r.NextPart();
        if !e.IsNil() {
            chk(fmt::Sprintf!("%-11s err=%v", string(name), e));
        } else {
            chk(fmt::Sprintf!("%-11s x=%q vals=%v y=%q body=%q", string(name),
                p.Header.Get(string("X")), p.Header.Values(string("X")),
                p.Header.Get(string("X-Y")), goish::string::from_bytes(&p.Body)));
        }
        i += 1;
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 10/10\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 10\n", f as i64);
    goish::os::Exit(1);
}
