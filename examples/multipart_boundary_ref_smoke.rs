// multipart_boundary_ref_smoke — the boundary scanner, against Go.
//
// goish's multipart Reader is a SLIM port: a single pass over a body
// it already holds, where Go streams through a bufio.Reader. That
// design replaces thirteen of Go's declarations — scanUntilBoundary,
// partReader.Read, stickyErrorReader.Read, isBoundaryDelimiterLine,
// isFinalBoundary, skipLWSPChar and the rest — and reader.rs carries
// no `// go:` anchors, so NO tier checks any of it. This smoke is the
// check: the same inputs through both, compared.
//
// The cases are the ones a scanner gets wrong:
//
//   * LWSP after a boundary. RFC 2046 5.1 allows "optional linear
//     whitespace" before the terminating CRLF, and Go honours it with
//     skipLWSPChar on both the delimiter and the final boundary. A
//     reader matching the boundary exactly sees no parts at all.
//   * LF-only line endings, which Go accepts on the first boundary
//     and then switches to — "a violation of the spec, but occurs in
//     practice".
//   * A preamble before the first boundary, which RFC 2046 says to
//     discard rather than hand back as a part.
//   * A part with no headers, and a part with an empty body.
//
// GO[] is the verbatim output of tools/gen_multipart_lwsp_ref.go
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

static GO: [&str; 8] = [
    "plain      body=\"hello\" x=\"1\" next=EOF",
    "lwsp-delim body=\"hello\" x=\"1\" next=EOF",
    "lwsp-final body=\"hello\" x=\"1\" next=EOF",
    "lwsp-both  body=\"hello\" x=\"1\" next=EOF",
    "lf-only    body=\"hello\" x=\"1\" next=EOF",
    "preamble   body=\"hello\" x=\"1\" next=EOF",
    "no-headers body=\"hello\" x=\"\" next=EOF",
    "empty-body body=\"\" x=\"1\" next=EOF",
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
    let cases: [(&str, &str); 8] = [
        ("plain", "--B\r\nX: 1\r\n\r\nhello\r\n--B--\r\n"),
        ("lwsp-delim", "--B \r\nX: 1\r\n\r\nhello\r\n--B--\r\n"),
        ("lwsp-final", "--B\r\nX: 1\r\n\r\nhello\r\n--B-- \r\n"),
        ("lwsp-both", "--B \t\r\nX: 1\r\n\r\nhello\r\n--B-- \t\r\n"),
        ("lf-only", "--B\nX: 1\n\nhello\n--B--\n"),
        ("preamble", "ignore me\r\n--B\r\nX: 1\r\n\r\nhello\r\n--B--\r\n"),
        ("no-headers", "--B\r\n\r\nhello\r\n--B--\r\n"),
        ("empty-body", "--B\r\nX: 1\r\n\r\n\r\n--B--\r\n"),
    ];
    let mut i = 0;
    while i < cases.len() {
        let (name, body) = cases[i];
        let mut r = multipart::NewReader(goish::bytes(body), string("B"));
        let (p, e) = r.NextPart();
        if !e.IsNil() {
            chk(fmt::Sprintf!("%-10s err=%v", string(name), e));
        } else {
            let (_, e2) = r.NextPart();
            chk(fmt::Sprintf!("%-10s body=%q x=%q next=%v", string(name),
                goish::string::from_bytes(&p.Body), p.Header.Get(string("X")), e2));
        }
        i += 1;
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 8/8\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 8\n", f as i64);
    goish::os::Exit(1);
}
