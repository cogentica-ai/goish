// multipart_falseboundary_ref_smoke — data that only LOOKS like a
// boundary must not end a part.
//
// Go decides that with matchAfterPrefix (multipart.go line 295): after
// the boundary, the next byte must be space, tab, CR, LF, or `-` for
// the final boundary. Anything else and the match is ordinary content.
//
// goish matched the boundary prefix alone. A part carrying a line like
// `--Bxyz` was TRUNCATED there, and the text after it was then read as
// a header block, so the parse failed with "malformed header" — data
// loss first, confusing error second. This is the case that found it:
//
//     Go     [x="1" body="before\r\n--Bxyz\r\nafter"] end=EOF
//     goish  [x="1" body="before"] end=multipart: malformed header
//
// The check now runs on the part scan AND on the preamble scan, since
// a preamble carrying such a line must not open a part either.
//
// GO[] is the verbatim output of
// tools/gen_multipart_falseboundary_ref.go under scripts/goref.sh
// against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::mime::multipart;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 3] = [
    "false-prefix   [x=\"1\" body=\"before\\r\\n--Bxyz\\r\\nafter\"] end=EOF",
    "two-parts      [x=\"1\" body=\"one\"] [x=\"2\" body=\"two\"] end=EOF",
    "trailing-dash  [x=\"1\" body=\"data--B\"] end=EOF",
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
    let cases: [(&str, &str); 3] = [
        ("false-prefix", "--B\r\nX: 1\r\n\r\nbefore\r\n--Bxyz\r\nafter\r\n--B--\r\n"),
        ("two-parts", "--B\r\nX: 1\r\n\r\none\r\n--B\r\nX: 2\r\n\r\ntwo\r\n--B--\r\n"),
        ("trailing-dash", "--B\r\nX: 1\r\n\r\ndata--B\r\n--B--\r\n"),
    ];
    let mut i = 0;
    while i < cases.len() {
        let (name, body) = cases[i];
        let mut r = multipart::NewReader(goish::bytes(body), string("B"));
        let mut out: Vec<goish::string> = Vec::new();
        loop {
            let (p, e) = r.NextPart();
            if !e.IsNil() {
                out.push(fmt::Sprintf!("end=%v", e));
                break;
            }
            out.push(fmt::Sprintf!("[x=%q body=%q]", p.Header.Get(string("X")),
                goish::string::from_bytes(&p.Body)));
        }
        let mut joined = string::new();
        let mut k = 0;
        while k < out.len() {
            if k > 0 { joined = joined + string(" "); }
            joined = joined + out[k].clone();
            k += 1;
        }
        chk(fmt::Sprintf!("%-14s %s", string(name), joined));
        i += 1;
    }
    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    // Nothing failed AND every row RAN. Checking only FAILED lets a
    // smoke whose assertions were never wired report success — which
    // happened once, in os_file_readdir_ref_smoke.
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok 3/3\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 3\n", f as i64);
    goish::os::Exit(1);
}
