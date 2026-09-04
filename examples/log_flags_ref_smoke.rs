//! Pinned against Go 1.25.5: `log`'s flag rendering, and the caller
//! location `Lshortfile` reports.
//!
//! `log.SetFlags(log.Lshortfile)` printed `???:0:` in every goish
//! program. `Logger.Output` ignored its `calldepth` argument and
//! hard-coded that pair, behind a doc comment that said:
//!
//!     `calldepth` is accepted for API compatibility; goish has no
//!     runtime.Caller so it is unused.
//!
//! goish HAS runtime::Caller, and has for a while — net/http's
//! `relevantCaller` walks frames with it and http_misc_decls_smoke
//! asserts it names a real function. The claim was false, and the
//! false claim is why nobody looked: `???:0` reads like a documented
//! limitation rather than a bug.
//!
//! Go falls back to exactly `???` and 0 too — but only when
//! runtime.Caller reports it could not recover the frame.
//!
//! What is pinned: every flag combination's rendering, including the
//! two that are easy to get backwards —
//!
//!   * `Lmsgprefix` moves the prefix from the START of the line to
//!     just before the MESSAGE, so "P: FILE:LINE: hello" becomes
//!     "FILE:LINE: P: hello";
//!   * `Lshortfile` and `Llongfile` render the same here because the
//!     reference rewrites the path, which is the point: what is
//!     checked is that a real file and line appear at all.
//!
//! The date, time and source location are rewritten to DATE, TIME and
//! FILE:LINE on both sides — the Go reference does it with regexps,
//! this file with the scanner below — so the smoke pins the FORMAT
//! without pinning the clock or this machine's paths.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh log <logflags_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use goish::{fmt, log, slice, string, sync, Any};

// A writer that captures into a shared buffer, so the smoke can read
// back exactly what the Logger wrote.
struct Cap(Arc<sync::Mutex<alloc::vec::Vec<u8>>>);
impl goish::io::Writer for Cap {
    fn Write(&mut self, p: goish::slice<u8>) -> (goish::int, goish::error) {
        let n = p.Len();
        self.0.Lock().extend_from_slice(&p.to_vec());
        return (n, goish::errors::nil);
    }
}

fn norm(s: &str) -> String {
    // Rewrite the three volatile shapes the Go reference rewrites:
    // a source location, a date and a clock time.
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    let dig = |k: usize| k < b.len() && b[k].is_ascii_digit();
    while i < b.len() {
        // dddd/dd/dd
        if dig(i)
            && dig(i + 1)
            && dig(i + 2)
            && dig(i + 3)
            && i + 10 <= b.len()
            && b[i + 4] == b'/'
            && b[i + 7] == b'/'
            && dig(i + 5)
            && dig(i + 6)
            && dig(i + 8)
            && dig(i + 9)
        {
            out.push_str("DATE");
            i += 10;
            continue;
        }
        // dd:dd:dd(.digits)?
        if dig(i)
            && dig(i + 1)
            && i + 8 <= b.len()
            && b[i + 2] == b':'
            && b[i + 5] == b':'
            && dig(i + 3)
            && dig(i + 4)
            && dig(i + 6)
            && dig(i + 7)
        {
            let mut k = i + 8;
            if k < b.len() && b[k] == b'.' {
                k += 1;
                while dig(k) {
                    k += 1;
                }
            }
            out.push_str("TIME");
            i = k;
            continue;
        }
        // <path>.rs:<digits>
        if b[i] == b'/' || b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_' {
            let st = i;
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b"._/-".contains(&b[j])) {
                j += 1;
            }
            let word = &s[st..j];
            if word.ends_with(".rs") && j < b.len() && b[j] == b':' && dig(j + 1) {
                let mut k = j + 1;
                while dig(k) {
                    k += 1;
                }
                out.push_str("FILE:LINE");
                i = k;
                continue;
            }
            out.push_str(word);
            i = j;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    return out;
}

fn show(tag: &'static str, flag: goish::int, prefix: &'static str) {
    let buf = Arc::new(sync::Mutex::new(alloc::vec::Vec::new()));
    let l = log::New(
        Box::new(Cap(buf.clone())),
        string::from_static(prefix),
        flag,
    );
    let mut a = slice::<Any>::new();
    a = goish::append!(a, Any::new(string("hello")));
    l.Println(a);
    let raw = buf.Lock().clone();
    let got = core::str::from_utf8(&raw).unwrap_or("");
    chk(fmt::Sprintf!(
        "%-22s %q",
        string::from_static(tag),
        string::from_bytes(norm(got).as_bytes())
    ));
}

/// Go's output, verbatim.
const GO: [&str; 9] = [
    "no-flags               \"hello\\n\"",
    "shortfile              \"FILE:LINE: hello\\n\"",
    "longfile               \"FILE:LINE: hello\\n\"",
    "date-time              \"DATE TIME hello\\n\"",
    "date-time-short        \"DATE TIME FILE:LINE: hello\\n\"",
    "prefix-short           \"P: FILE:LINE: hello\\n\"",
    "msgprefix-short        \"FILE:LINE: P: hello\\n\"",
    "microseconds           \"TIME hello\\n\"",
    "utc-date               \"DATE hello\\n\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

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

#[goish::main]
fn main() {
    show("no-flags", 0 as goish::int, "");
    show("shortfile", log::Lshortfile, "");
    show("longfile", log::Llongfile, "");
    show("date-time", log::Ldate | log::Ltime, "");
    show(
        "date-time-short",
        log::Ldate | log::Ltime | log::Lshortfile,
        "",
    );
    show("prefix-short", log::Lshortfile, "P: ");
    show("msgprefix-short", log::Lshortfile | log::Lmsgprefix, "P: ");
    show("microseconds", log::Ltime | log::Lmicroseconds, "");
    show("utc-date", log::Ldate | log::LUTC, "");

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("log flags: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
