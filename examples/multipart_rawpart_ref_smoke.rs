// multipart_rawpart_ref_smoke — NextRawPart, and a Part you can read.
//
// Go's NextPart hides a `Content-Transfer-Encoding: quoted-printable`
// header and decodes the body transparently; NextRawPart does neither,
// which is what a proxy relaying a part, or a signature check over the
// encoded form, needs. goish had only the decoding one, so the bytes
// as sent were unreachable.
//
// Go's Part is also an io.Reader — `io.Copy(dst, part)` is how a
// handler writes an upload to a file. goish's Part exposed `Body` and
// nothing else, so that spelling did not compile.
//
// GO[] is the verbatim output of tools/gen_multipart_rawpart_ref.go
// under scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::Reader as _;
use goish::mime::multipart;
use goish::types::byte;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 3] = [
    "NextPart    body=\"a=b\" cte=\"\"",
    "NextRawPart body=\"a=3Db\" cte=\"quoted-printable\"",
    "Part.Read   n1=2 \"a=\" e1=<nil> n2=2 \"3D\" e2=<nil>",
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

const BODY: &str = "--B\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db\r\n--B--\r\n";

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn mk() -> multipart::Reader {
    return multipart::NewReader(goish::bytes(BODY), string("B"));
}

fn run() {
    let mut r = mk();
    let (mut p, e) = r.NextPart();
    if !e.IsNil() {
        fmt::Printf!("NextPart err=%v\n", e);
        goish::os::Exit(1);
    }
    let (b, _) = goish::io::ReadAll(&mut p);
    chk(fmt::Sprintf!(
        "NextPart    body=%q cte=%q",
        goish::string::from_bytes(&b),
        p.Header.Get(string("Content-Transfer-Encoding"))
    ));

    let mut r2 = mk();
    let (mut p2, e2) = r2.NextRawPart();
    if !e2.IsNil() {
        fmt::Printf!("NextRawPart err=%v\n", e2);
        goish::os::Exit(1);
    }
    let (b2, _) = goish::io::ReadAll(&mut p2);
    chk(fmt::Sprintf!(
        "NextRawPart body=%q cte=%q",
        goish::string::from_bytes(&b2),
        p2.Header.Get(string("Content-Transfer-Encoding"))
    ));

    // Read in small bites: a Part is a READER, not a one-shot handout.
    let mut r3 = mk();
    let (mut p3, _) = r3.NextRawPart();
    let mut buf = goish::make!([]byte, 2);
    let (n1, e1) = p3.Read(&mut buf);
    let s1 = goish::string::from_bytes(&buf.slice(0, n1));
    let (n2, e2b) = p3.Read(&mut buf);
    let s2 = goish::string::from_bytes(&buf.slice(0, n2));
    chk(fmt::Sprintf!(
        "Part.Read   n1=%d %q e1=%v n2=%d %q e2=%v",
        n1 as i64, s1, e1, n2 as i64, s2, e2b
    ));

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 3/3\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 3\n", f as i64);
    goish::os::Exit(1);
}
