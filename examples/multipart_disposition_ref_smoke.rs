// multipart_disposition_ref_smoke — FormName and FileName, against Go.
//
// Two rules, both easy to get subtly wrong, and one of them is a
// defence rather than a convenience:
//
//   * FormName is empty unless the disposition is exactly "form-data"
//     (multipart.go line 76). A part sent as `attachment` has a name=
//     parameter and is still not a form field.
//   * FileName applies filepath.Base, because "RFC 7578, Section 4.2
//     requires that if a filename is provided, the directory path
//     information must not be used" (multipart.go line 99). goish
//     returned the parameter verbatim once, so a part sent with
//     filename="../../etc/passwd" reported exactly that and a handler
//     doing the obvious os.Create(part.FileName()) wrote outside its
//     upload directory. That is fixed; this is what keeps it fixed.
//
// The `windows` row is deliberate: filepath.Base on a unix host does
// not treat a backslash as a separator, so Go returns the whole
// `C:\dir\a.txt`. goish reproduces the host-specific answer rather
// than improving on it, because a port that is cleverer than Go is a
// port that diverges.
//
// GO[] is the verbatim output of
// tools/gen_multipart_disposition_ref.go under scripts/goref.sh
// against Go 1.25.5.

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

static GO: [&str; 7] = [
    "form-data    form=\"f\" file=\"a.txt\"",
    "attachment   form=\"\" file=\"a.txt\"",
    "traversal    form=\"f\" file=\"passwd\"",
    "abs-path     form=\"f\" file=\"passwd\"",
    "windows      form=\"f\" file=\"C:\\\\dir\\\\a.txt\"",
    "no-filename  form=\"f\" file=\"\"",
    "dot-dot      form=\"f\" file=\"..\"",
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
    let cases: [(&str, &str); 7] = [
        ("form-data", "form-data; name=\"f\"; filename=\"a.txt\""),
        ("attachment", "attachment; name=\"f\"; filename=\"a.txt\""),
        ("traversal", "form-data; name=\"f\"; filename=\"../../etc/passwd\""),
        ("abs-path", "form-data; name=\"f\"; filename=\"/etc/passwd\""),
        ("windows", "form-data; name=\"f\"; filename=\"C:\\\\dir\\\\a.txt\""),
        ("no-filename", "form-data; name=\"f\""),
        ("dot-dot", "form-data; name=\"f\"; filename=\"..\""),
    ];
    let mut i = 0;
    while i < cases.len() {
        let (name, cd) = cases[i];
        let body = string("--B\r\nContent-Disposition: ") + string(cd) + string("\r\n\r\nx\r\n--B--\r\n");
        let mut r = multipart::NewReader(goish::bytes(body), string("B"));
        let (p, e) = r.NextPart();
        if !e.IsNil() {
            chk(fmt::Sprintf!("%-12s err=%v", string(name), e));
        } else {
            chk(fmt::Sprintf!("%-12s form=%q file=%q", string(name), p.FormName(), p.FileName()));
        }
        i += 1;
    }
    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    // Nothing failed AND every row RAN. Checking only FAILED lets a
    // smoke whose assertions were never wired report success — which
    // happened once, in os_file_readdir_ref_smoke.
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok 7/7\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 7\n", f as i64);
    goish::os::Exit(1);
}
