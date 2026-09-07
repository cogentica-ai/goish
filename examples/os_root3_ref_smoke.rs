// os_root3_ref_smoke — Root.Readlink, ReadFile and WriteFile.
//
// The three operations needing no syscall the tree did not already
// have. Each gets the same three refusals as everything else on the
// walk (ROADMAP §2q), because an operation added to a shared guarded
// path inherits the guarantee and NOT the coverage — which is how a
// Root.Stat that let the kernel follow a symlink got written with
// every other row passing.
//
// Two rows carry the contract:
//
//   * `readlink:escape` SUCCEEDS and returns a path OUTSIDE the root.
//     That is correct: Readlink acts on the link, and reading a link
//     is not following one. Refusing it would be a different bug.
//   * `writefile:escape` is refused, and `secret_intact` proves what
//     that buys — a write through a symlink pointing out of the root
//     would have overwritten the file outside.
//
// GO[] is the verbatim output of tools/gen_os_root3_ref.go under
// scripts/goref.sh, transcribed programmatically.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

/// Every mismatch below lands here; the process exits non-zero if it is
/// not zero (ROADMAP §2b-vii).
static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

use goish::gostring::string;
use goish::os;
use goish::types::int;
use goish::{fmt, strings};

const GO: [&str; 15] = [
    "readlink:inside_link    target=\"ok.txt\" err=<nil>",
    "readlink:escape         target=\"OUT/secret.txt\" err=<nil>",
    "readlink:ok.txt         target=\"\" err=readlinkat ok.txt: invalid argument",
    "readlink:../secret.txt  err=readlinkat ../secret.txt: path escapes from parent",
    "readlink:/etc/passwd    err=readlinkat /etc/passwd: path escapes from parent",
    "readfile:ok.txt         data=\"hello\" err=<nil>",
    "readfile:inside_link    data=\"hello\" err=<nil>",
    "readfile:../secret.txt  err=openat ../secret.txt: path escapes from parent",
    "readfile:/etc/passwd    err=openat /etc/passwd: path escapes from parent",
    "readfile:escape         err=openat escape: path escapes from parent",
    "writefile:new           err=<nil> readback=\"written\"",
    "writefile:../secret.txt err=openat ../secret.txt: path escapes from parent",
    "writefile:/etc/passwd   err=openat /etc/passwd: path escapes from parent",
    "writefile:escape        err=openat escape: path escapes from parent",
    "secret_intact           true",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let base = os::TempDir() + "/goish_os_root3";
    let _ = os::RemoveAll(&base);
    let inside = base.clone() + "/inside";
    let _ = os::MkdirAll(&(inside.clone() + "/sub"), os::FileMode(0o755));
    let _ = os::WriteFile(&(inside.clone() + "/ok.txt"), b"hello".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(base.clone() + "/secret.txt"), b"secret".as_ref(), os::FileMode(0o644));
    let _ = os::Symlink(base.clone() + "/secret.txt", inside.clone() + "/escape");
    let _ = os::Symlink(string::from_static("ok.txt"), inside.clone() + "/inside_link");

    let scrub = |e: goish::errors::error| -> string {
        if e.IsNil() {
            return string::from_static("<nil>");
        }
        let mut s = e.Error();
        s = strings::ReplaceAll(s, inside.clone() + "/", string::new());
        s = strings::ReplaceAll(s, inside.clone(), string::from_static("."));
        s = strings::ReplaceAll(s, base.clone() + "/", string::from_static("OUT/"));
        s = strings::ReplaceAll(s, base.clone(), string::from_static("OUT"));
        return s;
    };
    let scrub_target = |t: string| -> string {
        return strings::ReplaceAll(t, base.clone() + "/", string::from_static("OUT/"));
    };

    let (r, rerr) = os::OpenRoot(inside.clone());
    if !rerr.IsNil() {
        fmt::Printf!("[!!] OpenRoot: %v\n", rerr);
        goish::os::Exit(1);
    }
    let r = r.MustTake();
    let escapes: [&str; 2] = ["../secret.txt", "/etc/passwd"];

    for n in ["inside_link", "escape", "ok.txt"].iter() {
        let (tgt, err) = r.Readlink(string::from(*n));
        chk(&mut ln, &fmt::Sprintf!("%-23s target=%q err=%s",
            string::from_static("readlink:") + string::from(*n), scrub_target(tgt), scrub(err)));
    }
    for n in escapes.iter() {
        let (_, err) = r.Readlink(string::from(*n));
        chk(&mut ln, &fmt::Sprintf!("%-23s err=%s",
            string::from_static("readlink:") + string::from(*n), scrub(err)));
    }

    for n in ["ok.txt", "inside_link"].iter() {
        let (b, err) = r.ReadFile(string::from(*n));
        chk(&mut ln, &fmt::Sprintf!("%-23s data=%q err=%s",
            string::from_static("readfile:") + string::from(*n),
            string::from_bytes(b.as_ref()), scrub(err)));
    }
    for n in ["../secret.txt", "/etc/passwd", "escape"].iter() {
        let (_, err) = r.ReadFile(string::from(*n));
        chk(&mut ln, &fmt::Sprintf!("%-23s err=%s",
            string::from_static("readfile:") + string::from(*n), scrub(err)));
    }

    let werr = r.WriteFile(string::from_static("written.txt"), b"written".as_ref(), os::FileMode(0o644));
    let (rb, _) = r.ReadFile(string::from_static("written.txt"));
    chk(&mut ln, &fmt::Sprintf!("%-23s err=%s readback=%q",
        string::from_static("writefile:new"), scrub(werr), string::from_bytes(rb.as_ref())));
    for n in ["../secret.txt", "/etc/passwd", "escape"].iter() {
        let e = r.WriteFile(string::from(*n), b"x".as_ref(), os::FileMode(0o644));
        chk(&mut ln, &fmt::Sprintf!("%-23s err=%s",
            string::from_static("writefile:") + string::from(*n), scrub(e)));
    }
    let (out, _) = os::ReadFile(base.clone() + "/secret.txt");
    chk(&mut ln, &fmt::Sprintf!("%-23s %v", string::from_static("secret_intact"),
        string::from_bytes(out.as_ref()) == string::from_static("secret")));

    let _ = os::RemoveAll(&base);
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    let f = FAILED.load(core::sync::atomic::Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
