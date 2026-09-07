// os_root2_ref_smoke — the operations that ride on Root's walk.
//
// The point is NOT that Stat and Mkdir work. It is that each one
// inherits the ESCAPE rules: an operation that resolved its own path
// would pass a "stat a file inside" row and be completely unprotected,
// while every row in os_root_ref_smoke still passed. So each operation
// here gets the same three refusals — "..", an absolute path, and a
// symlink pointing outside.
//
// Three rows are contract details a reasonable implementation gets
// wrong, and all three come from WHICH operations follow a symlink on
// the final component:
//
//   * `mkdir:escape` is "file exists", NOT an escape. mkdirat never
//     follows the last component, so the existing link is in the way
//     before its target is ever considered.
//   * `remove:escape` SUCCEEDS, and `secret_survived` proves what it
//     did: unlinkat removes the NAME, so the link inside the root goes
//     and the file outside is untouched.
//   * `lstat:escape` succeeds and reports a symlink, where
//     `stat:escape` is refused — Stat follows and lands outside, Lstat
//     describes the link, which is inside.
//
// GO[] is the verbatim output of tools/gen_os_root2_ref.go under
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
use goish::io::Closer;
use goish::os;
use goish::types::int;
use goish::{fmt, strings};

const GO: [&str; 21] = [
    "stat:ok.txt          name=\"ok.txt\" size=5 err=<nil>",
    "stat:../secret.txt   err=statat ../secret.txt: path escapes from parent",
    "stat:/etc/passwd     err=statat /etc/passwd: path escapes from parent",
    "stat:escape          err=statat escape: path escapes from parent",
    "lstat:escape         is_symlink=true err=<nil>",
    "mkdir:new            err=<nil>",
    "mkdir:again          err=mkdirat new: file exists",
    "mkdir:../secret.txt  err=mkdirat ../secret.txt: path escapes from parent",
    "mkdir:/etc/passwd    err=mkdirat /etc/passwd: path escapes from parent",
    "mkdir:escape         err=mkdirat escape: file exists",
    "remove:new           err=<nil>",
    "remove:missing       err=removeat gone: no such file or directory",
    "remove:../secret.txt err=removeat ../secret.txt: path escapes from parent",
    "remove:/etc/passwd   err=removeat /etc/passwd: path escapes from parent",
    "remove:escape        err=<nil>",
    "secret_survived      true",
    "openinroot:ok.txt    err=<nil>",
    "openinroot:escape    err=openat ../secret.txt: path escapes from parent",
    "create:made.txt      err=<nil>",
    "rootinroot:sub       err=<nil>",
    "rootinroot:..        err=openat ..: path escapes from parent",
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
    let base = os::TempDir() + "/goish_os_root2";
    let _ = os::RemoveAll(&base);
    let inside = base.clone() + "/inside";
    let _ = os::MkdirAll(&(inside.clone() + "/sub"), os::FileMode(0o755));
    let _ = os::WriteFile(&(inside.clone() + "/ok.txt"), b"hello".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(base.clone() + "/secret.txt"), b"secret".as_ref(), os::FileMode(0o644));
    let _ = os::Symlink(base.clone() + "/secret.txt", inside.clone() + "/escape");

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

    let (r, rerr) = os::OpenRoot(inside.clone());
    if !rerr.IsNil() {
        fmt::Printf!("[!!] OpenRoot: %v\n", rerr);
        goish::os::Exit(1);
    }
    let r = r.MustTake();
    let escapes: [&str; 3] = ["../secret.txt", "/etc/passwd", "escape"];

    let (fi, err) = r.Stat(string::from_static("ok.txt"));
    let (nm, sz) = if err.IsNil() {
        (fi.Name(), fi.Size())
    } else {
        (string::new(), int::from(-1))
    };
    chk(&mut ln, &fmt::Sprintf!("%-20s name=%q size=%d err=%s",
        string::from_static("stat:ok.txt"), nm, sz, scrub(err)));
    for n in escapes.iter() {
        let (_, err) = r.Stat(string::from(*n));
        chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
            string::from_static("stat:") + string::from(*n), scrub(err)));
    }

    let (li, err) = r.Lstat(string::from_static("escape"));
    let is_link = err.IsNil() && (li.Mode() & os::ModeSymlink) != os::FileMode(0);
    chk(&mut ln, &fmt::Sprintf!("%-20s is_symlink=%v err=%s",
        string::from_static("lstat:escape"), is_link, scrub(err)));

    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s", string::from_static("mkdir:new"),
        scrub(r.Mkdir(string::from_static("new"), os::FileMode(0o755)))));
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s", string::from_static("mkdir:again"),
        scrub(r.Mkdir(string::from_static("new"), os::FileMode(0o755)))));
    for n in escapes.iter() {
        chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
            string::from_static("mkdir:") + string::from(*n),
            scrub(r.Mkdir(string::from(*n), os::FileMode(0o755)))));
    }

    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s", string::from_static("remove:new"),
        scrub(r.Remove(string::from_static("new")))));
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s", string::from_static("remove:missing"),
        scrub(r.Remove(string::from_static("gone")))));
    for n in escapes.iter() {
        chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
            string::from_static("remove:") + string::from(*n),
            scrub(r.Remove(string::from(*n)))));
    }
    let (_, serr) = os::Stat(base.clone() + "/secret.txt");
    chk(&mut ln, &fmt::Sprintf!("%-20s %v", string::from_static("secret_survived"), serr.IsNil()));

    let (f, err) = os::OpenInRoot(inside.clone(), string::from_static("ok.txt"));
    if !f.IsNil() {
        let mut f = f.MustTake();
        let _ = f.Close();
    }
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
        string::from_static("openinroot:ok.txt"), scrub(err)));
    let (_, err) = os::OpenInRoot(inside.clone(), string::from_static("../secret.txt"));
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
        string::from_static("openinroot:escape"), scrub(err)));

    let (cf, err) = r.Create(string::from_static("made.txt"));
    if !cf.IsNil() {
        let mut cf = cf.MustTake();
        let _ = cf.Close();
    }
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
        string::from_static("create:made.txt"), scrub(err)));

    let (sub, err) = r.OpenRoot(string::from_static("sub"));
    if !sub.IsNil() {
        let _ = sub.MustTake().Close();
    }
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
        string::from_static("rootinroot:sub"), scrub(err)));
    let (_, err) = r.OpenRoot(string::from_static(".."));
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%s",
        string::from_static("rootinroot:.."), scrub(err)));

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
