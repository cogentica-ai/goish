// os_root4_ref_smoke — Root's mutating half: Rename, Link, Symlink,
// Chmod, Chown, Lchown.
//
// Rename and Link take TWO names, so each has two ways out of the root
// and both are pinned. An implementation that resolved the first name
// through the walk and took the second at face value would pass every
// single-name row in the tree and still let a caller move a file out.
//
// Symlink is the interesting one: `symlink:abs_target` SUCCEEDS. The
// target is never resolved — it is bytes stored in the link — so
// creating a link to /etc/passwd is allowed, and the very next row
// shows the same Root refusing to FOLLOW what it just allowed to
// exist. The check belongs at resolution, not at creation, because a
// link's meaning depends on who resolves it.
//
// `chmod:symlink_escape` is refused and `secret_mode` proves what that
// buys: the chmod would have followed the link and changed the mode of
// a file outside the root. `lchown:link` succeeds for the mirror
// reason — it acts on the link itself, which is inside.
//
// GO[] is the verbatim output of tools/gen_os_root4_ref.go under
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

const GO: [&str; 19] = [
    "rename:ok            err=<nil>",
    "rename:from_escape   err=renameat ../secret.txt stolen.txt: path escapes from parent",
    "rename:to_escape     err=renameat b.txt ../stolen.txt: path escapes from parent",
    "link:ok              err=<nil>",
    "link:from_escape     err=linkat ../secret.txt stolen2.txt: path escapes from parent",
    "link:to_escape       err=linkat b.txt ../stolen2.txt: path escapes from parent",
    "symlink:ok           err=<nil>",
    "symlink:abs_target   err=<nil>",
    "symlink:name_escape  err=symlinkat b.txt ../evil_sym: path escapes from parent",
    "open:passwd_sym      err=openat passwd_sym: path escapes from parent",
    "chmod:ok             err=<nil>",
    "chmod:perm           0600",
    "chmod:escape         err=chmodat ../secret.txt: path escapes from parent",
    "chmod:symlink_escape err=chmodat escape: path escapes from parent",
    "secret_mode          0600",
    "chown:ok             err=<nil>",
    "chown:escape         err=chownat ../secret.txt: path escapes from parent",
    "lchown:link          err=<nil>",
    "lchown:escape        err=lchownat ../secret.txt: path escapes from parent",
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
    let base = os::TempDir() + "/goish_os_root4";
    let _ = os::RemoveAll(&base);
    let inside = base.clone() + "/inside";
    let _ = os::MkdirAll(&inside, os::FileMode(0o755));
    let _ = os::WriteFile(&(inside.clone() + "/a.txt"), b"A".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(inside.clone() + "/b.txt"), b"B".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(base.clone() + "/secret.txt"), b"secret".as_ref(), os::FileMode(0o600));
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
    let row = |ln: &mut usize, name: &str, e: goish::errors::error| {
        chk(ln, &fmt::Sprintf!("%-20s err=%s", string::from(name), scrub(e)));
    };

    let (r, rerr) = os::OpenRoot(inside.clone());
    if !rerr.IsNil() {
        fmt::Printf!("[!!] OpenRoot: %v\n", rerr);
        goish::os::Exit(1);
    }
    let r = r.MustTake();

    row(&mut ln, "rename:ok", r.Rename(string::from_static("a.txt"), string::from_static("moved.txt")));
    row(&mut ln, "rename:from_escape", r.Rename(string::from_static("../secret.txt"), string::from_static("stolen.txt")));
    row(&mut ln, "rename:to_escape", r.Rename(string::from_static("b.txt"), string::from_static("../stolen.txt")));

    row(&mut ln, "link:ok", r.Link(string::from_static("b.txt"), string::from_static("b_link.txt")));
    row(&mut ln, "link:from_escape", r.Link(string::from_static("../secret.txt"), string::from_static("stolen2.txt")));
    row(&mut ln, "link:to_escape", r.Link(string::from_static("b.txt"), string::from_static("../stolen2.txt")));

    row(&mut ln, "symlink:ok", r.Symlink(string::from_static("b.txt"), string::from_static("b_sym")));
    row(&mut ln, "symlink:abs_target", r.Symlink(string::from_static("/etc/passwd"), string::from_static("passwd_sym")));
    row(&mut ln, "symlink:name_escape", r.Symlink(string::from_static("b.txt"), string::from_static("../evil_sym")));
    let (_, e) = r.Open(string::from_static("passwd_sym"));
    row(&mut ln, "open:passwd_sym", e);

    row(&mut ln, "chmod:ok", r.Chmod(string::from_static("b.txt"), os::FileMode(0o600)));
    let (fi, _) = r.Stat(string::from_static("b.txt"));
    chk(&mut ln, &fmt::Sprintf!("%-20s %04o", string::from_static("chmod:perm"), fi.Mode().Perm()));
    row(&mut ln, "chmod:escape", r.Chmod(string::from_static("../secret.txt"), os::FileMode(0o777)));
    row(&mut ln, "chmod:symlink_escape", r.Chmod(string::from_static("escape"), os::FileMode(0o777)));
    let (ofi, _) = os::Stat(base.clone() + "/secret.txt");
    chk(&mut ln, &fmt::Sprintf!("%-20s %04o", string::from_static("secret_mode"), ofi.Mode().Perm()));

    let (uid, gid) = (os::Getuid(), os::Getgid());
    row(&mut ln, "chown:ok", r.Chown(string::from_static("b.txt"), uid, gid));
    row(&mut ln, "chown:escape", r.Chown(string::from_static("../secret.txt"), uid, gid));
    row(&mut ln, "lchown:link", r.Lchown(string::from_static("escape"), uid, gid));
    row(&mut ln, "lchown:escape", r.Lchown(string::from_static("../secret.txt"), uid, gid));

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
