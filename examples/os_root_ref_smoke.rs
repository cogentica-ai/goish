// os_root_ref_smoke — os.Root refuses a traversal.
//
// Root is directory-limited filesystem access: every component is
// resolved with openat(2) relative to the root's directory fd and with
// O_NOFOLLOW, so a "..", an absolute path, or a symlink pointing
// outside cannot escape even when an attacker picks the name. goish
// had none of it, and could not have: the tree had no openat at all,
// only SYS_OPEN.
//
// The rows that matter are the refusals — those ARE the security
// contract — and three of them exist to catch implementations that
// look right:
//
//   * `inside_link` and `dir_link/deep.txt` must SUCCEED. Root follows
//     symlinks; it refuses escapes, not indirection. An implementation
//     that simply rejected every symlink would pass every escape row
//     below and still be wrong.
//   * `out_and_back` is `../inside/ok.txt` — it resolves to a file
//     INSIDE the root, and Go still refuses it. Anything that cleans
//     the path lexically and checks the final destination allows it.
//     Go refuses the moment a component escapes.
//
// GO[] is the verbatim output of tools/gen_os_root_ref.go under
// scripts/goref.sh, with the temp directory scrubbed the same way on
// both sides.

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

const GO: [&str; 20] = [
    "name_is_arg              true",
    "open:ok.txt              err=<nil>",
    "open:sub                 err=<nil>",
    "open:../secret.txt       err=openat ../secret.txt: path escapes from parent",
    "open:..                  err=openat ..: path escapes from parent",
    "open:/etc/passwd         err=openat /etc/passwd: path escapes from parent",
    "open:sub/../ok.txt       err=<nil>",
    "open:escape              err=openat escape: path escapes from parent",
    "open:rel_escape          err=openat rel_escape: path escapes from parent",
    "open:nope.txt            err=openat nope.txt: no such file or directory",
    "open:inside_link         err=<nil>",
    "open:dir_link/deep.txt   err=<nil>",
    "open:dangling            err=openat dangling: no such file or directory",
    "open:out_and_back        err=openat out_and_back: path escapes from parent",
    "open:sub/../../secret.txt err=openat sub/../../secret.txt: path escapes from parent",
    "open:./ok.txt            err=<nil>",
    "open:                    err=openat : empty path",
    "root_on_file             err=open ok.txt: not a directory",
    "root_on_missing          err=open nope: no such file or directory",
    "after_close              name_ok=true err=openat ok.txt: file already closed",
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
    let base = os::TempDir() + "/goish_os_root";
    let _ = os::RemoveAll(&base);
    let inside = base.clone() + "/inside";
    let _ = os::MkdirAll(&(inside.clone() + "/sub"), os::FileMode(0o755));
    let _ = os::WriteFile(&(inside.clone() + "/ok.txt"), b"hello".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(inside.clone() + "/sub/deep.txt"), b"deep".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(base.clone() + "/secret.txt"), b"secret".as_ref(), os::FileMode(0o644));
    let _ = os::Symlink(base.clone() + "/secret.txt", inside.clone() + "/escape");
    let _ = os::Symlink(string::from_static("../secret.txt"), inside.clone() + "/rel_escape");
    let _ = os::Symlink(string::from_static("ok.txt"), inside.clone() + "/inside_link");
    let _ = os::Symlink(string::from_static("sub"), inside.clone() + "/dir_link");
    let _ = os::Symlink(string::from_static("nowhere.txt"), inside.clone() + "/dangling");
    let _ = os::Symlink(string::from_static("../inside/ok.txt"), inside.clone() + "/out_and_back");

    // Same scrub the Go generator applies, so the rows compare.
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
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", string::from_static("name_is_arg"), r.Name() == inside));

    let names: [&str; 16] = [
        "ok.txt", "sub", "../secret.txt", "..", "/etc/passwd", "sub/../ok.txt",
        "escape", "rel_escape", "nope.txt", "inside_link", "dir_link/deep.txt",
        "dangling", "out_and_back", "sub/../../secret.txt", "./ok.txt", "",
    ];
    for n in names.iter() {
        let (f, err) = r.Open(string::from(*n));
        if !f.IsNil() {
            let mut f = f.MustTake();
            let _ = f.Close();
        }
        chk(&mut ln, &fmt::Sprintf!("%-24s err=%s",
            string::from_static("open:") + string::from(*n), scrub(err)));
    }

    let (_, e1) = os::OpenRoot(inside.clone() + "/ok.txt");
    chk(&mut ln, &fmt::Sprintf!("%-24s err=%s", string::from_static("root_on_file"), scrub(e1)));
    let (_, e2) = os::OpenRoot(inside.clone() + "/nope");
    chk(&mut ln, &fmt::Sprintf!("%-24s err=%s", string::from_static("root_on_missing"), scrub(e2)));

    let (r2, _) = os::OpenRoot(inside.clone());
    let r2 = r2.MustTake();
    let name_before = r2.Name();
    let _ = r2.Close();
    let (_, e3) = r2.Open(string::from_static("ok.txt"));
    chk(&mut ln, &fmt::Sprintf!("%-24s name_ok=%v err=%s",
        string::from_static("after_close"), r2.Name() == name_before, scrub(e3)));

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
