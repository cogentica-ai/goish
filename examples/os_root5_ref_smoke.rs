// os_root5_ref_smoke — Root.MkdirAll, RemoveAll and Chtimes.
//
// RemoveAll inside a Root is where the os::RemoveAll defect would hurt
// most, so the rows are built to catch it: `tree/dirlink` points at a
// directory OUTSIDE the root and sits in the tree being removed. If
// the implementation follows it, `victim_intact` fails and the root's
// whole promise goes with it. os::RemoveAll DID follow it, deleting
// the target's contents, which is why this smoke exists in this shape.
//
// `no_evil_dir` is MkdirAll's version of the same idea: a refused
// MkdirAll must leave nothing behind, so `../evil/x` must not create
// `evil` on the way to discovering it escapes.
//
// `removeall:escape` reports Op `RemoveAll`, not `removeat` — Go names
// the operation the caller asked for rather than the syscall it
// reached.
//
// GO[] is the verbatim output of tools/gen_os_root5_ref.go under
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
use goish::{fmt, strings, time};

const GO: [&str; 14] = [
    "mkdirall:a/b/c    err=<nil>",
    "mkdirall:again    err=<nil>",
    "mkdirall:escape   err=mkdirat ../evil/x: path escapes from parent",
    "mkdirall:abs      err=mkdirat /tmp/evil/x: path escapes from parent",
    "no_evil_dir       true",
    "removeall:tree    err=<nil>",
    "tree_gone         true",
    "victim_intact     data=\"precious\" err=<nil>",
    "removeall:missing err=<nil>",
    "removeall:escape  err=RemoveAll ../victim: path escapes from parent",
    "victim_dir_alive  true",
    "chtimes:ok        err=<nil>",
    "chtimes:mtime     1700000123",
    "chtimes:escape    err=chtimesat ../victim: path escapes from parent",
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
    let base = os::TempDir() + "/goish_os_root5";
    let _ = os::RemoveAll(&base);
    let inside = base.clone() + "/inside";
    let victim = base.clone() + "/victim";
    let _ = os::MkdirAll(&inside, os::FileMode(0o755));
    let _ = os::MkdirAll(&victim, os::FileMode(0o755));
    let _ = os::WriteFile(&(victim.clone() + "/precious.txt"), b"precious".as_ref(), os::FileMode(0o644));
    let _ = os::WriteFile(&(inside.clone() + "/f.txt"), b"F".as_ref(), os::FileMode(0o644));

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
        chk(ln, &fmt::Sprintf!("%-17s err=%s", string::from(name), scrub(e)));
    };

    let (r, rerr) = os::OpenRoot(inside.clone());
    if !rerr.IsNil() {
        fmt::Printf!("[!!] OpenRoot: %v\n", rerr);
        goish::os::Exit(1);
    }
    let r = r.MustTake();

    row(&mut ln, "mkdirall:a/b/c", r.MkdirAll(string::from_static("a/b/c"), os::FileMode(0o755)));
    row(&mut ln, "mkdirall:again", r.MkdirAll(string::from_static("a/b/c"), os::FileMode(0o755)));
    row(&mut ln, "mkdirall:escape", r.MkdirAll(string::from_static("../evil/x"), os::FileMode(0o755)));
    row(&mut ln, "mkdirall:abs", r.MkdirAll(string::from_static("/tmp/evil/x"), os::FileMode(0o755)));
    let (_, e) = os::Stat(base.clone() + "/evil");
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("no_evil_dir"), os::IsNotExist(e)));

    let _ = os::MkdirAll(&(inside.clone() + "/tree/sub"), os::FileMode(0o755));
    let _ = os::WriteFile(&(inside.clone() + "/tree/x.txt"), b"X".as_ref(), os::FileMode(0o644));
    let _ = os::Symlink(victim.clone(), inside.clone() + "/tree/dirlink");
    let _ = os::Symlink(string::from_static("nowhere"), inside.clone() + "/tree/dangling");
    row(&mut ln, "removeall:tree", r.RemoveAll(string::from_static("tree")));
    let (_, e) = r.Stat(string::from_static("tree"));
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("tree_gone"), os::IsNotExist(e)));
    let (b, rderr) = os::ReadFile(victim.clone() + "/precious.txt");
    chk(&mut ln, &fmt::Sprintf!("%-17s data=%q err=%v", string::from_static("victim_intact"),
        string::from_bytes(b.as_ref()), rderr));

    row(&mut ln, "removeall:missing", r.RemoveAll(string::from_static("gone")));
    row(&mut ln, "removeall:escape", r.RemoveAll(string::from_static("../victim")));
    let (_, e) = os::Stat(victim.clone());
    chk(&mut ln, &fmt::Sprintf!("%-17s %v", string::from_static("victim_dir_alive"), e.IsNil()));

    let at = time::Unix(1700000000, 0);
    let mt = time::Unix(1700000123, 0);
    row(&mut ln, "chtimes:ok", r.Chtimes(string::from_static("f.txt"), at, mt));
    let (fi, _) = r.Stat(string::from_static("f.txt"));
    chk(&mut ln, &fmt::Sprintf!("%-17s %d", string::from_static("chtimes:mtime"), fi.ModTime().Unix()));
    row(&mut ln, "chtimes:escape", r.Chtimes(string::from_static("../victim"), at, mt));

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
