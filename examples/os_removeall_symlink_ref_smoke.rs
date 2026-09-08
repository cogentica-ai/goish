// os_removeall_symlink_ref_smoke — RemoveAll must not follow a symlink.
//
// Go's removeAll tries Remove FIRST — which unlinks a symlink of any
// kind — and only recurses after LSTAT says the thing is a directory.
// goish used Stat, which FOLLOWS, and that breaks two ways:
//
//   * a symlink to a DIRECTORY stats as IsDir, so ReadDir followed it
//     and the recursion deleted the TARGET's contents, outside the
//     tree being removed. `victim_intact` and `victim_entries` are the
//     rows that catch it. This is the destructive one:
//     `RemoveAll(workdir)` where the workdir holds a link to somewhere
//     real would empty that somewhere.
//   * a DANGLING symlink stats as "does not exist", which goish's
//     RemoveAll treats as success and skips — leaving the link behind
//     and the parent directory non-empty, so the rmdir then fails.
//     `removed` catches it.
//
// The second is how this was found: os_root4_ref_smoke passed 19/19
// and left its temp tree on disk, because the tree contained a symlink
// the cleanup silently declined to remove.
//
// GO[] is the verbatim output of tools/gen_removeall_symlink_ref.go
// under scripts/goref.sh.

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
use goish::fmt;

const GO: [&str; 4] = [
    "removeall       err=<nil>",
    "removed         true",
    "victim_intact   data=\"precious\" err=<nil>",
    "victim_entries  1",
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
    let base = os::TempDir() + "/goish_removeall_symlink";
    let _ = os::RemoveAll(&base);
    let victim = base.clone() + "/victim";
    let work = base.clone() + "/work";
    let _ = os::MkdirAll(&victim, os::FileMode(0o755));
    let _ = os::WriteFile(&(victim.clone() + "/precious.txt"), b"precious".as_ref(), os::FileMode(0o644));
    let _ = os::MkdirAll(&(work.clone() + "/sub"), os::FileMode(0o755));
    let _ = os::WriteFile(&(work.clone() + "/a.txt"), b"A".as_ref(), os::FileMode(0o644));
    let _ = os::Symlink(victim.clone(), work.clone() + "/dirlink");
    let _ = os::WriteFile(&(work.clone() + "/b.txt"), b"B".as_ref(), os::FileMode(0o644));
    let _ = os::Symlink(string::from_static("b.txt"), work.clone() + "/blink");
    let _ = os::Symlink(string::from_static("nowhere.txt"), work.clone() + "/dangling");

    let err = os::RemoveAll(&work);
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from_static("removeall"), err));

    let (_, serr) = os::Stat(work.clone());
    chk(&mut ln, &fmt::Sprintf!("%-15s %v", string::from_static("removed"), os::IsNotExist(serr)));

    let (b, rerr) = os::ReadFile(victim.clone() + "/precious.txt");
    chk(&mut ln, &fmt::Sprintf!("%-15s data=%q err=%v", string::from_static("victim_intact"),
        string::from_bytes(b.as_ref()), rerr));
    let (ents, _) = os::ReadDir(victim.clone());
    chk(&mut ln, &fmt::Sprintf!("%-15s %d", string::from_static("victim_entries"), ents.Len()));

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
