// os_file_misc_ref_smoke — File.Chdir, File.Chown, Getpagesize and
// Process.Release.
//
// The row that matters is `release:signal`. Go's Release sets Pid to
// -1 — its own comment says it cannot change that, "for historical
// reasons" — and its pidSignal tests the RELEASED state BEFORE the
// done state, answering a different error for it. The order is not
// cosmetic: kill(-1, sig) means "every process this user may signal",
// so a Signal that reached the syscall after Release would be
// catastrophic. `release:pid` pins the -1 and `release:signal` pins
// the refusal that has to sit in front of it.
//
// GO[] is the verbatim output of tools/gen_os_file_misc_ref.go under
// scripts/goref.sh.

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
use goish::os::exec;
use goish::types::int;
use goish::fmt;

const GO: [&str; 10] = [
    "getpagesize     4096",
    "chdir:ok        err=<nil> moved=true",
    "chdir:relative  data=\"F\" err=true",
    "chdir:notdir    err=true",
    "chdir:closed    err=true",
    "chown:ok        err=<nil>",
    "chown:closed    err=true",
    "release:err     <nil>",
    "release:pid     -1",
    "release:signal  err=os: process already released",
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
    chk(&mut ln, &fmt::Sprintf!("%-15s %d", string::from_static("getpagesize"), os::Getpagesize()));

    let base = os::TempDir() + "/goish_file_misc";
    let _ = os::RemoveAll(&base);
    let sub = base.clone() + "/sub";
    let _ = os::MkdirAll(&sub, os::FileMode(0o755));
    let _ = os::WriteFile(&(sub.clone() + "/f.txt"), b"F".as_ref(), os::FileMode(0o644));

    let (before, _) = os::Getwd();
    let (d, oerr) = os::Open(sub.clone());
    if !oerr.IsNil() {
        fmt::Printf!("[!!] open: %v\n", oerr);
        goish::os::Exit(1);
    }
    let mut d = d.MustTake();
    let cerr = d.Chdir();
    let (after, _) = os::Getwd();
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v moved=%v",
        string::from_static("chdir:ok"), cerr, after != before));
    let (b, rerr) = os::ReadFile(string::from_static("f.txt"));
    chk(&mut ln, &fmt::Sprintf!("%-15s data=%q err=%v", string::from_static("chdir:relative"),
        string::from_bytes(b.as_ref()), rerr.IsNil()));
    let _ = os::Chdir(before.clone());
    let _ = d.Close();

    let (f, _) = os::Open(sub.clone() + "/f.txt");
    let mut f = f.MustTake();
    let e = f.Chdir();
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from_static("chdir:notdir"), !e.IsNil()));
    let _ = f.Close();
    let e = f.Chdir();
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from_static("chdir:closed"), !e.IsNil()));

    let (g, _) = os::Open(sub.clone() + "/f.txt");
    let mut g = g.MustTake();
    let oe = g.Chown(os::Getuid(), os::Getgid());
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from_static("chown:ok"), oe));
    let _ = g.Close();
    let oe = g.Chown(os::Getuid(), os::Getgid());
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from_static("chown:closed"), !oe.IsNil()));

    let mut args = goish::make!([]string, 0);
    args = goish::append!(args, string::from_static("-c"));
    args = goish::append!(args, string::from_static("exit 0"));
    let mut cmd = exec::Command(string::from_static("/bin/sh"), args);
    let _ = cmd.Start();
    let mut p = cmd.Process.clone().unwrap();
    let rel = p.Release();
    chk(&mut ln, &fmt::Sprintf!("%-15s %v", string::from_static("release:err"), rel));
    chk(&mut ln, &fmt::Sprintf!("%-15s %d", string::from_static("release:pid"), p.Pid));
    // SIGTERM is 15.
    let serr = p.Signal(int::from(15));
    chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from_static("release:signal"), serr));

    let _ = os::RemoveAll(&base);
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    let fc = FAILED.load(core::sync::atomic::Ordering::Relaxed);
    if fc != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", fc as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
