// os_filemode_bits_smoke — setuid, setgid and sticky must survive the
// trip to the kernel.
//
// Go's `FileMode` keeps setuid at 1<<23, setgid at 1<<22 and sticky at
// 1<<20; the kernel wants them at 0o4000, 0o2000 and 0o1000. Go
// converts in `syscallMode` (os/file_posix.go:61). goish masked the
// FileMode with 0o7777 instead, under a comment saying the conversion
// "collapses to perm bits only" — which keeps nine meaningful bits and
// three meaningless ones, and drops all three special bits.
//
// Measured before the fix, with a nil error every time:
//
//     Chmod(f, 0755|ModeSetuid)   -> 0755, setuid LOST
//     Chmod(d, 0777|ModeSticky)   -> 0777, sticky LOST
//     Mkdir(d, 0777|ModeSticky)   -> sticky LOST
//     OpenFile(f, …, 0640|SetGID) -> setgid LOST
//
// The sticky case is the one that matters beyond correctness. On a
// shared directory it is the difference between "only the owner may
// delete their own files" and "anyone may delete anyone's" — the rule
// /tmp relies on. A caller that asks for it, gets a nil error, and does
// not get it has no way to notice.
//
// Four call sites converted a FileMode for a syscall — Chmod,
// File.Chmod, Mkdir and OpenFile — and all four were wrong the same
// way, which is what a shared `syscallMode` would have prevented.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::io::fs;
use goish::os;
use goish::types::int;

const GO: [&str; 7] = [
    "plain      asked=-rw-r--r-- got=-rw-r--r-- perm=0644 setuid=false setgid=false sticky=false err=<nil>",
    "setuid     asked=urwxr-xr-x got=urwxr-xr-x perm=0755 setuid=true setgid=false sticky=false err=<nil>",
    "setgid     asked=grwxr-xr-x got=grwxr-xr-x perm=0755 setuid=false setgid=true sticky=false err=<nil>",
    "sticky     asked=trwxrwxrwx got=trwxrwxrwx perm=0777 setuid=false setgid=false sticky=true err=<nil>",
    "all-three  asked=ugtrwx------ got=ugtrwx------ perm=0700 setuid=true setgid=true sticky=true err=<nil>",
    "mkdir-sticky   perm=0775 sticky=true err=<nil>",
    "openfile-setgid perm=0640 setgid=true err=<nil>",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let base = os::TempDir() + "/goish_filemode_bits";
    let _ = os::RemoveAll(&base);
    let _ = os::MkdirAll(&base, os::FileMode(0o755));

    let cases: [(&str, fs::FileMode); 5] = [
        ("plain", fs::FileMode(0o644)),
        ("setuid", fs::FileMode(0o755) | fs::ModeSetuid),
        ("setgid", fs::FileMode(0o755) | fs::ModeSetgid),
        ("sticky", fs::FileMode(0o777) | fs::ModeSticky),
        ("all-three", fs::FileMode(0o700) | fs::ModeSetuid | fs::ModeSetgid | fs::ModeSticky),
    ];
    for (name, m) in cases.iter() {
        let p = base.clone() + "/" + *name;
        let _ = os::WriteFile(&p, goish::convert::bytes(string::from("x")), os::FileMode(0o600));
        let err = os::Chmod(&p, *m);
        let (fi, _) = os::Stat(&p);
        let got = fi.Mode();
        chk(&mut ln, &fmt::Sprintf!(
            "%-10s asked=%v got=%v perm=%04o setuid=%v setgid=%v sticky=%v err=%v",
            *name, *m, got, got.Perm(),
            (got & fs::ModeSetuid) != fs::FileMode(0),
            (got & fs::ModeSetgid) != fs::FileMode(0),
            (got & fs::ModeSticky) != fs::FileMode(0), err));
    }

    // Mkdir and OpenFile take a mode through the same conversion.
    let d = base.clone() + "/shared";
    let err = os::Mkdir(&d, fs::FileMode(0o777) | fs::ModeSticky);
    let (fi, _) = os::Stat(&d);
    chk(&mut ln, &fmt::Sprintf!("mkdir-sticky   perm=%04o sticky=%v err=%v",
        fi.Mode().Perm(), (fi.Mode() & fs::ModeSticky) != fs::FileMode(0), err));

    let p = base.clone() + "/f";
    let (f, err) = os::OpenFile(&p, os::O_RDWR | os::O_CREATE, fs::FileMode(0o640) | fs::ModeSetgid);
    if !f.IsNil() {
        let mut f = f.MustTake();
        let _ = f.Close();
    }
    let (fi, _) = os::Stat(&p);
    chk(&mut ln, &fmt::Sprintf!("openfile-setgid perm=%04o setgid=%v err=%v",
        fi.Mode().Perm(), (fi.Mode() & fs::ModeSetgid) != fs::FileMode(0), err));

    let _ = os::RemoveAll(&base);
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
