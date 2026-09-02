// os_copyfs_ref_smoke — os.CopyFS against a running Go.
// (os/dir.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_copyfs_ref.go` run in `package os_test`
// by `scripts/goref.sh`.
//
// CopyFS did not exist in goish. Its edges are what make it worth
// having a smoke for rather than eyeballing:
//
//   * It REFUSES to overwrite. Files are opened O_CREATE|O_EXCL, so a
//     second copy into the same destination fails with ErrExist rather
//     than clobbering what is there. A port that dropped O_EXCL would
//     look identical on the first run and destroy data on the second.
//   * The mode written is `0666 | (source perm & 0777)`, NOT the source
//     mode — so a 0600 source lands world-readable and only the EXECUTE
//     bits actually carry across. That is Go's documented behaviour and
//     surprises people, which is exactly why it is pinned.
//   * The destination directory is created even when the source tree is
//     empty.
//
// The exact resulting mode depends on the process UMASK, so this smoke
// computes the expectation the way Go's own code does — the formula,
// masked by the umask it reads at runtime — rather than pinning the
// 0664/0775 the reference happened to produce under umask 002.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::io::fs;
use goish::os;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn bytes(x: &str) -> goish::goslice::slice<goish::types::byte> {
    return goish::goslice::slice::__from_vec(x.as_bytes().to_vec());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // The umask, read the only way there is: set it, then put it back.
    let um = syscall::Umask(0o022);
    syscall::Umask(um);

    let (src, _) = os::MkdirTemp("", "copyfs-src");
    let (top, _) = os::MkdirTemp("", "copyfs-dst");
    let dst = top.clone() + s("/out");

    let _ = os::MkdirAll(src.clone() + s("/sub/deep"), os::FileMode(0o755));
    let _ = os::WriteFile(
        src.clone() + s("/a.txt"),
        bytes("alpha"),
        os::FileMode(0o644),
    );
    let _ = os::WriteFile(
        src.clone() + s("/sub/b.txt"),
        bytes("beta"),
        os::FileMode(0o600),
    );
    let _ = os::WriteFile(
        src.clone() + s("/sub/deep/c.txt"),
        bytes("gamma"),
        os::FileMode(0o755),
    );

    // Go: copy err=<nil>
    let e = os::CopyFS(dst.clone(), os::DirFS(src.clone()).as_ref());
    if !e.IsNil() {
        fmt::Printf!("[!!] CopyFS FAIL %q\n", e.Error());
        failed += 1;
    }

    // Go: the tree lands with the same shape and the same contents.
    {
        let cases: [(&str, &str, u32); 3] = [
            ("/a.txt", "alpha", 0o644),
            ("/sub/b.txt", "beta", 0o600),
            ("/sub/deep/c.txt", "gamma", 0o755),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (rel, want, srcperm) = cases[i];
            let p = dst.clone() + s(rel);
            let (body, rerr) = os::ReadFile(p.clone());
            if !rerr.IsNil() {
                fmt::Printf!("[!!] missing %q\n", s(rel));
                failed += 1;
            } else if string::from_bytes(&body.clone().__into_vec()) != s(want) {
                fmt::Printf!("[!!] wrong contents at %q\n", s(rel));
                failed += 1;
            }
            // Go: 0666 | (src & 0777), then the kernel applies umask.
            let (fi, _) = os::Stat(p);
            let want_mode = (0o666u32 | (srcperm & 0o777)) & !(um as u32);
            let got_mode = fi.Mode().0 & 0o777;
            if got_mode != want_mode {
                fmt::Printf!(
                    "[!!] %s mode got %d want %d (umask %d)\n",
                    s(rel),
                    got_mode as i64,
                    want_mode as i64,
                    um
                );
                failed += 1;
            }
            i += 1;
        }
    }

    // Directories are recreated.
    {
        let (fi, err) = os::Stat(dst.clone() + s("/sub/deep"));
        if !err.IsNil() || !fi.IsDir() {
            fmt::Println!("[!!] sub/deep is not a directory");
            failed += 1;
        }
    }

    // Go: recopy err=true exist=true — O_EXCL refuses to clobber.
    {
        let e2 = os::CopyFS(dst.clone(), os::DirFS(src.clone()).as_ref());
        if e2.IsNil() {
            fmt::Println!("[!!] a second CopyFS should have failed");
            failed += 1;
        } else if !goish::errors::Is(e2.clone(), fs::ErrExist) {
            fmt::Printf!("[!!] recopy error is not ErrExist: %q\n", e2.Error());
            failed += 1;
        }
        // …and the original contents are untouched.
        let (body, _) = os::ReadFile(dst.clone() + s("/a.txt"));
        if string::from_bytes(&body.clone().__into_vec()) != s("alpha") {
            fmt::Println!("[!!] a failed recopy modified the destination");
            failed += 1;
        }
    }

    // Go: empty err=<nil> isdir=true — an empty source still creates
    // the destination directory.
    {
        let (empty, _) = os::MkdirTemp("", "copyfs-empty");
        let (top2, _) = os::MkdirTemp("", "copyfs-eout");
        let dst2 = top2.clone() + s("/empty-out");
        let e3 = os::CopyFS(dst2.clone(), os::DirFS(empty.clone()).as_ref());
        if !e3.IsNil() {
            fmt::Printf!("[!!] empty CopyFS FAIL %q\n", e3.Error());
            failed += 1;
        }
        let (fi, serr) = os::Stat(dst2);
        if !serr.IsNil() || !fi.IsDir() {
            fmt::Println!("[!!] empty CopyFS did not create the directory");
            failed += 1;
        }
        let _ = os::RemoveAll(empty);
        let _ = os::RemoveAll(top2);
    }

    let _ = os::RemoveAll(src);
    let _ = os::RemoveAll(top);

    if failed == 0 {
        fmt::Println!("ok - os.CopyFS matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
