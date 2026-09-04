// os_samefile_ref_smoke — os.SameFile and File.WriteString vs Go.
// (os/types.go, os/file.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_ossame_ref.go` run in `package os_test`
// by `scripts/goref.sh`.
//
// Neither function existed in goish. `WriteString` is about as common
// as os calls get, and `SameFile` could not exist at all, because
// `FileInfoData.Sys()` returned `Arc::new(())` — the raw stat was read,
// used for the size and mode, and then thrown away. A caller asking for
// the underlying data source got an empty tuple and no way to tell that
// was all it would ever get.
//
// SameFile answers about IDENTITY, not about paths or contents:
//
//   * Two names for one inode ARE the same file — the hard-link row.
//   * Two files with identical bytes are NOT — the same-bytes row.
//   * A FileInfo that did not come from this package's Stat is never
//     the same file as anything, INCLUDING ITSELF. Go gets that from a
//     type assertion to *fileStat; goish keeps `sys: None` for an
//     in-memory FileInfo and answers false, which is the same rule.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::os;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eqb(failed: &mut int, got: bool, want: bool, what: &str) {
    if got == want {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %v want %v\n", s(what), got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let (dir, derr) = os::MkdirTemp("", "samefile");
    if !derr.IsNil() {
        fmt::Println!("[!!] MkdirTemp failed");
        syscall::Exit(1);
    }
    let a = dir.clone() + s("/a");
    let b = dir.clone() + s("/b");
    let link = dir.clone() + s("/link");

    let _ = os::WriteFile(
        a.clone(),
        goish::goslice::slice::__from_vec(b"same".to_vec()),
        0o644,
    );
    let _ = os::WriteFile(
        b.clone(),
        goish::goslice::slice::__from_vec(b"same".to_vec()),
        0o644,
    );
    let lerr = os::Link(a.clone(), link.clone());
    if !lerr.IsNil() {
        fmt::Printf!("[!!] Link failed: %q\n", lerr.Error());
        failed += 1;
    }

    let (fa, _) = os::Stat(a.clone());
    let (fa2, _) = os::Stat(a.clone());
    let (fb, _) = os::Stat(b.clone());
    let (fl, _) = os::Stat(link.clone());

    // Go: same-self true, same-restat true — a second Stat of the same
    // path is the same file, which is what makes SameFile useful at all.
    eqb(&mut failed, os::SameFile(&fa, &fa), true, "same-self");
    eqb(&mut failed, os::SameFile(&fa, &fa2), true, "same-restat");
    // Go: same-hardlink true — two NAMES, one inode.
    eqb(&mut failed, os::SameFile(&fa, &fl), true, "same-hardlink");
    // Go: diff-same-bytes false — identical contents, different files.
    eqb(
        &mut failed,
        os::SameFile(&fa, &fb),
        false,
        "diff-same-bytes",
    );

    let (fd, _) = os::Stat(dir.clone());
    let (fd2, _) = os::Stat(dir.clone());
    eqb(&mut failed, os::SameFile(&fd, &fd2), true, "same-dir");
    eqb(&mut failed, os::SameFile(&fd, &fa), false, "dir-vs-file");

    // A FileInfo built in memory has no kernel identity, so it is never
    // the same file as anything — including itself.
    {
        let m = os::FileInfoData::new(
            s("mem"),
            4,
            os::FileMode(0o644),
            goish::time::Time::default(),
            false,
        );
        eqb(
            &mut failed,
            os::SameFile(&m, &m),
            false,
            "in-memory-never-same",
        );
    }

    // Go: writestring 5 0 6 — the BYTE count, so "héllo" is 6 and not
    // 5, and the file ends up 11 bytes for 10 runes.
    {
        let w = dir.clone() + s("/w");
        let (f, cerr) = os::Create(w.clone());
        if !cerr.IsNil() {
            fmt::Println!("[!!] Create failed");
            failed += 1;
        } else {
            let mut f = f;
            let (n1, _) = f.Must().WriteString("hello");
            let (n2, _) = f.Must().WriteString("");
            let (n3, _) = f.Must().WriteString("héllo");
            let _ = f.MustMut().Close();
            if n1 != 5 || n2 != 0 || n3 != 6 {
                fmt::Printf!(
                    "[!!] writestring FAIL got %d %d %d want 5 0 6\n",
                    n1,
                    n2,
                    n3
                );
                failed += 1;
            }
            let (body, _) = os::ReadFile(w.clone());
            if body.Len() != 11 {
                fmt::Printf!("[!!] writestring body len %d want 11\n", body.Len());
                failed += 1;
            }
            let got = string::from_bytes(&body.clone().__into_vec());
            if got != s("hellohéllo") {
                fmt::Printf!("[!!] writestring body %q\n", got);
                failed += 1;
            }
        }
    }

    let _ = os::RemoveAll(dir);

    if failed == 0 {
        fmt::Println!("ok - os.SameFile and WriteString match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
