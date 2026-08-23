// os_rename_link_truncate_smoke — exercise os.Rename, os.Link,
// os.Truncate (file_unix.go:26 / 403 / 344).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::fmt;
use goish::os;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let dir = string("/tmp/goish-rlt-smoke");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::Mkdir(dir.clone(), 0o755);

    let src = string("/tmp/goish-rlt-smoke/src.txt");
    let dst = string("/tmp/goish-rlt-smoke/dst.txt");
    let _ = os::WriteFile(src.clone(), bytes("hello"), 0o644);

    // 1. Rename file → file works; Stat new path; old gone.
    {
        let err = os::Rename(src.clone(), dst.clone());
        let (_, e_dst) = os::Stat(dst.clone());
        let (_, e_src) = os::Stat(src.clone());
        if err.IsNil() && e_dst.IsNil() && !e_src.IsNil() {
            fmt::Println!("[ 1] Rename moves file         PASS");
        } else {
            fmt::Println!("[ 1] Rename moves file         FAIL");
            failed += 1;
        }
    }

    // 2. Rename to directory destination → error (prelude IsDir guard).
    {
        let _ = os::Mkdir(string("/tmp/goish-rlt-smoke/adir"), 0o755);
        let err = os::Rename(dst.clone(), string("/tmp/goish-rlt-smoke/adir"));
        if !err.IsNil() {
            fmt::Println!("[ 2] Rename onto dir → err     PASS");
        } else {
            fmt::Println!("[ 2] Rename onto dir → err     FAIL");
            failed += 1;
        }
    }

    // 3. Rename missing → error.
    {
        let err = os::Rename(
            string("/tmp/goish-rlt-smoke/nonexistent"),
            string("/tmp/goish-rlt-smoke/whatever"),
        );
        if !err.IsNil() {
            fmt::Println!("[ 3] Rename missing → err      PASS");
        } else {
            fmt::Println!("[ 3] Rename missing → err      FAIL");
            failed += 1;
        }
    }

    // 4. Link creates a hard link; both paths point to same content.
    {
        let link = string("/tmp/goish-rlt-smoke/hardlink");
        let err = os::Link(dst.clone(), link.clone());
        let (data, derr) = os::ReadFile(link.clone());
        if err.IsNil() && derr.IsNil() && data.Len() == 5 {
            fmt::Println!("[ 4] Link hardlink             PASS");
        } else {
            fmt::Println!("[ 4] Link hardlink             FAIL");
            failed += 1;
        }
    }

    // 5. Link onto existing path → error.
    {
        let err = os::Link(dst.clone(), string("/tmp/goish-rlt-smoke/hardlink"));
        if !err.IsNil() {
            fmt::Println!("[ 5] Link existing → err       PASS");
        } else {
            fmt::Println!("[ 5] Link existing → err       FAIL");
            failed += 1;
        }
    }

    // 6. Truncate shrinks file.
    {
        let err = os::Truncate(dst.clone(), 3);
        let (fi, ferr) = os::Stat(dst.clone());
        if err.IsNil() && ferr.IsNil() && fi.Size() == 3 {
            fmt::Println!("[ 6] Truncate shrinks          PASS");
        } else {
            fmt::Println!("[ 6] Truncate shrinks          FAIL");
            failed += 1;
        }
    }

    // 7. Truncate grows file (sparse).
    {
        let err = os::Truncate(dst.clone(), 100);
        let (fi, ferr) = os::Stat(dst.clone());
        if err.IsNil() && ferr.IsNil() && fi.Size() == 100 {
            fmt::Println!("[ 7] Truncate grows            PASS");
        } else {
            fmt::Println!("[ 7] Truncate grows            FAIL");
            failed += 1;
        }
    }

    // 8. Truncate missing → error.
    {
        let err = os::Truncate(string("/tmp/goish-rlt-smoke/missing.txt"), 10);
        if !err.IsNil() {
            fmt::Println!("[ 8] Truncate missing → err    PASS");
        } else {
            fmt::Println!("[ 8] Truncate missing → err    FAIL");
            failed += 1;
        }
    }

    let _ = os::RemoveAll(dir);

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
