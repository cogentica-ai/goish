// os_mkdir_all_smoke — exercise os::MkdirAll + os::RemoveAll
// (slim line-by-line ports of os/path.go:19 / :73).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::os;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    let root = string("/tmp/goish-mkdirall-smoke");

    // Pre-clean any leftover state from a prior run.
    let _ = os::RemoveAll(root.clone());

    // 1. MkdirAll creates a 3-level deep tree.
    {
        let deep = string("/tmp/goish-mkdirall-smoke/a/b/c");
        let err = os::MkdirAll(deep.clone(), 0o755);
        let (fi, serr) = os::Stat(deep);
        if err.IsNil() && serr.IsNil() && fi.IsDir() {
            Println!("[ 1] MkdirAll deep             PASS");
        } else {
            Println!("[ 1] MkdirAll deep             FAIL");
            failed += 1;
        }
    }

    // 2. MkdirAll on existing dir returns nil (idempotent).
    {
        let err = os::MkdirAll(string("/tmp/goish-mkdirall-smoke/a"), 0o755);
        if err.IsNil() {
            Println!("[ 2] MkdirAll idempotent       PASS");
        } else {
            Println!("[ 2] MkdirAll idempotent       FAIL");
            failed += 1;
        }
    }

    // 3. Files inside the tree.
    {
        let _ = os::WriteFile(
            string("/tmp/goish-mkdirall-smoke/a/file1.txt"),
            bytes("one"),
            0o644,
        );
        let _ = os::WriteFile(
            string("/tmp/goish-mkdirall-smoke/a/b/c/file2.txt"),
            bytes("two"),
            0o644,
        );
        let (data, err) = os::ReadFile(string("/tmp/goish-mkdirall-smoke/a/b/c/file2.txt"));
        if err.IsNil() && data.Len() == 3 {
            Println!("[ 3] write into deep dir       PASS");
        } else {
            Println!("[ 3] write into deep dir       FAIL");
            failed += 1;
        }
    }

    // 4. RemoveAll removes the entire tree, files included.
    {
        let err = os::RemoveAll(root.clone());
        let (_, serr) = os::Stat(root.clone());
        if err.IsNil() && !serr.IsNil() {
            Println!("[ 4] RemoveAll cleans tree     PASS");
        } else {
            Println!("[ 4] RemoveAll cleans tree     FAIL err={}", err.IsNil());
            failed += 1;
        }
    }

    // 5. RemoveAll on a missing path returns nil.
    {
        let err = os::RemoveAll(string("/tmp/goish-mkdirall-smoke-nonexistent-xyz"));
        if err.IsNil() {
            Println!("[ 5] RemoveAll missing → nil   PASS");
        } else {
            Println!("[ 5] RemoveAll missing → nil   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 5", failed);
        syscall::Exit(1);
    }
}
