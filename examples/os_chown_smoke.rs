// os_chown_smoke — exercise os.Chown + os.Lchown (file_posix.go:105
// + 121). Real-uid changes need root; we exercise the no-op path
// (uid = -1, gid = -1) and the missing-path error path.

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

    let dir = string("/tmp/goish-chown-smoke");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::Mkdir(dir.clone(), 0o755);
    let target = string("/tmp/goish-chown-smoke/target.txt");
    let _ = os::WriteFile(target.clone(), bytes("hello"), 0o644);

    // 1. Chown with uid=-1, gid=-1 → no-op, succeeds for any user.
    {
        let err = os::Chown(target.clone(), -1, -1);
        if err.IsNil() {
            Println!("[ 1] Chown -1,-1 no-op         PASS");
        } else {
            Println!("[ 1] Chown -1,-1 no-op         FAIL");
            failed += 1;
        }
    }

    // 2. Lchown with -1,-1 — same no-op.
    {
        let err = os::Lchown(target.clone(), -1, -1);
        if err.IsNil() {
            Println!("[ 2] Lchown -1,-1 no-op        PASS");
        } else {
            Println!("[ 2] Lchown -1,-1 no-op        FAIL");
            failed += 1;
        }
    }

    // 3. Chown on missing path → error.
    {
        let err = os::Chown(string("/tmp/goish-chown-nonexistent-xyz"), -1, -1);
        if !err.IsNil() {
            Println!("[ 3] Chown missing → err       PASS");
        } else {
            Println!("[ 3] Chown missing → err       FAIL");
            failed += 1;
        }
    }

    // 4. Lchown on missing path → error.
    {
        let err = os::Lchown(string("/tmp/goish-chown-nonexistent-xyz"), -1, -1);
        if !err.IsNil() {
            Println!("[ 4] Lchown missing → err      PASS");
        } else {
            Println!("[ 4] Lchown missing → err      FAIL");
            failed += 1;
        }
    }

    // 5. Lchown via symlink doesn't follow.
    {
        let link = string("/tmp/goish-chown-smoke/link");
        let _ = os::Symlink(target.clone(), link.clone());
        // Lchown on a symlink with -1,-1 should succeed (no-op).
        let err = os::Lchown(link, -1, -1);
        if err.IsNil() {
            Println!("[ 5] Lchown symlink no-op      PASS");
        } else {
            Println!("[ 5] Lchown symlink no-op      FAIL");
            failed += 1;
        }
    }

    let _ = os::RemoveAll(dir);

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
