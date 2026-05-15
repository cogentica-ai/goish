// os_chmod_symlink_smoke — exercise os.Chmod, os.Symlink, os.Readlink
// (file_posix.go:76 chmod, file_unix.go:417 symlink, file_unix.go:427
// readlink).

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

    let dir = string("/tmp/goish-chmod-symlink-smoke");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::Mkdir(dir.clone(), 0o755);

    let target = string("/tmp/goish-chmod-symlink-smoke/target.txt");
    let link = string("/tmp/goish-chmod-symlink-smoke/link.txt");
    let _ = os::WriteFile(target.clone(), bytes("hello"), 0o644);

    // 1. Chmod sets perm bits; Stat reports them back.
    {
        let err = os::Chmod(target.clone(), 0o600);
        let (fi, e) = os::Stat(target.clone());
        if err.IsNil() && e.IsNil() && (fi.Mode() & 0o777) == 0o600 {
            Println!("[ 1] Chmod 0600                PASS");
        } else {
            Println!("[ 1] Chmod 0600                FAIL mode=", fi.Mode().Bits());
            failed += 1;
        }
    }

    // 2. Chmod again to 0o755 round-trips.
    {
        let err = os::Chmod(target.clone(), 0o755);
        let (fi, e) = os::Stat(target.clone());
        if err.IsNil() && e.IsNil() && (fi.Mode() & 0o777) == 0o755 {
            Println!("[ 2] Chmod 0755 round trip     PASS");
        } else {
            Println!("[ 2] Chmod 0755 round trip     FAIL");
            failed += 1;
        }
    }

    // 3. Chmod on missing path → error.
    {
        let err = os::Chmod(string("/tmp/goish-chmod-nonexistent-xyz"), 0o600);
        if !err.IsNil() {
            Println!("[ 3] Chmod missing → err       PASS");
        } else {
            Println!("[ 3] Chmod missing → err       FAIL");
            failed += 1;
        }
    }

    // 4. Symlink + Readlink round trip.
    {
        let err = os::Symlink(target.clone(), link.clone());
        let (got, rerr) = os::Readlink(link.clone());
        if err.IsNil() && rerr.IsNil() && got == target {
            Println!("[ 4] Symlink + Readlink        PASS");
        } else {
            Println!("[ 4] Symlink + Readlink        FAIL got=", got);
            failed += 1;
        }
    }

    // 5. Readlink on regular file → error.
    {
        let (_, err) = os::Readlink(target.clone());
        if !err.IsNil() {
            Println!("[ 5] Readlink regular → err    PASS");
        } else {
            Println!("[ 5] Readlink regular → err    FAIL");
            failed += 1;
        }
    }

    // 6. Symlink with existing dest → error (newname already a symlink).
    {
        let err = os::Symlink(target.clone(), link.clone());
        if !err.IsNil() {
            Println!("[ 6] Symlink dup → err         PASS");
        } else {
            Println!("[ 6] Symlink dup → err         FAIL");
            failed += 1;
        }
    }

    // 7. Readlink missing path → error.
    {
        let (_, err) = os::Readlink(string("/tmp/goish-readlink-nonexistent-xyz"));
        if !err.IsNil() {
            Println!("[ 7] Readlink missing → err    PASS");
        } else {
            Println!("[ 7] Readlink missing → err    FAIL");
            failed += 1;
        }
    }

    // 8. Readlink with relative target preserves it as written.
    {
        let rel_link = string("/tmp/goish-chmod-symlink-smoke/rel-link");
        let _ = os::Symlink(string("../some/relative/path"), rel_link.clone());
        let (got, err) = os::Readlink(rel_link);
        if err.IsNil() && got == "../some/relative/path" {
            Println!("[ 8] Readlink relative target  PASS");
        } else {
            Println!("[ 8] Readlink relative target  FAIL got=", got);
            failed += 1;
        }
    }

    let _ = os::RemoveAll(dir);

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
