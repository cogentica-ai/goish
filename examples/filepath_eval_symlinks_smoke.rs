// filepath_eval_symlinks_smoke — exercise filepath.EvalSymlinks
// (path.go:147 + symlink.go:16 walkSymlinks) and the os.Lstat
// dependency it relies on (file.go:417 → stat_unix.go).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::os;
use goish::path::filepath;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    let dir = string("/tmp/goish-evalsymlinks-smoke");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::Mkdir(dir.clone(), 0o755);

    let target = string("/tmp/goish-evalsymlinks-smoke/target.txt");
    let link = string("/tmp/goish-evalsymlinks-smoke/link.txt");
    let _ = os::WriteFile(target.clone(), bytes("hi"), 0o644);

    // 1. Lstat on a symlink reports ModeSymlink.
    {
        let _ = os::Symlink(target.clone(), link.clone());
        let (fi, err) = os::Lstat(link.clone());
        if err.IsNil() && (fi.Mode() & os::ModeSymlink) != 0 {
            Println!("[ 1] Lstat sees ModeSymlink     PASS");
        } else {
            Println!("[ 1] Lstat sees ModeSymlink     FAIL");
            failed += 1;
        }
    }

    // 2. Stat (follows) does NOT report ModeSymlink (regular file).
    {
        let (fi, err) = os::Stat(link.clone());
        if err.IsNil() && (fi.Mode() & os::ModeSymlink) == 0 {
            Println!("[ 2] Stat follows symlink      PASS");
        } else {
            Println!("[ 2] Stat follows symlink      FAIL");
            failed += 1;
        }
    }

    // 3. EvalSymlinks resolves a single absolute symlink.
    {
        let (got, err) = filepath::EvalSymlinks(link.clone());
        if err.IsNil() && got == target {
            Println!("[ 3] EvalSymlinks abs link     PASS");
        } else {
            Println!("[ 3] EvalSymlinks abs link     FAIL got=", got);
            failed += 1;
        }
    }

    // 4. EvalSymlinks on a non-link returns Clean(input).
    {
        let (got, err) = filepath::EvalSymlinks(target.clone());
        if err.IsNil() && got == target {
            Println!("[ 4] EvalSymlinks no link      PASS");
        } else {
            Println!("[ 4] EvalSymlinks no link      FAIL got=", got);
            failed += 1;
        }
    }

    // 5. EvalSymlinks resolves a relative symlink.
    {
        let rel_link = string("/tmp/goish-evalsymlinks-smoke/rel-link.txt");
        let _ = os::Symlink(string("target.txt"), rel_link.clone());
        let (got, err) = filepath::EvalSymlinks(rel_link);
        if err.IsNil() && got == target {
            Println!("[ 5] EvalSymlinks rel link     PASS");
        } else {
            Println!("[ 5] EvalSymlinks rel link     FAIL got=", got);
            failed += 1;
        }
    }

    // 6. EvalSymlinks resolves a chain (link → link → file).
    {
        let chain1 = string("/tmp/goish-evalsymlinks-smoke/chain1.txt");
        let chain2 = string("/tmp/goish-evalsymlinks-smoke/chain2.txt");
        let _ = os::Symlink(target.clone(), chain1.clone());
        let _ = os::Symlink(chain1.clone(), chain2.clone());
        let (got, err) = filepath::EvalSymlinks(chain2);
        if err.IsNil() && got == target {
            Println!("[ 6] EvalSymlinks chain        PASS");
        } else {
            Println!("[ 6] EvalSymlinks chain        FAIL got=", got);
            failed += 1;
        }
    }

    // 7. EvalSymlinks with "." element collapses correctly.
    {
        let p = string("/tmp/goish-evalsymlinks-smoke/./target.txt");
        let (got, err) = filepath::EvalSymlinks(p);
        if err.IsNil() && got == target {
            Println!("[ 7] EvalSymlinks dot          PASS");
        } else {
            Println!("[ 7] EvalSymlinks dot          FAIL got=", got);
            failed += 1;
        }
    }

    // 8. EvalSymlinks with ".." backs up one level.
    {
        let p = string("/tmp/goish-evalsymlinks-smoke/sub/../target.txt");
        // Need /sub to exist for the walk to traverse it.
        let _ = os::Mkdir(string("/tmp/goish-evalsymlinks-smoke/sub"), 0o755);
        let (got, err) = filepath::EvalSymlinks(p);
        if err.IsNil() && got == target {
            Println!("[ 8] EvalSymlinks dotdot       PASS");
        } else {
            Println!("[ 8] EvalSymlinks dotdot       FAIL got=", got);
            failed += 1;
        }
    }

    // 9. EvalSymlinks on missing path → error.
    {
        let (_, err) = filepath::EvalSymlinks(string(
            "/tmp/goish-evalsymlinks-smoke/missing.txt",
        ));
        if !err.IsNil() {
            Println!("[ 9] EvalSymlinks missing      PASS");
        } else {
            Println!("[ 9] EvalSymlinks missing      FAIL");
            failed += 1;
        }
    }

    // 10. EvalSymlinks on a cycle → "too many links".
    {
        let a = string("/tmp/goish-evalsymlinks-smoke/cycA");
        let b = string("/tmp/goish-evalsymlinks-smoke/cycB");
        let _ = os::Symlink(string("cycB"), a.clone());
        let _ = os::Symlink(string("cycA"), b.clone());
        let (_, err) = filepath::EvalSymlinks(a);
        if !err.IsNil() {
            Println!("[10] EvalSymlinks cycle        PASS");
        } else {
            Println!("[10] EvalSymlinks cycle        FAIL");
            failed += 1;
        }
    }

    let _ = os::RemoveAll(dir);

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
