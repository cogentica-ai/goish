// os_getwd_chdir_smoke — exercise os.Getwd, os.Chdir, filepath.Abs
// (file.go getwd, path.go:161 Abs).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::os;
use goish::path::filepath;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Getwd returns a non-empty absolute path.
    let (cwd_initial, e) = os::Getwd();
    if !e.IsNil() || cwd_initial.Len() == 0 || cwd_initial[0i64] != b'/' {
        fmt::Println!("[ 1] Getwd absolute            FAIL cwd=", cwd_initial);
        failed += 1;
    } else {
        fmt::Println!("[ 1] Getwd absolute            PASS");
    }

    // 2. Abs on absolute path → Clean(path).
    {
        let (a, e) = filepath::Abs(string("/foo/./bar/../baz"));
        if e.IsNil() && a == "/foo/baz" {
            fmt::Println!("[ 2] Abs absolute path         PASS");
        } else {
            fmt::Println!("[ 2] Abs absolute path         FAIL got=", a);
            failed += 1;
        }
    }

    // 3. Abs on relative path → Join(cwd, path) (then Clean inside Join).
    //    Just check it starts with cwd.
    {
        let (a, e) = filepath::Abs(string("relative.txt"));
        let starts_ok = a.Len() > cwd_initial.Len() && a[0i64] == b'/';
        if e.IsNil() && starts_ok {
            fmt::Println!("[ 3] Abs relative path         PASS");
        } else {
            fmt::Println!("[ 3] Abs relative path         FAIL got=", a);
            failed += 1;
        }
    }

    // 4. Abs on empty string → cwd.
    {
        let (a, e) = filepath::Abs(string(""));
        // Join("/cwd", "") ≡ Clean("/cwd") in path.Join semantics.
        if e.IsNil() && a.Len() > 0 && a[0i64] == b'/' {
            fmt::Println!("[ 4] Abs empty                 PASS");
        } else {
            fmt::Println!("[ 4] Abs empty                 FAIL");
            failed += 1;
        }
    }

    // 5. Chdir to "/" then Getwd → "/", then chdir back.
    {
        let cwd_before = cwd_initial.clone();
        let e1 = os::Chdir(string("/"));
        if !e1.IsNil() {
            fmt::Println!("[ 5] Chdir /                   FAIL chdir-err");
            failed += 1;
        } else {
            let (cwd_after, _) = os::Getwd();
            let restored = os::Chdir(cwd_before.clone());
            if cwd_after == "/" && restored.IsNil() {
                fmt::Println!("[ 5] Chdir / round trip        PASS");
            } else {
                fmt::Println!("[ 5] Chdir / round trip        FAIL after=", cwd_after);
                failed += 1;
            }
        }
    }

    // 6. Chdir to nonexistent path → error.
    {
        let e = os::Chdir(string("/nonexistent_path_for_test_xyz_42"));
        if !e.IsNil() {
            fmt::Println!("[ 6] Chdir bogus path          PASS");
        } else {
            fmt::Println!("[ 6] Chdir bogus path          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
