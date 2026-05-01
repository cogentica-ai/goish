// filepath_walk_smoke — exercise filepath.Walk + filepath.WalkDir +
// SkipDir / SkipAll (path.go:256–433).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes;
use goish::errors;
use goish::os;
use goish::path::filepath;
use goish::{nil, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    let root = string("/tmp/goish-walk-smoke");
    let _ = os::RemoveAll(root.clone());
    let _ = os::Mkdir(root.clone(), 0o755);
    let _ = os::Mkdir(string("/tmp/goish-walk-smoke/sub"), 0o755);
    let _ = os::Mkdir(string("/tmp/goish-walk-smoke/sub/inner"), 0o755);
    let _ = os::Mkdir(string("/tmp/goish-walk-smoke/skipme"), 0o755);
    let _ = os::WriteFile(string("/tmp/goish-walk-smoke/a.txt"), bytes("a"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-walk-smoke/b.txt"), bytes("b"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-walk-smoke/sub/c.txt"), bytes("c"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-walk-smoke/sub/inner/d.txt"), bytes("d"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-walk-smoke/skipme/secret.txt"), bytes("s"), 0o644);

    // 1. WalkDir visits every entry (root + 3 dirs + 4 files + skipme/secret = 9).
    {
        let mut count: i64 = 0;
        let err = filepath::WalkDir(root.clone(), |_p, _d, e| {
            if e.IsNil() {
                count += 1;
            }
            nil
        });
        if err.IsNil() && count == 9 {
            Println!("[ 1] WalkDir all entries       PASS");
        } else {
            Println!("[ 1] WalkDir all entries       FAIL count=", count);
            failed += 1;
        }
    }

    // 2. WalkDir order is lexical, root first.
    {
        let mut paths: Vec<goish::string> = Vec::new();
        let _ = filepath::WalkDir(root.clone(), |p, _d, e| {
            if e.IsNil() {
                paths.push(p);
            }
            nil
        });
        // First entry is root itself.
        if paths.len() >= 2 && paths[0] == root && paths[1] == "/tmp/goish-walk-smoke/a.txt" {
            Println!("[ 2] WalkDir root-first        PASS");
        } else {
            Println!("[ 2] WalkDir root-first        FAIL");
            failed += 1;
        }
    }

    // 3. SkipDir on a directory skips its contents.
    {
        let mut visited_secret = false;
        let _ = filepath::WalkDir(root.clone(), |p, d, _e| {
            if p == "/tmp/goish-walk-smoke/skipme" {
                return filepath::SkipDir();
            }
            if d.Name() == "secret.txt" {
                visited_secret = true;
            }
            nil
        });
        if !visited_secret {
            Println!("[ 3] WalkDir SkipDir skips     PASS");
        } else {
            Println!("[ 3] WalkDir SkipDir skips     FAIL");
            failed += 1;
        }
    }

    // 4. SkipAll bails entirely.
    {
        let mut count: i64 = 0;
        let err = filepath::WalkDir(root.clone(), |_p, _d, _e| {
            count += 1;
            if count >= 2 {
                return filepath::SkipAll();
            }
            nil
        });
        if err.IsNil() && count == 2 {
            Println!("[ 4] WalkDir SkipAll bails     PASS");
        } else {
            Println!("[ 4] WalkDir SkipAll bails     FAIL count=", count);
            failed += 1;
        }
    }

    // 5. Returning a non-sentinel error stops the walk.
    {
        let stop_err = errors::New(string("stop"));
        let mut count: i64 = 0;
        let err = filepath::WalkDir(root.clone(), |_p, _d, _e| {
            count += 1;
            if count == 3 {
                return stop_err.clone();
            }
            nil
        });
        if !err.IsNil() && count == 3 {
            Println!("[ 5] WalkDir error propagates  PASS");
        } else {
            Println!("[ 5] WalkDir error propagates  FAIL");
            failed += 1;
        }
    }

    // 6. WalkDir on missing root → fn called once with err.
    {
        let mut calls: i64 = 0;
        let _ = filepath::WalkDir(string("/tmp/goish-walk-nonexistent"), |_p, _d, _e| {
            calls += 1;
            nil
        });
        if calls == 1 {
            Println!("[ 6] WalkDir bad root reports  PASS");
        } else {
            Println!("[ 6] WalkDir bad root reports  FAIL calls=", calls);
            failed += 1;
        }
    }

    // 7. Walk (older API) visits same node count as WalkDir.
    {
        let mut count: i64 = 0;
        let err = filepath::Walk(root.clone(), |_p, _info, e| {
            if e.IsNil() {
                count += 1;
            }
            nil
        });
        if err.IsNil() && count == 9 {
            Println!("[ 7] Walk total nodes          PASS");
        } else {
            Println!("[ 7] Walk total nodes          FAIL count=", count);
            failed += 1;
        }
    }

    // 8. Walk with SkipDir on a directory.
    {
        let mut visited_inner = false;
        let _ = filepath::Walk(root.clone(), |_p, info, _e| {
            if info.Name() == "sub" && info.IsDir() {
                return filepath::SkipDir();
            }
            if info.Name() == "d.txt" {
                visited_inner = true;
            }
            nil
        });
        if !visited_inner {
            Println!("[ 8] Walk SkipDir on subdir    PASS");
        } else {
            Println!("[ 8] Walk SkipDir on subdir    FAIL");
            failed += 1;
        }
    }

    let _ = os::RemoveAll(root);

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
