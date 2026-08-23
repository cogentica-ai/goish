// filepath_glob_smoke — exercise filepath.Glob (match.go:243),
// including hierarchical patterns, no-meta pass-through, and bad
// patterns.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::fmt;
use goish::os;
use goish::path::filepath;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let dir = string("/tmp/goish-glob-smoke");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::Mkdir(dir.clone(), 0o755);
    let _ = os::Mkdir(string("/tmp/goish-glob-smoke/sub"), 0o755);
    let _ = os::WriteFile(string("/tmp/goish-glob-smoke/a.txt"), bytes("a"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-glob-smoke/b.txt"), bytes("b"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-glob-smoke/c.dat"), bytes("c"), 0o644);
    let _ = os::WriteFile(string("/tmp/goish-glob-smoke/sub/d.txt"), bytes("d"), 0o644);

    // 1. Glob without meta returns input if it exists.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/a.txt"));
        if err.IsNil() && m.Len() == 1 && m[0i64] == "/tmp/goish-glob-smoke/a.txt" {
            fmt::Println!("[ 1] Glob no-meta exists       PASS");
        } else {
            fmt::Println!("[ 1] Glob no-meta exists       FAIL len=", m.Len() as i64);
            failed += 1;
        }
    }

    // 2. Glob without meta returns empty if missing.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/missing.txt"));
        if err.IsNil() && m.Len() == 0 {
            fmt::Println!("[ 2] Glob no-meta missing      PASS");
        } else {
            fmt::Println!("[ 2] Glob no-meta missing      FAIL");
            failed += 1;
        }
    }

    // 3. Glob "*.txt" returns sorted .txt files.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/*.txt"));
        if err.IsNil()
            && m.Len() == 2
            && m[0i64] == "/tmp/goish-glob-smoke/a.txt"
            && m[1i64] == "/tmp/goish-glob-smoke/b.txt"
        {
            fmt::Println!("[ 3] Glob *.txt sorted         PASS");
        } else {
            fmt::Println!("[ 3] Glob *.txt sorted         FAIL len=", m.Len() as i64);
            failed += 1;
        }
    }

    // 4. Glob "*.dat" finds single file.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/*.dat"));
        if err.IsNil() && m.Len() == 1 && m[0i64] == "/tmp/goish-glob-smoke/c.dat" {
            fmt::Println!("[ 4] Glob *.dat single         PASS");
        } else {
            fmt::Println!("[ 4] Glob *.dat single         FAIL");
            failed += 1;
        }
    }

    // 5. Glob "?.txt" matches single-char names only.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/?.txt"));
        if err.IsNil() && m.Len() == 2 {
            fmt::Println!("[ 5] Glob ?.txt                PASS");
        } else {
            fmt::Println!("[ 5] Glob ?.txt                FAIL len=", m.Len() as i64);
            failed += 1;
        }
    }

    // 6. Glob [ab].txt — character class.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/[ab].txt"));
        if err.IsNil() && m.Len() == 2 {
            fmt::Println!("[ 6] Glob [ab].txt             PASS");
        } else {
            fmt::Println!("[ 6] Glob [ab].txt             FAIL");
            failed += 1;
        }
    }

    // 7. Hierarchical: /tmp/goish-glob-smoke/sub/*.txt
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/sub/*.txt"));
        if err.IsNil() && m.Len() == 1 && m[0i64] == "/tmp/goish-glob-smoke/sub/d.txt" {
            fmt::Println!("[ 7] Glob hierarchical sub     PASS");
        } else {
            fmt::Println!("[ 7] Glob hierarchical sub     FAIL");
            failed += 1;
        }
    }

    // 8. No matches yields empty.
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/*.zzz"));
        if err.IsNil() && m.Len() == 0 {
            fmt::Println!("[ 8] Glob no-matches empty     PASS");
        } else {
            fmt::Println!("[ 8] Glob no-matches empty     FAIL");
            failed += 1;
        }
    }

    // 9. Bad pattern → ErrBadPattern.
    {
        let (_, err) = filepath::Glob(string("/tmp/[a-"));
        if !err.IsNil() {
            fmt::Println!("[ 9] Glob bad pattern → err    PASS");
        } else {
            fmt::Println!("[ 9] Glob bad pattern → err    FAIL");
            failed += 1;
        }
    }

    // 10. Two-level wildcard: /tmp/goish-glob-smoke/*/*.txt
    {
        let (m, err) = filepath::Glob(string("/tmp/goish-glob-smoke/*/*.txt"));
        if err.IsNil() && m.Len() == 1 && m[0i64] == "/tmp/goish-glob-smoke/sub/d.txt" {
            fmt::Println!("[10] Glob two-level wildcard   PASS");
        } else {
            fmt::Println!("[10] Glob two-level wildcard   FAIL len=", m.Len() as i64);
            failed += 1;
        }
    }

    let _ = os::RemoveAll(dir);

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
