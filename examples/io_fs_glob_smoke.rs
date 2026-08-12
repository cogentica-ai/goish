// io_fs_glob_smoke — pin io/fs.Glob against Go 1.25.5.
//
//   scripts/goref.sh io/fs glob_ref.go   (over an fstest.MapFS)
//     Glob("*.txt")     = ["a.txt" "b.txt"]
//     Glob("*")         = ["a.txt" "b.txt" "c.log" "sub"]
//     Glob("*.log")     = ["c.log"]
//     Glob("sub/*.txt") = ["sub/d.txt"]
//     Glob("*/*.txt")   = ["sub/d.txt"]
//     Glob("*/*/*.txt") = ["sub/deep/f.txt"]
//     Glob("a.txt")     = ["a.txt"]        no metachars: Stat fast path
//     Glob("nope.txt")  = []               missing file is NOT an error
//     Glob("sub")       = ["sub"]          a directory matches
//     Glob("[ab].txt")  = ["a.txt" "b.txt"]
//     Glob("?.txt")     = ["a.txt" "b.txt"]
//     Glob("sub/*")     = ["sub/d.txt" "sub/deep" "sub/e.log"]  lexical
//     Glob("[")         = [], "syntax error in pattern"
//
// Two behaviours that are easy to get backwards, and are pinned below:
// a pattern with no metacharacters naming a file that does not exist
// returns (nil, nil) rather than an error — Glob's documented contract
// is that a bad *pattern* is the only error it ever returns — and
// results come back in lexicographical order, which is why "sub/deep"
// sorts between the two files in the last case.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{MapFile, MapFS};
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    for (name, data) in [
        ("a.txt", "1"),
        ("b.txt", "2"),
        ("c.log", "3"),
        ("sub/d.txt", "4"),
        ("sub/e.log", "5"),
        ("sub/deep/f.txt", "6"),
    ]
    .iter()
    {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(data.as_bytes().to_vec());
        m.Set(s(name), Arc::new(f));
    }
    return MapFS(m);
}

fn joined(m: &slice<string>) -> string {
    let mut out: Vec<u8> = Vec::new();
    for i in 0..m.Len() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(m[i].as_bytes());
    }
    return string::from_bytes(&out);
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let fsys = newfs();

    // 1. Every pattern shape, compared as a space-joined list so
    //    ordering is part of the assertion.
    {
        let cases: &[(&str, &str)] = &[
            ("*.txt", "a.txt b.txt"),
            ("*", "a.txt b.txt c.log sub"),
            ("*.log", "c.log"),
            ("sub/*.txt", "sub/d.txt"),
            ("*/*.txt", "sub/d.txt"),
            ("*/*/*.txt", "sub/deep/f.txt"),
            ("a.txt", "a.txt"),
            ("sub", "sub"),
            ("[ab].txt", "a.txt b.txt"),
            ("?.txt", "a.txt b.txt"),
            // Lexicographic: "deep" sorts between "d.txt" and "e.log".
            ("sub/*", "sub/d.txt sub/deep sub/e.log"),
        ];
        let mut ok = true;
        for (pat, want) in cases.iter() {
            let (m, err) = fs::Glob(&fsys, s(pat));
            let got = joined(&m);
            if err != errors::nil || got != s(want) {
                fmt::Println!("    Glob(", *pat, ") = [", got, "] want [", *want, "]");
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 1] patterns and ordering     PASS");
        } else {
            fmt::Println!("[ 1] patterns and ordering     FAIL");
            failed += 1;
        }
    }

    // 2. A literal pattern naming nothing is (empty, nil) — NOT an
    //    error. Go documents that a malformed pattern is the only
    //    error Glob returns, and this is the case that tempts a port
    //    into surfacing the Stat failure.
    {
        let (m, err) = fs::Glob(&fsys, s("nope.txt"));
        if m.Len() == 0 && err == errors::nil {
            fmt::Println!("[ 2] missing literal is no err PASS");
        } else {
            fmt::Println!("[ 2] missing literal is no err FAIL");
            failed += 1;
        }
    }

    // 3. A malformed pattern IS an error, and it is path.ErrBadPattern.
    {
        let (m, err) = fs::Glob(&fsys, s("["));
        if m.Len() == 0
            && err != errors::nil
            && err.Error() == s("syntax error in pattern")
        {
            fmt::Println!("[ 3] bad pattern errors        PASS");
        } else {
            fmt::Println!("[ 3] bad pattern errors        FAIL");
            failed += 1;
        }
    }

    // 4. A pattern with no match under a real directory returns empty
    //    without error too.
    {
        let (m, err) = fs::Glob(&fsys, s("sub/*.md"));
        if m.Len() == 0 && err == errors::nil {
            fmt::Println!("[ 4] no matches, no error      PASS");
        } else {
            fmt::Println!("[ 4] no matches, no error      FAIL");
            failed += 1;
        }
    }

    // 5. MapFS.Glob delegates to fs::Glob and agrees with it. Go
    //    wraps the receiver in fsOnly to stop fs.Glob recursing back
    //    through the GlobFS check; goish has no such fast path, so this
    //    pins that the delegation terminates and matches.
    {
        let (via_method, e1) = fsys.Glob(s("*.txt"));
        let (via_free, e2) = fs::Glob(&fsys, s("*.txt"));
        if e1 == errors::nil && e2 == errors::nil && joined(&via_method) == joined(&via_free)
        {
            fmt::Println!("[ 5] MapFS.Glob delegates      PASS");
        } else {
            fmt::Println!("[ 5] MapFS.Glob delegates      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
