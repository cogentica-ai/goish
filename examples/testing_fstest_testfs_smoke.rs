// testing_fstest_testfs_smoke — fstest.TestFS, the whole conformance
// suite driven end to end.
//
// This is the payoff for every check ported before it: TestFS walks the
// tree from the root and runs checkDir / checkStat / checkFile /
// checkGlob / checkOpen / checkBadPath / checkDirList against every
// entry, requiring four independent readings of each directory to
// agree.
//
// Check 1 is therefore a real statement about goish: MapFS, io/fs's
// ReadDir/Stat/ReadFile/Glob/Sub, and path.Match all satisfy the same
// conformance suite Go holds its own filesystems to.
//
// Checks 2 and 3 assert the two directions of the `expected` list,
// because TestFS is meaningless if either is missing: with no expected
// names the filesystem must be EMPTY, and with names given every one
// must be found.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{MapFS, MapFile, TestFS};
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn names(xs: &[&str]) -> slice<string> {
    let mut v: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for x in xs.iter() {
        v.push(s(x));
    }
    return slice::__from_vec(v);
}

fn build(files: &[&str]) -> Arc<dyn fs::FS + Send + Sync> {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    for n in files.iter() {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(b"content".to_vec());
        m.Set(s(n), Arc::new(f));
    }
    return Arc::new(MapFS(m));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A real MapFS passes the full conformance suite, including the
    //    fs.Sub subtree pass that TestFS runs for the first expected
    //    name containing a slash.
    {
        let fsys = build(&["a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt"]);
        let err = TestFS(
            fsys,
            &names(&["a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt"]),
        );
        if err == errors::nil {
            fmt::Println!("[ 1] MapFS passes TestFS       PASS");
        } else {
            fmt::Println!("[ 1] MapFS passes TestFS       FAIL\n", err.Error());
            failed += 1;
        }
    }

    // 2. An expected name that is not present must be reported.
    {
        let fsys = build(&["a.txt"]);
        let err = TestFS(fsys, &names(&["a.txt", "missing.txt"]));
        let msg = if err != errors::nil {
            err.Error()
        } else {
            s("")
        };
        let m: &str = msg.as_ref();
        if err != errors::nil && m.contains("expected but not found: missing.txt") {
            fmt::Println!("[ 2] missing expected caught   PASS");
        } else {
            fmt::Println!("[ 2] missing expected caught   FAIL");
            failed += 1;
        }
    }

    // 3. With NO expected names the filesystem must be empty. This is
    //    the direction that makes `TestFS(fsys)` an assertion rather
    //    than a no-op.
    {
        let fsys = build(&["a.txt"]);
        let err = TestFS(fsys, &names(&[]));
        let msg = if err != errors::nil {
            err.Error()
        } else {
            s("")
        };
        let m: &str = msg.as_ref();
        if err != errors::nil && m.contains("expected empty file system") {
            fmt::Println!("[ 3] non-empty vs no expected  PASS");
        } else {
            fmt::Println!("[ 3] non-empty vs no expected  FAIL");
            failed += 1;
        }
    }

    // 4. A genuinely empty filesystem with no expected names passes.
    {
        let fsys = build(&[]);
        let err = TestFS(fsys, &names(&[]));
        if err == errors::nil {
            fmt::Println!("[ 4] empty FS, no expected     PASS");
        } else {
            fmt::Println!("[ 4] empty FS, no expected     FAIL ", err.Error());
            failed += 1;
        }
    }

    // 5. Extra files are allowed when names ARE given — Go: "fsys must
    //    contain at least the listed files; it can also contain
    //    others."
    {
        let fsys = build(&["a.txt", "b.txt", "sub/c.txt"]);
        let err = TestFS(fsys, &names(&["a.txt", "sub/c.txt"]));
        if err == errors::nil {
            fmt::Println!("[ 5] extra files allowed       PASS");
        } else {
            fmt::Println!("[ 5] extra files allowed       FAIL ", err.Error());
            failed += 1;
        }
    }

    // 6. Deep nesting works — checkDir recurses, and the subtree pass
    //    re-runs the whole suite under fs.Sub.
    {
        let fsys = build(&["x/y/z/deep.txt"]);
        let err = TestFS(fsys, &names(&["x/y/z/deep.txt"]));
        if err == errors::nil {
            fmt::Println!("[ 6] deep nesting + Sub pass   PASS");
        } else {
            fmt::Println!("[ 6] deep nesting + Sub pass   FAIL ", err.Error());
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
