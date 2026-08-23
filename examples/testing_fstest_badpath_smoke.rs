// testing_fstest_badpath_smoke — fstest's checkBadPath, checkOpen and
// checkFileRead.
//
// checkBadPath is the check that catches an FS doing its own path
// cleaning. Every spelling it tries denotes the same file on a Unix
// filesystem — "/a/b", "a//b", "a/./b", "a\b", "a/../a/b" — and
// io/fs requires all of them to be REJECTED: only the canonical
// unrooted slash-separated form is a valid fs.FS path. An
// implementation that helpfully normalised "a//b" to "a/b" would pass
// every functional test and fail here, which is exactly what this is
// for.
//
// So the assertions run both ways: a conforming FS (MapFS) must produce
// zero complaints, and a deliberately lenient one must produce them.
// Only checking the first direction would pass a checkBadPath that
// never reported anything at all.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{fsTester, MapFS, MapFile};
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    let mut a = MapFile::default();
    a.Data = slice::__from_vec(b"hello".to_vec());
    m.Set(s("sub/a.txt"), Arc::new(a));
    return MapFS(m);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A conforming FS rejects every malformed spelling, so
    //    checkBadPath records nothing.
    {
        let fsys = newfs();
        let mut t = fsTester::default();
        t.checkOpen(&fsys, s("sub/a.txt"));
        if t.Errors().Len() == 0 {
            fmt::Println!("[ 1] conforming FS is silent   PASS");
        } else {
            fmt::Println!(
                "[ 1] conforming FS is silent   FAIL ",
                t.Errors()[0].Error()
            );
            failed += 1;
        }
    }

    // 2. A lenient opener — one that accepts anything — must be caught.
    //    This is the direction that proves checkBadPath actually
    //    reports; without it, a no-op implementation passes check 1.
    {
        let mut t = fsTester::default();
        t.checkBadPath(s("sub/a.txt"), "Open", |_name| {
            // Accepts every spelling, including the malformed ones.
            return errors::nil;
        });
        // Go builds 2 unconditional forms + 4 for the first '/' + 4 for
        // the last '/'. "sub/a.txt" has exactly one slash, so both
        // branches fire on the same index: 10 spellings, all accepted,
        // all reported.
        if t.Errors().Len() == 10 {
            fmt::Println!("[ 2] lenient FS is caught      PASS");
        } else {
            fmt::Println!(
                "[ 2] lenient FS is caught      FAIL got ",
                t.Errors().Len() as i64
            );
            failed += 1;
        }
    }

    // 3. A path with no slash gets only the two unconditional forms,
    //    since neither the Index nor the LastIndex branch fires.
    {
        let mut t = fsTester::default();
        t.checkBadPath(s("a.txt"), "Open", |_name| {
            return errors::nil;
        });
        if t.Errors().Len() == 2 {
            fmt::Println!("[ 3] no-slash path: 2 forms    PASS");
        } else {
            fmt::Println!(
                "[ 3] no-slash path: 2 forms    FAIL got ",
                t.Errors().Len() as i64
            );
            failed += 1;
        }
    }

    // 4. "." gets a third unconditional form, "/", which Go appends
    //    only for the root.
    {
        let mut t = fsTester::default();
        t.checkBadPath(s("."), "Open", |_name| {
            return errors::nil;
        });
        if t.Errors().Len() == 3 {
            fmt::Println!("[ 4] root adds the / form      PASS");
        } else {
            fmt::Println!(
                "[ 4] root adds the / form      FAIL got ",
                t.Errors().Len() as i64
            );
            failed += 1;
        }
    }

    // 5. checkFileRead reports only when the two reads differ.
    {
        let mut t = fsTester::default();
        let a = slice::__from_vec(b"hello".to_vec());
        let b = slice::__from_vec(b"hello".to_vec());
        t.checkFileRead(s("f"), "ReadFile vs Open", a, b);
        let same_ok = t.Errors().Len() == 0;

        let c = slice::__from_vec(b"hello".to_vec());
        let d = slice::__from_vec(b"world".to_vec());
        t.checkFileRead(s("f"), "ReadFile vs Open", c, d);
        let diff_ok = t.Errors().Len() == 1;

        if same_ok && diff_ok {
            fmt::Println!("[ 5] checkFileRead compares    PASS");
        } else {
            fmt::Println!("[ 5] checkFileRead compares    FAIL");
            failed += 1;
        }
    }

    // 6. The canonical path itself still opens — checkBadPath must not
    //    be so aggressive that it rejects the real file.
    {
        let fsys = newfs();
        let (f, err) = fs::FS::Open(&fsys, s("sub/a.txt"));
        if err == errors::nil {
            f.Close();
            fmt::Println!("[ 6] canonical path still opens PASS");
        } else {
            fmt::Println!("[ 6] canonical path still opens FAIL");
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
