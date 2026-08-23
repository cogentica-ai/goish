// testing_fstest_glob_smoke — fstest's checkGlob.
//
// The pattern-mangling loop is what makes this check worth having. For
// each rune of the directory name it emits one of five EQUIVALENT
// spellings, cycling by (i+j)%5:
//
//     r        [r]        [r-r]        [\r]        [\r-\r]
//
// All five denote the same single character, so a correct glob engine
// returns identical results for every one. An engine that mishandles
// single-element character classes, degenerate ranges, or escapes
// inside brackets diverges on exactly one spelling — which globbing the
// plain name would never reveal.
//
// Check 2 exercises that directly against goish's path.Match, since
// that is the engine underneath fs.Glob.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs::{self, DirEntry};
use goish::testing::fstest::{fsTester, MapFS, MapFile};
use goish::{errors, fmt, path, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    // Names chosen so some contain 'a' and some do not — checkGlob
    // hunts for exactly such a letter to build a selective pattern.
    for n in ["sub/apple.txt", "sub/box.txt", "sub/cart.txt"].iter() {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(b"x".to_vec());
        m.Set(s(n), Arc::new(f));
    }
    return MapFS(m);
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let fsys = newfs();

    // 1. A conforming filesystem produces no complaints.
    {
        let (list, err) = fs::ReadDir(&fsys, s("sub"));
        if err != errors::nil {
            fmt::Println!("[ 1] conforming glob           FAIL (readdir)");
            failed += 1;
        } else {
            let mut t = fsTester::default();
            let fs2 = newfs();
            t.checkGlob(s("sub"), &list, |pat| {
                return fs2.Glob(pat);
            });
            if t.Errors().Len() == 0 {
                fmt::Println!("[ 1] conforming glob           PASS");
            } else {
                fmt::Println!(
                    "[ 1] conforming glob           FAIL ",
                    t.Errors()[0].Error()
                );
                failed += 1;
            }
        }
    }

    // 2. The five spellings checkGlob generates are genuinely
    //    equivalent under path.Match. This is the property the whole
    //    check rests on, asserted directly rather than inferred.
    {
        let spellings: &[&str] = &["s", "[s]", "[s-s]", "[\\s]", "[\\s-\\s]"];
        let mut ok = true;
        for sp in spellings.iter() {
            let (m1, e1) = path::Match(s(sp), s("s"));
            let (m2, e2) = path::Match(s(sp), s("t"));
            // Must match "s" and must not match "t", for every spelling.
            if e1 != errors::nil || e2 != errors::nil || !m1 || m2 {
                fmt::Println!("    spelling ", *sp, " diverges");
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 2] five spellings equivalent PASS");
        } else {
            fmt::Println!("[ 2] five spellings equivalent FAIL");
            failed += 1;
        }
    }

    // 3. A glob that silently returns nothing is caught. This is the
    //    direction proving checkGlob compares results at all — without
    //    it, a no-op checkGlob passes check 1.
    {
        let (list, _) = fs::ReadDir(&fsys, s("sub"));
        let mut t = fsTester::default();
        t.checkGlob(s("sub"), &list, |_pat| {
            // Never matches anything, and never reports a bad pattern.
            return (slice::new(), errors::nil);
        });
        // Two complaints: the undetected bad pattern, and the wrong
        // output.
        if t.Errors().Len() >= 2 {
            fmt::Println!("[ 3] broken glob caught        PASS");
        } else {
            fmt::Println!(
                "[ 3] broken glob caught        FAIL got ",
                t.Errors().Len() as i64
            );
            failed += 1;
        }
    }

    // 4. A malformed pattern must be reported by the engine — the
    //    first thing checkGlob probes for.
    {
        let (_, err) = fsys.Glob(s("sub/nonexist/[]"));
        if err != errors::nil {
            fmt::Println!("[ 4] bad pattern detected      PASS");
        } else {
            fmt::Println!("[ 4] bad pattern detected      FAIL");
            failed += 1;
        }
    }

    let _: &dyn DirEntry;
    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
