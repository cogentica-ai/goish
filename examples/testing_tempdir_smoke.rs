// testing_tempdir_smoke — common.TempDir.
//
// goish's previous TempDir was hand-rolled and wrong in three ways that
// each show up here:
//
//   * It never removed anything. Every call left a directory under
//     /tmp for the life of the machine. Go ties the directory's
//     lifetime to the test by registering a Cleanup — check 4.
//   * It numbered directories from ONE process-wide counter, so the
//     name told you nothing about which test made it. Go gives each
//     test its own parent directory and numbers WITHIN it — check 3.
//   * It replaced only '/' and NUL. Go drops every character outside a
//     small allowlist, so a test name containing a glob metacharacter
//     cannot produce a directory that misbehaves under MkdirTemp —
//     check 5.
//
// Check 4 is the load-bearing one, and it has to observe the directory
// from OUTSIDE the test: while the test is running the directory must
// exist, and once the test has returned it must be gone. Asserting only
// the first half is what let the leak survive.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::sync::Mutex;
use goish::testing;
use goish::{errors, fmt, os, strings, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

static SEEN: Mutex<alloc::vec::Vec<string>> = Mutex::new(alloc::vec::Vec::new());

fn remember(d: string) {
    SEEN.Lock().push(d);
}

fn nth(i: usize) -> string {
    let g = SEEN.Lock();
    if i < g.len() {
        return g[i].clone();
    }
    return s("<none>");
}

fn exists(p: string) -> bool {
    let (_, err) = os::Stat(p);
    return err == errors::nil;
}

/// Two calls from one test: distinct directories, both under the same
/// parent, and both live while the test runs.
fn two_dirs(t: &mut testing::T) {
    let a = t.TempDir();
    let b = t.TempDir();
    remember(a.clone());
    remember(b.clone());
    if !exists(a.clone()) || !exists(b.clone()) {
        t.Error(s("TempDir did not create the directory"));
    }
}

/// A test whose name is full of characters that would be awkward in a
/// path — separators, glob metacharacters, a NUL-adjacent range.
fn awkward_name(t: &mut testing::T) {
    remember(t.TempDir());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let code = testing::Main(&[("TwoDirs", two_dirs)]);
    let a = nth(0);
    let b = nth(1);
    SEEN.Lock().clear();

    let _ = testing::Main(&[("Awk/ward*na[me]?", awkward_name)]);
    let awk = nth(0);
    SEEN.Lock().clear();

    // 1. The tree ran green.
    {
        if code == 0 {
            fmt::Println!("[ 1] tree runs green           PASS");
        } else {
            fmt::Println!("[ 1] tree runs green           FAIL");
            failed += 1;
        }
    }

    // 2. Two calls in one test return DIFFERENT directories. Returning
    //    the same one would let a test overwrite its own fixtures.
    {
        if a != b && a != s("<none>") && b != s("<none>") {
            fmt::Println!("[ 2] two calls differ          PASS");
        } else {
            fmt::Println!("[ 2] two calls differ          FAIL [", a, "] [", b, "]");
            failed += 1;
        }
    }

    // 3. …and both sit under the SAME per-test parent, numbered within
    //    it. Go's format is %s%c%03d, so the leaves are 001 and 002.
    {
        let pa = goish::path::Dir(a.clone());
        let pb = goish::path::Dir(b.clone());
        let la = goish::path::Base(a.clone());
        let lb = goish::path::Base(b.clone());
        if pa == pb && la == s("001") && lb == s("002") {
            fmt::Println!("[ 3] shared parent, numbered   PASS");
        } else {
            fmt::Println!("[ 3] shared parent, numbered   FAIL [", la, "] [", lb, "]");
            failed += 1;
        }
    }

    // 4. The directories are GONE now that the test has returned. This
    //    is what the old hand-rolled version never did — it created
    //    them and left them on disk forever.
    {
        if !exists(a.clone()) && !exists(b.clone()) {
            fmt::Println!("[ 4] cleanup removed them      PASS");
        } else {
            fmt::Println!("[ 4] cleanup removed them      FAIL (still on disk)");
            failed += 1;
        }
    }

    // 5. A test name full of path separators and glob metacharacters
    //    produces a directory containing none of them. Go drops
    //    everything outside its allowlist rather than substituting, so
    //    no '/', '*', '[' or '?' survives into the path.
    {
        let parent = goish::path::Base(goish::path::Dir(awk.clone()));
        let bad = strings::ContainsAny(parent.clone(), "/*[]?");
        if awk != s("<none>") && !bad && parent.Len() > 0 {
            fmt::Println!("[ 5] name is sanitised         PASS");
        } else {
            fmt::Println!("[ 5] name is sanitised         FAIL [", parent, "]");
            failed += 1;
        }
    }

    fmt::Println!("    dirs: ", a, " | ", b);

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
