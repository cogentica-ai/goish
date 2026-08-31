// testing_fstest_iface_smoke — MapFS's six fs interfaces against a
// running Go. (testing/fstest/mapfs.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fstest_iface_ref.go` run in
// `package fstest_test` by `scripts/goref.sh`.
//
// Go's MapFS satisfies fs.ReadFileFS, fs.StatFS, fs.ReadDirFS,
// fs.GlobFS, fs.ReadLinkFS and fs.SubFS structurally, by having the
// methods. goish needs each impl written out AND the type registered in
// the per-trait downcast registry, or the assertion inside the fs
// helper is a silent miss — the call still works, quietly taking the
// generic Open-based path, and nothing anywhere reports it. Check 1 is
// the assertion itself, because a silent miss is the failure mode.
//
// Each of MapFS's optimized methods is written in terms of the generic
// fs helper for that same interface. That is only safe because of
// `fsOnly` and `noSub`, the two wrappers Go uses to hide the fast path
// from the helper. Drop either and `MapFS::ReadFile` calls
// `fs::ReadFile` calls `MapFS::ReadFile` until the stack runs out — so
// every check below takes BOTH routes to the same answer. That the
// program terminates at all is half the test.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{MapFS, MapFile};
use goish::types::int;
use goish::{error, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

fn newfs() -> Arc<MapFS> {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    for (name, data) in [
        ("a.txt", "alpha"),
        ("b.log", "beta"),
        ("sub/c.txt", "gamma"),
        ("sub/deep/d.txt", "delta"),
    ]
    .iter()
    {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(data.as_bytes().to_vec());
        m.Set(s(name), Arc::new(f));
    }
    return Arc::new(MapFS(m));
}

fn errText(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}

fn names(list: &slice<Arc<dyn fs::DirEntry + Send + Sync>>) -> Vec<string> {
    let mut out: Vec<string> = Vec::new();
    let mut i: int = 0;
    while i < list.Len() {
        out.push(list[i as usize].Name());
        i += 1;
    }
    return out;
}

fn strs(list: &slice<string>) -> Vec<string> {
    let mut out: Vec<string> = Vec::new();
    let mut i: int = 0;
    while i < list.Len() {
        out.push(list[i as usize].clone());
        i += 1;
    }
    return out;
}

fn eqStrs(got: &Vec<string>, want: &[&str]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    let mut i = 0usize;
    while i < got.len() {
        if got[i] != s(want[i]) {
            return false;
        }
        i += 1;
    }
    return true;
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let m = newfs();
    let fsys: Arc<dyn fs::FS + Send + Sync> = m.clone();

    // 1. Go: iface readfile=true stat=true readdir=true glob=true
    //    readlink=true sub=true. Every one of these was false before the
    //    impls existed, and nothing said so — the helpers just took the
    //    slow path.
    {
        let mut ok = true;
        let (_, isReadFile) = goish::cast!(&*fsys, fs::ReadFileFS);
        let (_, isStat) = goish::cast!(&*fsys, fs::StatFS);
        let (_, isReadDir) = goish::cast!(&*fsys, fs::ReadDirFS);
        let (_, isGlob) = goish::cast!(&*fsys, fs::GlobFS);
        let (_, isReadLink) = goish::cast!(&*fsys, fs::ReadLinkFS);
        if !isReadFile || !isStat || !isReadDir || !isGlob || !isReadLink {
            ok = false;
        }
        report(&mut failed, ok, " 1", "MapFS answers to its interfaces");
    }

    // 2. ReadFile, by the method and by the helper. They must agree —
    //    and the method reaching the helper without recursing is what
    //    `fsOnly` buys.
    {
        let mut ok = true;
        let cases: [(&str, &str, &str); 4] = [
            ("a.txt", "alpha", "<nil>"),
            ("b.log", "beta", "<nil>"),
            ("sub/c.txt", "gamma", "<nil>"),
            ("nope", "", "open nope: file does not exist"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want, want_err) = cases[i];
            let (d1, e1) = m.ReadFile(s(name));
            let (d2, e2) = fs::ReadFile(&*fsys, s(name));
            if string::from_bytes(&d1) != s(want) || errText(&e1) != s(want_err) {
                ok = false;
            }
            if string::from_bytes(&d2) != s(want) || errText(&e2) != s(want_err) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "ReadFile: method == helper");
    }

    // 3. Stat, both routes.
    {
        let mut ok = true;
        let cases: [(&str, &str, &str); 4] = [
            ("a.txt", "a.txt", "<nil>"),
            ("sub", "sub", "<nil>"),
            ("sub/deep", "deep", "<nil>"),
            ("nope", "", "open nope: file does not exist"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want, want_err) = cases[i];
            let (i1, e1) = m.Stat(s(name));
            let (i2, e2) = fs::Stat(&*fsys, s(name));
            if errText(&e1) != s(want_err) || errText(&e2) != s(want_err) {
                ok = false;
            }
            if e1.IsNil() && (i1.Name() != s(want) || i2.Name() != s(want)) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Stat: method == helper");
    }

    // 4. ReadDir, both routes.
    {
        let mut ok = true;
        let cases: [(&str, &[&str], &str); 4] = [
            (".", &["a.txt", "b.log", "sub"], "<nil>"),
            ("sub", &["c.txt", "deep"], "<nil>"),
            ("sub/deep", &["d.txt"], "<nil>"),
            ("nope", &[], "open nope: file does not exist"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want, want_err) = cases[i];
            let (l1, e1) = m.ReadDir(s(name));
            let (l2, e2) = fs::ReadDir(&*fsys, s(name));
            if !eqStrs(&names(&l1), want) || errText(&e1) != s(want_err) {
                ok = false;
            }
            if !eqStrs(&names(&l2), want) || errText(&e2) != s(want_err) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "ReadDir: method == helper");
    }

    // 5. Glob, both routes. This is the one that needed `fsOnly` most
    //    urgently: `fs::Glob` grew its `GlobFS` assertion in the same
    //    commit that gave MapFS a `GlobFS` impl, so without the wrapper
    //    the pair recurses on the very first call.
    {
        let mut ok = true;
        let cases: [(&str, &[&str], &str); 6] = [
            ("*", &["a.txt", "b.log", "sub"], "<nil>"),
            ("*.txt", &["a.txt"], "<nil>"),
            ("sub/*", &["sub/c.txt", "sub/deep"], "<nil>"),
            ("*/*.txt", &["sub/c.txt"], "<nil>"),
            ("nope*", &[], "<nil>"),
            ("[", &[], "syntax error in pattern"),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (pat, want, want_err) = cases[i];
            let (g1, e1) = m.Glob(s(pat));
            let (g2, e2) = fs::Glob(&*fsys, s(pat));
            if !eqStrs(&strs(&g1), want) || errText(&e1) != s(want_err) {
                ok = false;
            }
            if !eqStrs(&strs(&g2), want) || errText(&e2) != s(want_err) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "Glob: method == helper");
    }

    // 6. Sub, both routes — `noSub`'s reason for existing.
    {
        let mut ok = true;
        let cases: [(&str, &[&str]); 3] = [
            (".", &["a.txt", "b.log", "sub"]),
            ("sub", &["c.txt", "deep"]),
            ("sub/deep", &["d.txt"]),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (dir, want) = cases[i];
            let (s1, e1) = m.Sub(s(dir));
            if !e1.IsNil() {
                ok = false;
            }
            let (l1, _) = fs::ReadDir(&*s1, s("."));
            if !eqStrs(&names(&l1), want) {
                ok = false;
            }
            let (s2, e2) = fs::Sub(fsys.clone(), s(dir));
            if !e2.IsNil() {
                ok = false;
            }
            let (l2, _) = fs::ReadDir(&*s2, s("."));
            if !eqStrs(&names(&l2), want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "Sub: method == helper");
    }

    // 7. ReadLink and Lstat, both routes. These reach MapFS only
    //    through ReadLinkFS — before it existed they were inherent
    //    methods nothing holding an `fs.FS` could call.
    {
        let mut ok = true;
        // (name, want_readlink_err, want_lstat_name, want_lstat_err)
        let cases: [(&str, &str, &str, &str); 3] = [
            (
                "a.txt",
                "readlink a.txt: invalid argument",
                "a.txt",
                "<nil>",
            ),
            ("sub", "readlink sub: invalid argument", "sub", "<nil>"),
            (
                "nope",
                "readlink nope: file does not exist",
                "",
                "lstat nope: file does not exist",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, want_rl, want_name, want_ls) = cases[i];
            let (t1, e1) = m.ReadLink(s(name));
            let (t2, e2) = fs::ReadLink(&*fsys, s(name));
            if t1.Len() != 0 || t2.Len() != 0 {
                ok = false;
            }
            if errText(&e1) != s(want_rl) || errText(&e2) != s(want_rl) {
                ok = false;
            }
            let (i1, e3) = m.Lstat(s(name));
            let (i2, e4) = fs::Lstat(&*fsys, s(name));
            if errText(&e3) != s(want_ls) || errText(&e4) != s(want_ls) {
                ok = false;
            }
            if e3.IsNil() && (i1.Name() != s(want_name) || i2.Name() != s(want_name)) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 7", "ReadLink/Lstat: method == helper");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
