// ioutil_ref_smoke — io/ioutil and FileMode formatting, against a
// running Go 1.25.5.
//
// `io/ioutil` was the one package of real size in the tree that no
// example imported. Two defects came out of the first run.
//
// 1. TempFile/TempDir ignored the pattern's `*`. Go replaces the LAST
//    `*` with the random part, so `TempFile(dir, "pre*suf")` yields a
//    name ENDING in `suf`; goish appended a counter to the whole
//    pattern and produced `pre*sufN`. A caller asking for `"*.json"`
//    got a file with no extension. Both now do what Go's do since 1.17
//    — call os.CreateTemp / os.MkdirTemp — which also inherits the
//    rejection of a pattern containing a path separator, and a real
//    retry loop instead of a process-local counter.
//
// 2. `%o` of a FileMode printed `-rw-r-----`. goish reached the
//    printer through `Stringer`, and the `impl<T: Stringer> Format for
//    T` blanket sends EVERY verb through the string. Go consults a
//    Stringer only for %v, %s, %q, %x and %X, and formats the
//    underlying value for the numeric verbs — so `Printf("%o", mode)`,
//    the ordinary way to log a mode, produced a symbolic string with
//    no digits in it. FileMode now implements `Format` directly and
//    switches on the verb.
//
// %x is pinned deliberately: it stays the hex of the STRING rather
// than of the number, because %x is one of the verbs Go's Stringer
// serves. Getting that "right" by making it numeric would be wrong.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::gostring::string;
use goish::io;
use goish::io::fs;
use goish::io::ioutil;
use goish::os;
use goish::path::filepath;
use goish::sort;
use goish::strings;
use goish::types::int;

const GO: [&str; 17] = [
    "TempDir                err=<nil> prefix-ok=true under-tmp=true",
    "WriteFile              err=<nil>",
    "ReadFile               \"hello ioutil\" err=<nil>",
    "WriteFile-mode         0640",
    "ReadFile-missing       is-not-exist=true",
    "ReadAll                \"abcdef\" err=<nil>",
    "ReadAll-empty          \"\" err=<nil> len=0",
    "ReadDir                [a a.txt b c] err=<nil> sorted=true",
    "TempFile               pre=true suf=true err=<nil>",
    "NopCloser              \"xyz\" close=<nil>",
    "Discard                n=1000 err=<nil>",
    "v=-rw-r----- s=-rw-r----- o=640 O=0640 d=416 x=2d72772d722d2d2d2d2d",
    "v=-rwxr-xr-x s=-rwxr-xr-x o=755 O=0755 d=493 x=2d727778722d78722d78",
    "v=---------- s=---------- o=0 O=0000 d=0 x=2d2d2d2d2d2d2d2d2d2d",
    "v=drwxr-xr-x s=drwxr-xr-x o=20000000755 O=20000000755 d=2147484141 x=64727778722d78722d78",
    "v=Lrwxrwxrwx s=Lrwxrwxrwx o=1000000777 O=1000000777 d=134218239 x=4c727778727778727778",
    "perm v=-rw-r----- o=0640 d=416",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let (dir, err) = ioutil::TempDir("", "goishref");
    chk(&mut ln, &fmt::Sprintf!("%-22s err=%v prefix-ok=%v under-tmp=%v", "TempDir", err,
        strings::Contains(filepath::Base(&dir), "goishref"),
        strings::HasPrefix(&dir, os::TempDir())));

    let p = filepath::Join(goish::goslice::slice::__from_vec(alloc::vec![dir.clone(), string::from("a.txt")]));
    let err = ioutil::WriteFile(&p, goish::convert::bytes(string::from("hello ioutil")), os::FileMode(0o640));
    chk(&mut ln, &fmt::Sprintf!("%-22s err=%v", "WriteFile", err));
    let (b, err) = ioutil::ReadFile(&p);
    chk(&mut ln, &fmt::Sprintf!("%-22s %q err=%v", "ReadFile", string::from_bytes(&b), err));
    let (fi, _) = os::Stat(&p);
    chk(&mut ln, &fmt::Sprintf!("%-22s %04o", "WriteFile-mode", fi.Mode().Perm()));

    let (_, err) = ioutil::ReadFile(filepath::Join(goish::goslice::slice::__from_vec(alloc::vec![dir.clone(), string::from("nope")])));
    chk(&mut ln, &fmt::Sprintf!("%-22s is-not-exist=%v", "ReadFile-missing", os::IsNotExist(err.clone())));

    let mut r = strings::NewReader("abcdef");
    let (all, err) = ioutil::ReadAll(&mut r);
    chk(&mut ln, &fmt::Sprintf!("%-22s %q err=%v", "ReadAll", string::from_bytes(&all), err));
    let mut r = strings::NewReader("");
    let (all, err) = ioutil::ReadAll(&mut r);
    chk(&mut ln, &fmt::Sprintf!("%-22s %q err=%v len=%d", "ReadAll-empty", string::from_bytes(&all), err, all.Len() as int));

    for n in ["c", "a", "b"].iter() {
        let q = filepath::Join(goish::goslice::slice::__from_vec(alloc::vec![dir.clone(), string::from(*n)]));
        let _ = ioutil::WriteFile(&q, goish::convert::bytes(string::from(*n)), os::FileMode(0o644));
    }
    let (ents, err) = ioutil::ReadDir(&dir);
    let mut names: Vec<string> = Vec::new();
    for e in ents.iter() {
        names.push(e.Name());
    }
    let mut parts = string::from("[");
    for (i, n) in names.iter().enumerate() {
        if i > 0 { parts = parts + " "; }
        parts = parts + n.clone();
    }
    parts = parts + "]";
    let sl = goish::goslice::slice::__from_vec(names.clone());
    chk(&mut ln, &fmt::Sprintf!("%-22s %s err=%v sorted=%v", "ReadDir", parts, err, sort::StringsAreSorted(&sl)));

    let (f, err) = ioutil::TempFile(&dir, "pre*suf");
    if err.IsNil() {
        let f = f.MustTake();
        let base = filepath::Base(&f.Name());
        chk(&mut ln, &fmt::Sprintf!("%-22s pre=%v suf=%v err=%v", "TempFile",
            strings::HasPrefix(&base, "pre"), strings::HasSuffix(&base, "suf"), err));
    } else {
        chk(&mut ln, &fmt::Sprintf!("%-22s err=%v", "TempFile", err));
    }

    let mut nc = ioutil::NopCloser(strings::NewReader("xyz"));
    let (got, _) = io::ReadAll(&mut nc);
    chk(&mut ln, &fmt::Sprintf!("%-22s %q close=%v", "NopCloser", string::from_bytes(&got), goish::io::Closer::Close(&mut nc)));

    let mut d = ioutil::Discard();
    let big = strings::Repeat("z", 1000);
    let mut src = strings::NewReader(&big);
    let (n, err) = io::Copy(&mut d, &mut src);
    chk(&mut ln, &fmt::Sprintf!("%-22s n=%d err=%v", "Discard", n, err));

    let _ = os::RemoveAll(&dir);

    let modes = [
        fs::FileMode(0o640),
        fs::FileMode(0o755),
        fs::FileMode(0),
        fs::ModeDir | fs::FileMode(0o755),
        fs::ModeSymlink | fs::FileMode(0o777),
    ];
    for m in modes.iter() {
        chk(&mut ln, &fmt::Sprintf!("v=%v s=%s o=%o O=%04o d=%d x=%x", *m, *m, *m, *m, *m, *m));
    }
    let p = fs::FileMode(0o640).Perm();
    chk(&mut ln, &fmt::Sprintf!("perm v=%v o=%04o d=%d", p, p, p));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
}
