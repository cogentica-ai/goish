// os_tempfile_ref_smoke — CreateTemp/MkdirTemp against a running Go.
// (os/tempfile.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_os_tempfile_ref.go` run in `package
// os_test` by `scripts/goref.sh`.
//
// These two take a CALLER-SUPPLIED pattern, and the one rule that keeps
// them safe is that a pattern may not contain a path separator:
// `prefixAndSuffix` rejects it, so the result can never leave the
// directory the caller named. goish had no such check. `CreateTemp(dir,
// "sub/x*")` created a file in a SUBDIRECTORY and `"../up*"` created one
// outside `dir` entirely — both silently, both returning a nil error.
// Anywhere the pattern comes from outside the program, that is a way
// out of the directory the caller chose.
//
// The rest is the pattern grammar, which is easy to get subtly wrong:
// the random string replaces the LAST `*` (so "a*b*c" keeps the first
// one as a literal), and is APPENDED when there is none — including for
// the empty pattern.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::os;
use goish::types::int;
use goish::{fmt, syscall};

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

// go: none — goish idiom: collapse each RUN of digits to '#', exactly
//     as the generator did on Go's side; the random part's length
//     varies between calls.
fn mask(x: &string) -> string {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut prev = false;
    for b in x.as_bytes().iter() {
        let d = *b >= b'0' && *b <= b'9';
        if d {
            if !prev {
                v.push(b'#');
            }
        } else {
            v.push(*b);
        }
        prev = d;
    }
    return string::__from_vec(v);
}

// go: none — goish idiom: the last path component of `p`.
fn base(p: &string) -> string {
    let bs = p.as_bytes();
    let mut start = bs.len();
    while start > 0 && bs[start - 1] != b'/' {
        start -= 1;
    }
    return string::from_bytes(&bs[start..]);
}

// go: none — goish idiom: everything before the last path component.
fn dirOf(p: &string) -> string {
    let bs = p.as_bytes();
    let mut end = bs.len();
    while end > 0 && bs[end - 1] != b'/' {
        end -= 1;
    }
    if end > 1 {
        end -= 1;
    }
    return string::from_bytes(&bs[..end]);
}

// (pattern, create outcome, mkdir outcome) — Go 1.25.5 verbatim.
// An outcome starting with '!' is the exact error text; otherwise it
// is the resulting BASE NAME with each run of digits collapsed to
// '#', because the random part's length varies between calls.
const CASES: [(&str, &str, &str); 14] = [
    ("", "#", "#"),
    ("x", "x#", "x#"),
    ("pre*", "pre#", "pre#"),
    ("*suf", "#suf", "#suf"),
    ("pre*suf", "pre#suf", "pre#suf"),
    ("a*b*c", "a*b#c", "a*b#c"),
    ("*", "#", "#"),
    ("**", "*#", "*#"),
    (
        "a/b",
        "!createtemp a/b: pattern contains path separator",
        "!mkdirtemp a/b: pattern contains path separator",
    ),
    (
        "/abs",
        "!createtemp /abs: pattern contains path separator",
        "!mkdirtemp /abs: pattern contains path separator",
    ),
    (
        "a/",
        "!createtemp a/: pattern contains path separator",
        "!mkdirtemp a/: pattern contains path separator",
    ),
    (
        "sub/x*",
        "!createtemp sub/x*: pattern contains path separator",
        "!mkdirtemp sub/x*: pattern contains path separator",
    ),
    (
        "../up*",
        "!createtemp ../up*: pattern contains path separator",
        "!mkdirtemp ../up*: pattern contains path separator",
    ),
    ("a\\b", "a\\b#", "a\\b#"),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    let (dir, derr) = os::MkdirTemp("", "goish_tmpsmoke*");
    if !derr.IsNil() {
        fmt::Println!("cannot make a scratch dir:", derr.Error());
        syscall::Exit(1);
    }

    // 1. CreateTemp: the pattern grammar, and the separator rejection.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CASES.len() {
            let (pat, want, _) = CASES[i];
            let (f, err) = os::CreateTemp(dir.clone(), pat);
            if want.as_bytes()[0] == b'!' {
                let wanted = &want[1..];
                if err.IsNil() {
                    fmt::Println!("   ", fmt::Sprintf!("%q", s(pat)), "expected an error");
                    ok = false;
                } else if err.Error() != s(wanted) {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(pat)),
                        "want",
                        fmt::Sprintf!("%q", s(wanted)),
                        "got",
                        fmt::Sprintf!("%q", err.Error())
                    );
                    ok = false;
                }
            } else if !err.IsNil() {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(pat)),
                    "unexpected",
                    err.Error()
                );
                ok = false;
            } else {
                let name = f.Must().Name();
                let mut ff = f;
                let _ = ff.MustMut().Close();
                if mask(&base(&name)) != s(want) {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(pat)),
                        "want",
                        fmt::Sprintf!("%q", s(want)),
                        "got",
                        fmt::Sprintf!("%q", mask(&base(&name)))
                    );
                    ok = false;
                }
                // The file must be IN the directory we named — this is
                // the assertion the missing separator check broke.
                if dirOf(&name) != dir {
                    fmt::Println!("   ", fmt::Sprintf!("%q", s(pat)), "escaped to", name);
                    ok = false;
                }
                let _ = os::Remove(name);
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "CreateTemp pattern rules");
    }

    // 2. MkdirTemp, same grammar and the same rejection.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CASES.len() {
            let (pat, _, want) = CASES[i];
            let (name, err) = os::MkdirTemp(dir.clone(), pat);
            if want.as_bytes()[0] == b'!' {
                let wanted = &want[1..];
                if err.IsNil() || err.Error() != s(wanted) {
                    let got = if err.IsNil() { s("<nil>") } else { err.Error() };
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(pat)),
                        "want",
                        fmt::Sprintf!("%q", s(wanted)),
                        "got",
                        fmt::Sprintf!("%q", got)
                    );
                    ok = false;
                }
            } else if !err.IsNil() {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(pat)),
                    "unexpected",
                    err.Error()
                );
                ok = false;
            } else {
                if mask(&base(&name)) != s(want) || dirOf(&name) != dir {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(pat)),
                        "want",
                        fmt::Sprintf!("%q", s(want)),
                        "got",
                        fmt::Sprintf!("%q", mask(&base(&name)))
                    );
                    ok = false;
                }
                let _ = os::Remove(name);
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "MkdirTemp pattern rules");
    }

    // 3. Two calls never collide.
    {
        let (a, _) = os::CreateTemp(dir.clone(), "c*");
        let (b, _) = os::CreateTemp(dir.clone(), "c*");
        let (an, bn) = (a.Must().Name(), b.Must().Name());
        let mut af = a;
        let mut bf = b;
        let _ = af.MustMut().Close();
        let _ = bf.MustMut().Close();
        let ok = an != bn;
        let _ = os::Remove(an);
        let _ = os::Remove(bn);
        report(&mut failed, ok, " 3", "two calls do not collide");
    }

    let _ = os::Remove(dir);

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
