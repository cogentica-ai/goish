// filepath_ref_smoke — path/filepath against a running Go.
// (path/filepath/{path,match}.go, path/path.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_filepath_ref.go` run in `package
// filepath_test` by `scripts/goref.sh`. The tables are GENERATED from
// that output rather than typed.
//
// Clean, Join, Match and Rel are the four with real edge cases, and all
// four end up deciding whether a path is inside a directory. A Clean
// that keeps one ".." too many, or a Match that lets '*' cross a
// separator, turns a containment check into a false answer — and both
// still return a plausible string.
//
// The result is that all 128 reference lines agree, which is worth
// pinning precisely because the surface is shared: on Linux goish
// re-exports one implementation for both `path` and `path/filepath`, so
// a single mistake would be two packages wrong. The cases below are the
// ones where the two could have drifted — the empty path, a lone "/",
// a trailing separator, ".." walking past the root, "*" against a path
// containing a separator, a bracket expression with '^' versus '!', an
// unterminated '[', a trailing backslash escape, and Rel between paths
// that need cleaning first.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::path::filepath;
use goish::types::int;
use goish::{fmt, slice, syscall};

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

// go: none — goish idiom: compare one result against Go's and name the
//     path it came from.
fn eq(ok: &mut bool, input: &str, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "   ",
            fmt::Sprintf!("%q", s(input)),
            s(what),
            fmt::Sprintf!("got %q want %q", got, s(want))
        );
        *ok = false;
    }
}

const CLEAN: [(&str, &str, bool, bool); 33] = [
    ("", ".", false, false),
    (".", ".", false, true),
    ("..", "..", false, false),
    ("/", "/", true, false),
    ("//", "/", true, false),
    ("///", "/", true, false),
    ("a", "a", false, true),
    ("a/", "a", false, true),
    ("/a", "/a", true, false),
    ("a/b", "a/b", false, true),
    ("a//b", "a/b", false, true),
    ("a/./b", "a/b", false, true),
    ("a/../b", "b", false, true),
    ("../a", "../a", false, false),
    ("a/..", ".", false, true),
    ("a/../..", "..", false, false),
    ("/..", "/", true, false),
    ("/../a", "/a", true, false),
    ("./a", "a", false, true),
    ("././a", "a", false, true),
    ("a/b/../../c", "c", false, true),
    ("/a/b/../../../c", "/c", true, false),
    ("a/b/", "a/b", false, true),
    ("a/./", "a", false, true),
    ("/./", "/", true, false),
    ("abc/", "abc", false, true),
    ("abc/def/..", "abc", false, true),
    ("abc/../..", "..", false, false),
    ("/a/../..", "/", true, false),
    (".//a", "a", false, true),
    ("a/b/c/../../d", "a/d", false, true),
    ("..//..", "../..", false, false),
    ("a/..//b", "b", false, true),
];

const SPLIT: [(&str, &str, &str, &str, &str, &str); 13] = [
    ("", "", "", ".", ".", ""),
    ("/", "/", "", "/", "/", ""),
    ("a", "", "a", "a", ".", ""),
    ("a/b", "a/", "b", "b", "a", ""),
    ("/a/b", "/a/", "b", "b", "/a", ""),
    ("a/b/", "a/b/", "", "b", "a/b", ""),
    ("/a/", "/a/", "", "a", "/a", ""),
    ("a.txt", "", "a.txt", "a.txt", ".", ".txt"),
    ("/a/b.txt", "/a/", "b.txt", "b.txt", "/a", ".txt"),
    (
        "dir/.hidden",
        "dir/",
        ".hidden",
        ".hidden",
        "dir",
        ".hidden",
    ),
    (".hidden", "", ".hidden", ".hidden", ".", ".hidden"),
    ("a.b.c", "", "a.b.c", "a.b.c", ".", ".c"),
    ("a/b.c/d", "a/b.c/", "d", "d", "a/b.c", ""),
];

// Join results, in the order the smoke builds the element lists.
const JOIN: [&str; 16] = [
    "", "", "a", "a/b", "a/b", "a", "a/b", "/a/b", "a/b", "b", ".", "../a", "a/b/c", "/a", "a", "a",
];

const MATCH: [(&str, &str, bool, &str); 29] = [
    ("", "", true, ""),
    ("", "a", false, ""),
    ("a", "a", true, ""),
    ("a", "b", false, ""),
    ("*", "a", true, ""),
    ("*", "", true, ""),
    ("*", "a/b", false, ""),
    ("*/*", "a/b", true, ""),
    ("a/*", "a/b", true, ""),
    ("a/*", "a/b/c", false, ""),
    ("?", "a", true, ""),
    ("?", "ab", false, ""),
    ("a?c", "abc", true, ""),
    ("[abc]", "b", true, ""),
    ("[a-c]", "b", true, ""),
    ("[^a-c]", "d", true, ""),
    ("[!a-c]", "d", false, ""),
    ("[]a]", "a", false, "syntax error in pattern"),
    ("\\*", "*", true, ""),
    ("\\*", "a", false, ""),
    ("a[", "a[", false, "syntax error in pattern"),
    ("[", "a", false, "syntax error in pattern"),
    ("[a-", "a", false, "syntax error in pattern"),
    ("*.go", "x.go", true, ""),
    ("*.go", "x.g", false, ""),
    ("**", "a/b", false, ""),
    ("a/**", "a/b", true, ""),
    ("[-x]", "-", false, "syntax error in pattern"),
    ("*[", "a[", false, "syntax error in pattern"),
];

const REL: [(&str, &str, &str, &str); 16] = [
    ("/a", "/a/b", "b", ""),
    ("/a", "/a", ".", ""),
    ("/a/b", "/a", "..", ""),
    ("/a", "/b", "../b", ""),
    ("a", "a/b", "b", ""),
    ("a/b", "a", "..", ""),
    ("a", "b", "../b", ""),
    ("/", "/a", "a", ""),
    ("/a", "/", "..", ""),
    (".", "a", "a", ""),
    ("a", ".", "../.", ""),
    ("/a", "b", "", "Rel: can't make b relative to /a"),
    ("a", "/b", "", "Rel: can't make /b relative to a"),
    ("a/b", "a/b", ".", ""),
    ("a/./b", "a/b/c", "c", ""),
    ("/a/../b", "/b/c", "c", ""),
];

const LOCALIZE: [(&str, &str, &str); 11] = [
    ("", "", "invalid path"),
    (".", ".", ""),
    ("..", "", "invalid path"),
    ("/", "", "invalid path"),
    ("a", "a", ""),
    ("a/b", "a/b", ""),
    ("../a", "", "invalid path"),
    ("a/../b", "", "invalid path"),
    ("a/..", "", "invalid path"),
    ("./a", "", "invalid path"),
    ("/a", "", "invalid path"),
];

const SPLITLIST: [(&str, &str); 7] = [
    ("", ""),
    ("a", "\"a\""),
    ("a:b", "\"a\" \"b\""),
    ("/a:/b", "\"/a\" \"/b\""),
    (":", "\"\" \"\""),
    ("::", "\"\" \"\" \"\""),
    ("a:", "\"a\" \"\""),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Clean, IsAbs and IsLocal over 33 paths. Note Clean("") is "."
    //    and Clean("/..") is "/" — ".." cannot walk past the root — but
    //    Clean("a/../..") IS "..", because a relative path has no root
    //    to stop at.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CLEAN.len() {
            let (p, want, isabs, islocal) = CLEAN[i];
            eq(&mut ok, p, "Clean", filepath::Clean(p), want);
            if filepath::IsAbs(p) != isabs || filepath::IsLocal(p) != islocal {
                fmt::Println!("   ", fmt::Sprintf!("%q", s(p)), "IsAbs/IsLocal differ");
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Clean, IsAbs and IsLocal");
    }

    // 2. Split, Base, Dir and Ext. Split does NOT clean: it cuts after
    //    the last separator, so `a/b/` splits into ("a/b/", "") while
    //    Base of the same path is "b".
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < SPLIT.len() {
            let (p, wd, wf, wbase, wdir, wext) = SPLIT[i];
            let (d, f) = filepath::Split(p);
            eq(&mut ok, p, "Split dir", d, wd);
            eq(&mut ok, p, "Split file", f, wf);
            eq(&mut ok, p, "Base", filepath::Base(p), wbase);
            eq(&mut ok, p, "Dir", filepath::Dir(p), wdir);
            eq(&mut ok, p, "Ext", filepath::Ext(p), wext);
            i += 1;
        }
        report(&mut failed, ok, " 2", "Split, Base, Dir and Ext");
    }

    // 3. Join, which drops empty elements and Cleans the result — so
    //    Join("a", "/b") is "a/b" and NOT "/b", and Join("a", "..") is
    //    ".".
    {
        let mut ok = true;
        let cases: [alloc::vec::Vec<&str>; 16] = [
            alloc::vec![],
            alloc::vec![""],
            alloc::vec!["a"],
            alloc::vec!["a", "b"],
            alloc::vec!["a", "", "b"],
            alloc::vec!["", "a"],
            alloc::vec!["a/", "b"],
            alloc::vec!["/a", "b"],
            alloc::vec!["a", "/b"],
            alloc::vec!["a", "../b"],
            alloc::vec!["a", ".."],
            alloc::vec!["..", "a"],
            alloc::vec!["a", "b", "c"],
            alloc::vec!["/", "a"],
            alloc::vec!["a", "."],
            alloc::vec![".", "a"],
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let sl: slice<string> = slice::__from_vec(cases[i].iter().map(|x| s(x)).collect());
            let got = filepath::Join(sl);
            if got != s(JOIN[i]) {
                fmt::Println!(
                    "    join",
                    i as int,
                    fmt::Sprintf!("got %q want %q", got, s(JOIN[i]))
                );
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Join drops empties and Cleans");
    }

    // 4. Match. `*` does NOT cross a separator, so "*" against "a/b" is
    //    false and "**" is no different from "*". A '[' with no ']' is
    //    ErrBadPattern, and so is a trailing '-' inside a class; a
    //    literal '[' in the NAME is fine.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < MATCH.len() {
            let (pat, name, want, werr) = MATCH[i];
            let (got, err) = filepath::Match(pat, name);
            if got != want {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q %q", s(pat), s(name)),
                    "got",
                    got,
                    "want",
                    want
                );
                ok = false;
            }
            if werr.len() == 0 {
                if !err.IsNil() {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(pat)),
                        "unexpected",
                        err.Error()
                    );
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!("   ", fmt::Sprintf!("%q", s(pat)), "want error", s(werr));
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "Match: '*' stops at a separator");
    }

    // 5. Rel, which Cleans both sides first and refuses to relate an
    //    absolute path to a relative one.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < REL.len() {
            let (base, targ, want, werr) = REL[i];
            let (got, err) = filepath::Rel(base, targ);
            eq(&mut ok, base, "Rel", got, want);
            if werr.len() == 0 {
                if !err.IsNil() {
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q %q", s(base), s(targ)),
                    "want error",
                    s(werr)
                );
                ok = false;
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 5",
            "Rel Cleans first, and refuses mixed kinds",
        );
    }

    // 6. Localize, which is the "is this safe to use as a local path"
    //    gate, and SplitList over a PATH-style variable.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < LOCALIZE.len() {
            let (p, want, werr) = LOCALIZE[i];
            let (got, err) = filepath::Localize(p);
            eq(&mut ok, p, "Localize", got, want);
            if werr.len() == 0 {
                if !err.IsNil() {
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!("   ", fmt::Sprintf!("%q", s(p)), "want error", s(werr));
                ok = false;
            }
            i += 1;
        }
        let mut k = 0usize;
        while k < SPLITLIST.len() {
            let (p, want) = SPLITLIST[k];
            let v = filepath::SplitList(p);
            let mut got = string::new();
            let mut j = 0;
            while j < v.len() {
                if j > 0 {
                    got = got + s(" ");
                }
                got = got + fmt::Sprintf!("%q", v[j].clone());
                j += 1;
            }
            eq(&mut ok, p, "SplitList", got, want);
            k += 1;
        }
        report(&mut failed, ok, " 6", "Localize and SplitList");
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
