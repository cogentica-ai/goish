// filepath_lexical_smoke — path/filepath's lexical surface against a
// running Go. (path/filepath/path.go, path_unix.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_filepath_ref.go` run in
// `package filepath_test` by `scripts/goref.sh`.
//
// Glob, Walk, WalkDir and EvalSymlinks already have smokes of their
// own; this covers the half that never touches a filesystem and had no
// anchors: Rel, IsLocal, Localize, SplitList, ToSlash, FromSlash and
// VolumeName.
//
// Rel is the one to worry about. It has to agree with Clean on both
// arguments, count how many ".." get it from base to target, and REFUSE
// when that count cannot be known — a relative base against an absolute
// target, or a base that walks above what it can see. Every "can't make
// X relative to Y" below is a case where returning a plausible path
// would be worse than an error.
//
// Localize is the security-shaped one, and it was wrong: it called a
// local copy of io/fs.ValidPath, and the copy said YES to the empty
// string, so Localize("") returned ("", nil) where Go returns an error.
// The copy is gone; io/fs owns the predicate.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::path::filepath;
use goish::types::int;
use goish::{fmt, syscall};

fn s(b: &[u8]) -> string {
    return string::from_bytes(b);
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

// (base, targ, want, err text or "")
const RELS: [(&[u8], &[u8], &[u8], &str); 29] = [
    (b"\x61\x2f\x62", b"\x61\x2f\x62", b"\x2e", ""),
    (b"\x61\x2f\x62\x2f\x2e", b"\x61\x2f\x62", b"\x2e", ""),
    (
        b"\x61\x2f\x62",
        b"\x61\x2f\x62\x2f\x63\x2f\x64",
        b"\x63\x2f\x64",
        "",
    ),
    (
        b"\x61\x2f\x62",
        b"\x61\x2f\x62\x2f\x2e\x2e\x2f\x63",
        b"\x2e\x2e\x2f\x63",
        "",
    ),
    (b"\x61\x2f\x62\x2f\x63", b"\x61\x2f\x62", b"\x2e\x2e", ""),
    (
        b"\x61\x2f\x62\x2f\x63",
        b"\x61",
        b"\x2e\x2e\x2f\x2e\x2e",
        "",
    ),
    (
        b"\x61\x2f\x62\x2f\x63",
        b"\x61\x2f\x62\x2f\x63\x2f\x64\x2f\x65",
        b"\x64\x2f\x65",
        "",
    ),
    (
        b"\x61\x2f\x62\x2f\x63",
        b"\x78\x2f\x79\x2f\x7a",
        b"\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x78\x2f\x79\x2f\x7a",
        "",
    ),
    (b"\x61", b"\x61", b"\x2e", ""),
    (b"\x61", b"\x2e", b"\x2e\x2e\x2f\x2e", ""),
    (b"\x2e", b"\x61", b"\x61", ""),
    (b"\x2e", b"\x2e", b"\x2e", ""),
    (
        b"\x2e\x2e",
        b"\x61",
        b"",
        "Rel: can't make a relative to ..",
    ),
    (
        b"\x2e\x2e\x2f\x2e\x2e",
        b"\x61",
        b"",
        "Rel: can't make a relative to ../..",
    ),
    (
        b"\x2f\x61\x2f\x62",
        b"\x2f\x61\x2f\x62\x2f\x63",
        b"\x63",
        "",
    ),
    (
        b"\x2f\x61\x2f\x62\x2f\x63",
        b"\x2f\x61\x2f\x62",
        b"\x2e\x2e",
        "",
    ),
    (b"\x2f\x61", b"\x2f\x61", b"\x2e", ""),
    (b"\x2f", b"\x2f\x61\x2f\x62", b"\x61\x2f\x62", ""),
    (b"\x2f\x61\x2f\x62", b"\x2f", b"\x2e\x2e\x2f\x2e\x2e", ""),
    (
        b"\x2f\x61\x2f\x62",
        b"\x2f\x63\x2f\x64",
        b"\x2e\x2e\x2f\x2e\x2e\x2f\x63\x2f\x64",
        "",
    ),
    (b"\x2f", b"\x2f", b"\x2e", ""),
    (
        b"\x61\x2f\x62",
        b"\x2f\x61\x2f\x62",
        b"",
        "Rel: can't make /a/b relative to a/b",
    ),
    (
        b"\x2f\x61\x2f\x62",
        b"\x61\x2f\x62",
        b"",
        "Rel: can't make a/b relative to /a/b",
    ),
    (
        b"\x61\x2f\x2e\x2f\x62",
        b"\x61\x2f\x62\x2f\x63",
        b"\x63",
        "",
    ),
    (b"\x61\x2f\x2f\x62", b"\x61\x2f\x62\x2f\x63", b"\x63", ""),
    (b"\x61\x2f\x62\x2f", b"\x61\x2f\x62\x2f\x63", b"\x63", ""),
    (b"\x2e\x2e", b"\x2e\x2e", b"\x2e", ""),
    (
        b"\x2e\x2e\x2f\x61",
        b"\x2e\x2e\x2f\x62",
        b"\x2e\x2e\x2f\x62",
        "",
    ),
    (
        b"\x61\x2f\x2e\x2e\x2f\x2e\x2e",
        b"\x62",
        b"",
        "Rel: can't make b relative to a/../..",
    ),
];

// (path, IsLocal, Localize, err text or "")
const LOCALS: [(&[u8], bool, &[u8], &str); 26] = [
    (b"", false, b"", "invalid path"),
    (b"\x2e", true, b"\x2e", ""),
    (b"\x2e\x2e", false, b"", "invalid path"),
    (b"\x2f", false, b"", "invalid path"),
    (b"\x61", true, b"\x61", ""),
    (b"\x61\x2f\x62", true, b"\x61\x2f\x62", ""),
    (b"\x61\x2f\x62\x2f\x63", true, b"\x61\x2f\x62\x2f\x63", ""),
    (b"\x2e\x2f\x61", true, b"", "invalid path"),
    (b"\x61\x2f\x2e\x2f\x62", true, b"", "invalid path"),
    (b"\x61\x2f\x2e\x2e\x2f\x62", true, b"", "invalid path"),
    (b"\x61\x2f\x2e\x2e", true, b"", "invalid path"),
    (b"\x61\x2f\x2e\x2e\x2f\x2e\x2e", false, b"", "invalid path"),
    (b"\x2f\x61", false, b"", "invalid path"),
    (b"\x2e\x2e\x2f\x61", false, b"", "invalid path"),
    (
        b"\x61\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x62",
        false,
        b"",
        "invalid path",
    ),
    (
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        true,
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        "",
    ),
    (b"\x61\x2f\x2f\x62", true, b"", "invalid path"),
    (b"\x61\x2f", true, b"", "invalid path"),
    (b"\x2f\x61\x2f\x62", false, b"", "invalid path"),
    (b"\x2e\x2e\x61", true, b"\x2e\x2e\x61", ""),
    (b"\x61\x2e\x2e", true, b"\x61\x2e\x2e", ""),
    (b"\x61\x2f\x2e\x2e\x62", true, b"\x61\x2f\x2e\x2e\x62", ""),
    (b"\x61\x5c\x62", true, b"\x61\x5c\x62", ""),
    (b"\x61\x5c", true, b"\x61\x5c", ""),
    (b"\x5c", true, b"\x5c", ""),
    (b"\x61\x00\x62", true, b"", "invalid path"),
];

// (input, SplitList)
const SPLITLIST: [(&[u8], &[&[u8]]); 9] = [
    (b"", &[]),
    (b"\x3a", &[b"", b""]),
    (b"\x61", &[b"\x61"]),
    (b"\x61\x3a\x62", &[b"\x61", b"\x62"]),
    (b"\x61\x3a\x62\x3a\x63", &[b"\x61", b"\x62", b"\x63"]),
    (b"\x3a\x3a", &[b"", b"", b""]),
    (b"\x61\x3a\x3a\x62", &[b"\x61", b"", b"\x62"]),
    (b"\x3a\x61", &[b"", b"\x61"]),
    (b"\x61\x3a", &[b"\x61", b""]),
];

// (path, ToSlash, FromSlash, VolumeName)
const SLASHES: [(&[u8], &[u8], &[u8], &[u8]); 5] = [
    (b"", b"", b"", b""),
    (b"\x61\x2f\x62", b"\x61\x2f\x62", b"\x61\x2f\x62", b""),
    (b"\x61\x5c\x62", b"\x61\x5c\x62", b"\x61\x5c\x62", b""),
    (
        b"\x43\x3a\x5c\x78",
        b"\x43\x3a\x5c\x78",
        b"\x43\x3a\x5c\x78",
        b"",
    ),
    (
        b"\x2f\x61\x2f\x62",
        b"\x2f\x61\x2f\x62",
        b"\x2f\x61\x2f\x62",
        b"",
    ),
];
#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Rel over 29 pairs, including the five that must be errors.
    //    Note Rel("a", ".") is "../." — Go does NOT clean the result
    //    back to "..", because the target it was given was ".".
    {
        let mut ok = true;
        let mut i = 0;
        while i < RELS.len() {
            let (base, targ, want, want_err) = RELS[i];
            let (got, err) = filepath::Rel(s(base), s(targ));
            if got != s(want) {
                ok = false;
            }
            if want_err == "" {
                if !err.IsNil() {
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(want_err.as_bytes()) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Rel x29 (incl. 5 refusals)");
    }

    // 2. IsLocal and Localize. They are NOT the same predicate:
    //    IsLocal("./a") is true — the path stays inside — but
    //    Localize("./a") is an error, because "./a" is not an
    //    io/fs.ValidPath. A backslash is a legal filename byte on Unix
    //    and passes; a NUL never does.
    {
        let mut ok = true;
        let mut i = 0;
        while i < LOCALS.len() {
            let (p, want_local, want_loc, want_err) = LOCALS[i];
            if filepath::IsLocal(s(p)) != want_local {
                ok = false;
            }
            let (loc, err) = filepath::Localize(s(p));
            if loc != s(want_loc) {
                ok = false;
            }
            if want_err == "" {
                if !err.IsNil() {
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(want_err.as_bytes()) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "IsLocal/Localize x26");
    }

    // 3. Localize("") is an error. Stated on its own because it is the
    //    case the local ValidPath copy got wrong, and because an
    //    extractor that trusts Localize to reject a path it cannot use
    //    would have written to "".
    {
        let mut ok = true;
        let (loc, err) = filepath::Localize(s(b""));
        if loc.Len() != 0 || err.IsNil() || err.Error() != s(b"invalid path") {
            ok = false;
        }
        report(&mut failed, ok, " 3", "Localize(\"\") is an error");
    }

    // 4. SplitList. The empty string is an EMPTY list, not a
    //    one-element list holding "" — every other input splits on ':'
    //    and keeps its empty fields.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SPLITLIST.len() {
            let (p, want) = SPLITLIST[i];
            let got = filepath::SplitList(s(p));
            if got.Len() as usize != want.len() {
                ok = false;
            } else {
                let mut j = 0usize;
                while j < want.len() {
                    if got[j] != s(want[j]) {
                        ok = false;
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "SplitList x9 (\"\" is empty)");
    }

    // 5. ToSlash, FromSlash and VolumeName are identities and "" on
    //    Unix — including for a Windows-shaped path, which they must
    //    NOT try to interpret.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SLASHES.len() {
            let (p, ts, fs_, vn) = SLASHES[i];
            if filepath::ToSlash(s(p)) != s(ts) {
                ok = false;
            }
            if filepath::FromSlash(s(p)) != s(fs_) {
                ok = false;
            }
            if filepath::VolumeName(s(p)) != s(vn) {
                ok = false;
            }
            i += 1;
        }
        if filepath::Separator != b'/' || filepath::ListSeparator != b':' {
            ok = false;
        }
        report(&mut failed, ok, " 5", "ToSlash/FromSlash/VolumeName");
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
