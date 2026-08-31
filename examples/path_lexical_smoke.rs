// path_lexical_smoke — the whole `path` package against a running Go.
// (path/path.go, path/match.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_path_ref.go` run in `package path_test`
// by `scripts/goref.sh`.
//
// `path` is slash-only and purely lexical — it never touches a
// filesystem, so every answer is derivable from the string. That is
// what makes it easy to get ALMOST right, and it had no anchors at all
// until now: eleven functions counted as ported on a name match, none
// diffed against Go.
//
// The vectors are the places a lexical path routine goes wrong: Clean
// with ".." above the root ("/.." is "/", ".." is ".."), Join dropping
// empty elements before cleaning rather than after, Ext's rule that it
// is the LAST dot in the final element, Base's special answers for ""
// and "/", and Match's bracket expressions — negation, ranges, an
// escaped "]" or "-", an unterminated "[", a trailing backslash, and a
// reversed range, four of which are ErrBadPattern rather than false.
//
// `io/fs.Glob` rests on Match and `io/fs.subFS.fullName` on Join, both
// anchored earlier today, so a defect here would have surfaced there
// as a wrong answer with no obvious cause.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::gostring::string;
use goish::path;
use goish::types::int;
use goish::{fmt, slice, syscall};

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

// (path, Clean, Split.dir, Split.file, Ext, Base, IsAbs, Dir)
const PATHS: [(&[u8], &[u8], &[u8], &[u8], &[u8], &[u8], bool, &[u8]); 42] = [
    (b"", b"\x2e", b"", b"", b"", b"\x2e", false, b"\x2e"),
    (
        b"\x2e", b"\x2e", b"", b"\x2e", b"\x2e", b"\x2e", false, b"\x2e",
    ),
    (
        b"\x2e\x2e",
        b"\x2e\x2e",
        b"",
        b"\x2e\x2e",
        b"\x2e",
        b"\x2e\x2e",
        false,
        b"\x2e",
    ),
    (b"\x2f", b"\x2f", b"\x2f", b"", b"", b"\x2f", true, b"\x2f"),
    (
        b"\x2f\x2f",
        b"\x2f",
        b"\x2f\x2f",
        b"",
        b"",
        b"\x2f",
        true,
        b"\x2f",
    ),
    (
        b"\x2f\x2f\x2f",
        b"\x2f",
        b"\x2f\x2f\x2f",
        b"",
        b"",
        b"\x2f",
        true,
        b"\x2f",
    ),
    (b"\x61", b"\x61", b"", b"\x61", b"", b"\x61", false, b"\x2e"),
    (
        b"\x61\x2f\x62",
        b"\x61\x2f\x62",
        b"\x61\x2f",
        b"\x62",
        b"",
        b"\x62",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2f\x62\x2f\x63",
        b"\x61\x2f\x62\x2f\x63",
        b"\x61\x2f\x62\x2f",
        b"\x63",
        b"",
        b"\x63",
        false,
        b"\x61\x2f\x62",
    ),
    (
        b"\x61\x2f\x2f\x62",
        b"\x61\x2f\x62",
        b"\x61\x2f\x2f",
        b"\x62",
        b"",
        b"\x62",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2f\x2e\x2f\x62",
        b"\x61\x2f\x62",
        b"\x61\x2f\x2e\x2f",
        b"\x62",
        b"",
        b"\x62",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2f\x2e\x2e\x2f\x62",
        b"\x62",
        b"\x61\x2f\x2e\x2e\x2f",
        b"\x62",
        b"",
        b"\x62",
        false,
        b"\x2e",
    ),
    (
        b"\x61\x2f\x62\x2f\x2e\x2e",
        b"\x61",
        b"\x61\x2f\x62\x2f",
        b"\x2e\x2e",
        b"\x2e",
        b"\x2e\x2e",
        false,
        b"\x61\x2f\x62",
    ),
    (
        b"\x61\x2f\x62\x2f\x2e\x2e\x2f\x2e\x2e",
        b"\x2e",
        b"\x61\x2f\x62\x2f\x2e\x2e\x2f",
        b"\x2e\x2e",
        b"\x2e",
        b"\x2e\x2e",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2f\x62\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e",
        b"\x2e\x2e",
        b"\x61\x2f\x62\x2f\x2e\x2e\x2f\x2e\x2e\x2f",
        b"\x2e\x2e",
        b"\x2e",
        b"\x2e\x2e",
        false,
        b"\x2e",
    ),
    (
        b"\x2f\x61\x2f\x62\x2f\x2e\x2e\x2f\x2e\x2e",
        b"\x2f",
        b"\x2f\x61\x2f\x62\x2f\x2e\x2e\x2f",
        b"\x2e\x2e",
        b"\x2e",
        b"\x2e\x2e",
        true,
        b"\x2f\x61",
    ),
    (
        b"\x2f\x2e\x2e",
        b"\x2f",
        b"\x2f",
        b"\x2e\x2e",
        b"\x2e",
        b"\x2e\x2e",
        true,
        b"\x2f",
    ),
    (
        b"\x2f\x2e\x2e\x2f\x61",
        b"\x2f\x61",
        b"\x2f\x2e\x2e\x2f",
        b"\x61",
        b"",
        b"\x61",
        true,
        b"\x2f",
    ),
    (
        b"\x2e\x2e\x2f\x61",
        b"\x2e\x2e\x2f\x61",
        b"\x2e\x2e\x2f",
        b"\x61",
        b"",
        b"\x61",
        false,
        b"\x2e\x2e",
    ),
    (
        b"\x2e\x2e\x2f\x2e\x2e\x2f\x61",
        b"\x2e\x2e\x2f\x2e\x2e\x2f\x61",
        b"\x2e\x2e\x2f\x2e\x2e\x2f",
        b"\x61",
        b"",
        b"\x61",
        false,
        b"\x2e\x2e\x2f\x2e\x2e",
    ),
    (
        b"\x2e\x2f\x61",
        b"\x61",
        b"\x2e\x2f",
        b"\x61",
        b"",
        b"\x61",
        false,
        b"\x2e",
    ),
    (
        b"\x2e\x2f\x2e\x2f\x61",
        b"\x61",
        b"\x2e\x2f\x2e\x2f",
        b"\x61",
        b"",
        b"\x61",
        false,
        b"\x2e",
    ),
    (
        b"\x61\x2f",
        b"\x61",
        b"\x61\x2f",
        b"",
        b"",
        b"\x61",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2f\x2f",
        b"\x61",
        b"\x61\x2f\x2f",
        b"",
        b"",
        b"\x61",
        false,
        b"\x61",
    ),
    (
        b"\x2f\x61\x2f",
        b"\x2f\x61",
        b"\x2f\x61\x2f",
        b"",
        b"",
        b"\x61",
        true,
        b"\x2f\x61",
    ),
    (
        b"\x2f\x61\x2f\x2f",
        b"\x2f\x61",
        b"\x2f\x61\x2f\x2f",
        b"",
        b"",
        b"\x61",
        true,
        b"\x2f\x61",
    ),
    (
        b"\x61\x62\x63\x2f",
        b"\x61\x62\x63",
        b"\x61\x62\x63\x2f",
        b"",
        b"",
        b"\x61\x62\x63",
        false,
        b"\x61\x62\x63",
    ),
    (
        b"\x61\x62\x63\x2f\x64\x65\x66",
        b"\x61\x62\x63\x2f\x64\x65\x66",
        b"\x61\x62\x63\x2f",
        b"\x64\x65\x66",
        b"",
        b"\x64\x65\x66",
        false,
        b"\x61\x62\x63",
    ),
    (
        b"\x61\x62\x63\x2f\x2f\x64\x65\x66\x2f\x2f\x67\x68\x69",
        b"\x61\x62\x63\x2f\x64\x65\x66\x2f\x67\x68\x69",
        b"\x61\x62\x63\x2f\x2f\x64\x65\x66\x2f\x2f",
        b"\x67\x68\x69",
        b"",
        b"\x67\x68\x69",
        false,
        b"\x61\x62\x63\x2f\x64\x65\x66",
    ),
    (
        b"\x61\x2f\x62\x2f\x63\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x64",
        b"\x61\x2f\x64",
        b"\x61\x2f\x62\x2f\x63\x2f\x2e\x2e\x2f\x2e\x2e\x2f",
        b"\x64",
        b"",
        b"\x64",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2f\x62\x2f\x63\x2f\x2e\x2f\x64",
        b"\x61\x2f\x62\x2f\x63\x2f\x64",
        b"\x61\x2f\x62\x2f\x63\x2f\x2e\x2f",
        b"\x64",
        b"",
        b"\x64",
        false,
        b"\x61\x2f\x62\x2f\x63",
    ),
    (
        b"\x2f\x61\x2f\x62\x2f\x63\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x64",
        b"\x2f\x64",
        b"\x2f\x61\x2f\x62\x2f\x63\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f",
        b"\x64",
        b"",
        b"\x64",
        true,
        b"\x2f",
    ),
    (
        b"\x78\x2f\x79\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x7a",
        b"\x2e\x2e\x2f\x7a",
        b"\x78\x2f\x79\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f",
        b"\x7a",
        b"",
        b"\x7a",
        false,
        b"\x2e\x2e",
    ),
    (
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        b"",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        false,
        b"\x2e",
    ),
    (
        b"\x61\x2f\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x61\x2f\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x61\x2f",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        b"\x2e\x68\x69\x64\x64\x65\x6e",
        false,
        b"\x61",
    ),
    (
        b"\x61\x2e\x62\x2e\x63",
        b"\x61\x2e\x62\x2e\x63",
        b"",
        b"\x61\x2e\x62\x2e\x63",
        b"\x2e\x63",
        b"\x61\x2e\x62\x2e\x63",
        false,
        b"\x2e",
    ),
    (
        b"\x61\x2f\x62\x2e\x63\x2f\x64",
        b"\x61\x2f\x62\x2e\x63\x2f\x64",
        b"\x61\x2f\x62\x2e\x63\x2f",
        b"\x64",
        b"",
        b"\x64",
        false,
        b"\x61\x2f\x62\x2e\x63",
    ),
    (
        b"\x66\x69\x6c\x65\x2e\x74\x78\x74",
        b"\x66\x69\x6c\x65\x2e\x74\x78\x74",
        b"",
        b"\x66\x69\x6c\x65\x2e\x74\x78\x74",
        b"\x2e\x74\x78\x74",
        b"\x66\x69\x6c\x65\x2e\x74\x78\x74",
        false,
        b"\x2e",
    ),
    (
        b"\x66\x69\x6c\x65\x2e\x74\x61\x72\x2e\x67\x7a",
        b"\x66\x69\x6c\x65\x2e\x74\x61\x72\x2e\x67\x7a",
        b"",
        b"\x66\x69\x6c\x65\x2e\x74\x61\x72\x2e\x67\x7a",
        b"\x2e\x67\x7a",
        b"\x66\x69\x6c\x65\x2e\x74\x61\x72\x2e\x67\x7a",
        false,
        b"\x2e",
    ),
    (
        b"\x2e\x63\x6f\x6e\x66\x69\x67",
        b"\x2e\x63\x6f\x6e\x66\x69\x67",
        b"",
        b"\x2e\x63\x6f\x6e\x66\x69\x67",
        b"\x2e\x63\x6f\x6e\x66\x69\x67",
        b"\x2e\x63\x6f\x6e\x66\x69\x67",
        false,
        b"\x2e",
    ),
    (
        b"\x64\x69\x72\x2e\x64\x2f\x66\x69\x6c\x65",
        b"\x64\x69\x72\x2e\x64\x2f\x66\x69\x6c\x65",
        b"\x64\x69\x72\x2e\x64\x2f",
        b"\x66\x69\x6c\x65",
        b"",
        b"\x66\x69\x6c\x65",
        false,
        b"\x64\x69\x72\x2e\x64",
    ),
    (
        b"\x2f\x75\x73\x72\x2f\x6c\x6f\x63\x61\x6c\x2f\x67\x6f\x2f\x73\x72\x63",
        b"\x2f\x75\x73\x72\x2f\x6c\x6f\x63\x61\x6c\x2f\x67\x6f\x2f\x73\x72\x63",
        b"\x2f\x75\x73\x72\x2f\x6c\x6f\x63\x61\x6c\x2f\x67\x6f\x2f",
        b"\x73\x72\x63",
        b"",
        b"\x73\x72\x63",
        true,
        b"\x2f\x75\x73\x72\x2f\x6c\x6f\x63\x61\x6c\x2f\x67\x6f",
    ),
];

// (elements, Join)
const JOINS: [(&[&[u8]], &[u8]); 17] = [
    (&[], b""),
    (&[b""], b""),
    (&[b"\x61"], b"\x61"),
    (&[b"\x61", b"\x62"], b"\x61\x2f\x62"),
    (&[b"\x61", b"", b"\x62"], b"\x61\x2f\x62"),
    (&[b"", b"\x61", b"\x62"], b"\x61\x2f\x62"),
    (&[b"\x61", b"\x62", b""], b"\x61\x2f\x62"),
    (&[b"", b""], b""),
    (&[b"\x2f", b"\x61"], b"\x2f\x61"),
    (&[b"\x61", b"\x2f\x62"], b"\x61\x2f\x62"),
    (&[b"\x61\x2f", b"\x2f\x62"], b"\x61\x2f\x62"),
    (&[b"\x61", b"\x2e\x2e", b"\x62"], b"\x62"),
    (&[b"\x61", b"\x2e\x2e\x2f\x2e\x2e"], b"\x2e\x2e"),
    (&[b"\x2f", b""], b"\x2f"),
    (&[b"", b"\x2f"], b"\x2f"),
    (&[b"\x61", b"\x62\x2f\x2e\x2e\x2f\x63"], b"\x61\x2f\x63"),
    (&[b"\x2e\x2e", b"\x61"], b"\x2e\x2e\x2f\x61"),
];

// (pattern, name, matched, err text or "")
const MATCHES: [(&[u8], &[u8], bool, &str); 50] = [
    (b"", b"", true, ""),
    (b"", b"\x61", false, ""),
    (b"\x2a", b"", true, ""),
    (b"\x2a", b"\x61", true, ""),
    (b"\x2a", b"\x61\x2f\x62", false, ""),
    (b"\x61", b"\x61", true, ""),
    (b"\x61", b"\x62", false, ""),
    (b"\x61\x2a", b"\x61\x62\x63", true, ""),
    (b"\x61\x2a", b"\x61\x62\x2f\x63", false, ""),
    (b"\x2a\x2f\x2a", b"\x61\x2f\x62", true, ""),
    (b"\x2a\x2f\x2a", b"\x61\x2f\x62\x2f\x63", false, ""),
    (b"\x2a\x2a", b"\x61\x2f\x62", false, ""),
    (b"\x3f", b"\x61", true, ""),
    (b"\x3f", b"", false, ""),
    (b"\x3f", b"\x61\x62", false, ""),
    (b"\x3f", b"\x2f", false, ""),
    (b"\x61\x3f\x63", b"\x61\x62\x63", true, ""),
    (b"\x61\x3f\x63", b"\x61\x2f\x63", false, ""),
    (b"\x5b\x61\x62\x63\x5d", b"\x62", true, ""),
    (b"\x5b\x61\x62\x63\x5d", b"\x64", false, ""),
    (b"\x5b\x61\x2d\x63\x5d", b"\x62", true, ""),
    (b"\x5b\x61\x2d\x63\x5d", b"\x64", false, ""),
    (b"\x5b\x5e\x61\x62\x63\x5d", b"\x64", true, ""),
    (b"\x5b\x5e\x61\x62\x63\x5d", b"\x62", false, ""),
    (b"\x5b\x5e\x61\x2d\x63\x5d", b"\x64", true, ""),
    (
        b"\x5b\x5d\x61\x5d",
        b"\x61",
        false,
        "syntax error in pattern",
    ),
    (b"\x5b\x2d\x5d", b"\x2d", false, "syntax error in pattern"),
    (
        b"\x5b\x61\x2d\x5d",
        b"\x2d",
        false,
        "syntax error in pattern",
    ),
    (b"\x5b\x5c\x5d\x5d", b"\x5d", true, ""),
    (b"\x5b\x5c\x2d\x5d", b"\x2d", true, ""),
    (b"\x61\x5c\x2a\x62", b"\x61\x2a\x62", true, ""),
    (b"\x61\x5c\x2a\x62", b"\x61\x78\x62", false, ""),
    (b"\x5b", b"\x61", false, "syntax error in pattern"),
    (b"\x5b\x5e", b"\x61", false, "syntax error in pattern"),
    (b"\x5b\x61\x2d", b"\x61", false, "syntax error in pattern"),
    (b"\x61\x5c", b"\x61", false, "syntax error in pattern"),
    (b"\x5b\x7a\x2d\x61\x5d", b"\x62", false, ""),
    (b"\x2a\x78", b"\x61\x62\x63\x78", true, ""),
    (b"\x2a\x78", b"\x61\x62\x63\x79", false, ""),
    (b"\x61\x2a\x62\x2a\x63", b"\x61\x62\x63", true, ""),
    (b"\x61\x2a\x62\x2a\x63", b"\x61\x78\x62\x79\x63", true, ""),
    (b"\x61\x2a\x62\x2a\x63", b"\x61\x78\x62\x79\x64", false, ""),
    (b"\x2a\x2e\x74\x78\x74", b"\x61\x2e\x74\x78\x74", true, ""),
    (
        b"\x2a\x2e\x74\x78\x74",
        b"\x61\x2f\x62\x2e\x74\x78\x74",
        false,
        "",
    ),
    (b"\xe6\x97\xa5\x2a", b"\xe6\x97\xa5\xe6\x9c\xac", true, ""),
    (b"\x3f", b"\xe6\x97\xa5", true, ""),
    (
        b"\x5b\xe6\x97\xa5\xe6\x9c\xac\x5d",
        b"\xe6\x97\xa5",
        true,
        "",
    ),
    (
        b"\x5b\xe6\x97\xa5\xe6\x9c\xac\x5d",
        b"\xe8\xaa\x9e",
        false,
        "",
    ),
    (b"\xff", b"\xff", true, ""),
    (b"\x3f", b"\xff", true, ""),
];
#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Clean over 42 paths, including every ".."-above-the-root case.
    //    "/.." is "/" — the root has no parent — but ".." on its own
    //    stays "..", because a relative path's parent is not knowable
    //    lexically.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PATHS.len() {
            let (p, want, _, _, _, _, _, _) = PATHS[i];
            if path::Clean(s(p)) != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Clean x42");
    }

    // 2. Split: dir keeps the final slash, file is what follows it, and
    //    dir+file is always the original string.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PATHS.len() {
            let (p, _, want_dir, want_file, _, _, _, _) = PATHS[i];
            let (d, f) = path::Split(s(p));
            if d != s(want_dir) || f != s(want_file) {
                ok = false;
            }
            // The invariant Go's docs state: Split's halves concatenate
            // back to the input.
            let mut joined: Vec<u8> = Vec::new();
            joined.extend_from_slice(d.as_bytes());
            joined.extend_from_slice(f.as_bytes());
            if string::from_bytes(&joined) != s(p) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "Split (dir+file == input)");
    }

    // 3. Ext, Base, IsAbs, Dir. Ext is the LAST dot in the final
    //    element, so "file.tar.gz" is ".gz" and "dir.d/file" is "".
    //    Base("") is "." and Base("/") is "/".
    {
        let mut ok = true;
        let mut i = 0;
        while i < PATHS.len() {
            let (p, _, _, _, want_ext, want_base, want_abs, want_dir) = PATHS[i];
            if path::Ext(s(p)) != s(want_ext) {
                ok = false;
            }
            if path::Base(s(p)) != s(want_base) {
                ok = false;
            }
            if path::IsAbs(s(p)) != want_abs {
                ok = false;
            }
            if path::Dir(s(p)) != s(want_dir) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Ext/Base/IsAbs/Dir x42");
    }

    // 4. Join. Empty elements are dropped BEFORE the result is cleaned,
    //    so Join("a", "", "b") is "a/b" and Join("", "") is "" — not
    //    "." as a Clean of the empty string would give.
    {
        let mut ok = true;
        let mut i = 0;
        while i < JOINS.len() {
            let (elems, want) = JOINS[i];
            let mut v: Vec<string> = Vec::new();
            let mut j = 0usize;
            while j < elems.len() {
                v.push(s(elems[j]));
                j += 1;
            }
            if path::Join(slice::__from_vec(v)) != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "Join x17 (empties dropped first)");
    }

    // 5. Match. A `*` never crosses a slash, `**` is not special, and
    //    four of these are ErrBadPattern rather than a false: an
    //    unterminated "[", "[^", "[a-", and a trailing backslash. A
    //    REVERSED range "[z-a]" is not an error — it simply matches
    //    nothing.
    {
        let mut ok = true;
        let mut i = 0;
        while i < MATCHES.len() {
            let (pat, name, want, want_err) = MATCHES[i];
            let (got, err) = path::Match(s(pat), s(name));
            if got != want {
                ok = false;
            }
            if want_err == "" {
                if !err.IsNil() {
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != string::from_bytes(want_err.as_bytes()) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "Match x50 (incl. ErrBadPattern)");
    }

    // 6. ErrBadPattern is a shared sentinel, so `errors::Is` against it
    //    works — which is how `io/fs.Glob` reports a malformed pattern.
    {
        let mut ok = true;
        let (_, err) = path::Match(s(b"["), s(b"a"));
        if err.IsNil() {
            ok = false;
        }
        if !goish::errors::Is(err, path::ErrBadPattern) {
            ok = false;
        }
        let eb: goish::errors::error = path::ErrBadPattern.into();
        if eb.Error() != s(b"syntax error in pattern") {
            ok = false;
        }
        report(&mut failed, ok, " 6", "ErrBadPattern is a sentinel");
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
