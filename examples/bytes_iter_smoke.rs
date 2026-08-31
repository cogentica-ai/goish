// bytes_iter_smoke — bytes' iter.Seq splitters against a running Go.
// (bytes/iter.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_bytes_iter_ref.go` run in
// `package bytes_test` by `scripts/goref.sh`.
//
// Each Seq function yields exactly what its slice-building twin
// returns, so every vector is checked against the slice function too.
// The empty cases are what separate them: an empty separator splits
// into runes, an empty input yields one empty slice from SplitSeq but
// nothing at all from Lines or FieldsSeq, and a trailing separator
// yields a final empty fragment a naive loop drops.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::iter::Seq;
use goish::slices;
use goish::syscall;
use goish::types::{byte, rune};
use goish::unicode;

fn sl(b: &[u8]) -> slice<byte> {
    return slice::<byte>::__from_vec(b.to_vec());
}

fn raw(s: &slice<byte>) -> Vec<byte> {
    let r: &[byte] = s;
    return r.to_vec();
}

fn eq(got: &slice<slice<byte>>, want: &[&[u8]]) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if raw(&got[i as i64]) != want[i].to_vec() {
            return false;
        }
        i += 1;
    }
    return true;
}

// (input, sep, SplitSeq output)
const SPLIT: [(&[u8], &[u8], &[&[u8]]); 14] = [
    (b"", b"\x2c", &[b""]),
    (b"\x61", b"\x2c", &[b"\x61"]),
    (
        b"\x61\x2c\x62\x2c\x63",
        b"\x2c",
        &[b"\x61", b"\x62", b"\x63"],
    ),
    (
        b"\x61\x2c\x62\x2c\x2c\x63",
        b"\x2c",
        &[b"\x61", b"\x62", b"", b"\x63"],
    ),
    (b"\x2c\x61\x2c", b"\x2c", &[b"", b"\x61", b""]),
    (b"\x2c\x2c", b"\x2c", &[b"", b"", b""]),
    (b"\x61\x62\x63", b"", &[b"\x61", b"\x62", b"\x63"]),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        &[b"\x68", b"\xc3\xa9", b"\x6c", b"\x6c", b"\x6f"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"",
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (b"\x61\x2c\x2c\x62", b"\x2c\x2c", &[b"\x61", b"\x62"]),
    (
        b"\x61\x58\x58\x62\x58\x58\x63",
        b"\x58\x58",
        &[b"\x61", b"\x62", b"\x63"],
    ),
    (b"\x61\x62\x63", b"\x61\x62\x63", &[b"", b""]),
    (b"\x61\x62\x63", b"\x61\x62\x63\x64", &[b"\x61\x62\x63"]),
    (b"\xff\xfe", b"", &[b"\xff", b"\xfe"]),
];

// (input, sep, SplitAfterSeq output)
const AFTER: [(&[u8], &[u8], &[&[u8]]); 14] = [
    (b"", b"\x2c", &[b""]),
    (b"\x61", b"\x2c", &[b"\x61"]),
    (
        b"\x61\x2c\x62\x2c\x63",
        b"\x2c",
        &[b"\x61\x2c", b"\x62\x2c", b"\x63"],
    ),
    (
        b"\x61\x2c\x62\x2c\x2c\x63",
        b"\x2c",
        &[b"\x61\x2c", b"\x62\x2c", b"\x2c", b"\x63"],
    ),
    (b"\x2c\x61\x2c", b"\x2c", &[b"\x2c", b"\x61\x2c", b""]),
    (b"\x2c\x2c", b"\x2c", &[b"\x2c", b"\x2c", b""]),
    (b"\x61\x62\x63", b"", &[b"\x61", b"\x62", b"\x63"]),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        &[b"\x68", b"\xc3\xa9", b"\x6c", b"\x6c", b"\x6f"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"",
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (
        b"\x61\x2c\x2c\x62",
        b"\x2c\x2c",
        &[b"\x61\x2c\x2c", b"\x62"],
    ),
    (
        b"\x61\x58\x58\x62\x58\x58\x63",
        b"\x58\x58",
        &[b"\x61\x58\x58", b"\x62\x58\x58", b"\x63"],
    ),
    (b"\x61\x62\x63", b"\x61\x62\x63", &[b"\x61\x62\x63", b""]),
    (b"\x61\x62\x63", b"\x61\x62\x63\x64", &[b"\x61\x62\x63"]),
    (b"\xff\xfe", b"", &[b"\xff", b"\xfe"]),
];

// (input, Lines output — terminators kept)
const LINES: [(&[u8], &[&[u8]]); 10] = [
    (b"", &[]),
    (b"\x61", &[b"\x61"]),
    (b"\x61\x0a", &[b"\x61\x0a"]),
    (b"\x61\x0a\x62", &[b"\x61\x0a", b"\x62"]),
    (b"\x61\x0a\x62\x0a", &[b"\x61\x0a", b"\x62\x0a"]),
    (b"\x0a", &[b"\x0a"]),
    (b"\x0a\x0a", &[b"\x0a", b"\x0a"]),
    (
        b"\x61\x0d\x0a\x62\x0d\x0a",
        &[b"\x61\x0d\x0a", b"\x62\x0d\x0a"],
    ),
    (
        b"\x6e\x6f\x20\x6e\x65\x77\x6c\x69\x6e\x65\x20\x61\x74\x20\x65\x6e\x64",
        &[b"\x6e\x6f\x20\x6e\x65\x77\x6c\x69\x6e\x65\x20\x61\x74\x20\x65\x6e\x64"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\x0a\xe8\xaa\x9e",
        &[b"\xe6\x97\xa5\xe6\x9c\xac\x0a", b"\xe8\xaa\x9e"],
    ),
];

// (input, FieldsSeq output)
const FIELDS: [(&[u8], &[&[u8]]); 12] = [
    (b"", &[]),
    (b"\x20\x20\x20", &[]),
    (b"\x61", &[b"\x61"]),
    (b"\x61\x20\x62\x20\x63", &[b"\x61", b"\x62", b"\x63"]),
    (b"\x20\x20\x61\x20\x20\x62\x20\x20", &[b"\x61", b"\x62"]),
    (
        b"\x09\x0a\x0b\x0c\x0d\x20\x61\x20\x0d\x0c\x0b\x0a\x09",
        &[b"\x61"],
    ),
    (b"\x61\x20\x62", &[b"\x61", b"\x62"]),
    (b"\x61\x20\x62", &[b"\x61", b"\x62"]),
    (b"\x61\xe3\x80\x80\x62", &[b"\x61", b"\x62"]),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\x20\xe8\xaa\x9e",
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (b"\x6f\x6e\x65", &[b"\x6f\x6e\x65"]),
    (b"\xff\x20\xfe", &[b"\xff", b"\xfe"]),
];

// (predicate — 0 IsDigit, 1 == ',', 2 never; input, output)
const FFUNC: [(usize, &[u8], &[&[u8]]); 18] = [
    (0, b"", &[]),
    (0, b"\x61\x31\x62\x32\x63", &[b"\x61", b"\x62", b"\x63"]),
    (0, b"\x31\x32\x33\x34", &[]),
    (
        0,
        b"\x2c\x61\x2c\x2c\x62\x2c",
        &[b"\x2c\x61\x2c\x2c\x62\x2c"],
    ),
    (0, b"\x61\x62\x63", &[b"\x61\x62\x63"]),
    (
        0,
        b"\xe6\x97\xa5\x31\xe6\x9c\xac",
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac"],
    ),
    (1, b"", &[]),
    (1, b"\x61\x31\x62\x32\x63", &[b"\x61\x31\x62\x32\x63"]),
    (1, b"\x31\x32\x33\x34", &[b"\x31\x32\x33\x34"]),
    (1, b"\x2c\x61\x2c\x2c\x62\x2c", &[b"\x61", b"\x62"]),
    (1, b"\x61\x62\x63", &[b"\x61\x62\x63"]),
    (
        1,
        b"\xe6\x97\xa5\x31\xe6\x9c\xac",
        &[b"\xe6\x97\xa5\x31\xe6\x9c\xac"],
    ),
    (2, b"", &[]),
    (2, b"\x61\x31\x62\x32\x63", &[b"\x61\x31\x62\x32\x63"]),
    (2, b"\x31\x32\x33\x34", &[b"\x31\x32\x33\x34"]),
    (
        2,
        b"\x2c\x61\x2c\x2c\x62\x2c",
        &[b"\x2c\x61\x2c\x2c\x62\x2c"],
    ),
    (2, b"\x61\x62\x63", &[b"\x61\x62\x63"]),
    (
        2,
        b"\xe6\x97\xa5\x31\xe6\x9c\xac",
        &[b"\xe6\x97\xa5\x31\xe6\x9c\xac"],
    ),
];

// (input, SplitSeq / FieldsSeq / Lines each stopped after 2)
const STOP: [(&[u8], &[&[u8]], &[&[u8]], &[&[u8]]); 3] = [
    (
        b"\x61\x2c\x62\x2c\x63\x2c\x64",
        &[b"\x61", b"\x62"],
        &[b"\x61\x2c\x62\x2c\x63\x2c\x64"],
        &[b"\x61\x2c\x62\x2c\x63\x2c\x64"],
    ),
    (
        b"\x61\x20\x62\x20\x63\x20\x64",
        &[b"\x61\x20\x62\x20\x63\x20\x64"],
        &[b"\x61", b"\x62"],
        &[b"\x61\x20\x62\x20\x63\x20\x64"],
    ),
    (
        b"\x6c\x31\x0a\x6c\x32\x0a\x6c\x33\x0a\x6c\x34",
        &[b"\x6c\x31\x0a\x6c\x32\x0a\x6c\x33\x0a\x6c\x34"],
        &[b"\x6c\x31", b"\x6c\x32"],
        &[b"\x6c\x31\x0a", b"\x6c\x32\x0a"],
    ),
];

fn pred(i: usize, r: rune) -> bool {
    if i == 0 {
        return unicode::IsDigit(r);
    }
    if i == 1 {
        return r == 44;
    }
    return false;
}

fn take2<S: Seq<slice<byte>>>(seq: S) -> Vec<Vec<byte>> {
    let mut got: Vec<Vec<byte>> = Vec::new();
    seq.run(&mut |v: slice<byte>| {
        got.push(raw(&v));
        return got.len() < 2;
    });
    return got;
}

fn same(got: &[Vec<byte>], want: &[&[u8]]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if got[i] != want[i].to_vec() {
            return false;
        }
        i += 1;
    }
    return true;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. SplitSeq, against Go and against Split.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SPLIT.len() {
            let (s, sep, want) = SPLIT[i];
            if !eq(&slices::Collect(bytes::SplitSeq(sl(s), sl(sep))), want) {
                ok = false;
            }
            if !eq(&bytes::Split(sl(s), sl(sep)), want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] SplitSeq == Split         PASS");
        } else {
            fmt::Println!("[ 1] SplitSeq == Split         FAIL");
            failed += 1;
        }
    }

    // 2. SplitAfterSeq keeps the separator on the fragment before it.
    {
        let mut ok = true;
        let mut i = 0;
        while i < AFTER.len() {
            let (s, sep, want) = AFTER[i];
            if !eq(&slices::Collect(bytes::SplitAfterSeq(sl(s), sl(sep))), want) {
                ok = false;
            }
            if !eq(&bytes::SplitAfter(sl(s), sl(sep)), want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] SplitAfterSeq            PASS");
        } else {
            fmt::Println!("[ 2] SplitAfterSeq            FAIL");
            failed += 1;
        }
    }

    // 3. Lines keeps each terminator and yields nothing for an empty
    //    slice — unlike SplitSeq, which yields one empty fragment.
    {
        let mut ok = true;
        let mut i = 0;
        while i < LINES.len() {
            let (s, want) = LINES[i];
            if !eq(&slices::Collect(bytes::Lines(sl(s))), want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 3] Lines                    PASS");
        } else {
            fmt::Println!("[ 3] Lines                    FAIL");
            failed += 1;
        }
    }

    // 4. FieldsSeq, against Go and against Fields. Three of these split
    //    on a non-ASCII space — NBSP, LINE SEPARATOR and IDEOGRAPHIC
    //    SPACE — which is `unicode::IsSpace`, not an ASCII table.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FIELDS.len() {
            let (s, want) = FIELDS[i];
            if !eq(&slices::Collect(bytes::FieldsSeq(sl(s))), want) {
                ok = false;
            }
            if !eq(&bytes::Fields(sl(s)), want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] FieldsSeq == Fields      PASS");
        } else {
            fmt::Println!("[ 4] FieldsSeq == Fields      FAIL");
            failed += 1;
        }
    }

    // 5. FieldsFuncSeq over three predicates, including one that never
    //    matches and one that matches every rune.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FFUNC.len() {
            let (pi, s, want) = FFUNC[i];
            if !eq(
                &slices::Collect(bytes::FieldsFuncSeq(sl(s), move |r| pred(pi, r))),
                want,
            ) {
                ok = false;
            }
            if !eq(&bytes::FieldsFunc(sl(s), move |r| pred(pi, r)), want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 5] FieldsFuncSeq            PASS");
        } else {
            fmt::Println!("[ 5] FieldsFuncSeq            FAIL");
            failed += 1;
        }
    }

    // 6. A `yield` returning false stops the walk. This is the whole
    //    reason these return an iterator rather than a slice, and a
    //    port that eagerly collected and then replayed would pass every
    //    check above and fail only this one.
    {
        let mut ok = true;
        let mut i = 0;
        while i < STOP.len() {
            let (s, w_split, w_fields, w_lines) = STOP[i];
            if !same(&take2(bytes::SplitSeq(sl(s), sl(b","))), w_split) {
                ok = false;
            }
            if !same(&take2(bytes::FieldsSeq(sl(s))), w_fields) {
                ok = false;
            }
            if !same(&take2(bytes::Lines(sl(s))), w_lines) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 6] early stop honoured      PASS");
        } else {
            fmt::Println!("[ 6] early stop honoured      FAIL");
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
