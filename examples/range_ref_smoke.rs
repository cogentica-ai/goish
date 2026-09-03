// range_ref_smoke — the HTTP Range header parser, against a running Go.
// (net/http/fs.go parseRange)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_range_ref.go` run in
// `package http` by `scripts/goref.sh`. goish matched Go on all 144
// lines — no defects found. Thirty-six header shapes crossed with four
// file sizes, including zero.
//
// A Range header is attacker-controlled input that decides how much of
// a file a server reads and sends, so its parser is doing resource
// arithmetic on numbers a client chose. The failure modes are not
// "wrong bytes" — they are "read past the end of the file", "allocate
// something enormous", and "serve a byte range the caller never
// authorised".
//
// The rules, each pinned across every size:
//
//   * A start at or past the size is UNSATISFIABLE and rejects the
//     WHOLE header — not clamped, not skipped. "bytes=10-" over ten
//     bytes is an error, not an empty read.
//   * An END past the last byte IS clamped. The asymmetry with the
//     start is the rule, and a parser that clamps both is one a client
//     can walk off the end of.
//   * A suffix range counts back from the end, and one longer than the
//     file is clamped to the whole file rather than refused — so
//     "bytes=-1000" over ten bytes is the entire file.
//   * Overlapping and OUT-OF-ORDER ranges are allowed:
//     "bytes=2-3,0-1" is served in the order asked, and
//     "bytes=0-1,1-2" serves byte 1 twice. That is why a bound on the
//     COUNT has to live elsewhere — the parser will not stop a client
//     asking for the same bytes many times over.
//   * Malformed input is an error rather than a partial parse: a
//     reversed pair, a negative start, a non-number, a missing unit,
//     the wrong unit, a bare "bytes", and a value with two dashes.
//   * A number too large for int64 is an error, not a wraparound.
//
// Two answers that look wrong and are not:
//
//   * "bytes=-0" over a ten-byte file yields ONE range of length zero
//     starting at offset 10 — a valid, empty suffix. A parser that
//     rejected it would differ from Go on input a client can send.
//   * A ZERO-SIZE file makes almost everything unsatisfiable, but the
//     suffix forms still parse, yielding a zero-length range at
//     offset 0.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::http::fs as httpfs;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 144] = [
    "range size=0    \"\"                           -> n=0 []",
    "range size=0    \"bytes=0-0\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-\"                   -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=-1\"                   -> n=1 [0+0]",
    "range size=0    \"bytes=-5\"                   -> n=1 [0+0]",
    "range size=0    \"bytes=5-\"                   -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-9\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-100\"                -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=9-9\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=10-\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=10-20\"                -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=1000-\"                -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=-0\"                   -> n=1 [0+0]",
    "range size=0    \"bytes=-1000\"                -> n=1 [0+0]",
    "range size=0    \"bytes=0-0,2-2\"              -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-1,1-2\"              -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=2-3,0-1\"              -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes= 0-1\"                 -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-1 \"                 -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-1, 2-3\"             -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-1,,2-3\"             -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=0-1,\"                 -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=-\"                    -> err=\"invalid range\"",
    "range size=0    \"bytes=1-0\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=a-b\"                  -> err=\"invalid range\"",
    "range size=0    \"bytes=0-b\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=-a\"                   -> err=\"invalid range\"",
    "range size=0    \"bytes=0--1\"                 -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=+0-1\"                 -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"items=0-1\"                  -> err=\"invalid range\"",
    "range size=0    \"0-1\"                        -> err=\"invalid range\"",
    "range size=0    \"bytes\"                      -> err=\"invalid range\"",
    "range size=0    \"bytes=\"                     -> n=0 []",
    "range size=0    \"bytes=0-1-2\"                -> err=\"invalid range: failed to overlap\"",
    "range size=0    \"bytes=999999999999999999999-\" -> err=\"invalid range\"",
    "range size=0    \"bytes=0-999999999999999999999\" -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"\"                           -> n=0 []",
    "range size=1    \"bytes=0-0\"                  -> n=1 [0+1]",
    "range size=1    \"bytes=0-\"                   -> n=1 [0+1]",
    "range size=1    \"bytes=-1\"                   -> n=1 [0+1]",
    "range size=1    \"bytes=-5\"                   -> n=1 [0+1]",
    "range size=1    \"bytes=5-\"                   -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"bytes=0-9\"                  -> n=1 [0+1]",
    "range size=1    \"bytes=0-100\"                -> n=1 [0+1]",
    "range size=1    \"bytes=9-9\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"bytes=10-\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"bytes=10-20\"                -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"bytes=1000-\"                -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"bytes=-0\"                   -> n=1 [1+0]",
    "range size=1    \"bytes=-1000\"                -> n=1 [0+1]",
    "range size=1    \"bytes=0-0,2-2\"              -> n=1 [0+1]",
    "range size=1    \"bytes=0-1,1-2\"              -> n=1 [0+1]",
    "range size=1    \"bytes=2-3,0-1\"              -> n=1 [0+1]",
    "range size=1    \"bytes= 0-1\"                 -> n=1 [0+1]",
    "range size=1    \"bytes=0-1 \"                 -> n=1 [0+1]",
    "range size=1    \"bytes=0-1, 2-3\"             -> n=1 [0+1]",
    "range size=1    \"bytes=0-1,,2-3\"             -> n=1 [0+1]",
    "range size=1    \"bytes=0-1,\"                 -> n=1 [0+1]",
    "range size=1    \"bytes=-\"                    -> err=\"invalid range\"",
    "range size=1    \"bytes=1-0\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=1    \"bytes=a-b\"                  -> err=\"invalid range\"",
    "range size=1    \"bytes=0-b\"                  -> err=\"invalid range\"",
    "range size=1    \"bytes=-a\"                   -> err=\"invalid range\"",
    "range size=1    \"bytes=0--1\"                 -> err=\"invalid range\"",
    "range size=1    \"bytes=+0-1\"                 -> n=1 [0+1]",
    "range size=1    \"items=0-1\"                  -> err=\"invalid range\"",
    "range size=1    \"0-1\"                        -> err=\"invalid range\"",
    "range size=1    \"bytes\"                      -> err=\"invalid range\"",
    "range size=1    \"bytes=\"                     -> n=0 []",
    "range size=1    \"bytes=0-1-2\"                -> err=\"invalid range\"",
    "range size=1    \"bytes=999999999999999999999-\" -> err=\"invalid range\"",
    "range size=1    \"bytes=0-999999999999999999999\" -> err=\"invalid range\"",
    "range size=10   \"\"                           -> n=0 []",
    "range size=10   \"bytes=0-0\"                  -> n=1 [0+1]",
    "range size=10   \"bytes=0-\"                   -> n=1 [0+10]",
    "range size=10   \"bytes=-1\"                   -> n=1 [9+1]",
    "range size=10   \"bytes=-5\"                   -> n=1 [5+5]",
    "range size=10   \"bytes=5-\"                   -> n=1 [5+5]",
    "range size=10   \"bytes=0-9\"                  -> n=1 [0+10]",
    "range size=10   \"bytes=0-100\"                -> n=1 [0+10]",
    "range size=10   \"bytes=9-9\"                  -> n=1 [9+1]",
    "range size=10   \"bytes=10-\"                  -> err=\"invalid range: failed to overlap\"",
    "range size=10   \"bytes=10-20\"                -> err=\"invalid range: failed to overlap\"",
    "range size=10   \"bytes=1000-\"                -> err=\"invalid range: failed to overlap\"",
    "range size=10   \"bytes=-0\"                   -> n=1 [10+0]",
    "range size=10   \"bytes=-1000\"                -> n=1 [0+10]",
    "range size=10   \"bytes=0-0,2-2\"              -> n=2 [0+1 2+1]",
    "range size=10   \"bytes=0-1,1-2\"              -> n=2 [0+2 1+2]",
    "range size=10   \"bytes=2-3,0-1\"              -> n=2 [2+2 0+2]",
    "range size=10   \"bytes= 0-1\"                 -> n=1 [0+2]",
    "range size=10   \"bytes=0-1 \"                 -> n=1 [0+2]",
    "range size=10   \"bytes=0-1, 2-3\"             -> n=2 [0+2 2+2]",
    "range size=10   \"bytes=0-1,,2-3\"             -> n=2 [0+2 2+2]",
    "range size=10   \"bytes=0-1,\"                 -> n=1 [0+2]",
    "range size=10   \"bytes=-\"                    -> err=\"invalid range\"",
    "range size=10   \"bytes=1-0\"                  -> err=\"invalid range\"",
    "range size=10   \"bytes=a-b\"                  -> err=\"invalid range\"",
    "range size=10   \"bytes=0-b\"                  -> err=\"invalid range\"",
    "range size=10   \"bytes=-a\"                   -> err=\"invalid range\"",
    "range size=10   \"bytes=0--1\"                 -> err=\"invalid range\"",
    "range size=10   \"bytes=+0-1\"                 -> n=1 [0+2]",
    "range size=10   \"items=0-1\"                  -> err=\"invalid range\"",
    "range size=10   \"0-1\"                        -> err=\"invalid range\"",
    "range size=10   \"bytes\"                      -> err=\"invalid range\"",
    "range size=10   \"bytes=\"                     -> n=0 []",
    "range size=10   \"bytes=0-1-2\"                -> err=\"invalid range\"",
    "range size=10   \"bytes=999999999999999999999-\" -> err=\"invalid range\"",
    "range size=10   \"bytes=0-999999999999999999999\" -> err=\"invalid range\"",
    "range size=1000 \"\"                           -> n=0 []",
    "range size=1000 \"bytes=0-0\"                  -> n=1 [0+1]",
    "range size=1000 \"bytes=0-\"                   -> n=1 [0+1000]",
    "range size=1000 \"bytes=-1\"                   -> n=1 [999+1]",
    "range size=1000 \"bytes=-5\"                   -> n=1 [995+5]",
    "range size=1000 \"bytes=5-\"                   -> n=1 [5+995]",
    "range size=1000 \"bytes=0-9\"                  -> n=1 [0+10]",
    "range size=1000 \"bytes=0-100\"                -> n=1 [0+101]",
    "range size=1000 \"bytes=9-9\"                  -> n=1 [9+1]",
    "range size=1000 \"bytes=10-\"                  -> n=1 [10+990]",
    "range size=1000 \"bytes=10-20\"                -> n=1 [10+11]",
    "range size=1000 \"bytes=1000-\"                -> err=\"invalid range: failed to overlap\"",
    "range size=1000 \"bytes=-0\"                   -> n=1 [1000+0]",
    "range size=1000 \"bytes=-1000\"                -> n=1 [0+1000]",
    "range size=1000 \"bytes=0-0,2-2\"              -> n=2 [0+1 2+1]",
    "range size=1000 \"bytes=0-1,1-2\"              -> n=2 [0+2 1+2]",
    "range size=1000 \"bytes=2-3,0-1\"              -> n=2 [2+2 0+2]",
    "range size=1000 \"bytes= 0-1\"                 -> n=1 [0+2]",
    "range size=1000 \"bytes=0-1 \"                 -> n=1 [0+2]",
    "range size=1000 \"bytes=0-1, 2-3\"             -> n=2 [0+2 2+2]",
    "range size=1000 \"bytes=0-1,,2-3\"             -> n=2 [0+2 2+2]",
    "range size=1000 \"bytes=0-1,\"                 -> n=1 [0+2]",
    "range size=1000 \"bytes=-\"                    -> err=\"invalid range\"",
    "range size=1000 \"bytes=1-0\"                  -> err=\"invalid range\"",
    "range size=1000 \"bytes=a-b\"                  -> err=\"invalid range\"",
    "range size=1000 \"bytes=0-b\"                  -> err=\"invalid range\"",
    "range size=1000 \"bytes=-a\"                   -> err=\"invalid range\"",
    "range size=1000 \"bytes=0--1\"                 -> err=\"invalid range\"",
    "range size=1000 \"bytes=+0-1\"                 -> n=1 [0+2]",
    "range size=1000 \"items=0-1\"                  -> err=\"invalid range\"",
    "range size=1000 \"0-1\"                        -> err=\"invalid range\"",
    "range size=1000 \"bytes\"                      -> err=\"invalid range\"",
    "range size=1000 \"bytes=\"                     -> n=0 []",
    "range size=1000 \"bytes=0-1-2\"                -> err=\"invalid range\"",
    "range size=1000 \"bytes=999999999999999999999-\" -> err=\"invalid range\"",
    "range size=1000 \"bytes=0-999999999999999999999\" -> err=\"invalid range\"",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let headers: [&str; 36] = [
        "",
        "bytes=0-0",
        "bytes=0-",
        "bytes=-1",
        "bytes=-5",
        "bytes=5-",
        "bytes=0-9",
        "bytes=0-100",
        "bytes=9-9",
        "bytes=10-",
        "bytes=10-20",
        "bytes=1000-",
        "bytes=-0",
        "bytes=-1000",
        "bytes=0-0,2-2",
        "bytes=0-1,1-2",
        "bytes=2-3,0-1",
        "bytes= 0-1",
        "bytes=0-1 ",
        "bytes=0-1, 2-3",
        "bytes=0-1,,2-3",
        "bytes=0-1,",
        "bytes=-",
        "bytes=1-0",
        "bytes=a-b",
        "bytes=0-b",
        "bytes=-a",
        "bytes=0--1",
        "bytes=+0-1",
        "items=0-1",
        "0-1",
        "bytes",
        "bytes=",
        "bytes=0-1-2",
        "bytes=999999999999999999999-",
        "bytes=0-999999999999999999999",
    ];
    for size in [0i64, 1, 10, 1000] {
        for h in headers.iter() {
            let (rs, err) = httpfs::parseRange(s(h), size);
            if err != goish::nil {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("range size=%-4d %-28q -> err=%q", size, s(h), err.Error()),
                );
                continue;
            }
            let mut parts: Vec<string> = Vec::new();
            for i in 0..rs.Len() {
                parts.push(fmt::Sprintf!("%d+%d", rs[i].start, rs[i].length));
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "range size=%-4d %-28q -> n=%d [%s]",
                    size,
                    s(h),
                    rs.Len(),
                    strings::Join(slice::<string>::__from_vec(parts), s(" "))
                ),
            );
        }
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
