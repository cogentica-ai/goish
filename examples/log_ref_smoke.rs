// log_ref_smoke — the log package's header format against a running Go.
// (log/log.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_log_ref.go` run in `package log_test` by
// `scripts/goref.sh`. Digits are masked to 0 on both sides so the
// vectors do not depend on the clock; separators, spacing, order and
// the newline rule are compared exactly.
//
// The package-level `Print` family wrote a hard-coded
// `YYYY/MM/DD HH:MM:SS ` header straight to Stderr rather than going
// through the standard logger. Three consequences:
//
//   * `SetOutput`, `SetFlags` and `SetPrefix` did not exist at package
//     level, and could not have worked if they had — there was no
//     standard logger to configure. `log.SetFlags(0)` is the first
//     thing many programs do.
//   * `log::Printf!("x=%d", 7)` emitted NO trailing newline. Go's
//     Printf goes through Output, which supplies one.
//   * The header ignored every flag: no Lmicroseconds, no LUTC, no
//     Lmsgprefix, no way to turn the timestamp off.
//
// The `Logger` type itself was already close to Go's — its
// `formatHeader` is a real port — but it was missing Println, the
// Fatal family and the Panic family, so the only way to reach the
// header was through the package-level path that ignored it.
//
// Ported here: Go's `std` standard logger, the package-level
// Default/SetOutput/Flags/SetFlags/Prefix/SetPrefix/Output, and the six
// missing Logger methods. All eighteen flag-and-prefix combinations now
// render exactly as Go's do.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::sync::Arc;

use goish::bytes;
use goish::goany::Any;
use goish::goslice::slice;
use goish::gostring::string;
use goish::log;
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

// go: none — goish idiom: mask every digit so the vectors do not
//     depend on the clock, exactly as the generator did on Go's side.
fn mask(x: string) -> string {
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for b in x.as_bytes().iter() {
        if *b >= b'0' && *b <= b'9' {
            v.push(b'0');
        } else {
            v.push(*b);
        }
    }
    return string::__from_vec(v);
}

// go: none — goish idiom: Go's variadic `...any` as a `slice<Any>`.
fn av(items: &[Any]) -> slice<Any> {
    let mut v: alloc::vec::Vec<Any> = alloc::vec::Vec::new();
    for x in items.iter() {
        v.push(x.clone());
    }
    return slice::__from_vec(v);
}

// (flagset name, prefix index, want) — Go 1.25.5 verbatim, with
// every DIGIT masked to 0 so the vectors do not depend on the clock.
// Separators, spacing, order and the newline rule are exact.
const CASES: [(&str, usize, &str); 18] = [
    ("zero", 0, "ab\na b\nx=0\nnl=0\nraw\nrawnl\n"),
    ("zero", 1, "P: ab\nP: a b\nP: x=0\nP: nl=0\nP: raw\nP: rawnl\n"),
    ("date", 0, "0000/00/00 ab\n0000/00/00 a b\n0000/00/00 x=0\n0000/00/00 nl=0\n0000/00/00 raw\n0000/00/00 rawnl\n"),
    ("date", 1, "P: 0000/00/00 ab\nP: 0000/00/00 a b\nP: 0000/00/00 x=0\nP: 0000/00/00 nl=0\nP: 0000/00/00 raw\nP: 0000/00/00 rawnl\n"),
    ("time", 0, "00:00:00 ab\n00:00:00 a b\n00:00:00 x=0\n00:00:00 nl=0\n00:00:00 raw\n00:00:00 rawnl\n"),
    ("time", 1, "P: 00:00:00 ab\nP: 00:00:00 a b\nP: 00:00:00 x=0\nP: 00:00:00 nl=0\nP: 00:00:00 raw\nP: 00:00:00 rawnl\n"),
    ("std", 0, "0000/00/00 00:00:00 ab\n0000/00/00 00:00:00 a b\n0000/00/00 00:00:00 x=0\n0000/00/00 00:00:00 nl=0\n0000/00/00 00:00:00 raw\n0000/00/00 00:00:00 rawnl\n"),
    ("std", 1, "P: 0000/00/00 00:00:00 ab\nP: 0000/00/00 00:00:00 a b\nP: 0000/00/00 00:00:00 x=0\nP: 0000/00/00 00:00:00 nl=0\nP: 0000/00/00 00:00:00 raw\nP: 0000/00/00 00:00:00 rawnl\n"),
    ("micro", 0, "00:00:00.000000 ab\n00:00:00.000000 a b\n00:00:00.000000 x=0\n00:00:00.000000 nl=0\n00:00:00.000000 raw\n00:00:00.000000 rawnl\n"),
    ("micro", 1, "P: 00:00:00.000000 ab\nP: 00:00:00.000000 a b\nP: 00:00:00.000000 x=0\nP: 00:00:00.000000 nl=0\nP: 00:00:00.000000 raw\nP: 00:00:00.000000 rawnl\n"),
    ("datemicro", 0, "0000/00/00 00:00:00.000000 ab\n0000/00/00 00:00:00.000000 a b\n0000/00/00 00:00:00.000000 x=0\n0000/00/00 00:00:00.000000 nl=0\n0000/00/00 00:00:00.000000 raw\n0000/00/00 00:00:00.000000 rawnl\n"),
    ("datemicro", 1, "P: 0000/00/00 00:00:00.000000 ab\nP: 0000/00/00 00:00:00.000000 a b\nP: 0000/00/00 00:00:00.000000 x=0\nP: 0000/00/00 00:00:00.000000 nl=0\nP: 0000/00/00 00:00:00.000000 raw\nP: 0000/00/00 00:00:00.000000 rawnl\n"),
    ("utcstd", 0, "0000/00/00 00:00:00 ab\n0000/00/00 00:00:00 a b\n0000/00/00 00:00:00 x=0\n0000/00/00 00:00:00 nl=0\n0000/00/00 00:00:00 raw\n0000/00/00 00:00:00 rawnl\n"),
    ("utcstd", 1, "P: 0000/00/00 00:00:00 ab\nP: 0000/00/00 00:00:00 a b\nP: 0000/00/00 00:00:00 x=0\nP: 0000/00/00 00:00:00 nl=0\nP: 0000/00/00 00:00:00 raw\nP: 0000/00/00 00:00:00 rawnl\n"),
    ("msgprefix", 0, "0000/00/00 00:00:00 ab\n0000/00/00 00:00:00 a b\n0000/00/00 00:00:00 x=0\n0000/00/00 00:00:00 nl=0\n0000/00/00 00:00:00 raw\n0000/00/00 00:00:00 rawnl\n"),
    ("msgprefix", 1, "0000/00/00 00:00:00 P: ab\n0000/00/00 00:00:00 P: a b\n0000/00/00 00:00:00 P: x=0\n0000/00/00 00:00:00 P: nl=0\n0000/00/00 00:00:00 P: raw\n0000/00/00 00:00:00 P: rawnl\n"),
    ("msgprefixzero", 0, "ab\na b\nx=0\nnl=0\nraw\nrawnl\n"),
    ("msgprefixzero", 1, "P: ab\nP: a b\nP: x=0\nP: nl=0\nP: raw\nP: rawnl\n"),
];

const WANT_PKG: &str = "std: ab\nstd: a b\nstd: x=7\n";
const WANT_PKGMSGPREFIX: &str = "M hello\n";
const WANT_PKGPREFIX: &str = "std: ";
const WANT_PREFIX: &str = "pfx ";
const WANT_PREFIX2: &str = "q ";
const WANT_FLAGS: int = 3;
const WANT_FLAGS2: int = 16;
const WANT_PKGFLAGS: int = 0;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Eighteen flag-and-prefix combinations, each through Print,
    //    Println, Printf with and without a trailing newline, and
    //    Output with and without one.
    {
        let mut ok = true;
        let flags: [(&str, int); 9] = [
            ("zero", 0),
            ("date", log::Ldate),
            ("time", log::Ltime),
            ("std", log::LstdFlags),
            ("micro", log::Ltime | log::Lmicroseconds),
            ("datemicro", log::Ldate | log::Ltime | log::Lmicroseconds),
            ("utcstd", log::LstdFlags | log::LUTC),
            ("msgprefix", log::LstdFlags | log::Lmsgprefix),
            ("msgprefixzero", log::Lmsgprefix),
        ];
        let prefixes: [&str; 2] = ["", "P: "];
        let mut c = 0usize;
        while c < CASES.len() {
            let (name, pi, want) = CASES[c];
            let mut fi = 0usize;
            while fi < flags.len() && flags[fi].0 != name {
                fi += 1;
            }
            let buf = Arc::new(goish::sync::Mutex::new(bytes::Buffer::new()));
            let lg = log::New(Box::new(buf.clone()), prefixes[pi], flags[fi].1);
            lg.Print(av(&[Any::new(s("a")), Any::new(s("b"))]));
            lg.Println(av(&[Any::new(s("a")), Any::new(s("b"))]));
            lg.Printf("x=%d", av(&[Any::new(7i64)]));
            lg.Printf("nl=%d\n", av(&[Any::new(8i64)]));
            let _ = lg.Output(1, "raw");
            let _ = lg.Output(1, "rawnl\n");
            let got = mask(buf.Lock().String());
            if got != s(want) {
                fmt::Println!("   ", s(name), pi as int);
                fmt::Println!("      want", fmt::Sprintf!("%q", s(want)));
                fmt::Println!("      got ", fmt::Sprintf!("%q", got));
                ok = false;
            }
            c += 1;
        }
        report(&mut failed, ok, " 1", "18 flag/prefix combinations");
    }

    // 2. Flags and Prefix round-trip on a Logger.
    {
        let mut ok = true;
        let b2 = Arc::new(goish::sync::Mutex::new(bytes::Buffer::new()));
        let lg = log::New(Box::new(b2.clone()), "pfx ", log::LstdFlags);
        if lg.Flags() != WANT_FLAGS || lg.Prefix() != s(WANT_PREFIX) {
            ok = false;
        }
        lg.SetFlags(log::Lshortfile);
        lg.SetPrefix("q ");
        if lg.Flags() != WANT_FLAGS2 || lg.Prefix() != s(WANT_PREFIX2) {
            ok = false;
        }
        report(&mut failed, ok, " 2", "Flags/Prefix round-trip");
    }

    // 3. The package-level functions go through the standard logger, so
    //    SetOutput, SetFlags and SetPrefix reach them. This is the one
    //    that could not have passed before: there was no standard
    //    logger, and the three functions did not exist.
    {
        let mut ok = true;
        let b3 = Arc::new(goish::sync::Mutex::new(bytes::Buffer::new()));
        log::SetOutput(Box::new(b3.clone()));
        log::SetFlags(0);
        log::SetPrefix("std: ");
        log::Print!("a", "b");
        log::Println!("a", "b");
        // Go's Printf goes through Output, which supplies the newline.
        log::Printf!("x=%d", 7i64);
        if b3.Lock().String() != s(WANT_PKG) {
            fmt::Println!("   want", fmt::Sprintf!("%q", s(WANT_PKG)));
            fmt::Println!("   got ", fmt::Sprintf!("%q", b3.Lock().String()));
            ok = false;
        }
        if log::Flags() != WANT_PKGFLAGS || log::Prefix() != s(WANT_PKGPREFIX) {
            ok = false;
        }
        // Lmsgprefix moves the prefix to after the header.
        b3.Lock().Reset();
        log::SetPrefix("");
        log::SetFlags(log::Lmsgprefix);
        log::SetPrefix("M ");
        log::Println!("hello");
        if b3.Lock().String() != s(WANT_PKGMSGPREFIX) {
            ok = false;
        }
        // Go: log.Default() IS the logger the package functions use.
        if log::Default().Flags() != log::Flags() {
            ok = false;
        }
        report(&mut failed, ok, " 3", "package-level goes through std");
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
