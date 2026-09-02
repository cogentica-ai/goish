// slog_level_ref_smoke — slog.Level's text form against a running Go.
// (log/slog/level.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_slog_level_ref.go` run in `package slog`
// by `scripts/goref.sh`.
//
// goish had `Level` and its four constants and nothing else — no
// `String`, no `parse`, no `LevelVar`, no `Leveler`. level.go had no
// counterpart file at all.
//
// That matters more than a missing accessor usually would, because
// `Level.String` is NOT a lookup over four names: it renders the
// nearest named level plus a SIGNED offset, so `Level(1)` is "INFO+1"
// and `Level(-2)` is "DEBUG+2". A port that treats the four names as
// the whole vocabulary answers differently for every level a caller
// actually chooses — and does it silently, because the four common
// levels all land exactly on names.
//
// `parse` reads that syntax back and deliberately does NOT round-trip:
// "WARN-1" is level 3, whose String is "INFO+3". Go documents the
// asymmetry, and the rows below pin it rather than assuming symmetry.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::log::slog;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn bs(x: &str) -> slice<goish::types::byte> {
    return slice::__from_vec(x.as_bytes().to_vec());
}

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %q want %q\n", s(what), got, s(want));
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. String, MarshalText and MarshalJSON across the range — the
    //    four names, and every offset either side of them. Note -8 is
    //    "DEBUG-4" and not "DEBUG-8": the offset is from the NEAREST
    //    name below, and DEBUG is -4.
    {
        let cases: [(i64, &str, &str); 21] = [
            (-4, "DEBUG", "\"DEBUG\""),
            (0, "INFO", "\"INFO\""),
            (4, "WARN", "\"WARN\""),
            (8, "ERROR", "\"ERROR\""),
            (-8, "DEBUG-4", "\"DEBUG-4\""),
            (-5, "DEBUG-1", "\"DEBUG-1\""),
            (-4, "DEBUG", "\"DEBUG\""),
            (-3, "DEBUG+1", "\"DEBUG+1\""),
            (-1, "DEBUG+3", "\"DEBUG+3\""),
            (0, "INFO", "\"INFO\""),
            (1, "INFO+1", "\"INFO+1\""),
            (2, "INFO+2", "\"INFO+2\""),
            (3, "INFO+3", "\"INFO+3\""),
            (4, "WARN", "\"WARN\""),
            (5, "WARN+1", "\"WARN+1\""),
            (7, "WARN+3", "\"WARN+3\""),
            (8, "ERROR", "\"ERROR\""),
            (9, "ERROR+1", "\"ERROR+1\""),
            (12, "ERROR+4", "\"ERROR+4\""),
            (20, "ERROR+12", "\"ERROR+12\""),
            (-20, "DEBUG-16", "\"DEBUG-16\""),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (n, want_str, want_json) = cases[i];
            let l = slog::Level(n);
            eq(&mut failed, l.String(), want_str, "String");
            let (txt, _) = l.MarshalText();
            eq(
                &mut failed,
                string::from_bytes(&txt.clone().__into_vec()),
                want_str,
                "MarshalText",
            );
            let (js, _) = l.MarshalJSON();
            eq(
                &mut failed,
                string::from_bytes(&js.clone().__into_vec()),
                want_json,
                "MarshalJSON",
            );
            i += 1;
        }
        fmt::Println!("[  1 ] Level::String renders name+offset");
    }

    // 2. UnmarshalText. Case is ignored, an offset may be signed
    //    either way, and the result deliberately need not render back
    //    to the input: "WARN-1" is 3, whose String is "INFO+3". The
    //    refusals carry Go's exact wrapped text, including the
    //    strconv.Atoi message it wraps.
    {
        let cases: [(&str, &str, i64, &str); 22] = [
            ("DEBUG", "", -4, "DEBUG"),
            ("INFO", "", 0, "INFO"),
            ("WARN", "", 4, "WARN"),
            ("ERROR", "", 8, "ERROR"),
            ("debug", "", -4, "DEBUG"),
            ("info", "", 0, "INFO"),
            ("warn", "", 4, "WARN"),
            ("error", "", 8, "ERROR"),
            ("Debug", "", -4, "DEBUG"),
            ("INFO+2", "", 2, "INFO+2"),
            ("INFO-2", "", -2, "DEBUG+2"),
            ("DEBUG+3", "", -1, "DEBUG+3"),
            ("ERROR+4", "", 12, "ERROR+4"),
            ("WARN-1", "", 3, "INFO+3"),
            ("INFO+0", "", 0, "INFO"),
            ("info+2", "", 2, "INFO+2"),
            ("", "slog: level string \"\": unknown name", 0, ""),
            ("NOPE", "slog: level string \"NOPE\": unknown name", 0, ""),
            (
                "INFO+",
                "slog: level string \"INFO+\": strconv.Atoi: parsing \"+\": invalid syntax",
                0,
                "",
            ),
            (
                "INFO+x",
                "slog: level string \"INFO+x\": strconv.Atoi: parsing \"+x\": invalid syntax",
                0,
                "",
            ),
            ("+2", "slog: level string \"+2\": unknown name", 0, ""),
            (
                "INFO++2",
                "slog: level string \"INFO++2\": strconv.Atoi: parsing \"++2\": invalid syntax",
                0,
                "",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, want_err, want_n, want_str) = cases[i];
            let mut l = slog::Level(0);
            let err = l.UnmarshalText(bs(inp));
            if want_err.len() > 0 {
                if err.IsNil() {
                    fmt::Printf!("[!!] parse %q FAIL expected error\n", s(inp));
                    failed += 1;
                } else {
                    eq(&mut failed, err.Error(), want_err, inp);
                }
            } else if !err.IsNil() {
                fmt::Printf!("[!!] parse %q FAIL %q\n", s(inp), err.Error());
                failed += 1;
            } else {
                if l.0 != want_n {
                    fmt::Printf!("[!!] parse %q FAIL got %d want %d\n", s(inp), l.0, want_n);
                    failed += 1;
                }
                eq(&mut failed, l.String(), want_str, inp);
            }
            i += 1;
        }
        fmt::Println!("[  2 ] Level::UnmarshalText, offsets and refusals");
    }

    // 3. LevelVar: the ZERO value is LevelInfo, not level zero-as-unset,
    //    and its String is bracketed rather than bare.
    {
        let v = slog::LevelVar::new();
        eq(&mut failed, v.String(), "LevelVar(INFO)", "zero LevelVar");
        if v.Level().0 != 0 {
            fmt::Println!("[!!] LevelVar zero level FAIL");
            failed += 1;
        }
        v.Set(slog::LevelWarn);
        eq(&mut failed, v.String(), "LevelVar(WARN)", "set WARN");
        let (txt, _) = v.MarshalText();
        eq(
            &mut failed,
            string::from_bytes(&txt.clone().__into_vec()),
            "WARN",
            "LevelVar text",
        );
        let err = v.UnmarshalText(bs("ERROR+2"));
        if !err.IsNil() {
            fmt::Println!("[!!] LevelVar unmarshal FAIL");
            failed += 1;
        }
        eq(
            &mut failed,
            v.String(),
            "LevelVar(ERROR+2)",
            "after unmarshal",
        );
        if v.Level().0 != 10 {
            fmt::Printf!("[!!] LevelVar level FAIL got %d want 10\n", v.Level().0);
            failed += 1;
        }
        fmt::Println!("[  3 ] LevelVar zero is INFO");
    }

    if failed == 0 {
        fmt::Println!("ok - slog.Level matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
