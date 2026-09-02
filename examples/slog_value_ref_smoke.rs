// slog_value_ref_smoke — slog.Value/Attr/Record against a running Go.
// (log/slog/value.go, attr.go, record.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_slog_value_ref.go` run in `package slog`
// by `scripts/goref.sh`.
//
// `Value.String` is the renderer every built-in handler leans on, and
// goish did not have it — nor `StringValue`/`Int64Value`/`Float64Value`
// and the rest of the typed constructors, nor `Attr.String`, nor
// `Kind.String`, nor working `Record` accumulation. It had `AnyValue`
// and `GroupValue` and stopped there.
//
// It is not one formatter but one per Kind: Int64 decimal, Float64
// shortest-round-trip, Duration in Go's duration syntax, Time as
// `time.Time.String()` — NOT RFC 3339, which the handlers apply
// themselves — and a Group bracketed like a slice of Attrs.
//
// The Record half found a real defect rather than a gap. The
// hand-written `Record::Add` in the module root DISCARDED EVERY KEY: it
// walked the args two at a time and built `Attr{Key: "", …}` from the
// value alone, so `Add("user", u)` logged the value under an empty key
// and the key was simply gone. It also never called `argsToAttr`, so
// the `!BADKEY` handling for an odd or non-string argument did not
// happen either. The rows below are Go's answers for both.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::log::slog;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the fixed instant the Go reference used, so
//     the Time rows are deterministic.
fn fixed() -> goish::time::Time {
    return goish::time::Date(2024, 1, 2, 3, 4, 5, 123_456_789, goish::time::UTC);
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

    // 1. Value::String and Kind::String, per Kind.

    eq(
        &mut failed,
        slog::StringValue("hi").String(),
        "hi",
        "val string",
    );
    eq(
        &mut failed,
        slog::StringValue("hi").Kind().String(),
        "String",
        "kind string",
    );
    eq(
        &mut failed,
        slog::StringValue("").String(),
        "",
        "val string-empty",
    );
    eq(
        &mut failed,
        slog::StringValue("").Kind().String(),
        "String",
        "kind string-empty",
    );
    eq(
        &mut failed,
        slog::StringValue("a b").String(),
        "a b",
        "val string-space",
    );
    eq(
        &mut failed,
        slog::StringValue("a b").Kind().String(),
        "String",
        "kind string-space",
    );
    eq(
        &mut failed,
        slog::Int64Value(-7).String(),
        "-7",
        "val int64",
    );
    eq(
        &mut failed,
        slog::Int64Value(-7).Kind().String(),
        "Int64",
        "kind int64",
    );
    eq(
        &mut failed,
        slog::Int64Value(0).String(),
        "0",
        "val int64-zero",
    );
    eq(
        &mut failed,
        slog::Int64Value(0).Kind().String(),
        "Int64",
        "kind int64-zero",
    );
    eq(
        &mut failed,
        slog::Uint64Value(18446744073709551615u64).String(),
        "18446744073709551615",
        "val uint64",
    );
    eq(
        &mut failed,
        slog::Uint64Value(18446744073709551615u64).Kind().String(),
        "Uint64",
        "kind uint64",
    );
    eq(
        &mut failed,
        slog::BoolValue(true).String(),
        "true",
        "val bool-true",
    );
    eq(
        &mut failed,
        slog::BoolValue(true).Kind().String(),
        "Bool",
        "kind bool-true",
    );
    eq(
        &mut failed,
        slog::BoolValue(false).String(),
        "false",
        "val bool-false",
    );
    eq(
        &mut failed,
        slog::BoolValue(false).Kind().String(),
        "Bool",
        "kind bool-false",
    );
    eq(
        &mut failed,
        slog::Float64Value(1.5).String(),
        "1.5",
        "val float-1.5",
    );
    eq(
        &mut failed,
        slog::Float64Value(1.5).Kind().String(),
        "Float64",
        "kind float-1.5",
    );
    eq(
        &mut failed,
        slog::Float64Value(2.0).String(),
        "2",
        "val float-int",
    );
    eq(
        &mut failed,
        slog::Float64Value(2.0).Kind().String(),
        "Float64",
        "kind float-int",
    );
    eq(
        &mut failed,
        slog::Float64Value(0.1).String(),
        "0.1",
        "val float-tiny",
    );
    eq(
        &mut failed,
        slog::Float64Value(0.1).Kind().String(),
        "Float64",
        "kind float-tiny",
    );
    eq(
        &mut failed,
        slog::Float64Value(-0.25).String(),
        "-0.25",
        "val float-neg",
    );
    eq(
        &mut failed,
        slog::Float64Value(-0.25).Kind().String(),
        "Float64",
        "kind float-neg",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(1_500_000_000)).String(),
        "1.5s",
        "val dur-1.5s",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(1_500_000_000))
            .Kind()
            .String(),
        "Duration",
        "kind dur-1.5s",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(0)).String(),
        "0s",
        "val dur-0",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(0))
            .Kind()
            .String(),
        "Duration",
        "kind dur-0",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(1)).String(),
        "1ns",
        "val dur-ns",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(1))
            .Kind()
            .String(),
        "Duration",
        "kind dur-ns",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(-7_200_000_000_000)).String(),
        "-2h0m0s",
        "val dur-neg",
    );
    eq(
        &mut failed,
        slog::DurationValue(goish::time::Duration(-7_200_000_000_000))
            .Kind()
            .String(),
        "Duration",
        "kind dur-neg",
    );
    eq(
        &mut failed,
        slog::TimeValue(fixed()).String(),
        "2024-01-02 03:04:05.123456789 +0000 UTC",
        "val time",
    );
    eq(
        &mut failed,
        slog::TimeValue(fixed()).Kind().String(),
        "Time",
        "kind time",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::default()).String(),
        "<nil>",
        "val any-nil",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::default()).Kind().String(),
        "Any",
        "kind any-nil",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::new(goish::errors::New("boom"))).String(),
        "boom",
        "val any-err",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::new(goish::errors::New("boom")))
            .Kind()
            .String(),
        "Any",
        "kind any-err",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::new(42 as goish::types::int)).String(),
        "42",
        "val any-int",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::new(42 as goish::types::int))
            .Kind()
            .String(),
        "Int64",
        "kind any-int",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::new(s("s"))).String(),
        "s",
        "val any-str",
    );
    eq(
        &mut failed,
        slog::AnyValue(goish::goany::Any::new(s("s")))
            .Kind()
            .String(),
        "String",
        "kind any-str",
    );
    eq(
        &mut failed,
        slog::GroupValue(goish::goslice::slice::__from_vec(alloc::vec![
            slog::String("a", "1"),
            slog::Int("b", 2)
        ]))
        .String(),
        "[a=1 b=2]",
        "val group",
    );
    eq(
        &mut failed,
        slog::GroupValue(goish::goslice::slice::__from_vec(alloc::vec![
            slog::String("a", "1"),
            slog::Int("b", 2)
        ]))
        .Kind()
        .String(),
        "Group",
        "kind group",
    );
    eq(
        &mut failed,
        slog::GroupValue(goish::goslice::slice::new()).String(),
        "[]",
        "val group-empty",
    );
    eq(
        &mut failed,
        slog::GroupValue(goish::goslice::slice::new())
            .Kind()
            .String(),
        "Group",
        "kind group-empty",
    );
    eq(
        &mut failed,
        slog::GroupValue(goish::goslice::slice::__from_vec(alloc::vec![slog::Group(
            "g",
            goish::goslice::slice::__from_vec(alloc::vec![slog::String("a", "1")])
        )]))
        .String(),
        "[g=[a=1]]",
        "val group-nested",
    );
    eq(
        &mut failed,
        slog::GroupValue(goish::goslice::slice::__from_vec(alloc::vec![slog::Group(
            "g",
            goish::goslice::slice::__from_vec(alloc::vec![slog::String("a", "1")])
        )]))
        .Kind()
        .String(),
        "Group",
        "kind group-nested",
    );
    fmt::Println!("[  1 ] Value::String renders per Kind");

    // 2. Attr::String is "key=value" over that, and isEmpty is NOT
    //    "the key is empty" — an empty key with a real value survives.
    eq(
        &mut failed,
        slog::String("k", "v").String(),
        "k=v",
        "attr string",
    );
    eq(&mut failed, slog::Int("n", 7).String(), "n=7", "attr int");
    eq(
        &mut failed,
        slog::Bool("b", false).String(),
        "b=false",
        "attr bool",
    );
    eq(
        &mut failed,
        slog::Float64("f", 1.5).String(),
        "f=1.5",
        "attr float",
    );
    eq(
        &mut failed,
        slog::Duration("d", goish::time::Duration(90_000_000_000)).String(),
        "d=1m30s",
        "attr dur",
    );
    eq(
        &mut failed,
        slog::Time("t", fixed()).String(),
        "t=2024-01-02 03:04:05.123456789 +0000 UTC",
        "attr time",
    );
    eq(
        &mut failed,
        slog::Any("a", goish::goany::Any::default()).String(),
        "a=<nil>",
        "attr any",
    );
    eq(
        &mut failed,
        slog::Group(
            "g",
            goish::goslice::slice::__from_vec(alloc::vec![
                slog::String("a", "1"),
                slog::Int("b", 2)
            ]),
        )
        .String(),
        "g=[a=1 b=2]",
        "attr group",
    );
    eq(
        &mut failed,
        slog::Group("g", goish::goslice::slice::new()).String(),
        "g=[]",
        "attr group-empty",
    );
    eq(
        &mut failed,
        slog::String("", "v").String(),
        "=v",
        "attr empty-key",
    );
    eq(
        &mut failed,
        slog::String("k", "").String(),
        "k=",
        "attr empty-val",
    );
    if slog::String("", "v").isEmpty() {
        fmt::Println!("[!!] empty-key attr wrongly empty");
        failed += 1;
    }
    if !slog::Attr::default().isEmpty() {
        fmt::Println!("[!!] zero Attr not empty");
        failed += 1;
    }
    fmt::Println!("[  2 ] Attr::String and isEmpty");

    // 3. Record accumulation. `Add` must KEEP the key — this is the
    //    defect the port had — and iteration must preserve order.
    {
        let mut r = slog::NewRecord(fixed(), slog::LevelInfo, "msg", 0);
        r.AddAttrs(&[slog::String("a", "1")]);
        r.AddAttrs(&[slog::Int("b", 2), slog::Bool("c", true)]);
        r.Add(goish::goslice::slice::__from_vec(alloc::vec![
            goish::goany::Any::new(s("d")),
            goish::goany::Any::new(s("4")),
        ]));
        r.Add(goish::goslice::slice::__from_vec(alloc::vec![
            goish::goany::Any::new(slog::Int("e", 5)),
        ]));
        if r.NumAttrs() != 5 {
            fmt::Printf!("[!!] NumAttrs FAIL got %d want 5\n", r.NumAttrs());
            failed += 1;
        }
        let want: [&str; 5] = ["a=1", "b=2", "c=true", "d=4", "e=5"];
        let mut i = 0usize;
        r.Attrs(|a| {
            if i < want.len() {
                eq(&mut failed, a.String(), want[i], "rec attr");
            }
            i += 1;
            return true;
        });

        // An empty group is omitted on the way in, not rendered empty.
        let mut r2 = slog::NewRecord(fixed(), slog::LevelInfo, "m", 0);
        r2.AddAttrs(&[slog::Group("g", goish::goslice::slice::new())]);
        if r2.NumAttrs() != 0 {
            fmt::Println!("[!!] empty group not omitted");
            failed += 1;
        }

        // Clone must not share the backing array.
        let mut c = r.Clone();
        c.AddAttrs(&[slog::String("z", "9")]);
        if r.NumAttrs() != 5 || c.NumAttrs() != 6 {
            fmt::Printf!(
                "[!!] Clone FAIL orig=%d clone=%d\n",
                r.NumAttrs(),
                c.NumAttrs()
            );
            failed += 1;
        }

        // Iteration stops when the callback returns false.
        let mut seen = 0;
        r.Attrs(|_| {
            seen += 1;
            return seen < 2;
        });
        if seen != 2 {
            fmt::Println!("[!!] Attrs did not stop early");
            failed += 1;
        }
        fmt::Println!("[  3 ] Record keeps its keys");
    }

    if failed == 0 {
        fmt::Println!("ok - slog Value/Attr/Record match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
