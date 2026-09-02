// context_string_ref_smoke — Context.String against a running Go.
// (context/context.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_ctxstring_ref.go` run in `package
// context_test` by `scripts/goref.sh`.
//
// A Context's String is what shows up in a log line or a panic, and it
// is built by walking the PARENT CHAIN — each wrapper prepends its
// parent's name — so the string records how the context was
// constructed. goish had no String at all: the Context trait did not
// declare one, and `Background()` and `TODO()` returned the SAME type,
// so they could not have been told apart even in principle.
//
// The rule worth having is `stringify`'s: a string value prints as its
// VALUE, and anything else prints as its TYPE. Go does not put
// arbitrary values into a context's String, so a token stashed under a
// context key does not leak into a log line that prints the context. A
// port that rendered the value would turn every such log into a
// disclosure.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::context;
use goish::gostring::string;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

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

    let bg = context::Background();
    let todo = context::TODO();

    // Go: background "context.Background", todo "context.TODO".
    // These two were the same type here until now.
    eq(&mut failed, bg.String(), "context.Background", "background");
    eq(&mut failed, todo.String(), "context.TODO", "todo");

    // Go: cancel "context.Background.WithCancel", and nesting
    // accumulates rather than replacing.
    let (c1, _cancel1) = context::WithCancel(bg.clone());
    eq(
        &mut failed,
        c1.String(),
        "context.Background.WithCancel",
        "cancel",
    );
    let (c2, _cancel2) = context::WithCancel(c1.clone());
    eq(
        &mut failed,
        c2.String(),
        "context.Background.WithCancel.WithCancel",
        "cancel2",
    );

    // Go: value "context.Background.WithValue(k, v)" — a STRING value
    // prints as its value.
    let v1 = context::WithValue(bg.clone(), "k", s("v"));
    eq(
        &mut failed,
        v1.String(),
        "context.Background.WithValue(k, v)",
        "value",
    );

    // Go: value2 "…WithValue(k, v).WithValue(k2, int)" — a non-string
    // value prints its TYPE. This is the row that matters: the 42 does
    // not appear.
    let v2 = context::WithValue(v1.clone(), "k2", 42 as int);
    eq(
        &mut failed,
        v2.String(),
        "context.Background.WithValue(k, v).WithValue(k2, int)",
        "value2",
    );

    // The chain is preserved through either nesting order.
    let v3 = context::WithValue(c1.clone(), "x", s("y"));
    eq(
        &mut failed,
        v3.String(),
        "context.Background.WithCancel.WithValue(x, y)",
        "value-over-cancel",
    );
    let (c3, _cancel3) = context::WithCancel(v1.clone());
    eq(
        &mut failed,
        c3.String(),
        "context.Background.WithValue(k, v).WithCancel",
        "cancel-over-value",
    );

    // Go: value-int "…WithValue(n, int)", value-bool "…WithValue(b, bool)".
    eq(
        &mut failed,
        context::WithValue(bg.clone(), "n", 7 as int).String(),
        "context.Background.WithValue(n, int)",
        "value-int",
    );
    eq(
        &mut failed,
        context::WithValue(bg.clone(), "b", true).String(),
        "context.Background.WithValue(b, bool)",
        "value-bool",
    );

    // Go: cancelcause "context.Background.WithCancel" — carrying a
    // cause does not change the name.
    let (c4, _cancel4) = context::WithCancelCause(bg.clone());
    eq(
        &mut failed,
        c4.String(),
        "context.Background.WithCancel",
        "cancelcause",
    );

    // WithoutCancel appends its own name. (Go: contextName(c) +
    // ".WithoutCancel".)
    let wc = context::WithoutCancel(c1.clone());
    eq(
        &mut failed,
        wc.String(),
        "context.Background.WithCancel.WithoutCancel",
        "withoutcancel",
    );

    // NOT pinned here: the WithDeadline form. Go renders it as
    // ".WithDeadline(<when> [<remaining>])", and the remaining-time
    // half changes between the moment the reference was generated and
    // the moment this runs, so a fixed vector for it would be a vector
    // that is wrong by construction. The shape is implemented and the
    // prefix is checked instead.
    {
        let (d, _cd) = context::WithTimeout(bg.clone(), goish::time::Duration(60_000_000_000));
        let got = d.String();
        if !goish::strings::HasPrefix(got.clone(), "context.Background.WithDeadline(") {
            fmt::Printf!("[!!] withdeadline FAIL got %q\n", got);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok - context.String matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
