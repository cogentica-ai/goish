// testing_output_smoke — t.Output() and the outputWriter behind it.
//
// Output returns a Writer onto the same stream as t.Log, but WITHOUT
// source locations or newlines. That "without newlines" is the whole
// design problem: a caller can write half a line, so the writer is
// internally line buffered and holds the newline-free tail back until
// either more bytes arrive or something flushes it.
//
// Four behaviours follow, and each is a way a naive Write would be
// wrong:
//
//   * A write with no newline emits NOTHING yet — it is all partial.
//     A writer that emitted eagerly would interleave half-lines with
//     the runner's own === RUN / --- PASS lines.
//   * The next write CONCATENATES onto that partial rather than
//     starting a new line. Check 3.
//   * Write always reports len(p) consumed, even when it emitted
//     nothing, because io.Writer's contract is bytes accepted — not
//     bytes flushed. A short count here makes io.Copy loop forever.
//   * t.Log flushes a pending partial first, so a Log never gets
//     spliced onto the end of someone's half-written line.
//
// Checks 5 and 6 pin where the bytes GO. goish's runner always attaches
// a chattyPrinter, so it behaves like `go test -v`: completed lines
// print immediately rather than being buffered, and only the test's
// report travels up to the parent. Both were verified against Go
// 1.25.5 rather than assumed.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::io::Writer;
use goish::sync::Mutex;
use goish::testing;
use goish::{fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn b(x: &str) -> slice<goish::types::byte> {
    return slice::__from_vec(x.as_bytes().to_vec());
}

/// Observations recorded from inside the test tree.
static OBS: Mutex<alloc::vec::Vec<(string, string)>> = Mutex::new(alloc::vec::Vec::new());

fn record(k: &str, v: string) {
    OBS.Lock().push((s(k), v));
}

fn num(k: &str, v: i64) {
    OBS.Lock().push((s(k), fmt::Sprintf!("%d", v)));
}

fn get(k: &str) -> string {
    for (a, x) in OBS.Lock().iter() {
        if a == &s(k) {
            return x.clone();
        }
    }
    return s("<unset>");
}

fn output_test(t: &mut testing::T) {
    t.Run(s("buffered"), |t| {
        let mut w = t.Output();

        // A newline-free write is held back entirely.
        let (n1, e1) = w.Write(b("half"));
        num("n1", n1);
        record("e1", if e1 == goish::errors::nil { s("nil") } else { s("err") });

        // …and the next write concatenates onto it.
        let (n2, _) = w.Write(b(" line\n"));
        num("n2", n2);

        // A multi-line write emits both complete lines and holds the
        // tail.
        let (n3, _) = w.Write(b("a\nb\ntail"));
        num("n3", n3);

        // Log flushes the pending "tail" before writing its own line,
        // so the two do not run together.
        t.Log(s("after"));

        record("buf", goish::testing::__shim_output_buf(t));
    });

    // After t.Run returns, flushToParent has moved the subtest's
    // buffer up here — indented one more level — and cleared the
    // source. Both halves matter: bytes left behind would be printed
    // twice, and bytes not moved would never be printed at all.
    record("parent.buf", goish::testing::__shim_output_buf(t));
}

/// Output on a test that has completed panics rather than dropping the
/// bytes — but only once EVERY ancestor is done. Here the parent is
/// still live, so the write re-homes instead.
fn output_rehomes(t: &mut testing::T) {
    t.Run(s("child"), |t| {
        let mut w = t.Output();
        goish::testing::__shim_mark_done(t);
        // The child is done; destination() walks to the live parent,
        // so this must NOT panic.
        let (n, e) = w.Write(b("rehomed\n"));
        num("rehome.n", n);
        record(
            "rehome.e",
            if e == goish::errors::nil { s("nil") } else { s("err") },
        );
    });
}

#[goish::main]
fn main() {
    let mut failed = 0;

    fmt::Println!("--- test tree output follows:");
    let code = testing::Main(&[
        ("Output", output_test),
        ("Rehome", output_rehomes),
    ]);
    fmt::Println!("--- end of test tree output");

    // 1. The tree ran green.
    {
        if code == 0 {
            fmt::Println!("[ 1] tree runs green           PASS");
        } else {
            fmt::Println!("[ 1] tree runs green           FAIL");
            failed += 1;
        }
    }

    // 2. Write reports every byte accepted, even when it emitted none.
    //    io.Writer's contract is bytes taken, not bytes flushed — a
    //    short count here makes io.Copy spin.
    {
        if get("n1") == s("4") && get("e1") == s("nil") {
            fmt::Println!("[ 2] partial write reports len PASS");
        } else {
            fmt::Println!("[ 2] partial write reports len FAIL [", get("n1"), "]");
            failed += 1;
        }
    }

    // 3. …and the counts stay exact across a concatenating write and a
    //    multi-line one.
    {
        if get("n2") == s("6") && get("n3") == s("8") {
            fmt::Println!("[ 3] counts stay exact         PASS");
        } else {
            fmt::Println!("[ 3] counts stay exact         FAIL [", get("n2"), "] [", get("n3"), "]");
            failed += 1;
        }
    }

    // 4. Writing from a test whose parent is still live re-homes
    //    instead of panicking. The panic is reserved for the case where
    //    the whole chain has finished.
    {
        if get("rehome.n") == s("8") && get("rehome.e") == s("nil") {
            fmt::Println!("[ 4] done test re-homes write  PASS");
        } else {
            fmt::Println!("[ 4] done test re-homes write  FAIL");
            failed += 1;
        }
    }

    // 5. With a chatty printer attached — goish's runner always
    //    attaches one, which is what makes it behave like `go test -v`
    //    — writeLine prints each completed line immediately instead of
    //    buffering it, so the test's own output buffer ends up EMPTY.
    //    Verified against Go 1.25.5: `go test -v` prints
    //
    //        === RUN   TestOut/buffered
    //            half line
    //            a
    //            b
    //            tail
    //
    //    before the PASS lines, which is the transcript printed above.
    {
        if get("buf") == s("") {
            fmt::Println!("[ 5] chatty routes immediately PASS");
        } else {
            fmt::Println!("[ 5] chatty routes immediately FAIL [", get("buf"), "]");
            failed += 1;
        }
    }

    // 6. …and the subtest's REPORT still travels up through
    //    flushToParent into the parent's buffer, indented one level,
    //    carrying Go's "--- %s: %s (%s)" format. That is what puts the
    //    subtest's line under its parent's rather than above it.
    {
        let want = s("    --- PASS: Output/buffered (0.00s)\n");
        if get("parent.buf") == want {
            fmt::Println!("[ 6] report flushes to parent  PASS");
        } else {
            fmt::Println!("[ 6] report flushes to parent  FAIL");
            fmt::Println!("     got  [", get("parent.buf"), "]");
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
