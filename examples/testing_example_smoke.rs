// testing_example_smoke — InternalExample.processRunResult and
// toOutputDir.
//
// processRunResult is what decides whether an Example function passed:
// it compares what the example printed against its `// Output:`
// comment. Three details do real work:
//
//   * The comparison is on TRIMMED output, so a missing or extra
//     trailing newline in the Output comment does not fail an
//     otherwise-correct example. This is why examples are pleasant to
//     write; a strict comparison would make every one of them fragile.
//   * An Unordered example compares SORTED LINES, for output whose
//     order is genuinely unspecified — ranging a map, say. Checks 3
//     and 4 are the pair: unordered accepts a permutation, ordered
//     rejects the same one.
//   * `finished` is separate from the comparison. An example that
//     matched its output but exited early via Goexit still fails,
//     because it never got to the part that would have printed more.
//
// toOutputDir relocates a relative profile name under -outputdir and
// leaves an ABSOLUTE path alone — the flag redirects names the test
// binary chose, not paths the user spelled out in full.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::testing::example::InternalExample;
use goish::testing::toOutputDir;
use goish::time;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eg(output: &str, unordered: bool) -> InternalExample {
    return InternalExample {
        Name: s("ExampleThing"),
        F: || {},
        Output: s(output),
        Unordered: unordered,
    };
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let d = time::Duration(0);

    // 1. Matching output passes.
    {
        let e = eg("hello\n", false);
        if e.processRunResult(s("hello\n"), d, true) {
            fmt::Println!("[ 1] matching output passes    PASS");
        } else {
            fmt::Println!("[ 1] matching output passes    FAIL");
            failed += 1;
        }
    }

    // 2. Whitespace at either end is trimmed on BOTH sides, so the
    //    newline discipline of the Output comment does not matter.
    //    Without this every example would need its comment formatted
    //    exactly right.
    {
        let e = eg("\n  hello\n\n", false);
        let ok = e.processRunResult(s("hello"), d, true);
        let e2 = eg("hello", false);
        let ok2 = e2.processRunResult(s("\nhello\n\n"), d, true);
        if ok && ok2 {
            fmt::Println!("[ 2] output is trimmed         PASS");
        } else {
            fmt::Println!("[ 2] output is trimmed         FAIL");
            failed += 1;
        }
    }

    // 3. Genuinely different output fails.
    {
        fmt::Println!("    (the two FAIL lines below are expected)");
        let e = eg("hello\n", false);
        if !e.processRunResult(s("goodbye\n"), d, true) {
            fmt::Println!("[ 3] wrong output fails        PASS");
        } else {
            fmt::Println!("[ 3] wrong output fails        FAIL");
            failed += 1;
        }
    }

    // 4. An Unordered example accepts a permutation…
    {
        let e = eg("a\nb\nc\n", true);
        if e.processRunResult(s("c\na\nb\n"), d, true) {
            fmt::Println!("[ 4] unordered accepts permut. PASS");
        } else {
            fmt::Println!("[ 4] unordered accepts permut. FAIL");
            failed += 1;
        }
    }

    // 5. …and an ORDERED one rejects exactly that permutation. Without
    //    this pair, check 4 would also pass for an implementation that
    //    ignored line order everywhere.
    {
        let e = eg("a\nb\nc\n", false);
        if !e.processRunResult(s("c\na\nb\n"), d, true) {
            fmt::Println!("[ 5] ordered rejects permut.   PASS");
        } else {
            fmt::Println!("[ 5] ordered rejects permut.   FAIL");
            failed += 1;
        }
    }

    // 6. An example that did not finish fails even when its output
    //    matched — it stopped before it could print anything more.
    {
        fmt::Println!("    (one more expected FAIL line)");
        let e = eg("hello\n", false);
        if !e.processRunResult(s("hello\n"), d, false) {
            fmt::Println!("[ 6] unfinished fails          PASS");
        } else {
            fmt::Println!("[ 6] unfinished fails          FAIL");
            failed += 1;
        }
    }

    // 7. toOutputDir leaves a path alone when -outputdir is unset, and
    //    leaves an absolute path alone regardless.
    {
        let a = toOutputDir(s("cpu.prof"));
        let b = toOutputDir(s("/tmp/cpu.prof"));
        let c = toOutputDir(s(""));
        if a == s("cpu.prof") && b == s("/tmp/cpu.prof") && c == s("") {
            fmt::Println!("[ 7] toOutputDir is identity   PASS");
        } else {
            fmt::Println!("[ 7] toOutputDir is identity   FAIL [", a, "] [", b, "]");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
