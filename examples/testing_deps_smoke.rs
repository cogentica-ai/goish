// testing_deps_smoke — testing's testDeps seam and its matchStringOnly
// fallback.
//
// testDeps is how the `go test`-generated main package hands the
// testing package its profiling, coverage and fuzzing machinery.
// goish has no code generator, so matchStringOnly — the degraded
// implementation Go itself falls back to from testing.Main — is the
// only implementation in the tree. Porting it is what lets M.Run be
// ported verbatim later instead of being reshaped around the missing
// pieces.
//
// The load-bearing detail is that the stubs are NOT uniform. Fourteen
// of the fifteen members do no work, but they do nothing in three
// different ways, and the driver branches on the difference:
//
//   * StartCPUProfile / StopTestLog / WriteProfileTo /
//     CoordinateFuzzing / RunFuzzWorker / ReadCorpus return errMain,
//     so a caller asking for them gets a diagnosable failure.
//   * CheckCorpus returns NIL — success, not errMain. A fuzz target
//     with no engine behind it must not fail its corpus check.
//   * InitRuntimeCoverage returns three zero values, so the driver
//     sees "no coverage mode" and skips coverage entirely rather than
//     calling a nil teardown.
//
// Check 4 is the one that would catch a stub written by copying its
// neighbour: it pins CheckCorpus to nil, not to errMain.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::testing::{__shim_err_main, __shim_match_string_only};
use goish::{errors, fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let errMain = __shim_err_main();

    // 1. MatchString is the one real member — it forwards to the func
    //    the value was built from, including that func's error.
    {
        let p = __shim_match_string_only(
            |pat, str_| {
                return (pat == str_, errors::nil);
            },
            s("abc"),
            s("abc"),
        );
        let q = __shim_match_string_only(
            |pat, str_| {
                return (pat == str_, errors::nil);
            },
            s("abc"),
            s("xyz"),
        );
        if p.matched && p.matchErr == errors::nil && !q.matched {
            fmt::Println!("[ 1] MatchString forwards      PASS");
        } else {
            fmt::Println!("[ 1] MatchString forwards      FAIL");
            failed += 1;
        }
    }

    // 1b. …including the error, so a bad -run pattern is reportable.
    {
        let p = __shim_match_string_only(
            |_pat, _s| {
                return (false, errors::New(s("bad pattern")));
            },
            s("["),
            s("x"),
        );
        if p.matchErr != errors::nil && p.matchErr.Error() == s("bad pattern") {
            fmt::Println!("[ 2] MatchString error passes  PASS");
        } else {
            fmt::Println!("[ 2] MatchString error passes  FAIL");
            failed += 1;
        }
    }

    let p = __shim_match_string_only(
        |_pat, _s| {
            return (true, errors::nil);
        },
        s("x"),
        s("x"),
    );

    // 3. The six profiling/fuzzing members return errMain — the same
    //    error value, so `err == errMain` at a call site works.
    {
        let all = [
            ("StartCPUProfile", &p.startCPUProfile),
            ("StopTestLog", &p.stopTestLog),
            ("WriteProfileTo", &p.writeProfileTo),
            ("CoordinateFuzzing", &p.coordinateFuzzing),
            ("RunFuzzWorker", &p.runFuzzWorker),
            ("ReadCorpus", &p.readCorpusErr),
        ];
        let mut bad = s("");
        for (name, e) in all.iter() {
            if !errors::Is((*e).clone(), errMain.clone()) {
                // Report the FIRST divergence — reporting the last
                // would say "ReadCorpus" even when all six are wrong.
                if bad.Len() == 0 {
                    bad = s(name);
                }
            }
        }
        if bad.Len() == 0 {
            fmt::Println!("[ 3] stubs return errMain      PASS");
        } else {
            fmt::Println!("[ 3] stubs return errMain      FAIL [", bad, "]");
            failed += 1;
        }
    }

    // 4. CheckCorpus is the exception: nil, not errMain. Go returns
    //    success so a fuzz target's corpus check passes when there is
    //    no engine to check it against.
    {
        if p.checkCorpus == errors::nil {
            fmt::Println!("[ 4] CheckCorpus returns nil   PASS");
        } else {
            fmt::Println!("[ 4] CheckCorpus returns nil   FAIL");
            failed += 1;
        }
    }

    // 5. ReadCorpus yields an empty corpus alongside its error, so a
    //    caller that ignores the error still ranges over nothing.
    {
        if p.readCorpusLen == 0 {
            fmt::Println!("[ 5] ReadCorpus is empty       PASS");
        } else {
            fmt::Println!("[ 5] ReadCorpus is empty       FAIL");
            failed += 1;
        }
    }

    // 6. ImportPath is "" — the driver prints it, so a stub returning
    //    something else would leak into test output.
    {
        if p.importPath == s("") {
            fmt::Println!("[ 6] ImportPath is empty       PASS");
        } else {
            fmt::Println!("[ 6] ImportPath is empty       FAIL [", p.importPath, "]");
            failed += 1;
        }
    }

    // 7. InitRuntimeCoverage returns all three zero values. The two
    //    funcs being absent is what tells the driver to skip coverage;
    //    a non-nil teardown here would be called with no mode set.
    {
        if p.coverMode == s("") && !p.hasTearDown && !p.hasSnapcov {
            fmt::Println!("[ 7] no runtime coverage       PASS");
        } else {
            fmt::Println!("[ 7] no runtime coverage       FAIL");
            failed += 1;
        }
    }

    // 8. The five no-op members ran during the probe without panicking
    //    or hanging. Reaching this line is the assertion.
    {
        fmt::Println!("[ 8] no-op members are inert   PASS");
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
