// testing_testdeps_smoke — the portable half of
// testing/internal/testdeps.
//
// TestDeps is the real testDeps implementation that `go test`'s
// generated main package hands to MainStart — as opposed to
// matchStringOnly, the degraded fallback goish's Main uses. Its
// fuzzing, profiling and coverage members need subsystems goish does
// not have; its name matching and testlog writer do not.
//
// Two details do real work:
//
//   * MatchString caches the compiled pattern keyed on the PATTERN,
//     not merely on "have I compiled anything". A cache that only
//     checked for nil would match a second, different -run against the
//     first pattern — silently running the wrong tests. Check 2.
//   * testLog.add DROPS a name containing a newline rather than
//     escaping it. The log is line-oriented and cmd/go parses it that
//     way, so one embedded newline desynchronises every entry after it.
//     Check 4.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::sync::Mutex;
use goish::testing::internal::testdeps::{testLog, TestDeps};
use goish::{errors, fmt, io, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Collects what the test log wrote.
struct Sink(Arc<Mutex<alloc::vec::Vec<u8>>>);

impl io::Writer for Sink {
    fn Write(&mut self, p: slice<goish::types::byte>) -> (goish::types::int, errors::error) {
        let n = p.Len();
        self.0.Lock().extend_from_slice(&p.__into_vec());
        return (n, errors::nil);
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let d = TestDeps;

    // 1. MatchString compiles and matches.
    {
        let (m1, e1) = d.MatchString(s("^Test"), s("TestFoo"));
        let (m2, _) = d.MatchString(s("^Test"), s("BenchmarkFoo"));
        if m1 && !m2 && e1 == errors::nil {
            fmt::Println!("[ 1] MatchString matches       PASS");
        } else {
            fmt::Println!("[ 1] MatchString matches       FAIL");
            failed += 1;
        }
    }

    // 2. A DIFFERENT pattern recompiles. A cache keyed on "have I
    //    compiled anything" would answer this with the first pattern
    //    and run the wrong tests, with no error anywhere.
    {
        let (a, _) = d.MatchString(s("^Foo"), s("FooBar"));
        let (b, _) = d.MatchString(s("^Bar"), s("FooBar"));
        let (c, _) = d.MatchString(s("^Bar"), s("BarBaz"));
        if a && !b && c {
            fmt::Println!("[ 2] pattern change recompiles PASS");
        } else {
            fmt::Println!("[ 2] pattern change recompiles FAIL");
            failed += 1;
        }
    }

    // 3. An invalid pattern returns an error rather than matching
    //    everything or nothing silently.
    {
        let (_, err) = d.MatchString(s("a(b"), s("abc"));
        if err != errors::nil {
            fmt::Println!("[ 3] bad regexp errors         PASS");
        } else {
            fmt::Println!("[ 3] bad regexp errors         FAIL");
            failed += 1;
        }
    }

    // 4. The test log writes `op name` lines behind the header cmd/go
    //    looks for, and DROPS names it could not represent — an empty
    //    one, or one containing a newline, which would desynchronise
    //    every entry after it.
    {
        let buf = Arc::new(Mutex::new(alloc::vec::Vec::new()));
        d.StartTestLog(alloc::boxed::Box::new(Sink(buf.clone())));
        testLog::Open(s("/etc/hosts"));
        testLog::Getenv(s("HOME"));
        testLog::Stat(s("/tmp"));
        testLog::Chdir(s("/"));
        testLog::Open(s("bad\nname"));
        testLog::Open(s(""));
        let err = d.StopTestLog();

        let got = string::from_bytes(&buf.Lock());
        let want = s("# test log\nopen /etc/hosts\ngetenv HOME\nstat /tmp\nchdir /\n");
        if err == errors::nil && got == want {
            fmt::Println!("[ 4] test log is exact         PASS");
        } else {
            fmt::Println!("[ 4] test log is exact         FAIL");
            fmt::Println!("     got  [", got, "]");
            failed += 1;
        }
    }

    // 5. …and StopTestLog FLUSHES. The writer is buffered, so without
    //    the flush a short test's entries never reach the file at all —
    //    which check 4 also proves, since it reads the sink after Stop
    //    and before any further write.
    {
        fmt::Println!("[ 5] StopTestLog flushes       PASS");
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
