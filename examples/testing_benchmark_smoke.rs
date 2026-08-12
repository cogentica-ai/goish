// testing_benchmark_smoke — pin src/testing/benchmark.rs against
// Go 1.25.5.
//
// Every expectation is the literal output of running the real Go code
// through an in-package ref test:
//
//   scripts/goref.sh testing bench_ref.go
//     prettyPrint(0)          = "         0 ns/op"
//     prettyPrint(999.95)     = "      1000 ns/op"
//     prettyPrint(999.94)     = "       999.9 ns/op"
//     prettyPrint(99.995)     = "       100.0 ns/op"
//     prettyPrint(99.994)     = "        99.99 ns/op"
//     prettyPrint(9.9995)     = "        10.00 ns/op"
//     prettyPrint(0.99995)    = "         1.000 ns/op"
//     prettyPrint(0.099995)   = "         0.1000 ns/op"
//     prettyPrint(0.0099995)  = "         0.01000 ns/op"
//     prettyPrint(0.00099995) = "         0.001000 ns/op"
//     prettyPrint(0.0001)     = "         0.0001000 ns/op"
//     N=100 T=5s Bytes=1024 MemAllocs=250 MemBytes=8000:
//       NsPerOp=50000000 AllocsPerOp=2 AllocedBytesPerOp=80
//       mbPerSec=0.02048
//       String   = "     100\t  50000000 ns/op\t   0.02 MB/s"
//       MemString= "      80 B/op\t       2 allocs/op"
//     N=0: every derived metric is 0
//     Extra overrides: NsPerOp=42 AllocsPerOp=7 B/op=9 mbPerSec=3.5
//       String = "      10\t        42.00 ns/op\t   3.50 MB/s\t         1.250 custom"
//     benchmarkName(Foo,1)="Foo"  benchmarkName(Foo,8)="Foo-8"
//     predictN(1e9,1,0,1)=100         (prevns==0 rounds up to 1)
//     predictN(1e9,100,1000,100)=10000
//     predictN(1e9,1,1,1)=100
//     predictN(1e9,1e6,1000,1e6)=100000000
//     predictN(1e9,1,1e9,5)=6         (at least last+1)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::testing::benchmark::{benchmarkName, predictN, prettyPrint, BenchmarkResult};
use goish::time;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. prettyPrint's field widths, at every bracket boundary. These
    //    are the values where Go switches format, so an off-by-one in
    //    the ladder shows up here and nowhere else.
    {
        let cases: &[(f64, &str)] = &[
            (0.0, "         0 ns/op"),
            (1000.0, "      1000 ns/op"),
            (999.95, "      1000 ns/op"),
            (999.94, "       999.9 ns/op"),
            (100.0, "       100.0 ns/op"),
            (99.995, "       100.0 ns/op"),
            (99.994, "        99.99 ns/op"),
            (10.0, "        10.00 ns/op"),
            (9.9995, "        10.00 ns/op"),
            (1.0, "         1.000 ns/op"),
            (0.99995, "         1.000 ns/op"),
            (0.1, "         0.1000 ns/op"),
            (0.099995, "         0.1000 ns/op"),
            (0.01, "         0.01000 ns/op"),
            (0.0099995, "         0.01000 ns/op"),
            (0.001, "         0.001000 ns/op"),
            (0.00099995, "         0.001000 ns/op"),
            (0.0001, "         0.0001000 ns/op"),
        ];
        let mut ok = true;
        for (x, want) in cases.iter() {
            let mut buf = goish::bytes::Buffer::new();
            prettyPrint(&mut buf, *x, &s("ns/op"));
            let got = buf.String();
            if got != s(want) {
                fmt::Println!("    prettyPrint mismatch got [", got, "] want [", *want, "]");
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 1] prettyPrint brackets      PASS");
        } else {
            fmt::Println!("[ 1] prettyPrint brackets      FAIL");
            failed += 1;
        }
    }

    // 2. Derived per-operation metrics.
    {
        let mut r = BenchmarkResult::default();
        r.N = 100;
        r.T = time::Duration(5 * 1_000_000_000);
        r.Bytes = 1024;
        r.MemAllocs = 250;
        r.MemBytes = 8000;

        let mbs = r.mbPerSec();
        let mbs_ok = (mbs - 0.02048) < 1e-9 && (0.02048 - mbs) < 1e-9;
        if r.NsPerOp() == 50_000_000
            && r.AllocsPerOp() == 2
            && r.AllocedBytesPerOp() == 80
            && mbs_ok
        {
            fmt::Println!("[ 2] derived metrics           PASS");
        } else {
            fmt::Println!("[ 2] derived metrics           FAIL");
            failed += 1;
        }

        // 3. The full result line and the memory line.
        if r.String() == s("     100\t  50000000 ns/op\t   0.02 MB/s") {
            fmt::Println!("[ 3] BenchmarkResult.String    PASS");
        } else {
            fmt::Println!("[ 3] BenchmarkResult.String    FAIL got [", r.String(), "]");
            failed += 1;
        }
        if r.MemString() == s("      80 B/op\t       2 allocs/op") {
            fmt::Println!("[ 4] BenchmarkResult.MemString PASS");
        } else {
            fmt::Println!("[ 4] BenchmarkResult.MemString FAIL got [", r.MemString(), "]");
            failed += 1;
        }
    }

    // 5. N == 0 must not divide by zero; every metric reads 0.
    {
        let mut z = BenchmarkResult::default();
        z.T = time::Duration(1_000_000_000);
        if z.NsPerOp() == 0
            && z.AllocsPerOp() == 0
            && z.AllocedBytesPerOp() == 0
            && z.mbPerSec() == 0.0
        {
            fmt::Println!("[ 5] zero N is safe            PASS");
        } else {
            fmt::Println!("[ 5] zero N is safe            FAIL");
            failed += 1;
        }
    }

    // 6. Extra metrics override the computed ones, and an unrecognised
    //    key is appended to the line while the four built-ins are not.
    {
        let mut e = BenchmarkResult::default();
        e.N = 10;
        e.T = time::Duration(1_000_000_000);
        e.Extra.Set(s("ns/op"), 42.0);
        e.Extra.Set(s("allocs/op"), 7.0);
        e.Extra.Set(s("B/op"), 9.0);
        e.Extra.Set(s("MB/s"), 3.5);
        e.Extra.Set(s("custom"), 1.25);

        let overridden = e.NsPerOp() == 42
            && e.AllocsPerOp() == 7
            && e.AllocedBytesPerOp() == 9
            && e.mbPerSec() == 3.5;
        let line = e.String();
        let want = s("      10\t        42.00 ns/op\t   3.50 MB/s\t         1.250 custom");
        if overridden && line == want {
            fmt::Println!("[ 6] Extra overrides           PASS");
        } else {
            fmt::Println!("[ 6] Extra overrides           FAIL got [", line, "]");
            failed += 1;
        }
    }

    // 7. benchmarkName appends -N only when N != 1.
    {
        if benchmarkName(&s("Foo"), 1) == s("Foo") && benchmarkName(&s("Foo"), 8) == s("Foo-8") {
            fmt::Println!("[ 7] benchmarkName             PASS");
        } else {
            fmt::Println!("[ 7] benchmarkName             FAIL");
            failed += 1;
        }
    }

    // 8. predictN, including the divide-by-zero dodge (prevns == 0),
    //    the 100x growth cap, the 1e9 ceiling, and the last+1 floor.
    {
        let cases: &[(i64, i64, i64, i64, i64)] = &[
            (1_000_000_000, 1, 0, 1, 100),
            (1_000_000_000, 100, 1000, 100, 10_000),
            (1_000_000_000, 1, 1, 1, 100),
            (1_000_000_000, 1_000_000, 1000, 1_000_000, 100_000_000),
            (1_000_000_000, 1, 1_000_000_000, 5, 6),
        ];
        let mut ok = true;
        for (goalns, prevIters, prevns, last, want) in cases.iter() {
            let got = predictN(*goalns, *prevIters, *prevns, *last);
            if got as i64 != *want {
                fmt::Println!("    predictN mismatch got ", got as i64, " want ", *want);
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 8] predictN                  PASS");
        } else {
            fmt::Println!("[ 8] predictN                  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
