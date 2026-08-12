// go: file testing/benchmark.go decls: BenchmarkResult, BenchmarkResult.NsPerOp, BenchmarkResult.mbPerSec, BenchmarkResult.AllocsPerOp, BenchmarkResult.AllocedBytesPerOp, BenchmarkResult.String, BenchmarkResult.MemString, prettyPrint, benchmarkName, predictN
//
// testing/benchmark.go — the result type a benchmark reports, its
// derived per-operation metrics, and the column formatting `go test
// -bench` prints.
//
// **Partial port.** `B` itself — the timer, the iteration loop,
// RunParallel, and the runner that grows N until the measurement is
// long enough — is not here yet. Two things block it, both recorded so
// the next pass does not have to rediscover them:
//
//   * `b.ReportAllocs` and the B/op + allocs/op columns read
//     `runtime.ReadMemStats`, which goish does not have. mheap and
//     mcentral track the underlying numbers, so this is a matter of
//     exposing a Go-shaped MemStats rather than new accounting.
//   * `B.Loop`'s fast path is compiled specially by cmd/compile so the
//     loop body is not optimised away. goish is a library and has no
//     say in that.
//
// Everything in this file is reachable without either: pure arithmetic
// over a BenchmarkResult a caller filled in, plus the formatting.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gostring::string;
use crate::types::{float64, int, int64, uint64};

// go: sdk 1.25.5 testing/benchmark.go:531-540 BenchmarkResult
/// Go: "The results of a benchmark run."
#[derive(Clone, Default)]
pub struct BenchmarkResult {
    /// Go: "The number of iterations."
    pub N: int,
    /// Go: "The total time taken."
    pub T: crate::time::Duration,
    /// Go: "Bytes processed in one iteration."
    pub Bytes: int64,
    /// Go: "The total number of memory allocations."
    pub MemAllocs: uint64,
    /// Go: "The total number of bytes allocated."
    pub MemBytes: uint64,

    /// Go: "Extra records additional metrics reported by ReportMetric."
    pub Extra: crate::map<string, float64>,
}

impl BenchmarkResult {
    // go: sdk 1.25.5 testing/benchmark.go:543-551 BenchmarkResult.NsPerOp
    /// Go: nanoseconds per operation, or the `ns/op` metric if one was
    /// reported through `ReportMetric`.
    pub fn NsPerOp(&self) -> int64 {
        // Go: if v, ok := r.Extra["ns/op"]; ok { return int64(v) }
        let (v, ok) = self.Extra.Get(string::from_static("ns/op"));
        if ok {
            return v as int64;
        }
        // Go: if r.N <= 0 { return 0 }
        //     return r.T.Nanoseconds() / int64(r.N)
        if self.N <= 0 {
            return 0;
        }
        return self.T.Nanoseconds() / (self.N as int64);
    }

    // go: sdk 1.25.5 testing/benchmark.go:554-562 BenchmarkResult.mbPerSec
    /// Go: megabytes processed per second, from `Bytes` and the elapsed
    /// time, or the reported `MB/s` metric.
    pub fn mbPerSec(&self) -> float64 {
        // Go: if v, ok := r.Extra["MB/s"]; ok { return v }
        let (v, ok) = self.Extra.Get(string::from_static("MB/s"));
        if ok {
            return v;
        }
        // Go: if r.Bytes <= 0 || r.T <= 0 || r.N <= 0 { return 0 }
        if self.Bytes <= 0 || self.T.0 <= 0 || self.N <= 0 {
            return 0.0;
        }
        // Go: return (float64(r.Bytes) * float64(r.N) / 1e6) / r.T.Seconds()
        return ((self.Bytes as float64) * (self.N as float64) / 1e6) / self.T.Seconds();
    }

    // go: sdk 1.25.5 testing/benchmark.go:566-574 BenchmarkResult.AllocsPerOp
    /// Go: allocations per operation, or the reported `allocs/op`.
    pub fn AllocsPerOp(&self) -> int64 {
        let (v, ok) = self.Extra.Get(string::from_static("allocs/op"));
        if ok {
            return v as int64;
        }
        if self.N <= 0 {
            return 0;
        }
        return (self.MemAllocs as int64) / (self.N as int64);
    }

    // go: sdk 1.25.5 testing/benchmark.go:578-586 BenchmarkResult.AllocedBytesPerOp
    /// Go: bytes allocated per operation, or the reported `B/op`.
    pub fn AllocedBytesPerOp(&self) -> int64 {
        let (v, ok) = self.Extra.Get(string::from_static("B/op"));
        if ok {
            return v as int64;
        }
        if self.N <= 0 {
            return 0;
        }
        return (self.MemBytes as int64) / (self.N as int64);
    }

    // go: sdk 1.25.5 testing/benchmark.go:595-630 BenchmarkResult.String
    /// Go: "String returns a summary of the benchmark results. It
    /// follows the benchmark result line format from
    /// https://golang.org/design/14313-benchmark-format, not including
    /// the benchmark name. Extra metrics override built-in metrics of
    /// the same name. String does not include allocs/op or B/op, since
    /// those are reported by MemString."
    pub fn String(&self) -> string {
        let mut buf: Vec<u8> = Vec::new();
        // Go: fmt.Fprintf(buf, "%8d", r.N)
        push(&mut buf, crate::fmt::Sprintf!("%8d", self.N));

        // Go: get ns/op as a float, falling back to T/N.
        let (ns_extra, ok) = self.Extra.Get(string::from_static("ns/op"));
        let ns: float64 = if ok {
            ns_extra
        } else {
            (self.T.Nanoseconds() as float64) / (self.N as float64)
        };
        if ns != 0.0 {
            buf.push(b'\t');
            prettyPrint(&mut buf, ns, &string::from_static("ns/op"));
        }

        // Go: if mbs := r.mbPerSec(); mbs != 0 {
        //         fmt.Fprintf(buf, "\t%7.2f MB/s", mbs) }
        let mbs = self.mbPerSec();
        if mbs != 0.0 {
            push(&mut buf, crate::fmt::Sprintf!("\t%7.2f MB/s", mbs));
        }

        // Go: "Print extra metrics that aren't represented in the
        // standard metrics." Sorted, so the line is deterministic.
        let mut extraKeys: Vec<string> = Vec::new();
        for k in self.Extra.Keys().to_vec().into_iter() {
            let ks: &str = k.as_ref();
            match ks {
                // Go: built-in metrics reported elsewhere.
                "ns/op" | "MB/s" | "B/op" | "allocs/op" => {
                    continue;
                }
                _ => {}
            }
            extraKeys.push(k);
        }
        extraKeys.sort_by(|a, b| {
            let (x, y): (&str, &str) = (a.as_ref(), b.as_ref());
            return x.cmp(y);
        });
        for k in extraKeys.iter() {
            buf.push(b'\t');
            let (v, _) = self.Extra.Get(k.clone());
            prettyPrint(&mut buf, v, k);
        }
        return string::from_bytes(&buf);
    }

    // go: sdk 1.25.5 testing/benchmark.go:660-663 BenchmarkResult.MemString
    /// Go: "MemString returns r.AllocedBytesPerOp and r.AllocsPerOp in
    /// the same format as 'go test'."
    pub fn MemString(&self) -> string {
        // Go: fmt.Sprintf("%8d B/op\t%8d allocs/op",
        //         r.AllocedBytesPerOp(), r.AllocsPerOp())
        return crate::fmt::Sprintf!(
            "%8d B/op\t%8d allocs/op",
            self.AllocedBytesPerOp(),
            self.AllocsPerOp()
        );
    }
}

// go: none — goish idiom: Go writes through an `io.Writer`
// (`fmt.Fprintf(buf, ...)` on a `strings.Builder`). goish's callers
// here all build one byte vector, so the helper appends instead of
// going through the writer indirection.
fn push(buf: &mut Vec<u8>, s: string) {
    buf.extend_from_slice(s.as_bytes());
}

// go: sdk 1.25.5 testing/benchmark.go:632-657 prettyPrint
/// Go: "Print all numbers with 10 places before the decimal point and
/// small numbers with four sig figs. Field widths are chosen to fit the
/// whole part in 10 places while aligning the decimal point of all
/// fractional formats."
///
/// Deviation: Go takes an `io.Writer`; goish appends to the caller's
/// buffer, which is what both call sites want.
pub fn prettyPrint(w: &mut Vec<u8>, x: float64, unit: &string) {
    // Go: switch y := math.Abs(x); {
    let y = crate::math::Abs(x);
    let s: string = if y == 0.0 || y >= 999.95 {
        crate::fmt::Sprintf!("%10.0f %s", x, unit.clone())
    } else if y >= 99.995 {
        crate::fmt::Sprintf!("%12.1f %s", x, unit.clone())
    } else if y >= 9.9995 {
        crate::fmt::Sprintf!("%13.2f %s", x, unit.clone())
    } else if y >= 0.99995 {
        crate::fmt::Sprintf!("%14.3f %s", x, unit.clone())
    } else if y >= 0.099995 {
        crate::fmt::Sprintf!("%15.4f %s", x, unit.clone())
    } else if y >= 0.0099995 {
        crate::fmt::Sprintf!("%16.5f %s", x, unit.clone())
    } else if y >= 0.00099995 {
        crate::fmt::Sprintf!("%17.6f %s", x, unit.clone())
    } else {
        crate::fmt::Sprintf!("%18.7f %s", x, unit.clone())
    };
    w.extend_from_slice(s.as_bytes());
}

// go: sdk 1.25.5 testing/benchmark.go:666-671 benchmarkName
/// Go: append `-N` to a benchmark's name when it ran with a GOMAXPROCS
/// other than 1.
pub fn benchmarkName(name: &string, n: int) -> string {
    // Go: if n != 1 { return fmt.Sprintf("%s-%d", name, n) }
    //     return name
    if n != 1 {
        return crate::fmt::Sprintf!("%s-%d", name.clone(), n);
    }
    return name.clone();
}

// go: sdk 1.25.5 testing/benchmark.go:301-322 predictN
/// Go: choose the next iteration count from the previous run's timing,
/// aiming at `goalns` total nanoseconds.
///
/// Go: "Order of operations matters. For very fast benchmarks,
/// prevIters ~= prevns. If you divide first, you get 0 or 1, which can
/// hide an order of magnitude in execution time. So multiply first,
/// then divide."
pub fn predictN(goalns: int64, prevIters: int64, prevns: int64, last: int64) -> int {
    // Go: if prevns == 0 { // Round up to dodge divide by zero.
    //         prevns = 1 }
    let prevns = if prevns == 0 { 1 } else { prevns };

    let mut n: int64 = goalns * prevIters / prevns;
    // Go: "Run more iterations than we think we'll need (1.2x)."
    n += n / 5;
    // Go: "Don't grow too fast in case we had timing errors previously."
    n = n.min(100 * last);
    // Go: "Be sure to run at least one more than last time."
    n = n.max(last + 1);
    // Go: "Don't run more than 1e9 times."
    n = n.min(1_000_000_000);
    return n as int;
}
