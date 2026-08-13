// go: file testing/benchmark.go decls: B.Loop, B.loopSlowPath, B.stopOrScaleBLoop, B.run1, benchState.processBench, runBenchmarks, RunBenchmarks, B.Run, B.runN, B.launch, B.doBench, B.run, Benchmark, B.RunParallel, PB.Next, B.add, B.trimOutput, B.SetParallelism, durationOrCountFlag.String, durationOrCountFlag.Set, B.StartTimer, B.StopTimer, B.ResetTimer, B.SetBytes, B.ReportAllocs, B.Elapsed, B.ReportMetric, BenchmarkResult.NsPerOp, BenchmarkResult.mbPerSec, BenchmarkResult.AllocsPerOp, BenchmarkResult.AllocedBytesPerOp, BenchmarkResult.String, BenchmarkResult.MemString, prettyPrint, benchmarkName, predictN
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
//
// goishlint:ignore GOISH018 Benchmark, Loop, Next, RunParallel, SetParallelism, RunBenchmarks, checkParallel, Write, initBenchmarkFlags, trimOutput — B, PB and the benchmark runner are not ported; see the note above on ReadMemStats and B.Loop.
// goishlint:ignore GOISH021 benchState, benchmarkLock, memStats, unitMetric, discard, hideStdoutForTesting, labelsOnce — same: the runner's types and package state come with the runner.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gostring::string;
use crate::types::{float64, int, int64, uint64};
use crate::{float64 as to_float64, int as to_int, int64 as to_int64};

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
            return to_int64(v);
        }
        // Go: if r.N <= 0 { return 0 }
        //     return r.T.Nanoseconds() / int64(r.N)
        if self.N <= 0 {
            return 0;
        }
        return self.T.Nanoseconds() / to_int64(self.N);
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
        return (to_float64(self.Bytes) * to_float64(self.N) / 1e6) / self.T.Seconds();
    }

    // go: sdk 1.25.5 testing/benchmark.go:566-574 BenchmarkResult.AllocsPerOp
    /// Go: allocations per operation, or the reported `allocs/op`.
    pub fn AllocsPerOp(&self) -> int64 {
        let (v, ok) = self.Extra.Get(string::from_static("allocs/op"));
        if ok {
            return to_int64(v);
        }
        if self.N <= 0 {
            return 0;
        }
        return to_int64(self.MemAllocs) / to_int64(self.N);
    }

    // go: sdk 1.25.5 testing/benchmark.go:578-586 BenchmarkResult.AllocedBytesPerOp
    /// Go: bytes allocated per operation, or the reported `B/op`.
    pub fn AllocedBytesPerOp(&self) -> int64 {
        let (v, ok) = self.Extra.Get(string::from_static("B/op"));
        if ok {
            return to_int64(v);
        }
        if self.N <= 0 {
            return 0;
        }
        return to_int64(self.MemBytes) / to_int64(self.N);
    }

    // go: sdk 1.25.5 testing/benchmark.go:595-630 BenchmarkResult.String
    /// Go: "String returns a summary of the benchmark results. It
    /// follows the benchmark result line format from
    /// https://golang.org/design/14313-benchmark-format, not including
    /// the benchmark name. Extra metrics override built-in metrics of
    /// the same name. String does not include allocs/op or B/op, since
    /// those are reported by MemString."
    pub fn String(&self) -> string {
        // Go builds into a `strings.Builder`, which is an io.Writer;
        // goish's equivalent is bytes::Buffer, so prettyPrint keeps
        // Go's `w io.Writer` parameter instead of taking a raw Vec.
        let mut buf = crate::bytes::Buffer::new();
        // Go: fmt.Fprintf(buf, "%8d", r.N)
        push(&mut buf, crate::fmt::Sprintf!("%8d", self.N));

        // Go: get ns/op as a float, falling back to T/N.
        let (ns_extra, ok) = self.Extra.Get(string::from_static("ns/op"));
        let ns: float64 = if ok {
            ns_extra
        } else {
            to_float64(self.T.Nanoseconds()) / to_float64(self.N)
        };
        if ns != 0.0 {
            push(&mut buf, string::from_static("\t"));
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
            push(&mut buf, string::from_static("\t"));
            let (v, _) = self.Extra.Get(k.clone());
            prettyPrint(&mut buf, v, k);
        }
        return buf.String();
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
fn push(buf: &mut crate::bytes::Buffer, s: string) {
    let _ = crate::io::Writer::Write(buf, crate::slice::__from_vec(s.as_bytes().to_vec()));
}

// go: sdk 1.25.5 testing/benchmark.go:632-657 prettyPrint
/// Go: "Print all numbers with 10 places before the decimal point and
/// small numbers with four sig figs. Field widths are chosen to fit the
/// whole part in 10 places while aligning the decimal point of all
/// fractional formats."
///
pub fn prettyPrint(w: &mut dyn crate::io::Writer, x: float64, unit: &string) {
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
    let _ = w.Write(crate::slice::__from_vec(s.as_bytes().to_vec()));
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
    return to_int(n);
}

// ─── B — the benchmark handle ────────────────────────────────────────

// goishlint:ignore GOISH019 B — three fields absent, each because the
// machinery that reads it is absent: `loop`/`loopPoison*` (B.Loop needs
// cmd/compile to keep the loop body from being optimised away),
// `bstate` (the `go test -bench` driver), and `importPath` +
// `ctx`/`cancelCtx` (printed and cancelled by that driver and B.Loop).
// Go's embedded `common` is present as `Arc<TState>` — the shape `T`
// uses — rather than embedded.
// go: sdk 1.25.5 testing/benchmark.go:94-133 B
/// Go: "B is a type passed to Benchmark functions to manage benchmark
/// timing and control the number of iterations."
///
/// The timer methods, the metric derivations, `RunParallel`, and the
/// `Benchmark`/`runN`/`launch`/`doBench`/`Run` runner are all here. See
/// the ignore above for what is not and why.
pub struct B {
    /// Go: "The number of iterations."
    pub N: int,
    bytes: int64,
    timerOn: bool,
    showAllocResult: bool,
    /// Go: "The initial states of memStats.Mallocs and
    /// memStats.TotalAlloc."
    startAllocs: uint64,
    startBytes: uint64,
    /// Go: "The net total of this test after being run."
    netAllocs: uint64,
    netBytes: uint64,
    /// Go: "Extra metrics collected by ReportMetric."
    extra: crate::map<string, float64>,
    start: crate::time::Time,
    duration: crate::time::Duration,
    /// Go: `B.result BenchmarkResult` — the aggregate a parent
    /// benchmark accumulates from its sub-benchmarks.
    result: BenchmarkResult,
    /// Go: `B.missingBytes bool` — "one of the subbenchmarks does not
    /// have bytes set."
    missingBytes: bool,
    /// Go: `B.parallelism int` — "RunParallel creates parallelism*
    /// GOMAXPROCS goroutines".
    parallelism: int,
    /// Go: `B.output []byte` — what the benchmark logged.
    output: Vec<crate::types::byte>,
    /// Go: `B` embeds `common`, which is where Failed/Fatal/Log live.
    /// goish's `T` holds its common as `Arc<TState>` rather than
    /// embedding it; `B` now does the same, so RunParallel's final
    /// check reads the real failure state instead of a private flag.
    pub(crate) state: alloc::sync::Arc<crate::testing::TState>,
    /// Go: "number of iterations in the previous run".
    previousN: int,
    /// Go: "total duration of the previous run".
    previousDuration: crate::time::Duration,
    /// Go: `B.benchFunc func(b *B)` — the benchmark body.
    benchFunc: Option<alloc::sync::Arc<dyn Fn(&mut B) + Send + Sync>>,
    /// Go: `B.benchTime durationOrCountFlag` — a copy of -benchtime.
    benchTime: durationOrCountFlag,
    /// Go: `B.loop struct{ n, i uint64; done bool }` — B.Loop's state.
    r#loop: loopState,
}

/// Go: `B.loop`'s anonymous struct, named because Rust has none.
#[derive(Default, Clone, Copy)]
struct loopState {
    /// Go: "n is the target number of iterations. It gets bumped up as
    /// we go. When the benchmark loop is done, we commit this to b.N so
    /// users can do reporting based on it, but we avoid exposing it
    /// until then."
    n: crate::types::uint64,
    /// Go: "i is the current Loop iteration. It's strictly
    /// monotonically increasing toward n. The high bit is used to
    /// poison the Loop fast path and fall back to the slow path."
    i: crate::types::uint64,
    /// Go: "set when B.Loop return false".
    done: bool,
}

impl Default for B {
    // go: none — goish idiom: `B` used to derive Default; the
    // `Arc<TState>` it now holds is not Default, so the derive is
    // written out. Every other field keeps its zero value.
    fn default() -> Self {
        return B {
            N: 0,
            bytes: 0,
            timerOn: false,
            showAllocResult: false,
            startAllocs: 0,
            startBytes: 0,
            netAllocs: 0,
            netBytes: 0,
            extra: crate::map::new(),
            start: crate::time::Time::default(),
            duration: crate::time::Duration(0),
            result: BenchmarkResult::default(),
            missingBytes: false,
            parallelism: 1,
            output: Vec::new(),
            state: alloc::sync::Arc::new(crate::testing::TState::new()),
            previousN: 0,
            previousDuration: crate::time::Duration(0),
            benchFunc: None,
            benchTime: benchTime(),
            r#loop: loopState::default(),
        };
    }
}

impl B {
    // go: sdk 1.25.5 testing/benchmark.go:138-147 B.StartTimer
    /// Go: "StartTimer starts timing a test. This function is called
    /// automatically before a benchmark starts, but it can also be used
    /// to resume timing after a call to StopTimer."
    ///
    /// The memory sample is taken here, not just the clock, so that
    /// allocations made while the timer is stopped are excluded from
    /// the reported allocs/op.
    pub fn StartTimer(&mut self) {
        if !self.timerOn {
            let mut memStats = crate::runtime::MemStats::default();
            crate::runtime::ReadMemStats(&mut memStats);
            self.startAllocs = memStats.Mallocs;
            self.startBytes = memStats.TotalAlloc;
            self.start = crate::time::Now();
            self.timerOn = true;
            // Go: `b.loop.i &^= loopPoisonTimer`.
            self.r#loop.i &= !loopPoisonTimer;
        }
    }

    // go: sdk 1.25.5 testing/benchmark.go:151-161 B.StopTimer
    /// Go: "StopTimer stops timing a test. This can be used to pause
    /// the timer while performing complex initialization that you don't
    /// want to measure."
    pub fn StopTimer(&mut self) {
        if self.timerOn {
            self.duration = crate::time::Duration(
                self.duration.0 + crate::time::Since(self.start).0,
            );
            let mut memStats = crate::runtime::MemStats::default();
            crate::runtime::ReadMemStats(&mut memStats);
            self.netAllocs += memStats.Mallocs - self.startAllocs;
            self.netBytes += memStats.TotalAlloc - self.startBytes;
            self.timerOn = false;
            // Go: "If we hit B.Loop with the timer stopped, fail."
            self.r#loop.i |= loopPoisonTimer;
        }
    }

    // go: sdk 1.25.5 testing/benchmark.go:166-183 B.ResetTimer
    /// Go: "ResetTimer zeroes the elapsed benchmark time and memory
    /// allocation counters and deletes user-reported metrics. It does
    /// not affect whether the timer is running."
    pub fn ResetTimer(&mut self) {
        // Go: allocate or clear the extra map BEFORE reading memory
        // stats, so the map's own allocation is not charged to the
        // benchmark.
        self.extra = crate::map::new();
        if self.timerOn {
            let mut memStats = crate::runtime::MemStats::default();
            crate::runtime::ReadMemStats(&mut memStats);
            self.startAllocs = memStats.Mallocs;
            self.startBytes = memStats.TotalAlloc;
            self.start = crate::time::Now();
        }
        self.duration = crate::time::Duration(0);
        self.netAllocs = 0;
        self.netBytes = 0;
    }

    // go: sdk 1.25.5 testing/benchmark.go:187-187 B.SetBytes
    /// Go: "SetBytes records the number of bytes processed in a single
    /// operation. If this is called, the benchmark will report ns/op
    /// and MB/s."
    pub fn SetBytes(&mut self, n: int64) {
        self.bytes = n;
    }

    // go: sdk 1.25.5 testing/benchmark.go:192-194 B.ReportAllocs
    /// Go: "ReportAllocs enables malloc statistics for this benchmark.
    /// It is equivalent to setting -test.benchmem, but it only affects
    /// the benchmark function that calls ReportAllocs."
    pub fn ReportAllocs(&mut self) {
        self.showAllocResult = true;
    }

    // go: sdk 1.25.5 testing/benchmark.go:364-370 B.Elapsed
    /// Go: "Elapsed returns the measured elapsed time of the benchmark.
    /// The duration reported by Elapsed matches the one measured by
    /// StartTimer, and ResetTimer."
    pub fn Elapsed(&self) -> crate::time::Duration {
        let mut d = self.duration;
        if self.timerOn {
            d = crate::time::Duration(d.0 + crate::time::Since(self.start).0);
        }
        return d;
    }

    // go: sdk 1.25.5 testing/benchmark.go:381-389 B.ReportMetric
    /// Go: "ReportMetric adds "n unit" to the reported benchmark
    /// results. If the metric is per-iteration, the caller should divide
    /// by b.N, and by convention units should end in "/op". ReportMetric
    /// overrides any previously reported value for the same unit."
    ///
    /// Both panics are Go's. A unit with a space in it would break the
    /// benchmark output format, which is whitespace-delimited, so a
    /// silent accept would corrupt every downstream parser.
    pub fn ReportMetric(&mut self, n: float64, unit: &string) {
        // Go: if unit == "" { panic("metric unit must not be empty") }
        if unit.Len() == 0 {
            panic!("metric unit must not be empty");
        }
        // Go: if strings.IndexFunc(unit, unicode.IsSpace) >= 0 {
        //         panic("metric unit must not contain whitespace") }
        let u: &str = unit.as_ref();
        for c in u.chars() {
            let r: crate::types::rune = crate::rune(u32::from(c));
            if crate::unicode::IsSpace(r) {
                panic!("metric unit must not contain whitespace");
            }
        }
        self.extra.Set(unit.clone(), n);
    }

    // go: none — goish-only: assemble the BenchmarkResult a caller
    // reports. Go builds this inside `run1`/`doBench`, which belong to
    // the runner; exposing it lets a caller drive a benchmark by hand
    // (`StartTimer` / work / `StopTimer` / `Result`) without one.
    pub fn Result(&self) -> BenchmarkResult {
        let mut r = BenchmarkResult::default();
        r.N = self.N;
        r.T = self.Elapsed();
        r.Bytes = self.bytes;
        r.MemAllocs = self.netAllocs;
        r.MemBytes = self.netBytes;
        r.Extra = self.extra.clone();
        return r;
    }
}

// ─── the -benchtime flag's value type ────────────────────────────────

// go: sdk 1.25.5 testing/benchmark.go:38-42 durationOrCountFlag
/// Go: the value behind `-test.benchtime`, which accepts EITHER a
/// duration ("2s") or an iteration count ("100x"). The two are stored
/// in separate fields rather than a tagged union, and `n > 0` is what
/// distinguishes them.
#[derive(Clone, Copy, Default, PartialEq)]
#[allow(non_camel_case_types)]
pub struct durationOrCountFlag {
    pub d: crate::time::Duration,
    pub n: crate::types::int,
    pub allowZero: bool,
}

#[allow(non_snake_case)]
impl durationOrCountFlag {
    // go: sdk 1.25.5 testing/benchmark.go:44-49 durationOrCountFlag.String
    pub fn String(&self) -> crate::gostring::string {
        if self.n > 0 {
            return crate::fmt::Sprintf!("%dx", self.n);
        }
        return self.d.String();
    }

    // go: sdk 1.25.5 testing/benchmark.go:51-65 durationOrCountFlag.Set
    /// Note that a successful Set REPLACES the whole value, dropping
    /// `allowZero` — Go writes `*f = durationOrCountFlag{n: int(n)}`.
    /// That is deliberate on Go's part but easy to "fix" into a field
    /// assignment, which would let a later Set("0") through.
    pub fn Set(&mut self, s: crate::gostring::string) -> crate::errors::error {
        if crate::strings::HasSuffix(s.clone(), "x") {
            let body = s.slice(0, crate::types::int64::from(s.Len()) - 1);
            let (n, err) = crate::strconv::ParseInt(body, 10, 0);
            if err != crate::errors::nil || n < 0 || (!self.allowZero && n == 0) {
                return crate::errors::New(crate::gostring::string::from_static(
                    "invalid count",
                ));
            }
            *self = durationOrCountFlag {
                n: crate::int(n),
                ..Default::default()
            };
            return crate::errors::nil;
        }
        let (d, err) = crate::time::ParseDuration(s);
        if err != crate::errors::nil
            || d < crate::time::Duration(0)
            || (!self.allowZero && d == crate::time::Duration(0))
        {
            return crate::errors::New(crate::gostring::string::from_static(
                "invalid duration",
            ));
        }
        *self = durationOrCountFlag {
            d,
            ..Default::default()
        };
        return crate::errors::nil;
    }
}

// go: sdk 1.25.5 testing/benchmark.go:76-79 InternalBenchmark
/// Go: "An internal type but exported because it is cross-package; part
/// of the implementation of the 'go test' command."
///
/// Carried across ahead of the benchmark runner because `listTests`
/// names it, and listing benchmarks does not require running them.
#[allow(non_snake_case)]
pub struct InternalBenchmark {
    pub Name: crate::gostring::string,
    pub F: fn(&mut B),
}

#[allow(non_snake_case)]
impl B {
    // go: sdk 1.25.5 testing/benchmark.go:872-889 B.add
    /// Go: "add simulates running benchmarks in sequence in a single
    /// iteration. It is used to give some meaningful results in case of
    /// a benchmark that requires a lot of setup."
    ///
    /// `Bytes` is the awkward one: summing it across sub-benchmarks is
    /// meaningless unless EVERY one set it, so the first sub-benchmark
    /// without it poisons the total for good — the flag is never
    /// cleared, and the running sum is discarded at that point.
    pub fn add(&mut self, other: BenchmarkResult) {
        // Go: "The aggregated BenchmarkResults resemble running all
        // subbenchmarks as in sequence in a single benchmark."
        self.result.N = 1;
        self.result.T =
            crate::time::Duration(self.result.T.0 + other.NsPerOp());
        if other.Bytes == 0 {
            self.missingBytes = true;
            self.result.Bytes = 0;
        }
        if !self.missingBytes {
            self.result.Bytes += other.Bytes;
        }
        self.result.MemAllocs += crate::uint64(other.AllocsPerOp());
        self.result.MemBytes += crate::uint64(other.AllocedBytesPerOp());
    }

    // go: sdk 1.25.5 testing/benchmark.go:892-906 B.trimOutput
    /// Go: "The output is likely to appear multiple times because the
    /// benchmark is run multiple times, but at least it will be seen."
    ///
    /// Truncation is at the tenth NEWLINE, not at a byte count, so a
    /// benchmark that prints one enormous line is left intact while one
    /// that prints a hundred short ones is cut.
    pub fn trimOutput(&mut self) {
        const maxNewlines: int = 10;
        let mut nlCount: int = 0;
        let mut j = 0usize;
        while j < self.output.len() {
            if self.output[j] == b'\n' {
                nlCount += 1;
                if nlCount >= maxNewlines {
                    self.output.truncate(j);
                    self.output
                        .extend_from_slice(b"\n\t... [output truncated]\n");
                    break;
                }
            }
            j += 1;
        }
    }

    // go: sdk 1.25.5 testing/benchmark.go:989-993 B.SetParallelism
    /// Go: "SetParallelism sets the number of goroutines used by
    /// RunParallel to p*GOMAXPROCS. […] Call SetParallelism before
    /// RunParallel."
    ///
    /// A value below 1 is IGNORED rather than clamped or rejected —
    /// SetParallelism(0) leaves the previous setting in place.
    pub fn SetParallelism(&mut self, p: int) {
        if p >= 1 {
            self.parallelism = p;
        }
    }
}

// ─── RunParallel ─────────────────────────────────────────────────────

// go: sdk 1.25.5 testing/benchmark.go:909-914 PB
/// Go: "A PB is used by RunParallel for running parallel benchmarks."
///
/// The grain is why this type exists: workers claim iterations from the
/// shared counter in BATCHES, so the atomic is touched once per grain
/// rather than once per iteration.
#[allow(non_snake_case)]
pub struct PB {
    /// Go: "shared between all worker goroutines iteration counter".
    pub(crate) globalN: alloc::sync::Arc<core::sync::atomic::AtomicU64>,
    /// Go: "acquire that many iterations from globalN at once".
    pub(crate) grain: crate::types::uint64,
    /// Go: "local cache of acquired iterations".
    pub(crate) cache: crate::types::uint64,
    /// Go: "total number of iterations to execute (b.N)".
    pub(crate) bN: crate::types::uint64,
}

#[allow(non_snake_case)]
impl PB {
    // go: sdk 1.25.5 testing/benchmark.go:917-930 PB.Next
    /// Go: "Next reports whether there are more iterations to execute."
    ///
    /// The middle branch is the one that is easy to drop: when a batch
    /// would overshoot b.N, the worker takes the PARTIAL remainder
    /// rather than giving up. Without it the last `grain-1` iterations
    /// are never run and the benchmark quietly measures fewer
    /// operations than it reports.
    pub fn Next(&mut self) -> bool {
        if self.cache == 0 {
            let n = self
                .globalN
                .fetch_add(self.grain, core::sync::atomic::Ordering::AcqRel)
                + self.grain;
            if n <= self.bN {
                self.cache = self.grain;
            } else if n < self.bN + self.grain {
                self.cache = self.bN + self.grain - n;
            } else {
                return false;
            }
        }
        self.cache -= 1;
        return true;
    }
}

#[allow(non_snake_case)]
impl B {
    // go: none — goish idiom: Go's `B` embeds `common`, so `b.Failed()`
    // resolves to common.Failed through embedding. goish's `B` holds
    // its common as `Arc<TState>` (the same shape `T` uses), so the
    // delegation is written out. The port of common.Failed itself lives
    // in testing.rs.
    pub fn Failed(&self) -> bool {
        return self.state.failed.load(core::sync::atomic::Ordering::Acquire);
    }

    // go: sdk 1.25.5 testing/benchmark.go:945-984 B.RunParallel
    /// Go: "RunParallel runs a benchmark in parallel. It creates
    /// multiple goroutines and distributes b.N iterations among them."
    ///
    /// The grain is computed from the PREVIOUS run's rate so a batch is
    /// about 100µs of work: enough to amortise the atomic, short enough
    /// that a slow worker cannot hold the tail of the benchmark. It is
    /// clamped at both ends — below 1 it would spin on the atomic,
    /// above 1e4 one worker could hold 100µs/10ns of work while the
    /// others idle.
    pub fn RunParallel<F>(&mut self, body: F)
    where
        F: Fn(&mut PB) + Send + Sync + 'static,
    {
        if self.N == 0 {
            // Go: "Nothing to do when probing."
            return;
        }
        // Go: "Calculate grain size as number of iterations that take
        // ~100µs."
        let mut grain: crate::types::uint64 = 0;
        if self.previousN > 0 && self.previousDuration > crate::time::Duration(0) {
            grain = 100000 * crate::uint64(self.previousN)
                / crate::uint64(self.previousDuration.0);
        }
        if grain < 1 {
            grain = 1;
        }
        if grain > 10000 {
            grain = 10000;
        }

        let n = alloc::sync::Arc::new(core::sync::atomic::AtomicU64::new(0));
        let numProcs = self.parallelism * crate::runtime::GOMAXPROCS(0);
        let wg = alloc::sync::Arc::new(crate::sync::WaitGroup::new());
        let bN = crate::uint64(self.N);
        let body = alloc::sync::Arc::new(body);

        for _p in 0..numProcs {
            let n = n.clone();
            let wg2 = wg.clone();
            let body = body.clone();
            wg.Add(1);
            crate::go!(stack(64 * 1024), move || {
                let mut pb = PB {
                    globalN: n,
                    grain,
                    cache: 0,
                    bN,
                };
                body(&mut pb);
                wg2.Done();
            });
        }
        wg.Wait();

        // Go: a body that returned before Next() said stop has measured
        // fewer iterations than b.N claims, so the result would be a
        // lie. Fatal rather than a warning.
        if n.load(core::sync::atomic::Ordering::Acquire) <= bN && !self.Failed() {
            self.state
                .failed
                .store(true, core::sync::atomic::Ordering::Release);
            crate::fmt::Println!("RunParallel: body exited without pb.Next() == false");
        }
    }
}

// ─── the benchmark runner ────────────────────────────────────────────

// go: sdk 1.25.5 testing/benchmark.go:69 benchmarkLock
/// Go: "benchmarkLock ensures only one benchmark runs at a time." Two
/// benchmarks timing each other's allocations would both be wrong.
static benchmarkLock: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

// go: none — goish idiom: Go's `benchTime` is a package `var`
// initialised to `durationOrCountFlag{d: 1 * time.Second}`. Duration
// multiplication is not const in Rust, so it is a function returning
// the same value rather than a static.
/// Go: `var benchTime = durationOrCountFlag{d: 1 * time.Second}` — the
/// default -benchtime. A function here rather than a static because
/// Duration multiplication is not const.
#[allow(non_snake_case)]
fn benchTime() -> durationOrCountFlag {
    return durationOrCountFlag {
        d: crate::time::Duration(1_000_000_000),
        n: 0,
        allowZero: false,
    };
}

#[allow(non_snake_case)]
impl B {
    // go: sdk 1.25.5 testing/benchmark.go:197-227 B.runN
    // goishlint:ignore GOISH020 runN — Go's `b.loop` bookkeeping and
    // the ctx/cancelCtx it sets are for B.Loop, which needs cmd/compile
    // support and is not ported; there is nothing to reset and no
    // context to cancel.
    /// Go: run the benchmark body exactly n times, timed.
    ///
    /// benchmarkLock is held for the whole run: two benchmarks timing
    /// concurrently would each measure the other's allocations. The GC
    /// call before starting is Go "trying to get a comparable
    /// environment for each run by clearing garbage from previous
    /// runs"; goish has no GC, so there is nothing to clear.
    pub(crate) fn runN(&mut self, n: crate::types::int) {
        // Go: `benchmarkLock.Lock(); defer benchmarkLock.Unlock()`.
        // Explicit rather than a guard because B.Run releases this lock
        // and re-acquires it around a NESTED call — a pairing RAII
        // cannot express.
        benchmarkLock.LockManual();

        self.state.resetRaces();
        self.N = n;
        self.parallelism = 1;
        self.ResetTimer();
        self.StartTimer();
        if let Some(f) = self.benchFunc.clone() {
            f(self);
        }
        self.StopTimer();
        self.previousN = n;
        self.previousDuration = self.duration;

        // Go: `defer func() { b.runCleanup(normalPanic); b.checkRaces() }()`
        self.state.runCleanup();
        self.state.checkRaces();
        benchmarkLock.Unlock();
    }

    // go: sdk 1.25.5 testing/benchmark.go:328-359 B.launch
    /// Go: "launch launches the benchmark function. It gradually
    /// increases the number of benchmark iterations until the benchmark
    /// runs for the requested benchtime."
    ///
    /// The two arms are -benchtime=100x (a fixed count) and
    /// -benchtime=2s (a duration, reached by prediction). The duration
    /// arm stops on ANY of three conditions — failed, long enough, or
    /// 1e9 iterations — and the last is what keeps a benchmark whose
    /// body is essentially free from running forever.
    pub(crate) fn launch(&mut self) {
        if self.benchTime.n > 0 {
            // Go: "We already ran a single iteration in run1. If
            // -benchtime=1x was requested, use that result."
            if self.benchTime.n > 1 {
                self.runN(self.benchTime.n);
            }
        } else {
            let d = self.benchTime.d;
            let mut n: crate::types::int64 = 1;
            while !self.Failed() && self.duration < d && n < 1_000_000_000 {
                let last = n;
                let goalns = d.Nanoseconds();
                let prevIters = crate::int64(self.N);
                n = crate::int64(predictN(
                    goalns,
                    prevIters,
                    self.duration.Nanoseconds(),
                    last,
                ));
                self.runN(crate::int(n));
            }
        }
        self.result = BenchmarkResult {
            N: self.N,
            T: self.duration,
            Bytes: self.bytes,
            MemAllocs: self.netAllocs,
            MemBytes: self.netBytes,
            Extra: self.extra.clone(),
        };
    }

    // go: sdk 1.25.5 testing/benchmark.go:295-299 B.doBench
    // goishlint:ignore GOISH018 doBench — Go runs launch on its own
    // goroutine and waits on b.signal, so a FailNow inside the
    // benchmark unwinds that goroutine instead of the caller's. goish's
    // `B` is a `&mut` value that cannot cross a goroutine boundary, so
    // launch is called directly. The observable result is the same
    // unless the body calls FailNow, which would abort rather than
    // stopping the benchmark.
    pub(crate) fn doBench(&mut self) -> BenchmarkResult {
        self.launch();
        return self.result.clone();
    }

    // go: sdk 1.25.5 testing/benchmark.go:275-293 B.run
    // goishlint:ignore GOISH018 run — Go's version prints a goos/goarch/
    // pkg/cpu header once via labelsOnce and branches to
    // bstate.processBench when driven by `go test -bench`. goish has no
    // bstate driver, so only the func Benchmark path exists.
    pub(crate) fn run(&mut self) {
        self.doBench();
    }
}

// go: sdk 1.25.5 testing/benchmark.go:1003-1017 Benchmark
// goishlint:ignore GOISH018 Benchmark — Go calls run1 first and only
// proceeds if it returns true; run1's job is to bail out early when the
// benchmark registered sub-benchmarks or was skipped, neither of which
// goish's B can do yet. The single warm-up iteration run1 performs is
// kept, since launch's -benchtime=1x arm depends on it having happened.
/// Go: "Benchmark benchmarks a single function. It is useful for
/// creating custom benchmarks that do not use the 'go test' command."
#[allow(non_snake_case)]
pub fn Benchmark<F>(f: F) -> BenchmarkResult
where
    F: Fn(&mut B) + Send + Sync + 'static,
{
    let mut b = B::default();
    b.benchFunc = Some(alloc::sync::Arc::new(f));
    b.benchTime = benchTime();
    if b.run1() {
        b.run();
    }
    return b.result.clone();
}

#[allow(non_snake_case)]
impl B {
    // go: sdk 1.25.5 testing/benchmark.go:803-867 B.Run
    // goishlint:ignore GOISH018 Run — the bstate branches are absent:
    // goish has no `go test -bench` driver, so there is no matcher to
    // consult for the sub-benchmark's name and no partial-match case.
    // The goos/goarch/pkg/cpu header and the chatty name line go with
    // it. What remains is the path `func Benchmark` takes.
    /// Go: "Run benchmarks f as a subbenchmark with the given name. It
    /// reports whether there were any failures."
    ///
    /// The lock dance is the load-bearing part. A benchmark with
    /// sub-benchmarks is not itself measured, so it must RELEASE
    /// benchmarkLock before running them — otherwise the first
    /// sub-benchmark deadlocks against its own parent, which is still
    /// inside runN holding it.
    pub fn Run<F>(&mut self, name: crate::gostring::string, f: F) -> bool
    where
        F: Fn(&mut B) + Send + Sync + 'static,
    {
        // Go: "Since b has subbenchmarks, we will no longer run it as a
        // benchmark itself."
        self.state
            .hasSub
            .store(true, core::sync::atomic::Ordering::Release);
        benchmarkLock.Unlock();

        let benchName = if self.state.name.Lock().Len() == 0 {
            name
        } else {
            crate::fmt::Sprintf!("%s/%s", self.state.name.Lock().clone(), name)
        };

        let mut sub = B::default();
        *sub.state.name.Lock() = benchName;
        sub.state
            .bench
            .store(true, core::sync::atomic::Ordering::Release);
        sub.benchFunc = Some(alloc::sync::Arc::new(f));
        sub.benchTime = self.benchTime;

        // Go: `if sub.run1() { sub.run() }`. run1's early-outs need the
        // bstate driver; the warm-up iteration it performs is kept.
        if sub.run1() {
            sub.run();
        }
        self.add(sub.result.clone());

        // Go: `defer benchmarkLock.Lock()` — the parent is still inside
        // runN, which will Unlock on the way out, so the pair must
        // balance.
        benchmarkLock.LockManual();
        return !sub.Failed();
    }
}

// ─── the -bench driver ───────────────────────────────────────────────

// goishlint:ignore GOISH019 benchState — `match` is absent: goish's
// runBenchmarks filters with regexp::MatchString directly rather than
// threading a *matcher, since there is no generated main package to
// supply one.
// go: sdk 1.25.5 testing/benchmark.go:673-678 benchState
/// Go: the state shared across one `-bench` run — the name filter and
/// the column widths the result table is aligned to.
#[allow(non_camel_case_types, non_snake_case)]
pub struct benchState {
    /// Go: "The largest recorded benchmark name."
    pub maxLen: int,
    /// Go: "Maximum extension length."
    pub extLen: int,
}

#[allow(non_snake_case)]
impl benchState {
    // go: sdk 1.25.5 testing/benchmark.go:735-791 benchState.processBench
    // goishlint:ignore GOISH018 processBench — the chatty branches and
    // the `=== NAME` json line are absent (goish's benchmark path has
    // no chattyPrinter), as is the fresh-B rebuild for repeat runs,
    // which exists to give each -count iteration its own signal channel
    // and output buffer; goish re-runs the same B, whose timer state
    // runN resets anyway.
    /// Go: run one benchmark once per -cpu entry per -count, and print
    /// the aligned result line.
    ///
    /// The GOMAXPROCS check at the end is a real diagnostic, not
    /// bookkeeping: a benchmark that changed GOMAXPROCS and did not put
    /// it back would silently skew every benchmark after it, so the
    /// runner reports the culprit by name.
    pub fn processBench(&self, b: &mut B) {
        let (_, benchmarkMemory) = crate::testing::testing::__bench_flags();
        for (i, procs) in crate::testing::testing::cpuList().iter().enumerate() {
            for j in 0..crate::testing::testing::countFlag() {
                crate::runtime::GOMAXPROCS(*procs);
                let name = b.state.name.Lock().clone();
                let benchName = benchmarkName(&name, *procs);

                let r = b.doBench();
                if b.Failed() {
                    // Go: "We print it all, regardless, because we don't
                    // want to trim the reason the benchmark failed."
                    crate::fmt::Println!("--- FAIL: ", benchName.clone());
                    continue;
                }
                let mut results = r.String();
                if benchmarkMemory || b.showAllocResult {
                    results = crate::fmt::Sprintf!("%s\t%s", results, r.MemString());
                }
                crate::fmt::Println!(
                    crate::fmt::Sprintf!("%s\t%s", benchName.clone(), results)
                );

                let p = crate::runtime::GOMAXPROCS(-1);
                if p != *procs {
                    crate::fmt::Println!(
                        crate::fmt::Sprintf!(
                            "testing: %s left GOMAXPROCS set to %d",
                            benchName.clone(),
                            p
                        )
                    );
                }
                let _ = (i, j);
            }
        }
    }
}

// go: sdk 1.25.5 testing/benchmark.go:686-732 runBenchmarks
// goishlint:ignore GOISH020 runBenchmarks — Go takes `importPath` and
// the matchString func from the generated main package; goish has
// neither, and filters with regexp::MatchString, which is what Go's
// generated main passes.
/// Go: collect the benchmarks matching -test.bench, then run them.
///
/// The empty-pattern early return is why an ordinary `go test` run does
/// not benchmark anything: no -bench, no benchmarks, regardless of how
/// many are registered.
#[allow(non_snake_case)]
pub fn runBenchmarks(benchmarks: &[InternalBenchmark]) -> bool {
    let (pattern, _) = crate::testing::testing::__bench_flags();
    if pattern.Len() == 0 {
        return true;
    }

    let mut maxprocs: int = 1;
    for procs in crate::testing::testing::cpuList().iter() {
        if *procs > maxprocs {
            maxprocs = *procs;
        }
    }

    let mut st = benchState {
        maxLen: 0,
        extLen: benchmarkName(&crate::gostring::string::from_static(""), maxprocs).Len(),
    };

    let mut bs: Vec<&InternalBenchmark> = Vec::new();
    for bench in benchmarks.iter() {
        let (matched, _) = crate::regexp::MatchString(pattern.clone(), bench.Name.clone());
        if matched {
            bs.push(bench);
            let benchName = benchmarkName(&bench.Name, maxprocs);
            let l = benchName.Len() + st.extLen + 1;
            if l > st.maxLen {
                st.maxLen = l;
            }
        }
    }

    let mut failed = false;
    for bench in bs.into_iter() {
        let mut b = B::default();
        *b.state.name.Lock() = bench.Name.clone();
        b.state
            .bench
            .store(true, core::sync::atomic::Ordering::Release);
        b.benchFunc = Some(alloc::sync::Arc::new({
            let f = bench.F;
            move |x: &mut B| f(x)
        }));
        b.benchTime = benchTime();
        // Go runs everything under one "Main" B whose benchFunc calls
        // b.Run per benchmark; goish drives each directly, since
        // without a matcher the sub-naming Run performs is the only
        // thing that layer adds.
        b.run1();
        st.processBench(&mut b);
        if b.Failed() {
            failed = true;
        }
    }
    return !failed;
}

// go: sdk 1.25.5 testing/benchmark.go:682-684 RunBenchmarks
// goishlint:ignore GOISH020 RunBenchmarks — same dropped importPath and
// matchString parameters as runBenchmarks.
/// Go: "An internal function but exported because it is cross-package;
/// part of the implementation of the 'go test' command."
#[allow(non_snake_case)]
pub fn RunBenchmarks(benchmarks: &[InternalBenchmark]) -> bool {
    return runBenchmarks(benchmarks);
}

#[allow(non_snake_case)]
impl B {
    // go: sdk 1.25.5 testing/benchmark.go:231-269 B.run1
    // goishlint:ignore GOISH018 run1 — three absences, each because
    // what reads them is absent: the bstate maxLen extension (no
    // -bench column alignment without a bstate on B), the goroutine and
    // signal (goish's `B` is a `&mut` value that cannot cross a
    // goroutine boundary; the same deviation doBench carries), and the
    // chatty-gated output printing.
    /// Go: "run1 runs the first iteration of benchFunc. It reports
    /// whether more iterations of this benchmarks should be run."
    ///
    /// The return value is the point. `false` means "do not measure
    /// this" and covers three different situations: the benchmark
    /// FAILED, it registered sub-benchmarks (so it is a container, not
    /// a measurement), or it finished early via Skip. Collapsing that
    /// to a failure check alone would time container benchmarks and
    /// report meaningless numbers for them.
    pub(crate) fn run1(&mut self) -> bool {
        self.runN(1);
        if self.Failed() {
            return false;
        }
        // Go: "Only print the output if we know we are not going to
        // proceed. Otherwise it is printed in processBench."
        let finished = self.state.finished.load(core::sync::atomic::Ordering::Acquire);
        if self.state.hasSub.load(core::sync::atomic::Ordering::Acquire) || finished {
            return false;
        }
        return true;
    }
}

// ─── B.Loop ──────────────────────────────────────────────────────────

// go: sdk 1.25.5 testing/benchmark.go:520 loopPoisonTimer
/// Go: "The loopPoison constants can be OR'd into B.loop.i to cause it
/// to fall back to the slow path." Set by StopTimer, cleared by
/// StartTimer — so calling B.Loop with the timer stopped lands in the
/// slow path, which diagnoses it.
const loopPoisonTimer: crate::types::uint64 = 1u64 << 63;

// go: sdk 1.25.5 testing/benchmark.go:527 loopPoisonMask
/// Go: "the set of all loop poison bits."
const loopPoisonMask: crate::types::uint64 = !((1u64 << 63) - 1);

#[allow(non_snake_case)]
impl B {
    // go: sdk 1.25.5 testing/benchmark.go:497-515 B.Loop
    /// Go: "Loop returns true as long as the benchmark should continue
    /// running."
    ///
    /// **Caveat goish cannot fix.** cmd/compile recognises
    /// `for b.Loop()` and keeps the loop body from being optimised
    /// away. Nothing recognises it here, so a body whose result is
    /// unused may be eliminated in a release build and the benchmark
    /// will measure an empty loop. The state machine below is a
    /// faithful port; the optimisation barrier is not something a
    /// library can provide.
    pub fn Loop(&mut self) -> bool {
        // Go: "This is written such that the fast path is as fast as
        // possible and can be inlined."
        if self.r#loop.i < self.r#loop.n {
            self.r#loop.i += 1;
            return true;
        }
        return self.loopSlowPath();
    }

    // go: sdk 1.25.5 testing/benchmark.go:409-461 B.loopSlowPath
    /// Go: the three ways out of Loop's fast path — first call, target
    /// reached, or the timer was stopped.
    ///
    /// The poison bit is why the timer check works at all: StopTimer
    /// sets the high bit of `i`, which makes `i < n` false however few
    /// iterations have run, so the very next Loop call lands here and
    /// diagnoses it instead of silently timing nothing.
    pub(crate) fn loopSlowPath(&mut self) -> bool {
        if !self.timerOn {
            crate::fmt::Println!("B.Loop called with timer stopped");
            self.state
                .failed
                .store(true, core::sync::atomic::Ordering::Release);
            return false;
        }
        if self.r#loop.i & loopPoisonMask != 0 {
            panic!("unknown loop stop condition");
        }

        if self.r#loop.n == 0 {
            // Go: "It's the first call to b.Loop() in the benchmark
            // function."
            if self.benchTime.n > 0 {
                self.r#loop.n = crate::uint64(self.benchTime.n);
            } else {
                // Go: "Initialize target to 1 to kick start loop
                // scaling."
                self.r#loop.n = 1;
            }
            // Go: "Within a b.Loop loop, we don't use b.N (to avoid
            // confusion)."
            self.N = 0;
            self.ResetTimer();
            self.r#loop.i += 1;
            return true;
        }

        let more;
        if self.benchTime.n > 0 {
            if self.r#loop.i != crate::uint64(self.benchTime.n) {
                // Go: "We shouldn't be able to reach the slow path in
                // this case."
                panic!("iteration count < fixed target");
            }
            more = false;
        } else {
            more = self.stopOrScaleBLoop();
        }
        if !more {
            self.StopTimer();
            // Go: "Commit iteration count" — b.N becomes visible only
            // now, which is why a body reading b.N mid-loop sees 0.
            self.N = crate::int(crate::int64(self.r#loop.n));
            self.r#loop.done = true;
            return false;
        }

        self.r#loop.i += 1;
        return true;
    }

    // go: sdk 1.25.5 testing/benchmark.go:391-407 B.stopOrScaleBLoop
    /// Go: decide whether the b.Loop loop has run long enough, and if
    /// not, predict a new target from what it has measured so far.
    pub(crate) fn stopOrScaleBLoop(&mut self) -> bool {
        let t = self.Elapsed();
        if t >= self.benchTime.d {
            return false;
        }
        let goalns = self.benchTime.d.Nanoseconds();
        let prevIters = crate::int64(self.r#loop.n);
        self.r#loop.n = crate::uint64(predictN(goalns, prevIters, t.Nanoseconds(), prevIters));
        if self.r#loop.n & loopPoisonMask != 0 {
            // Go: "The iteration count should never get this high, but
            // if it did we'd be in big trouble."
            panic!("loop iteration target overflow");
        }
        return true;
    }
}
