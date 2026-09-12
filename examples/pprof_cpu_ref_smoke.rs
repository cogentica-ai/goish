// pprof_cpu_ref_smoke — StartCPUProfile / StopCPUProfile against Go
// (issue #9).
//
// Until now StartCPUProfile returned "cpu profiling not supported by
// the goish runtime". The sampler and the protobuf encoder both
// existed and were both verified; what was missing was the join, and
// the reason given was a lifetime: Go keeps its `io.Writer` interface
// value in a package variable from Start to Stop, and a `&mut dyn
// Writer` cannot outlive the call. That was written up as an open API
// decision. It was not one — goish already has a settled convention
// for a writer stored past the call (`flag.SetOutput`, `log.SetOutput`,
// `jsontext.Encoder`, `os/exec`): take it by value, box it inside.
//
// This file pins the OBSERVABLE contract, not the bytes. Two runs of a
// CPU profile never agree byte for byte — the PCs are this binary's and
// the timestamps are now — so the reference test parses instead, with
// `internal/profile`, which is what Go's own pprof tests use. Every row
// below came out of tools/gen_cpuprofile_ref.go under scripts/goref.sh
// and was transcribed into GO[] by a script, never by hand.
//
// The parse here is hand-rolled because goish has an encoder and no
// decoder. That is deliberate: reading the bytes back with a DIFFERENT
// piece of code than wrote them is the only way this catches a field
// number or a wire type that the encoder and a shared helper would
// agree on and Go would not.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::string as gostr;
use goish::types::byte;
use goish::io::Reader;
use goish::os;
use goish::runtime::pprof;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);

/// Go's output, from tools/gen_cpuprofile_ref.go.
const GO: [&str; 17] = [
    "stop_without_start ok",
    "double_start_err \"cpu profiling already in use\"",
    "gzip_magic 1f8b",
    "sample_type[0] samples/count",
    "sample_type[1] cpu/nanoseconds",
    "period_type cpu/nanoseconds",
    "period 10000000",
    "sample_values 2",
    "has_samples true",
    "has_locations true",
    "time_nanos_set true",
    "duration_set true",
    "value1_is_value0_times_period true",
    "double_stop ok",
    "failing_writer_stop_returned true",
    "failing_writer_panicked false",
    "restart_err true",
];

/// Compare one produced line against Go's row at the same index.
///
/// The index is explicit rather than a running counter so a row that
/// never runs cannot silently shift every later comparison onto its
/// neighbour's expectation. ROWS counts what actually ran, and the
/// tail refuses to print ok unless that reaches GO.len().
fn row(i: usize, got: &'static str) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == GO[i] {
        fmt::Printf!("[ok] %s\n", string::from_static(got));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        let want = if i < GO.len() { GO[i] } else { "<no such row>" };
        fmt::Printf!(
            "[!!] got  %s\n     want %s\n",
            string::from_static(got),
            string::from_static(want)
        );
    }
}

/// `row` for a line that has to be built at run time.
fn rowf(i: usize, got: string) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    let want = if i < GO.len() { GO[i] } else { "<no such row>" };
    if AsRef::<str>::as_ref(&got) == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] got  %s\n     want %s\n",
            got,
            string::from_static(want)
        );
    }
}

// ---- a minimal protobuf reader -------------------------------------

struct Buf<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Buf<'a> {
    fn eof(&self) -> bool {
        return self.i >= self.b.len();
    }
    fn varint(&mut self) -> u64 {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            v |= ((c & 0x7f) as u64) << shift;
            if c & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        return v;
    }
    /// (field number, wire type)
    fn tag(&mut self) -> (u32, u8) {
        let t = self.varint();
        return ((t >> 3) as u32, (t & 7) as u8);
    }
    fn sub(&mut self) -> Buf<'a> {
        let n = self.varint() as usize;
        let start = self.i;
        let end = if start + n <= self.b.len() {
            start + n
        } else {
            self.b.len()
        };
        self.i = end;
        return Buf {
            b: &self.b[start..end],
            i: 0,
        };
    }
    /// Skip a field whose contents this reader does not care about.
    fn skip(&mut self, wire: u8) {
        match wire {
            0 => {
                self.varint();
            }
            2 => {
                let n = self.varint() as usize;
                self.i = if self.i + n <= self.b.len() {
                    self.i + n
                } else {
                    self.b.len()
                };
            }
            5 => self.i += 4,
            1 => self.i += 8,
            _ => self.i = self.b.len(),
        }
    }
}

/// A repeated scalar, whether Go packed it or not. Go packs a repeated
/// varint only above two elements, so both encodings appear inside one
/// profile — a reader that handles only the packed form passes on the
/// location ids of a deep stack and fails on a two-value sample.
fn scalars(p: &mut Buf, wire: u8, out: &mut Vec<u64>) {
    if wire == 2 {
        let mut s = p.sub();
        while !s.eof() {
            out.push(s.varint());
        }
    } else {
        out.push(p.varint());
    }
}

struct Parsed {
    strings: Vec<string>,
    sample_type: Vec<(u64, u64)>,
    period_type: (u64, u64),
    period: u64,
    time_nanos: u64,
    duration_nanos: u64,
    n_samples: usize,
    n_locations: usize,
    first_values: Vec<u64>,
}

fn value_type(p: &mut Buf) -> (u64, u64) {
    let mut ty = 0u64;
    let mut unit = 0u64;
    while !p.eof() {
        let (f, w) = p.tag();
        match (f, w) {
            (1, 0) => ty = p.varint(),
            (2, 0) => unit = p.varint(),
            _ => p.skip(w),
        }
    }
    return (ty, unit);
}

fn parse(b: &[u8]) -> Parsed {
    let mut out = Parsed {
        strings: Vec::new(),
        sample_type: Vec::new(),
        period_type: (0, 0),
        period: 0,
        time_nanos: 0,
        duration_nanos: 0,
        n_samples: 0,
        n_locations: 0,
        first_values: Vec::new(),
    };
    let mut p = Buf { b: b, i: 0 };
    while !p.eof() {
        let (f, w) = p.tag();
        match (f, w) {
            (1, 2) => {
                let mut s = p.sub();
                let vt = value_type(&mut s);
                out.sample_type.push(vt);
            }
            (2, 2) => {
                let mut s = p.sub();
                let first = out.n_samples == 0;
                out.n_samples += 1;
                while !s.eof() {
                    let (sf, sw) = s.tag();
                    if sf == 2 && first {
                        scalars(&mut s, sw, &mut out.first_values);
                    } else {
                        s.skip(sw);
                    }
                }
            }
            (4, 2) => {
                p.sub();
                out.n_locations += 1;
            }
            (6, 2) => {
                let s = p.sub();
                out.strings.push(string::from_bytes(s.b));
            }
            (9, 0) => out.time_nanos = p.varint(),
            (10, 0) => out.duration_nanos = p.varint(),
            (11, 2) => {
                let mut s = p.sub();
                out.period_type = value_type(&mut s);
            }
            (12, 0) => out.period = p.varint(),
            _ => p.skip(w),
        }
    }
    return out;
}

// --------------------------------------------------------------------

/// A writer that refuses every Write, mirroring the reference's
/// `failWriter`.
struct FailWriter {}

impl goish::io::Writer for FailWriter {
    fn Write(&mut self, _p: goish::slice<byte>) -> (goish::types::int, goish::error) {
        return (0, goish::errors::New(gostr("boom")));
    }
}

/// Spin for roughly `ms` milliseconds of CPU. `time.Sleep` would not
/// do: ITIMER_PROF counts CPU time, so a sleeping process is sampled
/// zero times and the profile comes back empty.
fn burn(ms: i64) {
    let deadline = goish::time::Now().Add(goish::time::Duration(ms * 1_000_000));
    let mut x: i64 = 0;
    while goish::time::Now().Before(deadline) {
        let mut i: i64 = 0;
        while i < 50_000 {
            x = x.wrapping_add(i.wrapping_mul(i));
            i += 1;
        }
    }
    if x == i64::MIN {
        fmt::Printf!("");
    }
}

fn strat(p: &Parsed, i: u64) -> string {
    let n = i as usize;
    if n < p.strings.len() {
        return p.strings[n].clone();
    }
    return string::from_static("<out of range>");
}

#[goish::main]
fn main() {
    // 1. Stopping with nothing running is a no-op in Go. If it were not
    //    handled here it would be a panic on the None arm.
    pprof::StopCPUProfile();
    row(0, "stop_without_start ok");

    let (dir, derr) = os::MkdirTemp(gostr(""), gostr("goishcpu"));
    if !derr.IsNil() {
        fmt::Printf!("MkdirTemp: %s\n", derr.Error());
        os::Exit(1);
    }
    let path = goish::fmt::Sprintf!("%s/cpu.pprof", dir);

    let (f, cerr) = os::Create(path.clone());
    if !cerr.IsNil() {
        fmt::Printf!("Create: %s\n", cerr.Error());
        os::Exit(1);
    }
    let serr = pprof::StartCPUProfile(f.MustTake());
    if !serr.IsNil() {
        fmt::Printf!("StartCPUProfile: %s\n", serr.Error());
        os::Exit(1);
    }

    // 2. The second Start must fail, with Go's message. net/http/pprof
    //    puts this string in a 500 body, so it is a contract.
    let e2 = pprof::StartCPUProfile(goish::bytes::Buffer::default());
    rowf(
        1,
        goish::fmt::Sprintf!("double_start_err %q", e2.Error()),
    );

    burn(400);
    pprof::StopCPUProfile();

    let (raw, rerr) = os::ReadFile(path.clone());
    if !rerr.IsNil() {
        fmt::Printf!("ReadFile: %s\n", rerr.Error());
        os::Exit(1);
    }
    let rb = raw.as_ref();
    rowf(
        2,
        goish::fmt::Sprintf!(
            "gzip_magic %02x%02x",
            if rb.len() > 0 { rb[0] as i64 } else { -1 },
            if rb.len() > 1 { rb[1] as i64 } else { -1 }
        ),
    );

    // Inflate, then read the protobuf back with the reader above.
    let mut src = goish::bytes::NewReader(raw.clone());
    let (mut zr, zerr) = goish::compress::gzip::NewReader(&mut src);
    if !zerr.IsNil() {
        fmt::Printf!("gzip.NewReader: %s\n", zerr.Error());
        os::Exit(1);
    }
    let mut plain: Vec<u8> = Vec::new();
    let mut chunk: goish::slice<byte> = goish::make!([]byte, 4096);
    loop {
        let (n, err) = zr.Read(&mut chunk);
        if n > 0 {
            let c = chunk.as_ref();
            let mut i: usize = 0;
            while i < n as usize {
                plain.push(c[i]);
                i += 1;
            }
        }
        if !err.IsNil() {
            break;
        }
    }
    let p = parse(&plain);

    for i in 0..2usize {
        if i < p.sample_type.len() {
            let (t, u) = p.sample_type[i];
            rowf(
                3 + i,
                goish::fmt::Sprintf!(
                    "sample_type[%d] %s/%s",
                    i as i64,
                    strat(&p, t),
                    strat(&p, u)
                ),
            );
        } else {
            rowf(3 + i, goish::fmt::Sprintf!("sample_type[%d] missing", i as i64));
        }
    }
    rowf(
        5,
        goish::fmt::Sprintf!(
            "period_type %s/%s",
            strat(&p, p.period_type.0),
            strat(&p, p.period_type.1)
        ),
    );
    rowf(6, goish::fmt::Sprintf!("period %d", p.period as i64));
    rowf(
        7,
        goish::fmt::Sprintf!("sample_values %d", p.first_values.len() as i64),
    );
    rowf(
        8,
        goish::fmt::Sprintf!("has_samples %v", p.n_samples > 0),
    );
    rowf(
        9,
        goish::fmt::Sprintf!("has_locations %v", p.n_locations > 0),
    );
    rowf(
        10,
        goish::fmt::Sprintf!("time_nanos_set %v", p.time_nanos > 0),
    );
    rowf(
        11,
        goish::fmt::Sprintf!("duration_set %v", p.duration_nanos > 0),
    );
    // The identity that makes value[1] mean nanoseconds. Asserting it
    // against the period read back out of the same bytes catches an
    // encoder that writes a period it did not scale by.
    let ok = p.first_values.len() == 2
        && p.period != 0
        && p.first_values[1] == p.first_values[0] * p.period;
    rowf(
        12,
        goish::fmt::Sprintf!("value1_is_value0_times_period %v", ok),
    );

    // 3. Stopping twice.
    pprof::StopCPUProfile();
    row(13, "double_stop ok");

    // 4. A writer that fails every Write. `StopCPUProfile` has nowhere
    //    to report an error — Go's returns nothing — so the only
    //    question is whether it panics or hangs. Measured against Go:
    //    neither. Issue #9 lists this as a differential, and it was
    //    measured before this row existed but never asserted, which is
    //    the same as not having measured it.
    {
        let sink = FailWriter {};
        let e4 = pprof::StartCPUProfile(sink);
        if !e4.IsNil() {
            fmt::Printf!("start with failing writer: %s\n", e4.Error());
            os::Exit(1);
        }
        burn(150);
        pprof::StopCPUProfile();
        rowf(14, goish::fmt::Sprintf!("failing_writer_stop_returned %v", true));
        // Reaching here at all is the no-panic half: an unrecovered
        // panic in goish is fatal (issue #6), so the process would be
        // gone rather than printing a false.
        rowf(15, goish::fmt::Sprintf!("failing_writer_panicked %v", false));
    }

    // 5. Starting again after all that.
    let e3 = pprof::StartCPUProfile(goish::bytes::Buffer::default());
    rowf(16, goish::fmt::Sprintf!("restart_err %v", e3.IsNil()));
    pprof::StopCPUProfile();

    // A leftover in /tmp is a defect report, not tidiness.
    let _ = os::Remove(path);
    let _ = os::RemoveAll(dir);

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    if ran != GO.len() {
        fmt::Printf!(
            "\nFAILED: %d of %d rows ran — a skipped row is not a pass\n",
            ran as i64,
            GO.len() as i64
        );
        os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, GO.len() as i64);
}
