// pprof_heap_ref_smoke — Lookup("heap") and Lookup("allocs")
// (issue #9, contract items 4-6).
//
// Go's own output (tools/gen_heapprofile_ref.go under goref.sh, with
// MemProfileRate=1 as Go's own tests use) settled the shape, and the
// first thing it settled was that the obvious shortcut does not exist:
//
//     heap_sample_type[0] alloc_objects/count
//     heap_sample_type[1] alloc_space/bytes
//     heap_sample_type[2] inuse_objects/count
//     heap_sample_type[3] inuse_space/bytes
//     heap_period_type space/bytes
//     heap_period 1
//     heap_default_sample_type ""
//     heap_time_nanos_set true
//     heap_duration_set false
//     allocs_default_sample_type "alloc_space"
//
// — `heap` and `allocs` are the SAME four value types and differ only
// in default_sample_type. So "allocs needs no free tracking" was wrong,
// and inuse is why runtime/mprof.rs exists.
//
// Bytes cannot be pinned: the PCs are this binary's, the timestamp is
// now, and the bucket table contains whatever the program has
// allocated. So this parses, with a hand-rolled protobuf reader —
// different code from the encoder, so a wrong field number cannot be
// agreed on by both halves.
//
// ── a divergence this file states rather than hides ──
//
// Go's Profiles() returns SIX builtins: allocs, block, goroutine, heap,
// mutex, threadcreate. goish registers TWO. block and mutex need a
// blocking-profile substrate and goroutine/threadcreate need an
// all-goroutines registry, none of which exist — so Lookup returns nil
// for those four, which is Go's answer for a name it does not know. An
// empty profile would be worse: a caller cannot tell one from a quiet
// program. The row below asserts 2 and names the four that are missing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::io::Reader;
use goish::runtime::{mprof, pprof};
use goish::types::byte;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);

const N: usize = 300;
const SZ: usize = 4096;

fn check(name: &'static str, ok: bool, detail: string) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    if ok {
        fmt::Printf!("[ok] %s\n", string::from_static(name));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] %s — %s\n", string::from_static(name), detail);
    }
}

/// The workload. `#[inline(never)]` so the profile can name it; without
/// it the allocation is credited to whoever called it.
#[inline(never)]
fn heap_workload(n: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for _ in 0..n {
        let mut v: Vec<u8> = Vec::with_capacity(SZ);
        v.push(1);
        out.push(v);
    }
    return out;
}

// ---- a minimal protobuf reader ------------------------------------

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

/// A repeated scalar, packed or not. Go packs a repeated varint only
/// above two elements, so both encodings appear in one profile.
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

struct Loc {
    id: u64,
    fn_ids: Vec<u64>,
}

struct Fun {
    id: u64,
    name: u64,
}

struct Parsed {
    strings: Vec<string>,
    sample_type: Vec<(u64, u64)>,
    period_type: (u64, u64),
    period: u64,
    time_nanos: u64,
    duration_nanos: u64,
    default_sample_type: u64,
    /// (location ids, values) per sample.
    samples: Vec<(Vec<u64>, Vec<u64>)>,
    locations: Vec<Loc>,
    functions: Vec<Fun>,
}

fn parse(b: &[u8]) -> Parsed {
    let mut out = Parsed {
        strings: Vec::new(),
        sample_type: Vec::new(),
        period_type: (0, 0),
        period: 0,
        time_nanos: 0,
        duration_nanos: 0,
        default_sample_type: 0,
        samples: Vec::new(),
        locations: Vec::new(),
        functions: Vec::new(),
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
                let mut ids: Vec<u64> = Vec::new();
                let mut vals: Vec<u64> = Vec::new();
                while !s.eof() {
                    let (sf, sw) = s.tag();
                    match sf {
                        1 => scalars(&mut s, sw, &mut ids),
                        2 => scalars(&mut s, sw, &mut vals),
                        _ => s.skip(sw),
                    }
                }
                out.samples.push((ids, vals));
            }
            (4, 2) => {
                let mut s = p.sub();
                let mut loc = Loc {
                    id: 0,
                    fn_ids: Vec::new(),
                };
                while !s.eof() {
                    let (lf, lw) = s.tag();
                    match (lf, lw) {
                        (1, 0) => loc.id = s.varint(),
                        (4, 2) => {
                            let mut ln = s.sub();
                            while !ln.eof() {
                                let (nf, nw) = ln.tag();
                                match (nf, nw) {
                                    (1, 0) => loc.fn_ids.push(ln.varint()),
                                    _ => ln.skip(nw),
                                }
                            }
                        }
                        _ => s.skip(lw),
                    }
                }
                out.locations.push(loc);
            }
            (5, 2) => {
                let mut s = p.sub();
                let mut fu = Fun { id: 0, name: 0 };
                while !s.eof() {
                    let (ff, fw) = s.tag();
                    match (ff, fw) {
                        (1, 0) => fu.id = s.varint(),
                        (2, 0) => fu.name = s.varint(),
                        _ => s.skip(fw),
                    }
                }
                out.functions.push(fu);
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
            (14, 0) => out.default_sample_type = p.varint(),
            _ => p.skip(w),
        }
    }
    return out;
}

fn strat(p: &Parsed, i: u64) -> string {
    let n = i as usize;
    if n < p.strings.len() {
        return p.strings[n].clone();
    }
    return string::from_static("<out of range>");
}

/// Inflate a gzip stream into a byte vector.
fn gunzip(raw: goish::slice<byte>) -> Vec<u8> {
    let mut src = goish::bytes::NewReader(raw);
    let (mut zr, zerr) = goish::compress::gzip::NewReader(&mut src);
    if !zerr.IsNil() {
        fmt::Printf!("gzip.NewReader: %s\n", zerr.Error());
        goish::os::Exit(1);
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
    return plain;
}

/// Exercise one builtin and check it against Go's measured shape.
fn one(name: &'static str, want_default: &'static str) {
    let p = match pprof::Lookup(string::from_static(name)) {
        Some(p) => p,
        None => {
            check(
                "Lookup returns the builtin",
                false,
                fmt::Sprintf!("Lookup(%q) is nil", string::from_static(name)),
            );
            return;
        }
    };
    check(
        "Lookup returns the builtin",
        p.Name().as_ref() as &str == name,
        fmt::Sprintf!("name=%s", p.Name()),
    );

    let mut buf = goish::bytes::Buffer::default();
    let err = p.WriteTo(&mut buf, 0);
    check(
        "WriteTo(w, 0) succeeds",
        err.IsNil(),
        fmt::Sprintf!("err=%v", err),
    );
    if !err.IsNil() {
        return;
    }
    let raw = buf.Bytes();
    let rb = raw.as_ref();
    check(
        "the output is gzipped, as go tool pprof expects",
        rb.len() > 2 && rb[0] == 0x1f && rb[1] == 0x8b,
        fmt::Sprintf!("len=%d", raw.Len()),
    );

    let plain = gunzip(raw.clone());
    let pr = parse(&plain);

    let want_types: [(&str, &str); 4] = [
        ("alloc_objects", "count"),
        ("alloc_space", "bytes"),
        ("inuse_objects", "count"),
        ("inuse_space", "bytes"),
    ];
    let mut types_ok = pr.sample_type.len() == 4;
    if types_ok {
        for i in 0..4 {
            let (t, u) = pr.sample_type[i];
            if strat(&pr, t).as_ref() as &str != want_types[i].0
                || strat(&pr, u).as_ref() as &str != want_types[i].1
            {
                types_ok = false;
            }
        }
    }
    check(
        "all four of Go's value types, in Go's order",
        types_ok,
        fmt::Sprintf!("n=%d first=%s", pr.sample_type.len() as i64, {
            if pr.sample_type.is_empty() {
                string::from_static("none")
            } else {
                strat(&pr, pr.sample_type[0].0)
            }
        }),
    );
    check(
        "period_type is space/bytes",
        strat(&pr, pr.period_type.0).as_ref() as &str == "space"
            && strat(&pr, pr.period_type.1).as_ref() as &str == "bytes",
        fmt::Sprintf!(
            "%s/%s",
            strat(&pr, pr.period_type.0),
            strat(&pr, pr.period_type.1)
        ),
    );
    check(
        "period is MemProfileRate",
        pr.period == mprof::MemProfileRate() as u64,
        fmt::Sprintf!(
            "period=%d rate=%d",
            pr.period as i64,
            mprof::MemProfileRate()
        ),
    );
    // The ONE thing that distinguishes the two profiles.
    check(
        "default_sample_type is Go's",
        strat(&pr, pr.default_sample_type).as_ref() as &str == want_default,
        fmt::Sprintf!(
            "got=%q want=%q",
            strat(&pr, pr.default_sample_type),
            string::from_static(want_default)
        ),
    );
    check(
        "a snapshot has a timestamp and no duration",
        pr.time_nanos > 0 && pr.duration_nanos == 0,
        fmt::Sprintf!(
            "time=%v duration=%d",
            pr.time_nanos > 0,
            pr.duration_nanos as i64
        ),
    );
    check(
        "every sample carries four values",
        !pr.samples.is_empty() && pr.samples.iter().all(|(_, v)| v.len() == 4),
        fmt::Sprintf!("samples=%d", pr.samples.len() as i64),
    );

    // The workload has to be in there, named, and at the TOP of its
    // stack — the allocator frames between it and the sampler are
    // stripped by name, so a regression in that stripping shows up as
    // `alloc::raw_vec::…` in frame 0 rather than as a missing function.
    let mut workload_total_objects: u64 = 0;
    let mut workload_total_bytes: u64 = 0;
    let mut leading_is_allocator = false;
    for (ids, vals) in pr.samples.iter() {
        let mut hit = false;
        for (k, id) in ids.iter().enumerate() {
            for l in pr.locations.iter() {
                if l.id != *id {
                    continue;
                }
                for fid in l.fn_ids.iter() {
                    for f in pr.functions.iter() {
                        if f.id != *fid {
                            continue;
                        }
                        let fname = strat(&pr, f.name);
                        let fs: &str = fname.as_ref();
                        if fs.contains("heap_workload") {
                            hit = true;
                        }
                        // The prefix list has to cover what frame 0
                        // ACTUALLY is when stripping is off, which is
                        // `collect_frames_for_profile` — the stack
                        // walker itself. Leaving it out made this row
                        // pass with the stripping disabled, i.e. the
                        // row tested nothing. Found by perturbing.
                        if k == 0
                            && (fs.starts_with("alloc::")
                                || fs.starts_with("<alloc::")
                                || fs.starts_with("core::alloc::")
                                || fs.starts_with("goish::runtime::heap::")
                                || fs.starts_with("<goish::runtime::heap::")
                                || fs.starts_with("goish::runtime::mprof::")
                                || fs.starts_with("goish::runtime::collect_frames_for_profile")
                                || fs.starts_with("goish::runtime::segv::")
                                || fs.starts_with("__rustc::"))
                        {
                            leading_is_allocator = true;
                        }
                    }
                }
            }
        }
        if hit && vals.len() == 4 {
            workload_total_objects += vals[0];
            workload_total_bytes += vals[1];
        }
    }
    check(
        "the workload is symbolized in the profile",
        workload_total_objects > 0,
        string::from_static("heap_workload not found in any sample"),
    );
    check(
        "allocator frames are stripped from the top of the stack",
        !leading_is_allocator,
        string::from_static("frame 0 of some sample is allocator plumbing"),
    );
    check(
        "the workload's object count reaches what it allocated",
        workload_total_objects >= N as u64,
        fmt::Sprintf!("objects=%d want>=%d", workload_total_objects as i64, N as i64),
    );
    check(
        "the workload's byte count reaches what it allocated",
        workload_total_bytes >= (N * SZ) as u64,
        fmt::Sprintf!(
            "bytes=%d want>=%d",
            workload_total_bytes as i64,
            (N * SZ) as i64
        ),
    );
}

#[goish::main]
fn main() {
    // Go's own tests set the rate to 1 for exactly this reason: at the
    // 512 KiB default a small workload is sampled zero times and there
    // is nothing deterministic to assert.
    mprof::SetMemProfileRate(1);
    mprof::__reset();
    mprof::__rearm();
    let keep = heap_workload(N);

    one("heap", "");
    one("allocs", "alloc_space");

    // Go returns SIX builtins; goish registers two. Stated, not hidden.
    let all = pprof::Profiles();
    let mut names: Vec<string> = Vec::new();
    for i in 0..all.Len() {
        names.push(all[i].Name());
    }
    let mut have_heap = false;
    let mut have_allocs = false;
    for n in names.iter() {
        let s: &str = n.as_ref();
        if s == "heap" {
            have_heap = true;
        }
        if s == "allocs" {
            have_allocs = true;
        }
    }
    check(
        "Profiles() lists the two builtins goish has a substrate for",
        have_heap && have_allocs && all.Len() == 2,
        fmt::Sprintf!("n=%d", all.Len()),
    );
    // And the four Go has that goish does not must be ABSENT, not
    // present-and-empty.
    let mut absent = true;
    for missing in ["block", "mutex", "goroutine", "threadcreate"] {
        if pprof::Lookup(string::from_static(missing)).is_some() {
            absent = false;
        }
    }
    check(
        "the four unported builtins are nil, not empty profiles",
        absent,
        string::from_static("a builtin with no substrate is registered"),
    );

    // debug>=1 is Go's legacy text format, which is not ported. It must
    // say so rather than write an empty file.
    {
        let p = pprof::Lookup(string::from_static("heap")).unwrap();
        let mut buf = goish::bytes::Buffer::default();
        let err = p.WriteTo(&mut buf, 1);
        check(
            "debug>=1 reports unported rather than writing nothing",
            !err.IsNil() && buf.Len() == 0,
            fmt::Sprintf!("err=%v len=%d", err, buf.Len()),
        );
    }

    if keep.len() == usize::MAX {
        fmt::Printf!("");
    }
    mprof::SetMemProfileRate(512 * 1024);
    mprof::__reset();

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    // 13 rows per builtin, plus 3.
    let expect = 13 * 2 + 3;
    if ran != expect {
        fmt::Printf!("\nFAILED: %d rows ran, expected %d\n", ran as i64, expect as i64);
        goish::os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, ran as i64);
}
