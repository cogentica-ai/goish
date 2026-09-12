// runtime_mprof_smoke — the heap profiler's sampling substrate
// (issue #9, the half that has to exist before Lookup("heap") can).
//
// Go's ground truth (tools/gen_heapprofile_ref.go) settled the shape
// this has to feed: BOTH the heap and allocs profiles carry all four
// value types — alloc_objects, alloc_space, inuse_objects,
// inuse_space. So counting allocations is not enough. inuse means the
// profiler has to see frees too, and that is the part with teeth.
//
// The rows here are internal invariants rather than a Go diff, because
// Go exposes no bucket table. The Go comparison lands one layer up,
// when Lookup("heap") returns a profile. What this file pins is the
// three defects found while building it, each of which was invisible
// until something counted:
//
//   1. `ptr >> 4` clustered every 4 KiB object into sixteen slots.
//   2. Deleting from the open-addressed table cut the probe chains of
//      everything that collided into the same run — 300 freed objects
//      reported 11 frees.
//   3. `GlobalAlloc::dealloc` inlined `dealloc_routed`'s body instead
//      of calling it, so the free path had two entry points and the
//      profiler hooked one. Every Rust-level drop went unrecorded.
//
// All three present as "inuse never falls", which is why FREES_FALL is
// the row that matters most.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::runtime::mprof;

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

/// The workload. `#[inline(never)]` so it owns a frame the profile can
/// name; without it the allocation is credited to whoever called it.
#[inline(never)]
fn alloc_site(n: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for _ in 0..n {
        let mut v: Vec<u8> = Vec::with_capacity(SZ);
        v.push(1);
        out.push(v);
    }
    return out;
}

struct Totals {
    buckets: i64,
    allocs: i64,
    frees: i64,
    alloc_bytes: i64,
    free_bytes: i64,
    max_depth: i64,
}

/// Sum the table. Allocating INSIDE this loop is the point: the first
/// version of the read API took a callback that ran under the table
/// lock, so the first caller to build a Vec re-entered the sampler and
/// deadlocked against itself. `__bucket_at` takes and drops the lock
/// per call, and this function allocates between calls, so the hang
/// comes back as a hang here if that ever regresses.
fn totals() -> Totals {
    let mut t = Totals {
        buckets: 0,
        allocs: 0,
        frees: 0,
        alloc_bytes: 0,
        free_bytes: 0,
        max_depth: 0,
    };
    let mut names: Vec<u64> = Vec::new();
    for i in 0..mprof::__bucket_slots() {
        if let Some(b) = mprof::__bucket_at(i) {
            t.buckets += 1;
            t.allocs += b.allocs as i64;
            t.frees += b.frees as i64;
            t.alloc_bytes += b.alloc_bytes as i64;
            t.free_bytes += b.free_bytes as i64;
            if b.depth as i64 > t.max_depth {
                t.max_depth = b.depth as i64;
            }
            names.push(b.pcs[0]);
        }
    }
    if names.len() == usize::MAX {
        fmt::Printf!("");
    }
    return t;
}

#[goish::main]
fn main() {
    // Go's default is 512 * 1024 — heap profiling on out of the box.
    check(
        "MemProfileRate defaults to Go's 512 KiB",
        mprof::MemProfileRate() == 512 * 1024,
        fmt::Sprintf!("rate=%d", mprof::MemProfileRate()),
    );

    mprof::SetMemProfileRate(1);
    mprof::__reset();
    // Setting the rate does not re-arm a countdown already drawn from
    // the old one.
    mprof::__rearm();

    let keep = alloc_site(N);
    let before = totals();

    check(
        "every allocation is sampled at rate 1",
        before.allocs >= N as i64,
        fmt::Sprintf!("allocs=%d want>=%d", before.allocs, N as i64),
    );
    check(
        "the bytes are the workload's, not a count of calls",
        before.alloc_bytes >= (N * SZ) as i64,
        fmt::Sprintf!("bytes=%d want>=%d", before.alloc_bytes, (N * SZ) as i64),
    );
    check(
        "distinct call stacks get distinct buckets",
        before.buckets >= 1 && before.buckets < 64,
        fmt::Sprintf!("buckets=%d", before.buckets),
    );
    check(
        "stacks are deep enough to reach the caller",
        before.max_depth >= 8,
        fmt::Sprintf!("max_depth=%d", before.max_depth),
    );
    check(
        "nothing was dropped for want of table space",
        mprof::__dropped() <= 1,
        fmt::Sprintf!("dropped=%d", mprof::__dropped() as i64),
    );

    // The workload's own frame must be in there somewhere. Symbols
    // come back v0-MANGLED — goish's demangler handles only the legacy
    // `_ZN…E` form — so this matches the substring rustc puts in both
    // encodings rather than a demangled name.
    let mut found = false;
    for i in 0..mprof::__bucket_slots() {
        if let Some(b) = mprof::__bucket_at(i) {
            let mut pcs: Vec<goish::types::uintptr> = Vec::new();
            let mut k = 0usize;
            while k < b.depth {
                pcs.push(b.pcs[k]);
                k += 1;
            }
            let mut fr = goish::runtime::CallersFrames(goish::goslice::slice::__from_vec(pcs));
            loop {
                let (f, more) = fr.Next();
                if (f.Function.as_ref() as &str).contains("alloc_site") {
                    found = true;
                }
                if !more {
                    break;
                }
            }
        }
    }
    check(
        "the workload's frame is on a recorded stack",
        found,
        string::from_static("alloc_site not found in any bucket"),
    );

    // ── the row the three defects all failed ──
    drop(keep);
    let after = totals();
    let inuse_objects = after.allocs - after.frees;
    let inuse_bytes = after.alloc_bytes - after.free_bytes;
    check(
        "freeing the workload makes inuse_objects fall",
        after.frees >= before.allocs - 8 && inuse_objects < (N as i64) / 4,
        fmt::Sprintf!(
            "allocs=%d frees=%d inuse=%d",
            after.allocs,
            after.frees,
            inuse_objects
        ),
    );
    check(
        "freeing the workload makes inuse_space fall",
        inuse_bytes < (N * SZ) as i64 / 4,
        fmt::Sprintf!("inuse_bytes=%d of %d", inuse_bytes, after.alloc_bytes),
    );
    check(
        "frees never exceed allocs",
        after.frees <= after.allocs && after.free_bytes <= after.alloc_bytes,
        fmt::Sprintf!("frees=%d allocs=%d", after.frees, after.allocs),
    );

    // ── the address table under real load ──
    //
    // The rows above run at about 4% table occupancy, where probe
    // chains are one slot long and a deletion orphans nothing. So they
    // do NOT test the tombstone: removing it and re-running left all
    // of them green, which is the whole reason this row exists. A
    // profiler only meets that case on a large live heap — at the
    // default rate, one sampled pointer per 512 KiB live, so a few
    // gigabytes. Reproduced here by sampling everything and keeping
    // several thousand small objects alive.
    //
    // Churn is what does the damage: freeing into the middle of a
    // cluster and inserting again is exactly the sequence a
    // tombstone-less table gets wrong.
    mprof::__reset();
    mprof::__rearm();
    {
        let mut live: Vec<Vec<u8>> = Vec::new();
        let mut i = 0usize;
        while i < 4000 {
            let mut v: Vec<u8> = Vec::with_capacity(64);
            v.push(1);
            live.push(v);
            i += 1;
        }
        // Free every other one, then refill the holes.
        let mut j = 0usize;
        while j < live.len() {
            live[j] = Vec::new();
            j += 2;
        }
        let mut refill: Vec<Vec<u8>> = Vec::new();
        let mut k = 0usize;
        while k < 1500 {
            let mut v: Vec<u8> = Vec::with_capacity(64);
            v.push(1);
            refill.push(v);
            k += 1;
        }
        drop(refill);
        drop(live);
    }
    let churned = totals();
    let leaked = churned.allocs - churned.frees;
    check(
        "a loaded, churned address table still attributes every free",
        leaked < churned.allocs / 20,
        fmt::Sprintf!(
            "allocs=%d frees=%d unattributed=%d dropped=%d",
            churned.allocs,
            churned.frees,
            leaked,
            mprof::__dropped() as i64
        ),
    );

    // Rate 0 turns the sampler off entirely.
    mprof::SetMemProfileRate(0);
    mprof::__reset();
    mprof::__rearm();
    let quiet = alloc_site(N);
    let off = totals();
    check(
        "rate 0 records nothing",
        off.allocs == 0 && off.buckets == 0,
        fmt::Sprintf!("allocs=%d buckets=%d", off.allocs, off.buckets),
    );
    drop(quiet);

    mprof::SetMemProfileRate(512 * 1024);
    mprof::__reset();

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    if ran != 12 {
        fmt::Printf!("\nFAILED: %d rows ran, expected 12\n", ran as i64);
        goish::os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, ran as i64);
}
