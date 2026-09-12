// alloc_hook_bench — what the heap profiler's allocation hook costs.
//
// NOT a test; it asserts nothing and is excluded from e2e. It exists so
// the number in `runtime/mprof.rs` can be re-measured rather than
// trusted.
//
// Run it in RELEASE and raise N:
//
//   cargo build --release --target x86_64-unknown-linux-gnu \
//       --example alloc_hook_bench
//   ./target/x86_64-unknown-linux-gnu/release/examples/alloc_hook_bench
//
// Two traps, both hit while writing this:
//
//   * a DEBUG build spends about 1400 ns per alloc/free pair, so the
//     ~6 ns the hook costs is far below the noise — in debug, rate 0
//     measured SLOWER than the 512 KiB default.
//   * without `black_box`, LLVM proves the Vec unused and deletes the
//     allocation. 20 million allocations then "take" 5 ms.
//
// Measured on this machine, release, 20M 64-byte pairs:
//
//   no hook at all     76-80 ns
//   hook, all inline   87-89 ns
//   hook, cold split   81-85 ns   <- current
//
// The no-hook row comes from commenting out the two calls in
// `heap.rs`; there is no build flag for it, deliberately, because a
// flag would be a second configuration to keep correct.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::fmt;
use goish::runtime::mprof;

#[inline(never)]
fn churn(n: usize, sz: usize) -> u64 {
    // `black_box` on both the size and the Vec: without it LLVM proves
    // the Vec unused and deletes the allocation, and 20 million
    // allocations "take" 5ms.
    let mut acc: u64 = 0;
    for i in 0..n {
        let want = core::hint::black_box(sz);
        let mut v: Vec<u8> = Vec::with_capacity(want);
        v.push((i & 0xff) as u8);
        let v = core::hint::black_box(v);
        acc += v[0] as u64;
        core::hint::black_box(&v);
    }
    acc
}

fn bench(label: &'static str, n: usize, sz: usize) {
    let t0 = goish::time::Now();
    let acc = churn(n, sz);
    let d = goish::time::Since(t0);
    let ns = d.0;
    fmt::Printf!(
        "%s  n=%d sz=%d  total=%dms  per_alloc=%dns  acc=%d\n",
        goish::gostring::string::from_static(label),
        n as i64, sz as i64, ns / 1_000_000, ns / (n as i64), acc as i64
    );
}

#[goish::main]
fn main() {
    // Small enough that a debug build finishes quickly. Raise it for a
    // release measurement — the numbers in the header used 20_000_000.
    let n = 500_000usize;
    // Warm up so span/mcache state is steady.
    bench("warmup       ", n / 10, 64);
    fmt::Printf!("rate=%d (shipping default)\n", mprof::MemProfileRate());
    bench("default 512K ", n, 64);
    mprof::SetMemProfileRate(0);
    bench("rate 0 (off) ", n, 64);
    mprof::SetMemProfileRate(512 * 1024);
    bench("default again", n, 64);
}
