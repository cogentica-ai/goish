// Smoke test: M16f-α step 3 — cheaprand / cheaprandn distribution.
//
// Verifies the wyrand port matches Go's behaviour qualitatively:
//   1. cheaprand() doesn't return a constant or get stuck.
//   2. cheaprandn(8) over 80_000 trials puts each of the 8 buckets
//      within ±5% of the mean (10_000 each), well inside what a
//      uniform RNG should manage.
//   3. cheaprandn(0) returns 0 (Go-compatible edge case).
//
// Cheap fairness check before we lean on this in select! pass-1.

#![no_std]
#![no_main]

use goish::runtime::rand::{cheaprand, cheaprandn};
use goish::syscall;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // ─── Test 1: cheaprand() advances ──────────────────────────────
    let a = cheaprand();
    let b = cheaprand();
    let c = cheaprand();
    // Three samples shouldn't all collide (probability ~2^-64).
    check(
        !(a == b && b == c),
        b"rand: cheaprand() returned same value 3 times\n",
    );

    // ─── Test 2: cheaprandn(8) bucket distribution ─────────────────
    const N: u32 = 8;
    const TRIALS: u32 = 80_000;
    const MEAN: u32 = TRIALS / N; // 10_000
    const TOL: u32 = MEAN / 20; // ±5% = 500

    let mut buckets: [u32; N as usize] = [0; N as usize];
    for _ in 0..TRIALS {
        let r = cheaprandn(N);
        check(r < N, b"rand: cheaprandn out of range\n");
        buckets[r as usize] += 1;
    }
    for i in 0..N as usize {
        let diff = if buckets[i] > MEAN {
            buckets[i] - MEAN
        } else {
            MEAN - buckets[i]
        };
        check(diff <= TOL, b"rand: bucket outside +/-5% tolerance\n");
    }

    // ─── Test 3: cheaprandn(0) returns 0 ───────────────────────────
    check(cheaprandn(0) == 0, b"rand: cheaprandn(0) != 0\n");

    // ─── Test 4: cheaprandn(1) always 0 ────────────────────────────
    for _ in 0..1000 {
        check(cheaprandn(1) == 0, b"rand: cheaprandn(1) != 0\n");
    }

    const OK: &[u8] = b"rand_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
