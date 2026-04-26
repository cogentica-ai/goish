// runtime::rand — tiny PRNG used by `select!` pass-1 fairness.
//
// Verbatim port of Go 1.25's `cheaprand` on amd64 (runtime/rand.go:227),
// which is wyrand:
//
//     mp.cheaprand += K1
//     hi, lo = mul64(mp.cheaprand, mp.cheaprand ^ K2)
//     return uint32(hi ^ lo)
//
// plus `cheaprandn` (runtime/rand.go:291) using Lemire's bounded
// reduction (uint32((cheaprand() * n) >> 32)) for fair `[0, n)` indices.
//
// Per-M state lives in `m.cheaprand` in Go. Single-M cooperative goish
// keeps one `AtomicU64` here; M17a will move state to per-M storage.
// `fetch_add` is used so the state is monotone even under multi-M
// concurrency (each thread sees a unique advance).
//
// Seed source: x86 `rdtsc` at init time, so each process run starts at
// a different state. Cheaper and more local than reading /dev/urandom,
// and good enough for select fairness (we don't need cryptographic
// quality — just bias-free index permutation).

use core::sync::atomic::{AtomicU64, Ordering};

const K1: u64 = 0xa0761d6478bd642f;
const K2: u64 = 0xe7037ed1a0b428db;

/// Global wyrand state. Seeded by `init()` in `__goish_rt0`.
static STATE: AtomicU64 = AtomicU64::new(0);

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Seed the cheaprand state from rdtsc. Called once from `__goish_rt0`.
/// Idempotent: if STATE is already non-zero (from a prior init or a
/// prior cheaprand call), do nothing.
pub fn init() {
    let s = rdtsc().wrapping_mul(K1) ^ K2;
    // Mix in a nonzero fallback so a (theoretically possible) all-zero
    // rdtsc * K1 ^ K2 result still produces a usable seed.
    let s = if s == 0 { K1 ^ K2 } else { s };
    let _ = STATE.compare_exchange(0, s, Ordering::Relaxed, Ordering::Relaxed);
}

/// Port of Go's `cheaprand()` (runtime/rand.go:227). 32-bit uniform.
#[inline]
pub fn cheaprand() -> u32 {
    // `fetch_add` gives this caller a unique post-increment value
    // even under multi-M concurrency (M17a). The wyrand round mixes
    // it with K2 and returns the high/low XOR fold of the 128-bit
    // product.
    let new = STATE.fetch_add(K1, Ordering::Relaxed).wrapping_add(K1);
    let prod = (new as u128).wrapping_mul((new ^ K2) as u128);
    let hi = (prod >> 64) as u64;
    let lo = prod as u64;
    (hi ^ lo) as u32
}

/// Port of Go's `cheaprandn(n)` (runtime/rand.go:291). Returns a
/// uniform random in `[0, n)` via Lemire's bounded reduction. For
/// `n == 0`, returns 0 (matches Go's behaviour where the multiply
/// yields 0).
#[inline]
pub fn cheaprandn(n: u32) -> u32 {
    ((cheaprand() as u64).wrapping_mul(n as u64) >> 32) as u32
}
