// Benchmark: goish::string vs alloc::String, goish::slice<T> vs Vec<T>.
//
// Measures the wrapper cost of goish's user-facing types compared to
// the native Rust equivalents. Both goish types are thin newtypes
// over the corresponding alloc::* types (string wraps Vec<u8>,
// slice<T> wraps Vec<T>), so we expect ~zero overhead.
//
// Each operation runs N times under monotonic-clock timing
// (time::Now / time::Since). Results report ns/op and a ratio
// goish/native; ratios near 1.0 confirm the wrapper is free.

#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::hint::black_box;

use goish::time::{Now, Since};
use goish::types::int;
use goish::{Printf, syscall};
use goish::gostring::string as goish_string;
use goish::goslice::slice as goish_slice;

#[goish::main]
fn main() {
    const HEADER: &[u8] = b"\n=== bench: goish vs native (smaller ns/op = faster) ===\n\n";
    syscall::Write(syscall::STDOUT, HEADER.as_ptr(), HEADER.len());

    bench_string();
    bench_slice();

    const FOOTER: &[u8] = b"\nbench_string_slice: ok\n";
    syscall::Write(syscall::STDOUT, FOOTER.as_ptr(), FOOTER.len());
}

// ─── timing helper ────────────────────────────────────────────────

fn bench<F: FnMut()>(label: &[u8], iters: int, mut f: F) -> int {
    // Warm up.
    for _ in 0..16 {
        f();
    }
    let t0 = Now();
    for _ in 0..iters {
        f();
    }
    let elapsed = Since(t0);
    let total_ns = elapsed.Nanoseconds();
    let per_op = total_ns / iters;
    syscall::Write(syscall::STDOUT, b"  ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    Printf!(": %d ns/op (total %d ns over %d iters)\n", per_op, total_ns, iters);
    per_op
}

fn ratio_print(g: int, n: int) {
    // Print ratio as percent, integer-rounded.
    if n == 0 {
        Printf!("    ratio: native=0, undefined\n");
        return;
    }
    let pct = (g * 100) / n;
    Printf!("    ratio: goish/native = %d%% (lower=faster goish)\n\n", pct);
}

// ─── string benchmarks ───────────────────────────────────────────

fn bench_string() {
    const N: int = 100_000;
    const SAMPLE: &[u8] = b"Hello, goish! This is a sample string.";

    syscall::Write(
        syscall::STDOUT,
        b"--- string vs String ---\n".as_ptr(),
        25,
    );

    // 1. Construction from byte slice.
    let g1 = bench(b"goish::string::from_bytes", N, || {
        let _ = black_box(goish_string::from_bytes(SAMPLE));
    });
    let n1 = bench(b"alloc::String::from_utf8_lossy", N, || {
        let _ = black_box(String::from_utf8_lossy(SAMPLE).into_owned());
    });
    ratio_print(g1, n1);

    // 2. Construction from &'static str.
    let g2 = bench(b"goish::string::from_static", N, || {
        let _ = black_box(goish_string::from_static("Hello, goish!"));
    });
    let n2 = bench(b"alloc::String::from(&str)", N, || {
        let _ = black_box(String::from("Hello, goish!"));
    });
    ratio_print(g2, n2);

    // 3. Clone.
    let g_src = goish_string::from_bytes(SAMPLE);
    let n_src = String::from_utf8_lossy(SAMPLE).into_owned();
    let g3 = bench(b"goish::string::clone", N, || {
        let _ = black_box(g_src.clone());
    });
    let n3 = bench(b"alloc::String::clone", N, || {
        let _ = black_box(n_src.clone());
    });
    ratio_print(g3, n3);

    // 4. Equality (worst case: equal strings — must compare all bytes).
    let g_a = goish_string::from_bytes(SAMPLE);
    let g_b = goish_string::from_bytes(SAMPLE);
    let n_a = String::from_utf8_lossy(SAMPLE).into_owned();
    let n_b = String::from_utf8_lossy(SAMPLE).into_owned();
    let g4 = bench(b"goish::string equality", N, || {
        let _ = black_box(g_a == g_b);
    });
    let n4 = bench(b"alloc::String equality", N, || {
        let _ = black_box(n_a == n_b);
    });
    ratio_print(g4, n4);

    // 5. Length (single field load).
    let g5 = bench(b"goish::string::Len", N, || {
        let _ = black_box(g_src.Len());
    });
    let n5 = bench(b"alloc::String::len", N, || {
        let _ = black_box(n_src.len());
    });
    ratio_print(g5, n5);
}

// ─── slice benchmarks ────────────────────────────────────────────

fn bench_slice() {
    const N: int = 10_000;
    const SIZE: usize = 256;

    syscall::Write(
        syscall::STDOUT,
        b"--- slice<i64> vs Vec<i64> ---\n".as_ptr(),
        31,
    );

    // 1. Construction by repeated push (Vec) vs build-then-wrap (slice).
    let g1 = bench(b"goish::slice<i64> build (Vec+wrap)", N, || {
        let mut v: Vec<i64> = Vec::with_capacity(SIZE);
        for i in 0..SIZE {
            v.push(i as i64);
        }
        let _ = black_box(goish_slice::__from_vec(v));
    });
    let n1 = bench(b"alloc::Vec<i64>      build", N, || {
        let mut v: Vec<i64> = Vec::with_capacity(SIZE);
        for i in 0..SIZE {
            v.push(i as i64);
        }
        let _ = black_box(v);
    });
    ratio_print(g1, n1);

    // 2. Index access.
    let prebuilt_v: Vec<i64> = (0..SIZE as i64).collect();
    let prebuilt_s: goish_slice<i64> = goish_slice::__from_vec(prebuilt_v.clone());
    let g2 = bench(b"goish::slice<i64> index loop", N, || {
        let mut sum: i64 = 0;
        for i in 0..SIZE {
            sum = sum.wrapping_add(prebuilt_s[i as int]);
        }
        let _ = black_box(sum);
    });
    let n2 = bench(b"alloc::Vec<i64>      index loop", N, || {
        let mut sum: i64 = 0;
        for i in 0..SIZE {
            sum = sum.wrapping_add(prebuilt_v[i]);
        }
        let _ = black_box(sum);
    });
    ratio_print(g2, n2);

    // 3. Clone.
    let g3 = bench(b"goish::slice<i64> clone", N, || {
        let _ = black_box(prebuilt_s.clone());
    });
    let n3 = bench(b"alloc::Vec<i64>      clone", N, || {
        let _ = black_box(prebuilt_v.clone());
    });
    ratio_print(g3, n3);

    // 4. Iter sum (via Deref to [T]).
    let g4 = bench(b"goish::slice<i64> iter sum", N, || {
        let s: i64 = prebuilt_s.iter().sum();
        let _ = black_box(s);
    });
    let n4 = bench(b"alloc::Vec<i64>      iter sum", N, || {
        let s: i64 = prebuilt_v.iter().sum();
        let _ = black_box(s);
    });
    ratio_print(g4, n4);

    // 5. Length.
    let g5 = bench(b"goish::slice<i64>::Len", N, || {
        let _ = black_box(prebuilt_s.Len());
    });
    let n5 = bench(b"alloc::Vec<i64>::len", N, || {
        let _ = black_box(prebuilt_v.len());
    });
    ratio_print(g5, n5);
}
