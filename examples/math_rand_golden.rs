// math_rand_golden — bit-identity check against Go 1.25.5's math/rand.
//
// Loads testdata/golden.json (harvested from a Go program — see
// goish-v1/src/math/rand/testdata/README — and re-implements the
// minimal JSON walking needed to compare each method's output stream
// to Go's. Prints PASS/FAIL per method; non-zero exit on any FAIL so
// that `cargo run --example math_rand_golden` can be used as a CI gate.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::vec::Vec;
use goish::fmt;
use goish::math::rand;
use goish::slice;
use goish::strconv;
use goish::syscall;
use goish::types::{byte, int};

const GOLDEN: &str = include_str!("../src/math/rand/testdata/golden.json");

// ─── Tiny JSON walker (objects + integer arrays only) ────────────────

/// Locate the value blob for top-level key `name` in `s`. Returns the
/// (inclusive, exclusive) byte indices of the value text.
fn find_key(s: &str, name: &str) -> (usize, usize) {
    // Build `"name"` without going through `format!` (which pulls in
    // unwind-fmt machinery that the no_std no-glibc target lacks).
    let mut key_quoted = String::with_capacity(name.len() + 2);
    key_quoted.push('"');
    key_quoted.push_str(name);
    key_quoted.push('"');
    let idx = s
        .find(key_quoted.as_str())
        .unwrap_or_else(|| panic!("key not found"));
    let after = idx + key_quoted.len();
    let bytes = s.as_bytes();
    // Skip whitespace + ':' + whitespace.
    let mut i = after;
    while i < bytes.len()
        && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
    {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b':' {
        panic!("missing ':'");
    }
    i += 1;
    while i < bytes.len()
        && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
    {
        i += 1;
    }
    let open = bytes[i];
    let close = match open {
        b'{' => b'}',
        b'[' => b']',
        _ => panic!("unexpected open"),
    };
    let start = i;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut prev: u8 = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'"' && prev != b'\\' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return (start, i + 1);
            }
        }
        prev = c;
        i += 1;
    }
    panic!("unterminated value");
}

fn obj_get<'a>(body: &'a str, name: &str) -> &'a str {
    let (s, e) = find_key(body, name);
    &body[s..e]
}

fn parse_int_array_i128(s: &str) -> Vec<i128> {
    let open = s.find('[').unwrap();
    let close = s.rfind(']').unwrap();
    let inner = &s[open + 1..close];
    let mut out = Vec::new();
    for tok in inner.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        out.push(t.parse::<i128>().expect("int parse"));
    }
    out
}

fn collect_seeds() -> Vec<i64> {
    let (s, e) = find_key(GOLDEN, "seeds");
    parse_int_array_i128(&GOLDEN[s..e])
        .into_iter()
        .map(|v| v as i64)
        .collect()
}

/// Load `name` (top-level object) and return [(seed, golden-row)].
fn golden_rows(name: &str) -> Vec<(i64, Vec<i128>)> {
    let (s, e) = find_key(GOLDEN, name);
    let body = &GOLDEN[s + 1..e - 1];
    let seeds = collect_seeds();
    let mut out = Vec::new();
    for seed in seeds {
        // Convert i64 seed → decimal string without `format!`.
        let key_g: goish::string = strconv::Itoa(seed as int);
        // `goish::string` derefs/derives to `&str` via AsRef<str>.
        let key_str: &str = key_g.as_ref();
        let val = obj_get(body, key_str);
        out.push((seed, parse_int_array_i128(val)));
    }
    out
}

// ─── Per-method bit-identity assertions ──────────────────────────────

fn check_int63() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("int63") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Int63();
            if got as i128 != *want {
                fmt::Println!(
                    "    Int63 MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got,
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_uint64() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("uint64") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Uint64();
            if got as i128 != *want {
                fmt::Println!(
                    "    Uint64 MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got,
                    " want=",
                    *want as u64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_uint32() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("uint32") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Uint32();
            if got as i128 != *want {
                fmt::Println!(
                    "    Uint32 MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got as u64,
                    " want=",
                    *want as u32 as u64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_int31() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("int31") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Int31();
            if got as i128 != *want {
                fmt::Println!(
                    "    Int31 MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got as i64,
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_float64() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("float64") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got_bits = r.Float64().to_bits();
            if got_bits as i128 != *want {
                fmt::Println!(
                    "    Float64-bits MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got_bits,
                    " want=",
                    *want as u64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_float32() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("float32") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got_bits = r.Float32().to_bits();
            if got_bits as i128 != *want {
                fmt::Println!(
                    "    Float32-bits MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got_bits as u64,
                    " want=",
                    *want as u32 as u64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_int63n() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("int63n_100") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Int63n(100);
            if got as i128 != *want {
                fmt::Println!(
                    "    Int63n MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got,
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_int31n() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("int31n_100") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Int31n(100);
            if got as i128 != *want {
                fmt::Println!(
                    "    Int31n MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got as i64,
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_intn() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("intn_100") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got = r.Intn(100);
            if got as i128 != *want {
                fmt::Println!(
                    "    Intn MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got,
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_perm() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("perm_10") {
        let mut r = rand::New(rand::NewSource(seed));
        let got: slice<int> = r.Perm(10);
        for (i, want) in want_row.iter().enumerate() {
            let g: i64 = got[i as int];
            if g as i128 != *want {
                fmt::Println!(
                    "    Perm MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    g,
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_shuffle() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("shuffle_10") {
        let mut r = rand::New(rand::NewSource(seed));
        let mut a: Vec<i64> = (0..10).collect();
        let n = a.len() as int;
        let ptr = a.as_mut_ptr();
        r.Shuffle(n, |i, j| unsafe {
            let pi = ptr.offset(i as isize);
            let pj = ptr.offset(j as isize);
            core::ptr::swap(pi, pj);
        });
        for (i, want) in want_row.iter().enumerate() {
            if a[i] as i128 != *want {
                fmt::Println!(
                    "    Shuffle MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    a[i],
                    " want=",
                    *want as i64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_read() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("read_64") {
        let mut r = rand::New(rand::NewSource(seed));
        let mut buf: slice<byte> = goish::make!([]byte, 64);
        let _ = r.Read(&mut buf);
        for (i, want) in want_row.iter().enumerate() {
            let g: u8 = buf[i as int];
            if g as i128 != *want {
                fmt::Println!(
                    "    Read MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    g as u64,
                    " want=",
                    *want as u64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_normfloat64() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("normfloat64") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got_bits = r.NormFloat64().to_bits();
            if got_bits as i128 != *want {
                fmt::Println!(
                    "    NormFloat64-bits MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got_bits,
                    " want=",
                    *want as u64
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_expfloat64() -> bool {
    let mut ok = true;
    for (seed, want_row) in golden_rows("expfloat64") {
        let mut r = rand::New(rand::NewSource(seed));
        for (i, want) in want_row.iter().enumerate() {
            let got_bits = r.ExpFloat64().to_bits();
            if got_bits as i128 != *want {
                fmt::Println!(
                    "    ExpFloat64-bits MISMATCH seed=",
                    seed,
                    " idx=",
                    i,
                    " got=",
                    got_bits,
                    " want=",
                    *want as u64
                );
                ok = false;
            }
        }
    }
    ok
}

/// The package-level `Seed`/`Int63` must drive the same stream as an
/// explicitly constructed `New(NewSource(seed))`.
///
/// Salvaged from src/math/rand/mod.rs's deleted `#[cfg(test)]` module —
/// `cargo test` cannot link in this crate (the test harness pulls in
/// std, whose `panic_impl` lang item collides with goish's), so that
/// module was unreachable. It is the one case the golden file does not
/// cover, because the golden vectors are all taken through an explicit
/// Rand.
fn check_global_seed() -> bool {
    let mut ok = true;
    for &seed in [1i64, 42, 99, 1024, 0, -1, 7].iter() {
        rand::Seed(seed);
        let mut r = rand::New(rand::NewSource(seed));
        for _ in 0..8 {
            if rand::Int63() != r.Int63() {
                ok = false;
            }
        }
    }
    ok
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let cases: &[(&str, fn() -> bool)] = &[
        ("Int63", check_int63),
        ("Uint64", check_uint64),
        ("Uint32", check_uint32),
        ("Int31", check_int31),
        ("Float64", check_float64),
        ("Float32", check_float32),
        ("Int63n", check_int63n),
        ("Int31n", check_int31n),
        ("Intn", check_intn),
        ("Perm", check_perm),
        ("Shuffle", check_shuffle),
        ("Read", check_read),
        ("NormFloat64", check_normfloat64),
        ("ExpFloat64", check_expfloat64),
        ("global Seed", check_global_seed),
    ];
    for (name, f) in cases.iter() {
        if f() {
            fmt::Println!("[ ok ] math/rand bit-identical: ", *name);
        } else {
            fmt::Println!("[FAIL] math/rand bit-identical: ", *name);
            failed += 1;
        }
    }
    if failed == 0 {
        fmt::Println!("math_rand_golden: ALL PASS (15 methods)");
    } else {
        fmt::Println!("math_rand_golden: ", failed as i64, " FAILED");
        syscall::Exit(1);
    }
}
