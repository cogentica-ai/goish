// gomap range smoke — range!(m), maps::Keys/Values/Equal/Copy/DeleteFunc.

#![no_std]
#![no_main]

extern crate alloc;

use goish::maps;
use goish::slices;
use goish::{int, len, string, syscall};

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
    let mut m = goish::make!(map[string]int);
    m["a"] = 1;
    m["b"] = 2;
    m["c"] = 3;
    m["d"] = 4;
    m["e"] = 5;

    // ── range!(m) covers all entries exactly once ─────────────────────
    let mut sum: int = 0;
    let mut count: int = 0;
    for (_, v) in goish::range!(m) {
        sum += v;
        count += 1;
    }
    check(count == 5, b"map range: count != 5\n");
    check(sum == 15, b"map range: sum != 15\n");

    // ── range! on a borrowed map field inside a struct ────────────────
    // Tests the &&map<K,V> impl.
    struct Holder {
        inner: goish::map<string, int>,
    }
    let h = Holder { inner: m.clone() };
    let mut count2: int = 0;
    for (_, _) in goish::range!(h.inner) {
        count2 += 1;
    }
    check(count2 == 5, b"map range &&map: count wrong\n");

    // ── maps::Keys — all keys present ────────────────────────────────
    let ks = slices::Collect(maps::Keys(&m));
    check(len(&ks) == 5, b"maps::Keys len wrong\n");
    // Every key in the slice must exist in the map.
    for (_, k) in goish::range!(ks) {
        check(m.Has(k.clone()), b"maps::Keys: key not in map\n");
    }

    // ── maps::Values — all values present ────────────────────────────
    let vs = slices::Collect(maps::Values(&m));
    check(len(&vs) == 5, b"maps::Values len wrong\n");
    let mut vsum: int = 0;
    for (_, v) in goish::range!(vs) {
        vsum += v;
    }
    check(vsum == 15, b"maps::Values: sum wrong\n");

    // ── maps::Equal ───────────────────────────────────────────────────
    let mut m2 = goish::make!(map[string]int);
    m2["a"] = 1;
    m2["b"] = 2;
    m2["c"] = 3;
    m2["d"] = 4;
    m2["e"] = 5;
    check(
        maps::Equal(&m, &m2),
        b"maps::Equal: identical maps not equal\n",
    );

    m2["a"] = 99;
    check(
        !maps::Equal(&m, &m2),
        b"maps::Equal: different maps reported equal\n",
    );

    // ── maps::Clone ───────────────────────────────────────────────────
    let c = maps::Clone(&m);
    check(
        maps::Equal(&m, &c),
        b"maps::Clone: clone not equal to original\n",
    );

    // Mutating the clone must not affect the original.
    let mut c2 = maps::Clone(&m);
    c2["a"] = 999;
    check(
        m["a"] == 1,
        b"maps::Clone: mutating clone changed original\n",
    );

    // ── maps::Copy ────────────────────────────────────────────────────
    let mut dst = goish::make!(map[string]int);
    dst["z"] = 100;
    maps::Copy(&mut dst, &m);
    check(len(&dst) == 6, b"maps::Copy: len wrong\n");
    check(dst["z"] == 100, b"maps::Copy: pre-existing key lost\n");
    check(dst["a"] == 1, b"maps::Copy: copied key wrong\n");
    check(dst["e"] == 5, b"maps::Copy: copied key wrong\n");

    // ── maps::EqualFunc ───────────────────────────────────────────────
    // Two maps are "equal" if values are within 1 of each other.
    let mut mf1 = goish::make!(map[string]int);
    let mut mf2 = goish::make!(map[string]int);
    mf1["x"] = 10;
    mf2["x"] = 11;
    mf1["y"] = 20;
    mf2["y"] = 20;
    let fuzzy_eq = maps::EqualFunc(&mf1, &mf2, |a: &int, b: &int| (a - b).abs() <= 1);
    check(fuzzy_eq, b"maps::EqualFunc: fuzzy equal failed\n");

    mf2["x"] = 15; // now out of range
    let fuzzy_ne = maps::EqualFunc(&mf1, &mf2, |a: &int, b: &int| (a - b).abs() <= 1);
    check(
        !fuzzy_ne,
        b"maps::EqualFunc: fuzzy unequal reported equal\n",
    );

    // ── maps::DeleteFunc ─────────────────────────────────────────────
    let mut df = goish::make!(map[string]int);
    df["keep1"] = 1;
    df["drop1"] = -1;
    df["keep2"] = 2;
    df["drop2"] = -2;
    maps::DeleteFunc(&mut df, |_k: &string, v: &int| *v < 0);
    check(len(&df) == 2, b"maps::DeleteFunc: len wrong\n");
    check(
        df.Has(string::from_static("keep1")),
        b"maps::DeleteFunc: keep1 missing\n",
    );
    check(
        df.Has(string::from_static("keep2")),
        b"maps::DeleteFunc: keep2 missing\n",
    );
    check(
        !df.Has(string::from_static("drop1")),
        b"maps::DeleteFunc: drop1 still present\n",
    );
    check(
        !df.Has(string::from_static("drop2")),
        b"maps::DeleteFunc: drop2 still present\n",
    );

    // ── Range over int-keyed map (different key type) ─────────────────
    let mut im = goish::make!(map[int]int);
    let n: int = 50;
    let mut i: int = 0;
    while i < n {
        im[i] = i * 2;
        i += 1;
    }

    let mut rsum: int = 0;
    for (k, v) in goish::range!(im) {
        check(*v == k * 2, b"map range int: k*2 wrong\n");
        rsum += v;
    }
    // sum of 2*i for i in 0..50 = 2 * (49*50/2) = 2450
    check(rsum == 2450, b"map range int: rsum wrong\n");

    const OK: &[u8] = b"gomap range: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
