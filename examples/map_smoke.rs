// map<K,V> + maps package smoke test.

#![no_std]
#![no_main]

use goish::{delete, int, len, make, maps, range, slice, slices, string, syscall};

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
    // ─── Empty map / Set / Get / Has / Len ────────────────────────────

    let mut m = make!(map[string]int);
    check(len(&m) == 0, b"map: empty len wrong\n");
    check(!m.Has(string("foo")), b"map: empty Has wrong\n");
    let (v, ok) = m.Get(string("foo"));
    check(v == 0 && !ok, b"map: empty Get must return (0, false)\n");

    m.Set(string("alpha"), 1);
    m.Set(string("beta"), 2);
    m.Set(string("gamma"), 3);
    check(len(&m) == 3, b"map: post-Set len wrong\n");
    check(m.Has(string("beta")), b"map: Has after Set wrong\n");

    let (v, ok) = m.Get(string("beta"));
    check(v == 2 && ok, b"map: Get hit wrong\n");

    let (v, ok) = m.Get(string("zeta"));
    check(v == 0 && !ok, b"map: Get miss wrong\n");

    // ─── Bracket syntax: m[k] read / write ────────────────────────────

    // Read-on-miss returns Default::default() — for int that's 0.
    // Read does NOT mutate the map (matches Go).
    let n = m["zeta"];
    check(n == 0, b"map: m[missing] must read as 0\n");
    check(!m.Has(string("zeta")), b"map: m[missing] read must NOT insert\n");

    // Read existing.
    let n = m["alpha"];
    check(n == 1, b"map: m[\"alpha\"] read wrong\n");

    // Write inserts.
    m["delta"] = 4;
    check(m.Has(string("delta")), b"map: m[k]=v must insert\n");
    let (v, _) = m.Get(string("delta"));
    check(v == 4, b"map: m[k]=v value wrong\n");

    // Increment via compound op (read-modify-write through IndexMut).
    m["alpha"] += 10;
    let (v, _) = m.Get(string("alpha"));
    check(v == 11, b"map: m[k] += wrong\n");

    // Increment a previously-missing key (insert + add).
    m["epsilon"] += 7;
    let (v, _) = m.Get(string("epsilon"));
    check(v == 7, b"map: m[k] += on missing must insert+add\n");

    // ─── Delete ───────────────────────────────────────────────────────

    delete!(m, string("delta"));
    check(!m.Has(string("delta")), b"map: delete! wrong\n");

    // Delete a missing key is a no-op.
    delete!(m, string("never_there"));

    // ─── Keys / Values (unordered — hash map) ────────────────────────

    let mut m2 = make!(map[string]int);
    m2["c"] = 3;
    m2["a"] = 1;
    m2["b"] = 2;
    let mut keys = m2.Keys();
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let want: slice<string> = goish::slice!([]string{ "a", "b", "c" });
    check(slices::Equal(&keys, &want), b"map: Keys order wrong\n");

    // Values order follows Keys order — verify set not sequence.
    let mut total_v: int = 0;
    for (_, v) in range!(m2) { total_v += v; }
    check(total_v == 6, b"map: Values sum wrong\n");

    // ─── range!(m) sum (order is undefined) ───────────────────────────

    let mut total = 0;
    for (_, v) in range!(m2) {
        total += *v;
    }
    check(total == 6, b"map: range! sum wrong\n");

    // ─── maps package: Keys / Values / Equal / Clone / Copy ───────────

    let mut ks = slices::Collect(maps::Keys(&m2));
    ks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    check(slices::Equal(&ks, &want), b"map: maps::Keys wrong\n");

    // Verify all three values present (sum = 6).
    let vs = slices::Collect(maps::Values(&m2));
    let mut vsum: int = 0;
    for (_, v) in range!(vs) { vsum += v; }
    check(vsum == 6, b"map: maps::Values sum wrong\n");

    let m3 = maps::Clone(&m2);
    check(maps::Equal(&m2, &m3), b"map: maps::Clone equal wrong\n");
    check(m3.Has(string("a")), b"map: Clone keys wrong\n");

    let mut empty: goish::map<string, int> = make!(map[string]int);
    check(!maps::Equal(&m2, &empty), b"map: Equal vs empty wrong\n");

    maps::Copy(&mut empty, &m2);
    check(maps::Equal(&m2, &empty), b"map: Copy result wrong\n");

    // ─── Map<int, V> with bracket syntax ──────────────────────────────

    let mut counter = make!(map[int]int);
    counter[1] = 100;
    counter[2] = 200;
    counter[1] += 5;   // 105
    check(counter[1] == 105, b"map<int,int>: m[k]+= wrong\n");
    check(counter[99] == 0, b"map<int,int>: m[missing] zero wrong\n");

    const OK: &[u8] = b"map: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
