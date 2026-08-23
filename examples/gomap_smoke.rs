// gomap smoke — comprehensive map[K]V test: CRUD, growth, delete-then-reinsert.
//
// Specifically exercises the duplicate-key bug that could occur when a
// deleted slot appears before an existing key in the overflow chain.

#![no_std]
#![no_main]

use goish::maps;
use goish::{int, len, nil, string, syscall};

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
    // ── make! + basic insert ─────────────────────────────────────────
    let mut m = goish::make!(map[string]int);
    check(len(&m) == 0, b"map: initial len != 0\n");

    m["hello"] = 1;
    m["world"] = 2;
    m["foo"] = 3;
    check(len(&m) == 3, b"map: len after 3 inserts != 3\n");

    // ── bracket read ─────────────────────────────────────────────────
    check(m["hello"] == 1, b"map: m[hello] != 1\n");
    check(m["world"] == 2, b"map: m[world] != 2\n");
    check(m["foo"] == 3, b"map: m[foo] != 3\n");
    check(m["missing"] == 0, b"map: missing key must return zero\n");

    // ── Get (comma-ok) ───────────────────────────────────────────────
    let (v, ok) = m.Get(string::from_static("hello"));
    check(ok && v == 1, b"map: Get(hello) wrong\n");

    let (_, ok2) = m.Get(string::from_static("nothere"));
    check(!ok2, b"map: Get(missing) should return ok=false\n");

    // ── Has ──────────────────────────────────────────────────────────
    check(m.Has(string::from_static("foo")), b"map: Has(foo) wrong\n");
    check(
        !m.Has(string::from_static("gone")),
        b"map: Has(gone) wrong\n",
    );

    // ── update via index ─────────────────────────────────────────────
    m["hello"] = 42;
    check(m["hello"] == 42, b"map: update hello wrong\n");
    check(len(&m) == 3, b"map: len after update changed\n");

    // ── in-place increment ───────────────────────────────────────────
    m["foo"] += 10;
    check(m["foo"] == 13, b"map: in-place increment wrong\n");

    // ── delete! ──────────────────────────────────────────────────────
    goish::delete!(m, string::from_static("world"));
    check(len(&m) == 2, b"map: len after delete != 2\n");
    check(
        !m.Has(string::from_static("world")),
        b"map: world still in map after delete\n",
    );
    check(m["world"] == 0, b"map: deleted key must return zero\n");

    // ── delete non-existent (no panic) ───────────────────────────────
    goish::delete!(m, string::from_static("neverwas"));
    check(
        len(&m) == 2,
        b"map: len changed after delete of absent key\n",
    );

    // ── growth: insert enough keys to trigger rehash ──────────────────
    let mut big = goish::make!(map[int]int);
    let n: int = 200;
    let mut i: int = 0;
    while i < n {
        big[i] = i * i;
        i += 1;
    }
    check(len(&big) == n, b"map: big map len wrong after insert\n");

    i = 0;
    while i < n {
        check(big[i] == i * i, b"map: big map value wrong after growth\n");
        i += 1;
    }

    // ── delete-then-reinsert: stress the duplicate-key fix ────────────
    //
    // Strategy: insert 9 entries to force one into an overflow bucket.
    // Delete one from the main bucket (creating an empty slot). Then
    // call Set on the overflow entry — must UPDATE, not insert duplicate.
    let mut dm = goish::make!(map[int]int);
    let fill: int = 20; // well past the 8-slot-per-bucket threshold
    i = 0;
    while i < fill {
        dm[i] = i;
        i += 1;
    }
    check(len(&dm) == fill, b"map: delete-reinsert setup len wrong\n");

    // Delete odd keys, then update even keys — each Set must not create
    // a duplicate even if the deleted (now empty) slot precedes the key.
    i = 1;
    while i < fill {
        goish::delete!(dm, i);
        i += 2;
    }
    check(
        len(&dm) == fill / 2,
        b"map: len wrong after deleting odd keys\n",
    );

    // Re-set every even key to key*10. If the bug existed, len would grow
    // beyond fill/2 and some keys would appear twice in range! output.
    i = 0;
    while i < fill {
        dm[i] = i * 10; // update existing even key
        i += 2;
    }
    check(
        len(&dm) == fill / 2,
        b"map: len grew after updating even keys (duplicate bug)\n",
    );

    i = 0;
    while i < fill {
        check(dm[i] == i * 10, b"map: updated value wrong\n");
        i += 2;
    }

    // Count keys via range! to independently confirm no duplicates.
    let mut count: int = 0;
    for (_, _) in goish::range!(dm) {
        count += 1;
    }
    check(
        count == fill / 2,
        b"map: range count wrong (duplicate key?)\n",
    );

    // ── nil / Default handling ────────────────────────────────────────
    let nm: goish::map<string, int> = nil.into();
    check(nm == nil, b"map: nil map != nil\n");

    // ── int keys ─────────────────────────────────────────────────────
    let mut ints = goish::make!(map[int]string);
    ints[1] = string::from_static("one");
    ints[2] = string::from_static("two");
    check(
        ints[1] == string::from_static("one"),
        b"map: int key 1 wrong\n",
    );
    check(
        ints[2] == string::from_static("two"),
        b"map: int key 2 wrong\n",
    );

    // ── maps::Clone ───────────────────────────────────────────────────
    let cloned = maps::Clone(&m);
    check(len(&cloned) == len(&m), b"map: Clone len wrong\n");
    for (k, v) in goish::range!(m) {
        check(cloned[k.clone()] == *v, b"map: Clone value wrong\n");
    }

    // ── maps::Equal ───────────────────────────────────────────────────
    check(maps::Equal(&m, &cloned), b"map: Equal on clone wrong\n");

    const OK: &[u8] = b"gomap: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
