//! Pinned against Go 1.25.5: map semantics — the counterpart to
//! slice_alias_ref_smoke, and the opposite result.
//!
//! Slices diverge: goish's subslice copies where Go's aliases. The
//! obvious next question is whether goish's map diverges the same way,
//! because a Go map is a REFERENCE type and losing that would be worse
//! — every `m[k] = v` inside a helper would stop reaching the caller.
//!
//! It does not. goish matches Go on all eight comparable answers,
//! including the one a naive port gets wrong:
//!
//!   * **Reading a MISSING key does not insert it.** `len` is
//!     unchanged after the read. An implementation reaching for
//!     `entry().or_default()` — the obvious Rust spelling — would grow
//!     the map on every failed lookup, and nothing about the returned
//!     value would show it.
//!   * A missing key reads the ZERO value with ok=false, and the same
//!     is true of an empty map.
//!   * `delete` of a missing key is a no-op; deleting a present one
//!     drops the length and leaves the zero value behind.
//!   * Overwriting an existing key does not grow the map.
//!   * `Clear` empties in place.
//!
//! One Go question is NOT asked here, because goish cannot ask it.
//! Go's `m2 := m` shares the table; Rust MOVES, so `let m2 = m` leaves
//! `m` unusable and the aliasing question never arises rather than
//! being answered wrongly. The sharing that a Go program actually
//! depends on — a helper mutating the caller's map — is expressible
//! and IS checked: `mutate(&mut m)` is Go's `mutate(m)`, with the
//! sharing in the type system instead of behind it.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh sort <mapsem_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::gomap::map;
use goish::{delete, fmt, len, make, string};

/// Go's output, verbatim.
const GO: [&str; 8] = [
    "pass-shares                  [3 9]",
    "missing-key                  [0 false]",
    "len-unchanged-by-read        [3]",
    "delete-missing               [3]",
    "delete-present               [2 0]",
    "overwrite                    [2 20]",
    "nil-map-read                 [0 0 false]",
    "clear                        [0]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

fn line(tag: &'static str, parts: alloc::vec::Vec<string>) {
    let mut out = string("");
    for (i, x) in parts.iter().enumerate() {
        if i > 0 {
            out = out + string(" ");
        }
        out = out + x.clone();
    }
    chk(fmt::Sprintf!("%-28s [%s]", string::from_static(tag), out));
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
fn n(v: i64) -> string {
    fmt::Sprintf!("%d", v)
}
fn b(v: bool) -> string {
    fmt::Sprintf!("%v", v)
}

// Go passes the map by value and shares the table; goish passes &mut,
// which is the same sharing through the type system instead of behind
// it.
fn mutate(m: &mut map<string, i64>) {
    m.Set(string("fn"), 9);
}

#[goish::main]
fn main() {
    let mut m = make!(map[string]i64);
    m.Set(string("a"), 1);
    m.Set(string("b"), 2);

    mutate(&mut m);
    line(
        "pass-shares",
        alloc::vec![n(len(&m) as i64), n(m[string("fn")])],
    );

    let (v, ok) = m.Get(string("missing"));
    line("missing-key", alloc::vec![n(v), b(ok)]);
    line("len-unchanged-by-read", alloc::vec![n(len(&m) as i64)]);

    delete!(m, string("nope"));
    line("delete-missing", alloc::vec![n(len(&m) as i64)]);
    delete!(m, string("a"));
    line(
        "delete-present",
        alloc::vec![n(len(&m) as i64), n(m[string("a")])],
    );

    m.Set(string("b"), 20);
    line(
        "overwrite",
        alloc::vec![n(len(&m) as i64), n(m[string("b")])],
    );

    let nilm = make!(map[string]i64);
    let (nv, nok) = nilm.Get(string("x"));
    line(
        "nil-map-read",
        alloc::vec![n(len(&nilm) as i64), n(nv), b(nok)],
    );

    let mut c = make!(map[string]i64);
    c.Set(string("x"), 1);
    c.Set(string("y"), 2);
    c.Clear();
    line("clear", alloc::vec![n(len(&c) as i64)]);

    let failed = unsafe { FAILED };
    let total = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("map semantics: %d/%d match Go\n", total, total);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, total);
    goish::os::Exit(1);
}
