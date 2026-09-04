//! Pinned against Go 1.25.5: slice ALIASING — goish's largest
//! deliberate divergence, measured rather than asserted.
//!
//! Go's `xs[low:high]` is a VIEW into the same backing array. goish's
//! `xs.slice(low, high)` returns an independent COPY. That is a
//! documented v1 deviation — goslice.rs says so in its header and on
//! both methods, and ROADMAP.md tracks it — bought for Rust's borrow
//! checker, which cannot express two mutable views of one array
//! without unsafe.
//!
//! It was documented in three places and measured in none. Six of the
//! thirteen lines below differ from Go, and this is what they are:
//!
//!   * A reslice's CAP is the copy's length, not the distance to the
//!     parent's end: `a[1:3]` of a 5-element slice is cap 2 in goish,
//!     cap 4 in Go.
//!   * Writing through a reslice does NOT reach the parent.
//!   * `append` within capacity therefore does not overwrite the
//!     parent's next element — the single most surprising thing about
//!     Go slices, and goish simply does not do it.
//!   * `copy` into overlapping reslices is a no-op on the parent,
//!     because the reslices are copies.
//!   * Slicing to zero length does not keep the capacity.
//!
//! The seven that MATCH are as important: append beyond capacity, the
//! three-index form's length and cap, copy's return being the minimum
//! length, and append onto an empty slice all behave exactly as Go
//! does. The deviation is confined to aliasing.
//!
//! Two Go answers are deliberately not compared. `z == nil` on a slice
//! distinguishes a nil slice from an empty one; goish's `slice` has no
//! such state, so pinning an answer would invent one.
//!
//! If aliasing ever lands, this smoke fails on six lines and names
//! each — which is the point of pinning a divergence rather than
//! describing it.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh sort <slicealias_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::{append, copy, fmt, make, slice, string};

/// Go's output, verbatim.
const GO: [&str; 13] = [
    "reslice-len-cap                [2 4]",
    "write-through                  [99 99]",
    "append-in-cap                  [77 77 3 5]",
    "append-grow-copies             [1 42 3 true]",
    "three-index                    [2 2]",
    "three-index-append             [4 88]",
    "copy-short-dst                 [2 1 2]",
    "copy-long-dst                  [3 0]",
    "copy-overlap-fwd               [[1 1 2 3 4]]",
    "copy-overlap-back              [[2 3 4 5 5]]",
    "nil-slice                      [0 0]",
    "nil-append                     [1 1]",
    "zero-len-keeps-cap             [0 3]",
];

/// KNOWN DIVERGENCE, pinned: the lines where goish's copying
/// subslice answers differently from Go's aliasing one.
const DIVERGENT: [(usize, &str); 6] = [
    (0, "reslice-len-cap                [2 2]"),
    (1, "write-through                  [2 99]"),
    (2, "append-in-cap                  [3 77 3 4]"),
    (8, "copy-overlap-fwd               [[1 2 3 4 5]]"),
    (9, "copy-overlap-back              [[1 2 3 4 5]]"),
    (12, "zero-len-keeps-cap             [0 0]"),
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
    chk(fmt::Sprintf!("%-30s [%s]", string::from_static(tag), out));
}

/// Compare one line against Go — or against the pinned goish answer
/// where the aliasing deviation makes them differ.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    for (idx, expect) in DIVERGENT.iter() {
        if *idx == i {
            let want = string::from_static(expect);
            if got == want {
                return;
            }
            if got == string::from_static(GO[i]) {
                fmt::Printf!(
                    "KNOWN DIVERGENCE CHANGED at %d - goish now aliases like Go. Update this note.\n",
                    i as i64
                );
            } else {
                fmt::Printf!("DIFF pinned: %s\n", want);
                fmt::Printf!("     goish : %s\n", got);
            }
            unsafe { FAILED += 1 };
            return;
        }
    }
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
fn vs(s: &slice<i64>) -> string {
    let mut out = string("[");
    for i in 0..s.Len() {
        if i > 0 {
            out = out + string(" ");
        }
        out = out + n(s[i as usize]);
    }
    return out + string("]");
}

#[goish::main]
fn main() {
    let a = slice::<i64>::__from_vec(alloc::vec![1, 2, 3, 4, 5]);
    let mut bb = a.slice(1, 3);
    line("reslice-len-cap", alloc::vec![n(bb.Len()), n(bb.Cap())]);
    bb[0] = 99;
    line("write-through", alloc::vec![n(a[1]), n(bb[0])]);

    let c = slice::<i64>::__from_vec(alloc::vec![1, 2, 3, 4, 5]);
    let mut d = c.slice(0, 2);
    d = append!(d, 77);
    line(
        "append-in-cap",
        alloc::vec![n(c[2]), n(d[2]), n(d.Len()), n(d.Cap())],
    );

    let mut e = make!([]i64, 2, 2);
    e[0] = 1;
    e[1] = 2;
    let mut f = append!(e.clone(), 3);
    f[0] = 42;
    line(
        "append-grow-copies",
        alloc::vec![n(e[0]), n(f[0]), n(f.Len()), b(f.Cap() >= 3)],
    );

    let g = slice::<i64>::__from_vec(alloc::vec![1, 2, 3, 4, 5]);
    let mut h = g.slice3(1, 3, 3);
    line("three-index", alloc::vec![n(h.Len()), n(h.Cap())]);
    h = append!(h, 88);
    line("three-index-append", alloc::vec![n(g[3]), n(h[2])]);

    let src = slice::<i64>::__from_vec(alloc::vec![1, 2, 3]);
    let mut dst = make!([]i64, 2);
    let cn = copy!(dst, src.clone());
    line("copy-short-dst", alloc::vec![n(cn), n(dst[0]), n(dst[1])]);
    let mut dst2 = make!([]i64, 5);
    let cn = copy!(dst2, src.clone());
    line("copy-long-dst", alloc::vec![n(cn), n(dst2[3])]);

    let o = slice::<i64>::__from_vec(alloc::vec![1, 2, 3, 4, 5]);
    let mut od = o.slice(1, 5);
    let _ = copy!(od, o.slice(0, 4));
    line("copy-overlap-fwd", alloc::vec![vs(&o)]);
    let p = slice::<i64>::__from_vec(alloc::vec![1, 2, 3, 4, 5]);
    let mut pd = p.slice(0, 4);
    let _ = copy!(pd, p.slice(1, 5));
    line("copy-overlap-back", alloc::vec![vs(&p)]);

    let mut z = slice::<i64>::new();
    line("nil-slice", alloc::vec![n(z.Len()), n(z.Cap())]);
    z = append!(z, 1);
    line("nil-append", alloc::vec![n(z.Len()), n(z[0])]);

    let q = slice::<i64>::__from_vec(alloc::vec![1, 2, 3]);
    let r = q.slice(0, 0);
    line("zero-len-keeps-cap", alloc::vec![n(r.Len()), n(r.Cap())]);

    let failed = unsafe { FAILED };
    let total = GO.len() as i64;
    let div = DIVERGENT.len() as i64;
    if failed == 0 {
        fmt::Printf!(
            "slice aliasing: %d/%d match Go, %d pinned divergences\n",
            total - div,
            total - div,
            div
        );
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d line(s) unexpected\n", failed);
    goish::os::Exit(1);
}
