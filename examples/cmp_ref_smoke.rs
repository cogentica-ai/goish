// cmp_ref_smoke — the cmp package against a running Go.
// (cmp/cmp.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_cmp_ref.go` run in
// `package cmp_test` by `scripts/goref.sh`. goish matched Go on all 86
// lines — no defects found.
//
// cmp is three functions and two of them exist because of NaN.
//
// A float comparison built from < and > alone gets NaN wrong in a way
// that does not announce itself: NaN < x, x < NaN and NaN == NaN are
// ALL false, so a comparator written the obvious way reports "equal"
// for every pair involving NaN. Feed that to a sort and the result is
// not merely unsorted — the algorithm can be driven off the end of the
// slice, because partitioning relies on the comparator being a strict
// weak ordering and an inconsistent one breaks that invariant.
//
// Go's answer is a TOTAL order in which NaN sorts BEFORE every other
// value and equals itself. That is not IEEE semantics and is not meant
// to be: it is the ordering that makes sorting terminate and be
// deterministic. Every line mentioning nan pins it, as a full
// cross-product of eight float values against each other — 64 lines,
// because the interesting property is the whole table's consistency
// rather than any single answer.
//
// The `props` line states that consistency directly: Compare is
// antisymmetric, Compare and Less agree on every pair, and NaN equals
// NaN. The `sort` line then does what those invariants exist for —
// sorts a slice containing two NaNs and both infinities, and confirms
// the result is sorted by the same comparator.
//
// Two quieter cases, both easy to get wrong in the other direction:
//
//   * SIGNED ZERO. -0.0 and +0.0 compare EQUAL, so a sort will not
//     reorder them and a caller cannot use cmp to tell them apart.
//   * Or tests "is this the zero value", and NaN is NOT zero — so a
//     NaN first argument is returned rather than skipped, and Or can
//     hand back a value that does not equal itself. Pinned as
//     nan-passed-through and self-unequal.
//
// Or over an EMPTY argument list returns the zero value, which is the
// case a variadic implementation forgets.
//
// iter.Pull and Pull2 are absent from goish and deliberately so: Go
// builds them on runtime coroutines, goish would need a goroutine and
// channel pair, and the module records zero call sites in the target
// workload. That is a documented deferral, not a gap this smoke covers.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::cmp;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::math;
use goish::slices;
use goish::strings;
use goish::syscall;
use goish::types::{float64, int};
const GO: [&str; 86] = [
    "cmpf nan   nan   -> compare=0  less=false less-rev=false",
    "cmpf nan   -inf  -> compare=-1 less=true  less-rev=false",
    "cmpf nan   -1    -> compare=-1 less=true  less-rev=false",
    "cmpf nan   -0    -> compare=-1 less=true  less-rev=false",
    "cmpf nan   +0    -> compare=-1 less=true  less-rev=false",
    "cmpf nan   1     -> compare=-1 less=true  less-rev=false",
    "cmpf nan   +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf nan   max   -> compare=-1 less=true  less-rev=false",
    "cmpf -inf  nan   -> compare=1  less=false less-rev=true",
    "cmpf -inf  -inf  -> compare=0  less=false less-rev=false",
    "cmpf -inf  -1    -> compare=-1 less=true  less-rev=false",
    "cmpf -inf  -0    -> compare=-1 less=true  less-rev=false",
    "cmpf -inf  +0    -> compare=-1 less=true  less-rev=false",
    "cmpf -inf  1     -> compare=-1 less=true  less-rev=false",
    "cmpf -inf  +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf -inf  max   -> compare=-1 less=true  less-rev=false",
    "cmpf -1    nan   -> compare=1  less=false less-rev=true",
    "cmpf -1    -inf  -> compare=1  less=false less-rev=true",
    "cmpf -1    -1    -> compare=0  less=false less-rev=false",
    "cmpf -1    -0    -> compare=-1 less=true  less-rev=false",
    "cmpf -1    +0    -> compare=-1 less=true  less-rev=false",
    "cmpf -1    1     -> compare=-1 less=true  less-rev=false",
    "cmpf -1    +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf -1    max   -> compare=-1 less=true  less-rev=false",
    "cmpf -0    nan   -> compare=1  less=false less-rev=true",
    "cmpf -0    -inf  -> compare=1  less=false less-rev=true",
    "cmpf -0    -1    -> compare=1  less=false less-rev=true",
    "cmpf -0    -0    -> compare=0  less=false less-rev=false",
    "cmpf -0    +0    -> compare=0  less=false less-rev=false",
    "cmpf -0    1     -> compare=-1 less=true  less-rev=false",
    "cmpf -0    +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf -0    max   -> compare=-1 less=true  less-rev=false",
    "cmpf +0    nan   -> compare=1  less=false less-rev=true",
    "cmpf +0    -inf  -> compare=1  less=false less-rev=true",
    "cmpf +0    -1    -> compare=1  less=false less-rev=true",
    "cmpf +0    -0    -> compare=0  less=false less-rev=false",
    "cmpf +0    +0    -> compare=0  less=false less-rev=false",
    "cmpf +0    1     -> compare=-1 less=true  less-rev=false",
    "cmpf +0    +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf +0    max   -> compare=-1 less=true  less-rev=false",
    "cmpf 1     nan   -> compare=1  less=false less-rev=true",
    "cmpf 1     -inf  -> compare=1  less=false less-rev=true",
    "cmpf 1     -1    -> compare=1  less=false less-rev=true",
    "cmpf 1     -0    -> compare=1  less=false less-rev=true",
    "cmpf 1     +0    -> compare=1  less=false less-rev=true",
    "cmpf 1     1     -> compare=0  less=false less-rev=false",
    "cmpf 1     +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf 1     max   -> compare=-1 less=true  less-rev=false",
    "cmpf +inf  nan   -> compare=1  less=false less-rev=true",
    "cmpf +inf  -inf  -> compare=1  less=false less-rev=true",
    "cmpf +inf  -1    -> compare=1  less=false less-rev=true",
    "cmpf +inf  -0    -> compare=1  less=false less-rev=true",
    "cmpf +inf  +0    -> compare=1  less=false less-rev=true",
    "cmpf +inf  1     -> compare=1  less=false less-rev=true",
    "cmpf +inf  +inf  -> compare=0  less=false less-rev=false",
    "cmpf +inf  max   -> compare=1  less=false less-rev=true",
    "cmpf max   nan   -> compare=1  less=false less-rev=true",
    "cmpf max   -inf  -> compare=1  less=false less-rev=true",
    "cmpf max   -1    -> compare=1  less=false less-rev=true",
    "cmpf max   -0    -> compare=1  less=false less-rev=true",
    "cmpf max   +0    -> compare=1  less=false less-rev=true",
    "cmpf max   1     -> compare=1  less=false less-rev=true",
    "cmpf max   +inf  -> compare=-1 less=true  less-rev=false",
    "cmpf max   max   -> compare=0  less=false less-rev=false",
    "props antisymmetric=true compare-agrees-less=true nan-eq-nan=true",
    "sort -> [NaN NaN -Inf -1 1 3 +Inf] sorted=true",
    "cmpi -1                    1                     -> compare=-1 less=true",
    "cmpi 1                     -1                    -> compare=1  less=false",
    "cmpi 0                     0                     -> compare=0  less=false",
    "cmpi -9223372036854775808  9223372036854775807   -> compare=-1 less=true",
    "cmpi 9223372036854775807   -9223372036854775808  -> compare=1  less=false",
    "cmpi 5                     5                     -> compare=0  less=false",
    "cmps \"\"     \"\"     -> compare=0  less=false",
    "cmps \"\"     \"a\"    -> compare=-1 less=true",
    "cmps \"a\"    \"\"     -> compare=1  less=false",
    "cmps \"a\"    \"b\"    -> compare=-1 less=true",
    "cmps \"b\"    \"a\"    -> compare=1  less=false",
    "cmps \"a\"    \"a\"    -> compare=0  less=false",
    "cmps \"A\"    \"a\"    -> compare=-1 less=true",
    "cmps \"abc\"  \"abd\"  -> compare=-1 less=true",
    "cmps \"ab\"   \"abc\"  -> compare=-1 less=true",
    "cmps \"\\x00\" \"\"     -> compare=1  less=false",
    "cmps \"é\"    \"e\"    -> compare=1  less=false",
    "or-int 3 1 0 0",
    "or-str \"c\" \"a\" \"\" \"\"",
    "or-float 2.5 nan-passed-through=true self-unequal=true",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn showFloats(v: &slice<float64>) -> string {
    let mut parts: Vec<string> = Vec::new();
    for i in 0..v.Len() {
        parts.push(fmt::Sprintf!("%v", v[i]));
    }
    return string::from("[") + strings::Join(slice::<string>::__from_vec(parts), s(" ")) + "]";
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let nan = math::NaN();
    let inf = math::Inf(1);
    let ninf = math::Inf(-1);
    let negzero = math::Copysign(0.0, -1.0);
    let floats: [(&str, float64); 8] = [
        ("nan", nan),
        ("-inf", ninf),
        ("-1", -1.0),
        ("-0", negzero),
        ("+0", 0.0),
        ("1", 1.0),
        ("+inf", inf),
        ("max", math::MaxFloat64),
    ];
    for (an, av) in floats.iter() {
        for (bn, bv) in floats.iter() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "cmpf %-5s %-5s -> compare=%-2d less=%-5v less-rev=%v",
                    s(an),
                    s(bn),
                    cmp::Compare(av, bv),
                    cmp::Less(av, bv),
                    cmp::Less(bv, av)
                ),
            );
        }
    }
    {
        let vals: [float64; 6] = [nan, ninf, -1.0, 0.0, 1.0, inf];
        let mut total = true;
        let mut antisym = true;
        for a in vals.iter() {
            for b in vals.iter() {
                let c = cmp::Compare(a, b);
                if c != -cmp::Compare(b, a) {
                    antisym = false;
                }
                if (c < 0) != cmp::Less(a, b) {
                    total = false;
                }
            }
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "props antisymmetric=%v compare-agrees-less=%v nan-eq-nan=%v",
                antisym,
                total,
                cmp::Compare(&nan, &nan) == 0
            ),
        );
        let mut sv: slice<float64> =
            slice::__from_vec(alloc::vec![3.0, nan, 1.0, inf, nan, -1.0, ninf]);
        slices::SortFunc!(&mut sv, |a: &float64, b: &float64| -> int {
            return cmp::Compare(a, b);
        });
        let sorted = slices::IsSortedFunc(&sv, |a: &float64, b: &float64| -> int {
            return cmp::Compare(a, b);
        });
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("sort -> %s sorted=%v", showFloats(&sv), sorted),
        );
    }
    let ints: [(int, int); 6] = [
        (-1, 1),
        (1, -1),
        (0, 0),
        (math::MinInt64, math::MaxInt64),
        (math::MaxInt64, math::MinInt64),
        (5, 5),
    ];
    for (a, b) in ints.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "cmpi %-21d %-21d -> compare=%-2d less=%v",
                *a,
                *b,
                cmp::Compare(a, b),
                cmp::Less(a, b)
            ),
        );
    }
    let strs: [(&str, &str); 11] = [
        ("", ""),
        ("", "a"),
        ("a", ""),
        ("a", "b"),
        ("b", "a"),
        ("a", "a"),
        ("A", "a"),
        ("abc", "abd"),
        ("ab", "abc"),
        ("\u{0}", ""),
        ("é", "e"),
    ];
    for (a, b) in strs.iter() {
        let (x, y) = (s(a), s(b));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "cmps %-6q %-6q -> compare=%-2d less=%v",
                x.clone(),
                y.clone(),
                cmp::Compare(&x, &y),
                cmp::Less(&x, &y)
            ),
        );
    }
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "or-int %d %d %d %d",
            cmp::Or::<int>(&[0, 0, 3, 4]),
            cmp::Or::<int>(&[1, 2]),
            cmp::Or::<int>(&[0, 0]),
            cmp::Or::<int>(&[])
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "or-str %q %q %q %q",
            cmp::Or::<string>(&[string::new(), string::new(), s("c")]),
            cmp::Or::<string>(&[s("a"), s("b")]),
            cmp::Or::<string>(&[string::new(), string::new()]),
            cmp::Or::<string>(&[])
        ),
    );
    let orNaN = cmp::Or::<float64>(&[nan, 1.0]);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "or-float %g nan-passed-through=%v self-unequal=%v",
            cmp::Or::<float64>(&[0.0, 2.5]),
            math::IsNaN(orNaN),
            orNaN != orNaN
        ),
    );
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
