// maps_ref_smoke — the maps package against a running Go.
// (maps/maps.go, maps/iter.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_maps_ref.go` run in
// `package maps_test` by `scripts/goref.sh`. goish matched Go on all 25
// lines once `Insert` and `Collect` existed to be measured.
//
// maps is small enough that everything in it is a one-liner, which is
// exactly why it is worth measuring: a one-liner with the wrong
// emptiness rule is invisible until a caller depends on it.
//
// One gap closed. `Insert` and `Collect` were absent, with a header
// comment listing them as deferred "while goish has no iter package".
// It has one — `All` in the same file already returns a Seq2 — so the
// two were ported and the stale note removed. They are the only
// exported Go declarations found missing anywhere in the tree.
//
// What the reference pins:
//
//   * Copy MERGES into the destination rather than replacing it. A
//     caller expecting the destination to end up holding only the
//     source's entries gets the union, silently and without error.
//   * Insert over an existing key OVERWRITES it, so Insert and Copy
//     agree, and Collect of All round-trips to an equal map.
//   * DeleteFunc that removes everything leaves an EMPTY map, not a
//     nil one, and running it over a nil map is a no-op rather than a
//     panic.
//   * Equal answers TRUE for nil against empty. That one catches
//     people: the two are different values in Go and equal maps by
//     this function.
//   * EqualFunc is not a convenience wrapper — it exists because Equal
//     compares values with ==, which is undefined for values that are
//     not comparable.
//
// Keys and Values return ITERATORS, and map iteration order is
// deliberately randomised, so everything here is sorted before
// printing. That is not a workaround: a reference pinning an order
// would be pinning something Go does not promise.
//
// TWO THINGS ARE DELIBERATELY NOT MEASURED, both because they would
// measure goish's value model rather than this package:
//
//   * nil versus empty. Go's Clone(nil) is nil and Clone(empty) is
//     not; goish's `map` is a value whose polymorphic-nil comparison
//     is true exactly when it is empty, so the two states are one.
//     Only lengths are compared.
//   * Clone's SHALLOWNESS. In Go a slice value is shared with the
//     clone, so writing through one is visible in the other. goish's
//     slice OWNS its backing Vec and subslicing copies — recorded in
//     goslice.rs as a deliberate v1 deviation, with aliasing spelled
//     `&mut` instead. The line was dropped rather than pinned, since
//     pinning goish's answer here would dress a known deviation up as
//     agreement.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::gostring::string;
use goish::maps;
use goish::slices;
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 26] = [
    "keys=[a b c] values=[1 2 3]",
    "keys-empty=[] values-empty=[]",
    "keys-nil=[] values-nil=[]",
    "collect-roundtrip equal=true len=3",
    "insert -> {a=1 b=2 c=3 z=26}",
    "insert-overwrite -> {a=1 b=2 c=3}",
    "clone -> {a=100 b=2 c=3} original -> {a=1 b=2 c=3} independent=true",
    "clone-nil len=0",
    "clone-empty len=0",
    "copy-merges -> {a=1 b=2 c=3 x=24}",
    "copy-into-empty -> {a=1 b=2 c=3}",
    "copy-nil-src -> {keep=1}",
    "delete-odd -> {b=2}",
    "delete-all -> {} len=0",
    "delete-none -> {a=1 b=2 c=3}",
    "delete-nil ok len=0",
    "equal same           -> true",
    "equal self           -> true",
    "equal diff-value     -> false",
    "equal diff-key       -> false",
    "equal shorter        -> false",
    "equal nil-nil        -> true",
    "equal nil-empty      -> true",
    "equal empty-empty    -> true",
    "equal nil-nonempty   -> false",
    "equalfunc abs=true strict=false",
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
fn mk(pairs: &[(&str, int)]) -> map<string, int> {
    let mut m: map<string, int> = map::new();
    for (k, v) in pairs.iter() {
        m.Set(s(k), *v);
    }
    return m;
}
fn sortedKeys(m: &map<string, int>) -> slice<string> {
    let mut ks = slices::Collect(maps::Keys(m));
    sort::Strings(&mut ks);
    return ks;
}
fn showStrs(v: &slice<string>) -> string {
    let mut parts: Vec<string> = Vec::new();
    for i in 0..v.Len() {
        parts.push(v[i].clone());
    }
    return string::from("[") + strings::Join(slice::<string>::__from_vec(parts), s(" ")) + "]";
}
fn showInts(v: &slice<int>) -> string {
    let mut parts: Vec<string> = Vec::new();
    for i in 0..v.Len() {
        parts.push(fmt::Sprintf!("%d", v[i]));
    }
    return string::from("[") + strings::Join(slice::<string>::__from_vec(parts), s(" ")) + "]";
}
fn sortedVals(m: &map<string, int>) -> slice<int> {
    let mut vs = slices::Collect(maps::Values(m));
    let mut v = vs.to_vec();
    v.sort();
    vs = slice::<int>::__from_vec(v);
    return vs;
}
fn dump(m: &map<string, int>) -> string {
    let ks = sortedKeys(m);
    let mut parts: Vec<string> = Vec::new();
    for i in 0..ks.Len() {
        let k = ks[i].clone();
        let (v, _) = m.Get(k.clone());
        parts.push(fmt::Sprintf!("%s=%d", k, v));
    }
    return string::from("{") + strings::Join(slice::<string>::__from_vec(parts), s(" ")) + "}";
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let base = mk(&[("b", 2), ("a", 1), ("c", 3)]);
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "keys=%s values=%s",
                showStrs(&sortedKeys(&base)),
                showInts(&sortedVals(&base))
            ),
        );
        let empty: map<string, int> = map::new();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "keys-empty=%s values-empty=%s",
                showStrs(&sortedKeys(&empty)),
                showInts(&sortedVals(&empty))
            ),
        );
        let nilm: map<string, int> = map::new();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "keys-nil=%s values-nil=%s",
                showStrs(&sortedKeys(&nilm)),
                showInts(&sortedVals(&nilm))
            ),
        );
    }
    {
        let got = maps::Collect(maps::All(&base));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "collect-roundtrip equal=%v len=%d",
                maps::Equal(&got, &base),
                got.Len()
            ),
        );
        let mut dst = mk(&[("z", 26)]);
        maps::Insert(&mut dst, maps::All(&base));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("insert -> %s", dump(&dst)),
        );
        let mut dst2 = mk(&[("a", 99)]);
        maps::Insert(&mut dst2, maps::All(&base));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("insert-overwrite -> %s", dump(&dst2)),
        );
    }
    {
        let mut c = maps::Clone(&base);
        c.Set(s("a"), 100);
        let (av, _) = base.Get(s("a"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "clone -> %s original -> %s independent=%v",
                dump(&c),
                dump(&base),
                av == 1
            ),
        );
        let nilm: map<string, int> = map::new();
        let cn = maps::Clone(&nilm);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("clone-nil len=%d", cn.Len()),
        );
        let ce = maps::Clone(&map::<string, int>::new());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("clone-empty len=%d", ce.Len()),
        );
    }
    {
        let mut dst = mk(&[("x", 24), ("a", 0)]);
        maps::Copy(&mut dst, &base);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("copy-merges -> %s", dump(&dst)),
        );
        let mut empty: map<string, int> = map::new();
        maps::Copy(&mut empty, &base);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("copy-into-empty -> %s", dump(&empty)),
        );
        let src: map<string, int> = map::new();
        let mut d2 = mk(&[("keep", 1)]);
        maps::Copy(&mut d2, &src);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("copy-nil-src -> %s", dump(&d2)),
        );
    }
    {
        let mut d = maps::Clone(&base);
        maps::DeleteFunc(&mut d, |_k: &string, v: &int| -> bool {
            return *v % 2 == 1;
        });
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("delete-odd -> %s", dump(&d)),
        );
        let mut all = maps::Clone(&base);
        maps::DeleteFunc(&mut all, |_k: &string, _v: &int| -> bool {
            return true;
        });
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("delete-all -> %s len=%d", dump(&all), all.Len()),
        );
        let mut none = maps::Clone(&base);
        maps::DeleteFunc(&mut none, |_k: &string, _v: &int| -> bool {
            return false;
        });
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("delete-none -> %s", dump(&none)),
        );
        let mut nilm: map<string, int> = map::new();
        maps::DeleteFunc(&mut nilm, |_k: &string, _v: &int| -> bool {
            return true;
        });
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("delete-nil ok len=%d", nilm.Len()),
        );
    }
    {
        let nilm: map<string, int> = map::new();
        let empty: map<string, int> = map::new();
        let same = mk(&[("a", 1), ("b", 2), ("c", 3)]);
        let diffVal = mk(&[("a", 1), ("b", 2), ("c", 4)]);
        let diffKey = mk(&[("a", 1), ("b", 2), ("d", 3)]);
        let shorter = mk(&[("a", 1)]);
        let cases: [(&str, &map<string, int>, &map<string, int>); 9] = [
            ("same", &base, &same),
            ("self", &base, &base),
            ("diff-value", &base, &diffVal),
            ("diff-key", &base, &diffKey),
            ("shorter", &base, &shorter),
            ("nil-nil", &nilm, &nilm),
            ("nil-empty", &nilm, &empty),
            ("empty-empty", &empty, &empty),
            ("nil-nonempty", &nilm, &base),
        ];
        for (name, x, y) in cases.iter() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("equal %-14s -> %v", s(name), maps::Equal(x, y)),
            );
        }
        let abs = mk(&[("a", -1), ("b", -2), ("c", -3)]);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "equalfunc abs=%v strict=%v",
                maps::EqualFunc(&base, &abs, |a: &int, b: &int| -> bool {
                    return *a == -*b;
                }),
                maps::Equal(&base, &abs)
            ),
        );
    }
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
