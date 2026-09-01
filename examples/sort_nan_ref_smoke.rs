// sort_nan_ref_smoke — Go's float ordering, against a running Go.
// (cmp/cmp.go, slices/sort.go, sort/sort.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_sort_nan_ref.go` run in `package
// sort_test` by `scripts/goref.sh`.
//
// Go's ordering of floats is neither Rust's `PartialOrd` nor IEEE
// comparison. `cmp.Less` puts a NaN BEFORE every non-NaN; `cmp.Compare`
// calls two NaNs equal; and -0.0 equals 0.0. Everything in the standard
// library that sorts or searches goes through those two.
//
// goish's `cmp` said so in a comment and then did not do it: "Slim
// deviation: floating-point NaN handling is omitted because the goish
// public API doesn't expose f32/f64 types yet" — which stopped being
// true long ago. Leaving NaN to `x < y` is not a mild divergence:
// `x < y` is FALSE in both directions for a NaN, so a comparison sort
// treats one as equal to everything and can leave the slice unsorted.
//
// In practice it could not even be reached, because `cmp::Compare`,
// `slices::Sort!`, `slices::IsSorted`, `Min`, `Max` and `BinarySearch`
// were all bounded on `T: Ord`, which no Rust float satisfies. Calling
// any of them on a `[]float64` was a compile error.
//
// And `sort.Ints`, `sort.Strings` and `sort.Float64s` — the three most
// written calls in the package — did not exist at all, though all three
// of their `AreSorted` predicates did.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::types::{float64, int};
use goish::{cmp, fmt, slice, slices, sort, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: compare one rendering against Go's and say
//     what differed.
fn eq(ok: &mut bool, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "   ",
            s(what),
            "got",
            fmt::Sprintf!("%q", got),
            "want",
            s(want)
        );
        *ok = false;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let nan = f64::NAN;
    let inf = f64::INFINITY;
    let ninf = f64::NEG_INFINITY;

    // 1. cmp.Less and cmp.Compare over the awkward pairs. Columns are
    //    Go's: (x, y, less, compare).
    {
        let mut ok = true;
        let cases: [(float64, float64, bool, int); 10] = [
            (1.0, 2.0, true, -1),
            (2.0, 1.0, false, 1),
            (1.0, 1.0, false, 0),
            // Go: a NaN sorts before every non-NaN…
            (nan, 1.0, true, -1),
            (1.0, nan, false, 1),
            // …and two NaNs are EQUAL, which is what lets a sort
            // terminate with them in it.
            (nan, nan, false, 0),
            (ninf, nan, false, 1),
            (nan, ninf, true, -1),
            (inf, nan, false, 1),
            (ninf, inf, true, -1),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (x, y, wl, wc) = cases[i];
            if cmp::Less(&x, &y) != wl || cmp::Compare(&x, &y) != wc {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!(
                        "%v %v got less=%v cmp=%d want %v %d",
                        x,
                        y,
                        cmp::Less(&x, &y),
                        cmp::Compare(&x, &y),
                        wl,
                        wc
                    )
                );
                ok = false;
            }
            i += 1;
        }
        // Integers and strings are unaffected — `x != x` is never true
        // for them, which is why Go writes isNaN that way.
        if !cmp::Less(&1i64, &2i64) || cmp::Compare(&2i64, &1i64) != 1 {
            ok = false;
        }
        if !cmp::Less(&s("a"), &s("b")) || cmp::Compare(&s("b"), &s("a")) != 1 {
            ok = false;
        }
        report(&mut failed, ok, " 1", "cmp.Less/Compare know about NaN");
    }

    // 2. A genuine negative zero. Note that a Go CONSTANT `-0.0` is
    //    plain zero — untyped constants have no signed zero — so Go's
    //    reference reaches this through math.Copysign. Go: v="-0"
    //    less01=false less10=false cmp=0 eq=true.
    {
        let mut ok = true;
        let nz: float64 = -0.0;
        if cmp::Less(&nz, &0.0) || cmp::Less(&0.0, &nz) || cmp::Compare(&nz, &0.0) != 0 {
            ok = false;
        }
        // Go: sortnz [-1 -0 0 1] — equal under the ordering, so the
        // two zeros keep the order the sort happens to leave them in.
        let mut f: slice<float64> = goish::slice!([]f64{1.0, -0.0, 0.0, -1.0});
        slices::Sort!(f);
        eq(
            &mut ok,
            "sort with -0",
            fmt::Sprintf!("%v", f),
            "[-1 -0 0 1]",
        );
        report(&mut failed, ok, " 2", "-0.0 compares equal to 0.0");
    }

    // 3. slices.Sort and sort.Float64s over a slice with NaNs. Go:
    //    [NaN NaN -Inf 0 0 1 2 3 +Inf], and IsSorted says true.
    //
    //    Before this, none of these three calls compiled on a float
    //    slice at all.
    {
        let mut ok = true;
        let mk = || -> slice<float64> {
            goish::slice!([]f64{3.0, nan, 1.0, inf, nan, ninf, 2.0, 0.0, 0.0})
        };
        let mut a = mk();
        slices::Sort!(a);
        eq(
            &mut ok,
            "slices.Sort",
            fmt::Sprintf!("%v", a.clone()),
            "[NaN NaN -Inf 0 0 1 2 3 +Inf]",
        );
        if !slices::IsSorted(&a) {
            ok = false;
        }
        let mut b = mk();
        sort::Float64s(&mut b);
        eq(
            &mut ok,
            "sort.Float64s",
            fmt::Sprintf!("%v", b.clone()),
            "[NaN NaN -Inf 0 0 1 2 3 +Inf]",
        );
        if !sort::Float64sAreSorted(&b) {
            ok = false;
        }
        // Go: issorted a=true b=false c=false — a NaN counts as sorted
        // only at the front, which is where cmp.Less puts it.
        let f1: slice<float64> = goish::slice!([]f64{nan, 1.0, 2.0});
        let f2: slice<float64> = goish::slice!([]f64{1.0, nan, 2.0});
        let f3: slice<float64> = goish::slice!([]f64{1.0, 2.0, nan});
        if !slices::IsSorted(&f1) || slices::IsSorted(&f2) || slices::IsSorted(&f3) {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "NaNs sort to the front, and stay sorted",
        );
    }

    // 4. sort.Ints and sort.Strings. Go: [-1 2 2 5 9] and
    //    ["" "Apple" "apple" "pear"] — upper case before lower, because
    //    the order is over bytes.
    {
        let mut ok = true;
        let mut i2: slice<int> = goish::slice!([]int{5, 2, 9, 2, -1});
        sort::Ints(&mut i2);
        eq(
            &mut ok,
            "sort.Ints",
            fmt::Sprintf!("%v", i2),
            "[-1 2 2 5 9]",
        );
        let mut s2: slice<string> =
            goish::slice!([]string{s("pear"), s("Apple"), s("apple"), s("")});
        sort::Strings(&mut s2);
        eq(
            &mut ok,
            "sort.Strings",
            fmt::Sprintf!("%q", s2),
            "[\"\" \"Apple\" \"apple\" \"pear\"]",
        );
        // The generic forms agree.
        let mut i3: slice<int> = goish::slice!([]int{5, 2, 9, 2, -1});
        slices::Sort!(i3);
        eq(
            &mut ok,
            "slices.Sort ints",
            fmt::Sprintf!("%v", i3),
            "[-1 2 2 5 9]",
        );
        report(&mut failed, ok, " 4", "sort.Ints and sort.Strings exist");
    }

    // 5. SortStableFunc keeps ties in input order, which is the whole
    //    reason to reach for it. Go, sorting these by their second
    //    byte: ["b1" "d1" "a2" "c2" "e2"].
    {
        let mut ok = true;
        let mut xs: slice<string> = goish::slice!([]string{
            s("a2"), s("b1"), s("c2"), s("d1"), s("e2")
        });
        slices::SortStableFunc!(xs, |a: &string, b: &string| {
            cmp::Compare(&a.as_bytes()[1], &b.as_bytes()[1])
        });
        eq(
            &mut ok,
            "SortStableFunc",
            fmt::Sprintf!("%q", xs),
            "[\"b1\" \"d1\" \"a2\" \"c2\" \"e2\"]",
        );
        report(&mut failed, ok, " 5", "SortStableFunc keeps ties in order");
    }

    // 6. Min and Max. Go uses the BUILTIN min/max, whose float rule is
    //    "if any argument is a NaN, the result is a NaN" — not
    //    cmp.Less's rule and not `<`'s. Go: minmaxf 1 3, minmaxnan NaN
    //    NaN.
    {
        let mut ok = true;
        let ii: slice<int> = goish::slice!([]int{-1, 2, 2, 5, 9});
        if slices::Min(&ii) != -1 || slices::Max(&ii) != 9 {
            ok = false;
        }
        let ss: slice<string> = goish::slice!([]string{s(""), s("Apple"), s("apple"), s("pear")});
        if slices::Min(&ss) != s("") || slices::Max(&ss) != s("pear") {
            ok = false;
        }
        let fm: slice<float64> = goish::slice!([]f64{2.0, 1.0, 3.0});
        eq(
            &mut ok,
            "Min float",
            fmt::Sprintf!("%v", slices::Min(&fm)),
            "1",
        );
        eq(
            &mut ok,
            "Max float",
            fmt::Sprintf!("%v", slices::Max(&fm)),
            "3",
        );
        let fnn: slice<float64> = goish::slice!([]f64{2.0, nan, 3.0});
        eq(
            &mut ok,
            "Min NaN",
            fmt::Sprintf!("%v", slices::Min(&fnn)),
            "NaN",
        );
        eq(
            &mut ok,
            "Max NaN",
            fmt::Sprintf!("%v", slices::Max(&fnn)),
            "NaN",
        );
        report(&mut failed, ok, " 6", "Min/Max propagate a NaN");
    }

    // 7. BinarySearch follows cmp.Compare, so a NaN is findable at the
    //    front of a sorted float slice. Go: bsearch NaN i=0 found=true,
    //    1.5 i=4 found=false, 99 i=5 found=false.
    {
        let mut ok = true;
        let sorted: slice<float64> = goish::slice!([]f64{nan, ninf, 0.0, 1.0, 2.0, inf});
        let cases: [(float64, int, bool); 6] = [
            (nan, 0, true),
            (ninf, 1, true),
            (0.0, 2, true),
            (1.5, 4, false),
            (inf, 5, true),
            (99.0, 5, false),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (target, wi, wf) = cases[i];
            let (gi, gf) = slices::BinarySearch(&sorted, &target);
            if gi != wi || gf != wf {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("bsearch %v got %d %v want %d %v", target, gi, gf, wi, wf)
                );
                ok = false;
            }
            i += 1;
        }
        // And over ints, which already worked — kept so a regression in
        // the relaxed bound shows up here.
        let si: slice<int> = goish::slice!([]int{1, 3, 5, 7});
        let icases: [(int, int, bool); 5] = [
            (0, 0, false),
            (1, 0, true),
            (4, 2, false),
            (7, 3, true),
            (9, 4, false),
        ];
        let mut k = 0usize;
        while k < icases.len() {
            let (target, wi, wf) = icases[k];
            let (gi, gf) = slices::BinarySearch(&si, &target);
            if gi != wi || gf != wf {
                ok = false;
            }
            // Go: sort.SearchInts agrees on the insertion point.
            if sort::SearchInts(&si, target) != wi {
                ok = false;
            }
            k += 1;
        }
        report(&mut failed, ok, " 7", "BinarySearch follows cmp.Compare");
    }

    // 8. sort.Search and sort.Find, which were already right — pinned
    //    so the surrounding changes cannot quietly move them. Go:
    //    empty=0 all=0 none=5; find 5 i=2 found=true; find 4 i=2
    //    found=false.
    {
        let mut ok = true;
        if sort::Search(0, |_| true) != 0
            || sort::Search(5, |_| true) != 0
            || sort::Search(5, |_| false) != 5
        {
            ok = false;
        }
        let si: slice<int> = goish::slice!([]int{1, 3, 5, 7});
        let (i, found) = sort::Find(4, |i| cmp::Compare(&5i64, &si[i]));
        if i != 2 || !found {
            ok = false;
        }
        let (i2, found2) = sort::Find(4, |i| cmp::Compare(&4i64, &si[i]));
        if i2 != 2 || found2 {
            ok = false;
        }
        report(&mut failed, ok, " 8", "Search and Find are unchanged");
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
