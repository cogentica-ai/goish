// map_hint_ref_smoke — `make!(map[K]V, hint)` honours the hint (#23).
//
// The two-argument map arm used to read
//
//     (map[$kt:ty]$vt:ty, $hint:expr) => {{
//         let _ = $hint;
//         $crate::gomap::map::<$kt, $vt>::new()
//     }};
//
// — the hint evaluated and thrown away. A comment said that was
// deliberate while `gomap` was BTreeMap-backed and reserved for the
// hash-map port; the hash table landed and the hint path did not.
//
// ── what real Go says, measured rather than assumed ──
//
// A plain Go program (negative and huge hints come from variables,
// because a negative CONSTANT is a compile error):
//
//     negative_hint_panics   false   and the map works
//     huge_hint_panics       false   (1<<60) and the map works
//     hinted_len_is_zero     true
//     hinted_holds_all       true    (1000 into a hint of 1000)
//     zero_hint_len          0
//     hint_evaluated_times   1
//
// The first row is why this does NOT route through
// `builtin::__make_size`, which panics on a negative. That is correct
// for a slice — Go panics there too — and wrong for a map. Reusing it
// would have turned a working Go program into a panic.
//
// ── the bucket arithmetic ──
//
// `Set` grows when `count > BUCKET_COUNT` AND
// `count > LOAD_FACTOR_NUM * (1 << b) / LOAD_FACTOR_DEN` (8, and 6.5 per
// bucket). `with_capacity` walks the same predicate rather than a second
// copy of it, so the `b` it picks is exactly the one that does not grow
// on the insertion the hint was for. Expected, worked out from those
// constants and asserted below:
//
//     hint 0..=8 -> b=0, zero buckets (Go allocates lazily too)
//     hint 9     -> b=1   (threshold 6.5 -> 13)
//     hint 13    -> b=1
//     hint 14    -> b=2   (threshold 13 -> 26)
//     hint 100   -> b=4   (52 -> 104)
//     hint 1000  -> b=8   (832 -> 1664)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);
static HINT_CALLS: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: string) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    if ok {
        fmt::Printf!("[ok] %s\n", string::from_static(name));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] %s — %s\n", string::from_static(name), detail);
    }
}

/// A hint with a side effect, so "evaluated exactly once" is observable.
fn counting_hint() -> int {
    HINT_CALLS.fetch_add(1, Ordering::Relaxed);
    return 64;
}

#[goish::main]
fn main() {
    // ── the hint is evaluated exactly once ──
    HINT_CALLS.store(0, Ordering::Relaxed);
    let m = goish::make!(map[int]int, counting_hint());
    check(
        "the hint expression is evaluated exactly once",
        HINT_CALLS.load(Ordering::Relaxed) == 1,
        fmt::Sprintf!("calls=%d", HINT_CALLS.load(Ordering::Relaxed) as i64),
    );
    check(
        "a hinted map is still empty",
        goish::len(&m) == 0,
        fmt::Sprintf!("len=%d", goish::len(&m)),
    );

    // ── small hints keep Go's lazy, single-bucket behaviour ──
    let mut small_ok = true;
    let mut small_detail = string::from_static("");
    for h in [0i64, 1, 5, 8] {
        let m = goish::make!(map[int]int, h);
        if m.__b() != 0 || m.__bucket_len() != 0 {
            small_ok = false;
            small_detail = fmt::Sprintf!("hint=%d b=%d buckets=%d", h, m.__b() as i64, m.__bucket_len() as i64);
        }
    }
    check(
        "hints up to BUCKET_COUNT allocate nothing, as Go does",
        small_ok,
        small_detail,
    );

    // ── the chosen b, against the load-factor arithmetic ──
    let mut b_ok = true;
    let mut b_detail = string::from_static("");
    for (h, want_b) in [(9i64, 1u8), (13, 1), (14, 2), (100, 4), (1000, 8)] {
        let m = goish::make!(map[int]int, h);
        if m.__b() != want_b || m.__bucket_len() != (1usize << want_b) {
            b_ok = false;
            b_detail = fmt::Sprintf!(
                "hint=%d b=%d want=%d buckets=%d",
                h,
                m.__b() as i64,
                want_b as i64,
                m.__bucket_len() as i64
            );
        }
    }
    check("a hint picks the b the growth rule asks for", b_ok, b_detail);

    // ── the point of the whole exercise: no growth on the hinted fill ──
    {
        let mut m = goish::make!(map[int]int, 1000);
        let b_before = m.__b();
        let mut i: int = 0;
        while i < 1000 {
            m.Set(i, i * 2);
            i += 1;
        }
        check(
            "inserting the hinted count does not grow the table",
            m.__b() == b_before && goish::len(&m) == 1000,
            fmt::Sprintf!(
                "b %d -> %d, len=%d",
                b_before as i64,
                m.__b() as i64,
                goish::len(&m)
            ),
        );
        // And the entries are actually there, not just counted.
        let (v, ok) = m.Get(999);
        check(
            "the hinted map's entries are retrievable",
            ok && v == 1998,
            fmt::Sprintf!("m[999]=%d ok=%v", v, ok),
        );
    }

    // ── past the threshold it grows normally ──
    {
        // hint 9 gives b=1, whose threshold is 13 entries.
        let mut m = goish::make!(map[int]int, 9);
        let mut i: int = 0;
        while i < 13 {
            m.Set(i, i);
            i += 1;
        }
        let b_at_13 = m.__b();
        m.Set(13, 13);
        check(
            "one insertion past the load threshold grows",
            b_at_13 == 1 && m.__b() == 2,
            fmt::Sprintf!("b at 13 = %d, after 14 = %d", b_at_13 as i64, m.__b() as i64),
        );
    }

    // ── the edges Go does not panic on ──
    {
        let neg: int = -1;
        let mut m = goish::make!(map[int]int, neg);
        m.Set(1, 1);
        let (v, ok) = m.Get(1);
        check(
            "a negative hint behaves like an unhinted map, no panic",
            m.__b() == 0 && ok && v == 1,
            fmt::Sprintf!("b=%d ok=%v v=%d", m.__b() as i64, ok, v),
        );
    }
    {
        // 1<<60 entries of bucket-sized storage is far past any ceiling.
        let huge: int = 1i64 << 60;
        let mut m = goish::make!(map[int]int, huge);
        m.Set(7, 7);
        let (v, ok) = m.Get(7);
        check(
            "an absurd hint clamps instead of wrapping or allocating",
            m.__bucket_len() <= 1 && ok && v == 7,
            fmt::Sprintf!("buckets=%d ok=%v v=%d", m.__bucket_len() as i64, ok, v),
        );
    }

    // ── the unhinted form is untouched ──
    {
        let mut m = goish::make!(map[string]int);
        check(
            "make!(map[K]V) still allocates lazily",
            m.__b() == 0 && m.__bucket_len() == 0,
            fmt::Sprintf!("b=%d buckets=%d", m.__b() as i64, m.__bucket_len() as i64),
        );
        m.Set(string::from_static("k"), 1);
        let (v, ok) = m.Get(string::from_static("k"));
        check(
            "make!(map[K]V) still works",
            ok && v == 1 && goish::len(&m) == 1,
            fmt::Sprintf!("v=%d ok=%v len=%d", v, ok, goish::len(&m)),
        );
    }

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    if ran != 11 {
        fmt::Printf!("\nFAILED: %d rows ran, expected 11\n", ran as i64);
        goish::os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, ran as i64);
}
