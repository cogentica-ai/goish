// slice_nil_ref_smoke — nil versus allocated-empty slices (#14).
//
// Go's slice header can be nil, and that is observable: `[]int{} == nil`
// is FALSE, `var s []int` is true, and v1 JSON marshals the first as `[]`
// and the second as `null`. goish collapsed all of it —
// `PartialEq<Nil>` was `Len() == 0`, so all three zero-length values
// compared equal to nil.
//
// Every row comes from tools/gen_slice_nil_ref.go, which now covers v1
// and v2 (ROADMAP §2t):
//
//     nil_is_nil            true
//     literal_is_nil        false     []int{}
//     make_is_nil           false     make([]int, 0)
//     append_nil_is_nil     false     appending allocates
//     nil_slice0_is_nil     TRUE      nilSlice[:0] STAYS nil
//     empty_slice0_is_nil   false     emptyLiteral[:0] does not
//
//     marshal               v1         v2
//       nil                 null       []
//       []int{}             []         []
//       omitempty nil/empty {} / {}    {} / {}
//       omitzero  nil/empty -          {} / {"s":[]}
//
//     unmarshal, identical in v1 and v2
//       null -> nil, INCLUDING over an existing non-empty slice
//       []   -> allocated-empty, not nil
//
// ── two scoping decisions this file records ──
//
// 1. `slice::new()` stays NON-nil — it is the `[]T{}` spelling. Only
//    `Default::default()` and `nil.into()` are nil, which is
//    unambiguous because Go's zero value for a slice IS nil. `new()`
//    has 648 call sites and, unlike the map equivalent, a mistaken one
//    changes JSON output SILENTLY instead of panicking, so the
//    byte-exact JSON differentials are the only detector. That is the
//    reason for the narrow scope, not an oversight.
//
// 2. v1 marshal of a nil slice as `null` IS here, and it needed
//    `reflect` to carry nil-ness: `Value::Slice` gained an `is_nil`
//    header and `IsNil()` stopped being hard-coded false. Seventeen
//    construction sites across five files; all but two are synthesised
//    values that are non-nil by construction, and `reflect::Zero` of a
//    slice or map type is NIL, which is Go's zero value.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::v2 as json2;
use goish::gostring::string;
use goish::types::int;
use goish::{fmt, os, slice};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);

#[goish::reflect]
pub struct Rec {
    #[tag(r#"json:"s""#)]
    S: slice<int>,
}

#[goish::reflect]
pub struct OmitEmpty {
    #[tag(r#"json:"s,omitempty""#)]
    S: slice<int>,
}

#[goish::reflect]
pub struct OmitZero {
    #[tag(r#"json:"s,omitzero""#)]
    S: slice<int>,
}

fn check(name: &'static str, ok: bool, detail: string) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    if ok {
        fmt::Printf!("[ok] %s\n", string::from_static(name));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] %s — %s\n", string::from_static(name), detail);
    }
}

fn marshal2<T: json2::MarshalerTo>(v: &T) -> string {
    let (b, err) = json2::Marshal(v, &[]);
    if !err.IsNil() {
        return string::from_static("<error>");
    }
    return string::from_bytes(b.as_ref());
}

#[goish::main]
fn main() {
    // ── identity ──
    let z: slice<int> = Default::default();
    let made: slice<int> = goish::make!([]int, 0);
    check("var s []T is nil", z == goish::nil, string::from_static("Default is not nil"));
    check(
        "make([]T, 0) is NOT nil",
        !(made == goish::nil),
        string::from_static("make compared equal to nil"),
    );
    check(
        "slice::new() is the []T{} spelling, not nil",
        !(slice::<int>::new() == goish::nil),
        string::from_static("new() is nil"),
    );
    check(
        "both have length zero",
        goish::len(&z) == 0 && goish::len(&made) == 0,
        fmt::Sprintf!("%d / %d", goish::len(&z), goish::len(&made)),
    );

    // ── appending to nil allocates ──
    {
        let g = goish::append!(z.clone(), 1);
        check(
            "appending to a nil slice yields a non-nil slice",
            !(g == goish::nil) && goish::len(&g) == 1,
            fmt::Sprintf!("nil=%v len=%d", g == goish::nil, goish::len(&g)),
        );
    }

    // ── the row a flag-based implementation gets wrong ──
    check(
        "re-slicing a nil slice to zero PRESERVES nil",
        z.slice(0, 0) == goish::nil,
        string::from_static("nilSlice[:0] lost its nil-ness"),
    );
    check(
        "re-slicing an allocated-empty slice does NOT invent nil",
        !(made.slice(0, 0) == goish::nil),
        string::from_static("emptyLiteral[:0] became nil"),
    );

    // ── v2 marshal: both are [] ──
    check(
        "v2 marshals a nil slice as [], as Go's v2 does",
        marshal2(&z) == "[]",
        fmt::Sprintf!("got %s", marshal2(&z)),
    );
    check(
        "v2 marshals an empty slice as []",
        marshal2(&made) == "[]",
        fmt::Sprintf!("got %s", marshal2(&made)),
    );
    {
        let zero = Rec { S: Default::default() };
        check(
            "v2 marshals a zero-value record's slice field as []",
            marshal2(&zero) == "{\"s\":[]}",
            fmt::Sprintf!("got %s", marshal2(&zero)),
        );
    }

    // ── omitempty drops both; omitzero drops only nil ──
    {
        let a = OmitEmpty { S: Default::default() };
        let b = OmitEmpty { S: goish::make!([]int, 0) };
        check(
            "omitempty drops a nil slice AND an empty one",
            marshal2(&a) == "{}" && marshal2(&b) == "{}",
            fmt::Sprintf!("nil=%s empty=%s", marshal2(&a), marshal2(&b)),
        );
    }
    {
        let a = OmitZero { S: Default::default() };
        let b = OmitZero { S: goish::make!([]int, 0) };
        check(
            "omitzero drops ONLY nil, because nil is the zero value",
            marshal2(&a) == "{}" && marshal2(&b) == "{\"s\":[]}",
            fmt::Sprintf!("nil=%s empty=%s", marshal2(&a), marshal2(&b)),
        );
    }

    // ── v1 marshal: nil is null, empty is [] ──
    {
        let (b, e) = goish::encoding::json::Marshal(&z);
        let got = string::from_bytes(b.as_ref());
        check(
            "v1 marshals a nil slice as null",
            e.IsNil() && got == "null",
            fmt::Sprintf!("got %s", got),
        );
    }
    {
        let (b, e) = goish::encoding::json::Marshal(&made);
        let got = string::from_bytes(b.as_ref());
        check(
            "v1 marshals an allocated-empty slice as []",
            e.IsNil() && got == "[]",
            fmt::Sprintf!("got %s", got),
        );
    }
    {
        let zero = Rec { S: Default::default() };
        let (b, _) = goish::encoding::json::Marshal(&zero);
        let got = string::from_bytes(b.as_ref());
        check(
            "v1 marshals a zero-value record's slice field as null",
            got == "{\"s\":null}",
            fmt::Sprintf!("got %s", got),
        );
    }

    // ── decoders put null back as nil ──
    {
        let mut s: slice<int> = Default::default();
        let e = json2::Unmarshal(string::from_static("null").as_bytes(), &mut s, &[]);
        check(
            "v2 decodes null to a nil slice",
            e.IsNil() && s == goish::nil,
            fmt::Sprintf!("err=%v nil=%v", e, s == goish::nil),
        );
    }
    {
        let mut s: slice<int> = Default::default();
        let e = json2::Unmarshal(string::from_static("[]").as_bytes(), &mut s, &[]);
        check(
            "v2 decodes [] to an allocated-empty slice, not nil",
            e.IsNil() && !(s == goish::nil) && goish::len(&s) == 0,
            fmt::Sprintf!("err=%v nil=%v len=%d", e, s == goish::nil, goish::len(&s)),
        );
    }
    {
        let mut s: slice<int> = goish::make!([]int, 2);
        let e = json2::Unmarshal(string::from_static("null").as_bytes(), &mut s, &[]);
        check(
            "v2 decodes null OVER an existing slice, leaving nil",
            e.IsNil() && s == goish::nil && goish::len(&s) == 0,
            fmt::Sprintf!("err=%v nil=%v len=%d", e, s == goish::nil, goish::len(&s)),
        );
    }
    {
        let mut s: slice<int> = Default::default();
        let e = goish::encoding::json::Unmarshal(
            string::from_static("null").as_bytes(),
            &mut s,
        );
        check(
            "v1 decodes null to a nil slice too",
            e.IsNil() && s == goish::nil,
            fmt::Sprintf!("err=%v nil=%v", e, s == goish::nil),
        );
    }
    {
        let mut s: slice<int> = Default::default();
        let e = goish::encoding::json::Unmarshal(
            string::from_static("[]").as_bytes(),
            &mut s,
        );
        check(
            "v1 decodes [] to an allocated-empty slice",
            e.IsNil() && !(s == goish::nil),
            fmt::Sprintf!("err=%v nil=%v", e, s == goish::nil),
        );
    }

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    if ran != 20 {
        fmt::Printf!("\nFAILED: %d rows ran, expected 20\n", ran as i64);
        os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, ran as i64);
}
