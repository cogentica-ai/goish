// map_nil_ref_smoke — nil versus allocated-empty maps (#7, the nil half).
//
// Go's map is a header over backing state, and a nil header is
// DISTINGUISHABLE from one pointing at an empty table. goish collapsed
// the two: `From<Nil>` built an empty map, `m == nil` was `count == 0`,
// and a write to a nil map quietly succeeded.
//
// Every row here comes from tools/gen_map_alias_ref.go against real Go:
//
//     nil_is_nil                true
//     empty_is_nil              false      <- goish said true
//     nil_read / nil_read_ok    0 / 0,false
//     nil_len                   0
//     nil_range_iters           0
//     nil_delete_ok             true       deleting FROM nil is legal
//     nil_clear_ok              true       so is clearing it
//     nil_write_panic_msg       "assignment to entry in nil map"
//     mapsclone_of_nil_is_nil   true       <- NOT an empty map
//     nil_through_call_still_nil true
//
// The write-panic row is a SUBPROCESS (map_nil_write_probe), because
// goish's `recover!()` does not resume execution.
//
// ── what this half does NOT fix ──
//
// Aliasing. A copy of a non-nil map is still an independent deep copy,
// so `clone_aliases` and `return_aliases` remain divergent; those need
// the shared header and the `__iter` / `Index` / `GetRef` migration that
// ROADMAP §2u sizes. The nil flag is independently correct and survives
// that change unchanged.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::gostring::string;
use goish::os::exec;
use goish::types::int;
use goish::{fmt, map, os};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: string) {
    ROWS.fetch_add(1, Ordering::Relaxed);
    if ok {
        fmt::Printf!("[ok] %s\n", string::from_static(name));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] %s — %s\n", string::from_static(name), detail);
    }
}

/// Probes sit beside this binary whatever the profile or target dir.
fn probe_path(name: &str) -> string {
    let args = os::Args();
    let me = args[0].clone();
    let s: &str = me.as_ref();
    let cut = match s.rfind('/') {
        Some(i) => i + 1,
        None => 0,
    };
    return string::from(&s[..cut]) + string::from(name);
}

#[inline(never)]
fn round_trip(m: map<string, int>) -> map<string, int> {
    return m;
}

#[goish::main]
fn main() {
    // ── nil identity ──
    {
        let z: map<string, int> = goish::nil.into();
        check("a nil map is nil", z == goish::nil, string::from_static("z != nil"));
        check(
            "an allocated-empty map is NOT nil",
            !(goish::make!(map[string]int) == goish::nil),
            string::from_static("make!(map[K]V) compared equal to nil"),
        );
        check(
            "the zero value of a map is nil, as in Go",
            map::<string, int>::default() == goish::nil,
            string::from_static("Default is not nil"),
        );
    }

    // ── reads, len, range, delete and clear are all legal on nil ──
    {
        let mut z: map<string, int> = goish::nil.into();
        let (v, ok) = z.Get(string::from_static("missing"));
        check(
            "reading a nil map yields the zero value and false",
            v == 0 && !ok,
            fmt::Sprintf!("v=%d ok=%v", v, ok),
        );
        check("len of a nil map is 0", goish::len(&z) == 0, fmt::Sprintf!("len=%d", goish::len(&z)));
        let mut iters = 0;
        for _ in z.__iter() {
            iters += 1;
        }
        check("ranging a nil map yields nothing", iters == 0, fmt::Sprintf!("iters=%d", iters as i64));
        z.Delete(string::from_static("k"));
        check("deleting from a nil map is legal", z == goish::nil, string::from_static("delete changed nil-ness"));
        z.Clear();
        check("clearing a nil map is legal", z == goish::nil, string::from_static("clear changed nil-ness"));
    }

    // ── nil survives a copy and a call ──
    {
        let z: map<string, int> = goish::nil.into();
        check("a copy of a nil map is nil", z.clone() == goish::nil, string::from_static("clone of nil is not nil"));
        check(
            "nil survives being passed and returned",
            round_trip(z.clone()) == goish::nil,
            string::from_static("round trip lost nil"),
        );
    }

    // ── maps::Clone ──
    {
        let z: map<string, int> = goish::nil.into();
        check(
            "maps::Clone of a nil map is NIL, not empty",
            goish::maps::Clone(&z) == goish::nil,
            string::from_static("Clone(nil) is an allocated-empty map"),
        );
        let mut m: map<string, int> = goish::make!(map[string]int);
        m.Set(string::from_static("a"), 1);
        let c = goish::maps::Clone(&m);
        check(
            "maps::Clone of a non-nil map is not nil",
            !(c == goish::nil) && goish::len(&c) == 1,
            fmt::Sprintf!("len=%d", goish::len(&c)),
        );
    }

    // ── v1 marshal: a nil map is null, an empty one is {} ──
    //
    // Measured: v1 gives `null` / `{}`, v2 gives `{}` for both. Needed
    // `reflect` to carry nil-ness, the same change #14's slice half
    // required.
    {
        let nm: map<string, int> = Default::default();
        let (b, e) = goish::encoding::json::Marshal(&nm);
        let got = string::from_bytes(b.as_ref());
        check(
            "v1 marshals a nil map as null",
            e.IsNil() && got == "null",
            fmt::Sprintf!("got %s", got),
        );
    }
    {
        let em: map<string, int> = goish::make!(map[string]int);
        let (b, e) = goish::encoding::json::Marshal(&em);
        let got = string::from_bytes(b.as_ref());
        check(
            "v1 marshals an allocated-empty map as {}",
            e.IsNil() && got == "{}",
            fmt::Sprintf!("got %s", got),
        );
    }

    // ── unmarshalling into a nil map ──
    //
    // Go: "To unmarshal a JSON object into a map, Unmarshal first
    // establishes a map to use. If the map is nil, Unmarshal allocates a
    // new map." Measured in v1 and v2 alike, including the two edges:
    // an EMPTY object allocates, and JSON null does NOT.
    //
    // goish's decoder relied on the destination already being writable,
    // which held only while a default-constructed map was an empty one.
    // `var m map[string]string` ports to `Default::default()`, so two
    // existing examples panicked the moment nil identity landed — which
    // is how this was found.
    {
        let mut m: map<string, string> = Default::default();
        let e = goish::encoding::json::v2::Unmarshal(
            string::from_static("{\"a\":\"1\"}").as_bytes(),
            &mut m,
            &[],
        );
        let (v, ok) = m.Get(string::from_static("a"));
        check(
            "unmarshalling an object into a nil map allocates it",
            e.IsNil() && !(m == goish::nil) && ok && v == "1",
            fmt::Sprintf!("err=%v nil=%v v=%q", e, m == goish::nil, v),
        );
    }
    {
        let mut m: map<string, string> = Default::default();
        let e = goish::encoding::json::v2::Unmarshal(
            string::from_static("{}").as_bytes(),
            &mut m,
            &[],
        );
        check(
            "an EMPTY object allocates too, and is not nil",
            e.IsNil() && !(m == goish::nil) && goish::len(&m) == 0,
            fmt::Sprintf!("err=%v nil=%v len=%d", e, m == goish::nil, goish::len(&m)),
        );
    }
    {
        let mut m: map<string, string> = Default::default();
        let e = goish::encoding::json::v2::Unmarshal(
            string::from_static("null").as_bytes(),
            &mut m,
            &[],
        );
        check(
            "JSON null leaves a nil map nil, it does not allocate",
            e.IsNil() && m == goish::nil,
            fmt::Sprintf!("err=%v nil=%v", e, m == goish::nil),
        );
    }

    // ── the write panic, in its own process ──
    {
        let path = probe_path("map_nil_write_probe");
        let mut cmd = exec::Command(path.clone(), goish::make!([]string, 0));
        let (out, err) = cmd.CombinedOutput();
        let text = string::from_bytes(out.as_ref());
        let t: &str = text.as_ref();
        match &cmd.ProcessState {
            None => {
                check(
                    "the nil-write probe ran",
                    false,
                    fmt::Sprintf!("probe did not run: %s (%v) — build it with: cargo build --example map_nil_write_probe", path, err),
                );
            }
            Some(st) => {
                check(
                    "writing to a nil map kills the process",
                    st.ExitCode() != 0,
                    fmt::Sprintf!("exit=%d", st.ExitCode()),
                );
                check(
                    "it panics with Go's exact message",
                    t.contains("assignment to entry in nil map"),
                    fmt::Sprintf!("output=%q", text.clone()),
                );
                check(
                    "and it got as far as the write",
                    t.contains("about to write to a nil map")
                        && !t.contains("WROTE TO A NIL MAP"),
                    fmt::Sprintf!("output=%q", text),
                );
            }
        }
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
