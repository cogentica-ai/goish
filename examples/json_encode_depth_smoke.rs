// json_encode_depth_smoke — all THREE deep walks, pinned.
//
// `encode_value` serves Compact, Indent and Value::MarshalJSON;
// `encode_reflect` serves Marshal and is a different walk that this
// file did not cover until 2026-09-14 — which is how it came to be
// quadratic unnoticed. And `fmt`'s reflect printer is a third
// walk over the same tree, which had no deep coverage at all. See
// the second and third halves.
//
// `encode_value` is the encoder behind `Compact`, `Indent` and
// `Value::MarshalJSON`. It uses an EXPLICIT work stack rather than
// recursion, and the reason is measured: the recursive version managed
// depth 3500 and faulted at 4000 in a debug build, which made the
// encoder — not the parser — what `maxNestingDepth` was really
// protecting (see the note on that constant).
//
// Nothing watched that ceiling, so the property the work stack exists
// for was unguarded. This pins it, because it is easy to lose by
// accident: ANY recursion reintroduced in front of the stack lowers it,
// and the obvious way to do that is a `Value` clone.
//
// Measured while migrating the borrowed map walks for #7: making the
// work stack OWN its values needs one `Value::clone` of the root, and
// `Value`'s derived Clone recurses one frame per level. That single
// clone drops the ceiling from >100000 to ~12200 — an 8x loss —
// and it is the same regression `Unmarshal` already removed once. The
// 20000 row below is what turns red if it comes back.
//
// Run with a depth on argv to bisect a new ceiling by hand.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::encoding::json;
use goish::{fmt, int, os, string};

/// Build `{"k":{"k":{…}}}`, `depth` levels deep, WITHOUT recursing — so
/// the construction can never be what fails.
fn nest(depth: int) -> json::Value {
    let mut v = json::Value::Null;
    let mut i: int = 0;
    while i < depth {
        let mut m = json::Object::new();
        m.Set(string("k"), v);
        v = json::Value::Object(m);
        i += 1;
    }
    return v;
}

/// `{…}` nested `depth` deep is 6 bytes per level plus `null`:
/// `{"k":` is 5, `}` is 1, and the innermost value is `null`.
fn want_len(depth: int) -> int {
    return depth * 6 + 4;
}

#[goish::main]
fn main() {
    let args = os::Args();
    if args.Len() >= 2 {
        // Bisection mode: encode one depth and report. A stack overflow
        // here is the answer, not a failure.
        let (depth, err) = goish::strconv::Atoi(args[1i64].clone());
        if err != goish::nil {
            fmt::Println!("usage: json_encode_depth_smoke [DEPTH]");
            os::Exit(1);
        }
        let v = nest(depth);
        let (out, _) = json::Marshaler::MarshalJSON(&v);
        fmt::Printf!("depth=%d ok len=%d\n", depth, out.Len());
        os::Exit(0);
    }

    let mut failed: int = 0;
    let mut check = |name: &'static str, depth: int| {
        let v = nest(depth);
        let (out, err) = json::Marshaler::MarshalJSON(&v);
        let ok = err == goish::nil && out.Len() == want_len(depth);
        if ok {
            fmt::Printf!("[ok] %s depth=%d len=%d\n", name, depth, out.Len());
        } else {
            failed += 1;
            fmt::Printf!(
                "[!!] %s depth=%d len=%d want=%d err=%v\n",
                name,
                depth,
                out.Len(),
                want_len(depth),
                err
            );
        }
    };

    // The parser caps at 2000, so this is every depth a round trip can
    // reach. If this breaks, Compact and Indent are broken.
    check("round-trip reachable", 2000);

    // Well past the parser's cap, so only a hand-built Value gets here.
    // This is the row that fails if recursion reappears in front of the
    // work stack: the owned-stack attempt faulted between 12000 and
    // 12500, so 16000 is clear of it.
    //
    // 16000 and not higher because TWO other things here recurse, and
    // this row must not accidentally report the smaller of them.
    // Measured, debug build, 8 MiB goroutine stack:
    //
    //   Value::clone   faults 12000..12500   (derived, one frame/level)
    //   Value::drop    faults 19000..20000   (derived, one frame/level)
    //   encode_value   survives 100000       (explicit work stack)
    //
    // So the encoder is no longer what bounds a deep `Value` — its own
    // derived Clone and Drop are, and both are well above the parser's
    // cap of 2000, which is what makes a round trip safe. Anything that
    // brings the encoder back below those is what this row catches.
    check("beyond the clone ceiling", 16000);

    // ── the OTHER encoder ───────────────────────────────────────────
    //
    // `Marshal` is generic over `reflect::Reflect` and never calls
    // `encode_value`. It has its own walk, `encode_reflect`, and
    // nothing watched it — which is how it came to be QUADRATIC without
    // anyone noticing. Measured 2026-09-14, release build, the same
    // nested value:
    //
    //     depth  200    7.8 ms      depth 1600    499 ms
    //     depth  400   30.6 ms      depth 2400  1,127 ms
    //     depth  800  128.4 ms      depth 2600  allocator exhausted
    //
    // Four times the work for twice the depth, on a document 14 KB
    // long. The cause was `reflect::Value::MapIndex` returning
    // `v.clone()` — a DEEP copy of the whole remaining subtree, at
    // every level. Go's `MapIndex` returns a three-word header, so the
    // same code is linear there.
    //
    // With the borrow (`__map_index_ref` and its two siblings) the same
    // depths are 151 µs, 300 µs, 798 µs, 1.5 ms, 2.4 ms — linear, and
    // 2400 is 460x faster.
    //
    // Why this row is 10000 and the one above is 16000: the ceilings
    // are different walks. Measured, debug build:
    //
    //     encode_reflect   before  faults 2550..2600 (ALLOCATOR, and
    //                              identically in release — it was
    //                              never the stack)
    //                      after   faults 12000..13000 (stack)
    //
    // 10000 is Go's `maxNestingDepth`, so this row is also the evidence
    // for raising goish's from 2000 — which is a separate change,
    // because the margin at 10000 is 1.2x and §2d wants
    // `encode_reflect` iterative first.
    let mut marshal_check = |name: &'static str, depth: int| {
        let v = nest(depth);
        let (out, err) = json::Marshal(&v);
        let ok = err == goish::nil && out.Len() == want_len(depth);
        if ok {
            fmt::Printf!("[ok] %s depth=%d len=%d\n", name, depth, out.Len());
        } else {
            failed += 1;
            fmt::Printf!(
                "[!!] %s depth=%d len=%d want=%d err=%v\n",
                name,
                depth,
                out.Len(),
                want_len(depth),
                err
            );
        }
    };
    // The depth a round trip can reach today.
    marshal_check("Marshal round-trip reachable", 2000);
    // Four times the old ceiling. This is the row that fails if a
    // cloning accessor comes back into the walk.
    marshal_check("Marshal past the clone ceiling", 10000);

    // ── and the THIRD walk over the same tree ───────────────────────
    //
    // `fmt`'s reflect printer — what `%v` and `%+v` reach for a type
    // that derives Reflect — is a third recursive walk using the same
    // three cloning accessors, and it had NO deep-value coverage at
    // all, because `FmtBuf` is private so no example could reach it.
    //
    // It was quadratic too. Measured 2026-09-14, release build, on the
    // same nested value:
    //
    //     depth  200    8.5 ms -> 299 µs
    //     depth  400   42.1 ms -> 556 µs
    //     depth  800  143.2 ms -> 1.0 ms
    //     depth 1600  583.7 ms -> 1.8 ms      (320x)
    //     depth 20000       —  -> 28.2 ms
    //
    // So `fmt.Printf("%v", v)` on a deep structure — logging one, say —
    // cost half a second for 11 KB of output. Same cause, same fix.
    //
    // The length is checked, not just the absence of a fault: a walk
    // that silently truncated would be linear too.
    let mut fmt_check = |name: &'static str, depth: int, want: usize| {
        let v = nest(depth);
        let out = goish::fmt::__reflect_fmt_bytes(&v, b'v');
        if out.len() == want {
            fmt::Printf!("[ok] %s depth=%d len=%d\n", name, depth, out.len() as int);
        } else {
            failed += 1;
            fmt::Printf!(
                "[!!] %s depth=%d len=%d want=%d\n",
                name,
                depth,
                out.len() as int,
                want as int
            );
        }
    };
    // `map[k:map[k:…<nil>…]]` — 7 bytes per level plus `<nil>`.
    fmt_check("reflect printer round-trip reachable", 2000, 2000 * 7 + 5);
    fmt_check("reflect printer past the clone ceiling", 10000, 10000 * 7 + 5);

    if failed == 0 {
        fmt::Printf!("\nok 6/6\n");
        os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d of 6\n", failed);
    os::Exit(1);
}
