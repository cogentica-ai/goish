// json_encode_depth_smoke — `encode_value`'s depth ceiling, pinned.
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

    if failed == 0 {
        fmt::Printf!("\nok 2/2\n");
        os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d of 2\n", failed);
    os::Exit(1);
}
