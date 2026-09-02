// sync_map_ref_smoke — sync.Map's semantics against a running Go.
// (sync/map.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_syncmap_ref.go` run in `package
// sync_test` by `scripts/goref.sh`.
//
// Every file under src/sync/ carried ZERO provenance anchors —
// `port_coverage sync` reported 28 of 30 ported names as UNVERIFIED,
// matching Go by NAME ONLY. These are the primitives the rest of the
// tree is built on, so "matches by name" is a thin thing to rest on.
//
// sync.Map is the one whose semantics are fully deterministic
// single-threaded, so it can be diffed exactly. Each method returns a
// slightly different shape and the differences ARE the API:
//
//   * LoadOrStore's bool reports whether it LOADED, not whether it
//     stored — and on a hit it leaves the stored value alone.
//   * Swap returns the PREVIOUS value, with a bool for whether there
//     was one.
//   * CompareAndSwap and CompareAndDelete report whether they ACTED,
//     so a missing key is false and a value mismatch is false.
//   * LoadAndDelete returns what it removed.
//
// Invert any of those booleans and the code still compiles and still
// behaves on the common path. These two methods did not exist at all
// before this change — the file recorded why (they need `V: PartialEq`)
// and that note is now the impl block that provides them.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::sync::Map;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eqi(failed: &mut int, got: int, want: int, what: &str) {
    if got == want {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %d want %d\n", s(what), got, want);
    *failed += 1;
}

fn eqb(failed: &mut int, got: bool, want: bool, what: &str) {
    if got == want {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %v want %v\n", s(what), got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let m: Map<string, int> = Map::new();

    // Go: load-missing [<nil> false] — the zero value and false.
    {
        let (v, ok) = m.Load(s("missing"));
        eqb(&mut failed, ok, false, "load-missing ok");
        eqi(&mut failed, v, 0, "load-missing value");
    }

    m.Store(s("a"), 1);
    {
        let (v, ok) = m.Load(s("a"));
        eqb(&mut failed, ok, true, "load-present ok");
        eqi(&mut failed, v, 1, "load-present value");
    }

    // Go: loadorstore-new [2 false] — stored, so loaded=FALSE.
    {
        let (act, loaded) = m.LoadOrStore(s("b"), 2);
        eqi(&mut failed, act, 2, "loadorstore-new actual");
        eqb(&mut failed, loaded, false, "loadorstore-new loaded");
    }
    // Go: loadorstore-existing [2 true] — and the stored value is
    // UNCHANGED, still 2 rather than the 99 offered.
    {
        let (act, loaded) = m.LoadOrStore(s("b"), 99);
        eqi(&mut failed, act, 2, "loadorstore-existing actual");
        eqb(&mut failed, loaded, true, "loadorstore-existing loaded");
        let (v, _) = m.Load(s("b"));
        eqi(&mut failed, v, 2, "loadorstore-unchanged");
    }

    // Go: swap-existing [1 true], swap-missing [<nil> false].
    {
        let (prev, loaded) = m.Swap(s("a"), 10);
        eqi(&mut failed, prev, 1, "swap-existing previous");
        eqb(&mut failed, loaded, true, "swap-existing loaded");
        let (prev2, loaded2) = m.Swap(s("new"), 5);
        eqi(&mut failed, prev2, 0, "swap-missing previous");
        eqb(&mut failed, loaded2, false, "swap-missing loaded");
    }

    // Go: cas-match [true], cas-after [11], cas-mismatch [false],
    //     cas-after-mismatch [11], cas-missing-key [false].
    {
        eqb(
            &mut failed,
            m.CompareAndSwap(s("a"), 10, 11),
            true,
            "cas-match",
        );
        let (v, _) = m.Load(s("a"));
        eqi(&mut failed, v, 11, "cas-after");
        eqb(
            &mut failed,
            m.CompareAndSwap(s("a"), 999, 12),
            false,
            "cas-mismatch",
        );
        let (v2, _) = m.Load(s("a"));
        eqi(&mut failed, v2, 11, "cas-after-mismatch");
        eqb(
            &mut failed,
            m.CompareAndSwap(s("nope"), 1, 2),
            false,
            "cas-missing-key",
        );
    }

    // Go: cad-mismatch [false], cad-match [true], cad-after [<nil> false],
    //     cad-missing-key [false].
    {
        eqb(
            &mut failed,
            m.CompareAndDelete(s("a"), 999),
            false,
            "cad-mismatch",
        );
        eqb(
            &mut failed,
            m.CompareAndDelete(s("a"), 11),
            true,
            "cad-match",
        );
        let (v, ok) = m.Load(s("a"));
        eqi(&mut failed, v, 0, "cad-after value");
        eqb(&mut failed, ok, false, "cad-after ok");
        eqb(
            &mut failed,
            m.CompareAndDelete(s("gone"), 1),
            false,
            "cad-missing-key",
        );
    }

    // Go: loadanddelete [3 true] then [<nil> false].
    {
        m.Store(s("c"), 3);
        let (v, loaded) = m.LoadAndDelete(s("c"));
        eqi(&mut failed, v, 3, "loadanddelete value");
        eqb(&mut failed, loaded, true, "loadanddelete loaded");
        let (v2, loaded2) = m.LoadAndDelete(s("c"));
        eqi(&mut failed, v2, 0, "loadanddelete-again value");
        eqb(&mut failed, loaded2, false, "loadanddelete-again loaded");
    }

    // Deleting a key that was never there is a no-op, not a panic.
    m.Delete(s("never-there"));

    // Go: range-count [5] — b, new, x, y, z after the sequence above.
    {
        m.Store(s("x"), 1);
        m.Store(s("y"), 2);
        m.Store(s("z"), 3);
        let mut n: int = 0;
        m.Range(|_k, _v| {
            n += 1;
            return true;
        });
        eqi(&mut failed, n, 5, "range-count");

        // Go: range-early-stop [1] — returning false stops after one.
        let mut stopped: int = 0;
        m.Range(|_k, _v| {
            stopped += 1;
            return false;
        });
        eqi(&mut failed, stopped, 1, "range-early-stop");
    }

    // Go: after-clear [0].
    {
        m.Clear();
        let mut n: int = 0;
        m.Range(|_k, _v| {
            n += 1;
            return true;
        });
        eqi(&mut failed, n, 0, "after-clear");
    }

    // Go: "the zero Map is empty and ready for use" — goish spells that
    // as Default, since a Rust struct with a Mutex needs a constructor.
    {
        let z: Map<string, string> = Map::default();
        z.Store(s("k"), s("v"));
        let (v, ok) = z.Load(s("k"));
        eqb(&mut failed, ok, true, "zero-value-usable ok");
        if v != s("v") {
            fmt::Println!("[!!] zero-value-usable FAIL");
            failed += 1;
        }
        // Go: store-replaces [v2].
        z.Store(s("k"), s("v2"));
        let (v2, _) = z.Load(s("k"));
        if v2 != s("v2") {
            fmt::Println!("[!!] store-replaces FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok - sync.Map matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
