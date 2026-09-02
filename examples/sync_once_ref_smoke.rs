// sync_once_ref_smoke — sync.Once and the OnceFunc family against Go.
// (sync/once.go, sync/oncefunc.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_once_ref.go` run in `package sync_test`
// by `scripts/goref.sh`.
//
// These files carried no provenance anchors, like the rest of
// src/sync/: they matched Go by NAME ONLY, and `port_coverage sync`
// could not diff them.
//
// The guarantee is "exactly once", and the part worth checking is what
// happens on the calls AFTER the first: Do returns without running f
// again, and OnceValue hands back the CACHED value rather than
// recomputing. The zero-value row is the one that catches a real
// mistake — a port that uses the zero value as its "not computed yet"
// marker recomputes forever for a function that legitimately returns 0,
// and looks correct for every other function.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::sync::{Once, OnceFunc, OnceValue, OnceValues};
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

#[goish::main]
fn main() {
    let mut failed = 0;

    // Go: once-do calls=1 — five Do calls, one execution.
    {
        let o = Once::new();
        let n = Arc::new(goish::sync::Mutex::new(0 as int));
        for _ in 0..5 {
            let n2 = n.clone();
            o.Do(move || {
                *n2.Lock() += 1;
            });
        }
        let got = *n.Lock();
        eqi(&mut failed, got, 1, "once-do calls");
    }

    // Go: once-independent calls=1 — a second Once is its own.
    {
        let o2 = Once::new();
        let m = Arc::new(goish::sync::Mutex::new(0 as int));
        let m2 = m.clone();
        o2.Do(move || {
            *m2.Lock() += 1;
        });
        eqi(&mut failed, *m.Lock(), 1, "once-independent calls");
    }

    // Go: once-visible first=42 after-second-do=42 — the second Do does
    // not run its f, so the value the first one set survives.
    {
        let o3 = Once::new();
        let got = Arc::new(goish::sync::Mutex::new(0 as int));
        let g1 = got.clone();
        o3.Do(move || {
            *g1.Lock() = 42;
        });
        let before = *got.Lock();
        let g2 = got.clone();
        o3.Do(move || {
            *g2.Lock() = 99;
        });
        eqi(&mut failed, before, 42, "once-visible first");
        eqi(&mut failed, *got.Lock(), 42, "once-visible after second Do");
    }

    // Go: oncefunc calls=1.
    {
        let fnCalls = Arc::new(goish::sync::Mutex::new(0 as int));
        let f2 = fnCalls.clone();
        let wrapped = OnceFunc(move || {
            *f2.Lock() += 1;
        });
        wrapped();
        wrapped();
        wrapped();
        eqi(&mut failed, *fnCalls.Lock(), 1, "oncefunc calls");
    }

    // Go: oncevalue computations=1 values=7,7,7.
    {
        let comps = Arc::new(goish::sync::Mutex::new(0 as int));
        let c2 = comps.clone();
        let val = OnceValue(move || {
            *c2.Lock() += 1;
            return 7 as int;
        });
        let (a, b, c) = (val(), val(), val());
        eqi(&mut failed, *comps.Lock(), 1, "oncevalue computations");
        eqi(&mut failed, a, 7, "oncevalue a");
        eqi(&mut failed, b, 7, "oncevalue b");
        eqi(&mut failed, c, 7, "oncevalue c");
    }

    // Go: oncevalue-zero computations=1 values=0,0.
    //
    // This is the row that catches a port using the zero value as its
    // "not computed yet" marker: it would recompute on every call here
    // and look perfectly correct for every function that returns
    // something else.
    {
        let zcomps = Arc::new(goish::sync::Mutex::new(0 as int));
        let z2 = zcomps.clone();
        let zval = OnceValue(move || {
            *z2.Lock() += 1;
            return 0 as int;
        });
        let (z1v, z2v) = (zval(), zval());
        eqi(
            &mut failed,
            *zcomps.Lock(),
            1,
            "oncevalue-zero computations",
        );
        eqi(&mut failed, z1v, 0, "oncevalue-zero first");
        eqi(&mut failed, z2v, 0, "oncevalue-zero second");
    }

    // Go: oncevalues computations=1 first=(3,"x") second=(3,"x").
    {
        let vcomps = Arc::new(goish::sync::Mutex::new(0 as int));
        let v2 = vcomps.clone();
        let vals = OnceValues(move || {
            *v2.Lock() += 1;
            return (3 as int, s("x"));
        });
        let (i1, s1) = vals();
        let (i2, s2) = vals();
        eqi(&mut failed, *vcomps.Lock(), 1, "oncevalues computations");
        eqi(&mut failed, i1, 3, "oncevalues first int");
        eqi(&mut failed, i2, 3, "oncevalues second int");
        if s1 != s("x") || s2 != s("x") {
            fmt::Println!("[!!] oncevalues strings FAIL");
            failed += 1;
        }
    }

    // Go: independent 1 2 1 2 — each OnceValue caches its own.
    {
        let c1 = OnceValue(|| return 1 as int);
        let c2 = OnceValue(|| return 2 as int);
        eqi(&mut failed, c1(), 1, "independent c1");
        eqi(&mut failed, c2(), 2, "independent c2");
        eqi(&mut failed, c1(), 1, "independent c1 again");
        eqi(&mut failed, c2(), 2, "independent c2 again");
    }

    if failed == 0 {
        fmt::Println!("ok - sync.Once and the OnceFunc family match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
