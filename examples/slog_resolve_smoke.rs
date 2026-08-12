// slog_resolve_smoke — slog's LogValuer and Value.Resolve.
//
// LogValuer lets a value defer expensive work until a handler actually
// needs it, or expand itself into components. Resolve is what handlers
// call to collapse that.
//
// The bound is the substantive part. A LogValuer that returns itself —
// trivially, or through a two-type cycle — would spin forever inside a
// logging call. Go caps at 100 and returns an ERROR Value rather than
// panicking, because failing a log line is worse than logging a bad
// one. Checks 3 and 4 are the self-cycle and the two-type cycle; check
// 5 pins Go's guarantee that Resolve never returns KindLogValuer.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::gostring::string;
use goish::log::slog;
use goish::{fmt, syscall, Any};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

static CALLS: AtomicUsize = AtomicUsize::new(0);

/// Resolves in one hop to a plain string.
struct Lazy {
    out: string,
}

impl slog::LogValuer for Lazy {
    fn LogValue(&self) -> slog::Value {
        CALLS.fetch_add(1, Ordering::SeqCst);
        return slog::AnyValue(Any::new(self.out.clone()));
    }
}

/// Resolves to another LogValuer, which resolves to a string. Two hops.
struct TwoHop;

impl slog::LogValuer for TwoHop {
    fn LogValue(&self) -> slog::Value {
        CALLS.fetch_add(1, Ordering::SeqCst);
        return slog::LogValuerValue(Arc::new(Lazy { out: s("deep") }));
    }
}

/// Always resolves to itself — the cycle Resolve's bound exists for.
struct SelfCycle;

impl slog::LogValuer for SelfCycle {
    fn LogValue(&self) -> slog::Value {
        CALLS.fetch_add(1, Ordering::SeqCst);
        return slog::LogValuerValue(Arc::new(SelfCycle));
    }
}

/// Half of a two-type cycle: Ping -> Pong -> Ping -> …
struct Ping;
struct Pong;

impl slog::LogValuer for Ping {
    fn LogValue(&self) -> slog::Value {
        CALLS.fetch_add(1, Ordering::SeqCst);
        return slog::LogValuerValue(Arc::new(Pong));
    }
}
impl slog::LogValuer for Pong {
    fn LogValue(&self) -> slog::Value {
        CALLS.fetch_add(1, Ordering::SeqCst);
        return slog::LogValuerValue(Arc::new(Ping));
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A non-LogValuer Value resolves to itself, without calling
    //    anything. Resolve must be free for the common case.
    {
        CALLS.store(0, Ordering::SeqCst);
        let v = slog::AnyValue(Any::new(s("plain")));
        let r = slog::Resolve(&v);
        if r.Kind() == slog::KindString && CALLS.load(Ordering::SeqCst) == 0 {
            fmt::Println!("[ 1] plain value is untouched  PASS");
        } else {
            fmt::Println!("[ 1] plain value is untouched  FAIL");
            failed += 1;
        }
    }

    // 2. One hop resolves, calling LogValue exactly once.
    {
        CALLS.store(0, Ordering::SeqCst);
        let v = slog::LogValuerValue(Arc::new(Lazy { out: s("computed") }));
        let r = slog::Resolve(&v);
        if r.Kind() == slog::KindString && CALLS.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 2] one hop resolves          PASS");
        } else {
            fmt::Println!("[ 2] one hop resolves          FAIL");
            failed += 1;
        }
    }

    // 2b. Two hops chain through an intermediate LogValuer.
    {
        CALLS.store(0, Ordering::SeqCst);
        let v = slog::LogValuerValue(Arc::new(TwoHop));
        let r = slog::Resolve(&v);
        if r.Kind() == slog::KindString && CALLS.load(Ordering::SeqCst) == 2 {
            fmt::Println!("[ 3] two hops chain            PASS");
        } else {
            fmt::Println!("[ 3] two hops chain            FAIL");
            failed += 1;
        }
    }

    // 4. A self-cycle terminates at the bound rather than hanging, and
    //    yields an error Value. Reaching this line at all is the
    //    assertion — an unbounded Resolve never returns.
    {
        CALLS.store(0, Ordering::SeqCst);
        let v = slog::LogValuerValue(Arc::new(SelfCycle));
        let r = slog::Resolve(&v);
        let calls = CALLS.load(Ordering::SeqCst);
        if calls == (slog::maxLogValues as usize) && r.Kind() != slog::KindLogValuer {
            fmt::Println!("[ 4] self-cycle bounded        PASS");
        } else {
            fmt::Println!("[ 4] self-cycle bounded        FAIL calls=", calls as i64);
            failed += 1;
        }
    }

    // 5. A two-type cycle is caught by the same bound — the guard is a
    //    call count, not a same-type check, so Ping->Pong->Ping is
    //    caught exactly like Self->Self.
    {
        CALLS.store(0, Ordering::SeqCst);
        let v = slog::LogValuerValue(Arc::new(Ping));
        let r = slog::Resolve(&v);
        if CALLS.load(Ordering::SeqCst) == (slog::maxLogValues as usize)
            && r.Kind() != slog::KindLogValuer
        {
            fmt::Println!("[ 5] two-type cycle bounded    PASS");
        } else {
            fmt::Println!("[ 5] two-type cycle bounded    FAIL");
            failed += 1;
        }
    }

    // 6. Go's documented guarantee: "Resolve's return value is
    //    guaranteed not to be of Kind KindLogValuer" — including on the
    //    overflow path, which is the case that would be easy to miss.
    {
        for v in [
            slog::LogValuerValue(Arc::new(Lazy { out: s("a") })),
            slog::LogValuerValue(Arc::new(TwoHop)),
            slog::LogValuerValue(Arc::new(SelfCycle)),
        ]
        .iter()
        {
            if slog::Resolve(v).Kind() == slog::KindLogValuer {
                fmt::Println!("[ 6] never returns LogValuer   FAIL");
                failed += 1;
                break;
            }
        }
        if failed == 0 {
            fmt::Println!("[ 6] never returns LogValuer   PASS");
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
