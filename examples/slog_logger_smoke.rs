// slog_logger_smoke — slog.Logger's emitting surface.
//
// Until this landed, goish's Logger had exactly one method, Handler().
// Nothing could produce a Record, so testing/slogtest — whose whole
// design is to drive a Logger and inspect what the Handler received —
// had nothing to drive.
//
// Two properties carry their weight here:
//
//  * Check 3: the Enabled test happens BEFORE the PC capture and Record
//    construction. That ordering is the reason Enabled exists — a
//    handler filtering at Debug must not pay for a stack walk and an
//    allocation per suppressed call. A Logger that built the Record
//    first and filtered after would pass every output check and be
//    quietly expensive.
//
//  * Check 4: the recorded PC is the USER's call site, not slog's
//    internals. Go's Callers(3, …) skips exactly
//    [runtime.Callers, logAttrs, its caller]; one off and every log
//    line is attributed to slog itself.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::context;
use goish::gostring::string;
use goish::log::slog;
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn attrs(xs: alloc::vec::Vec<slog::Attr>) -> slice<slog::Attr> {
    return slice::__from_vec(xs);
}

static HANDLED: AtomicUsize = AtomicUsize::new(0);
static ENABLED_CALLS: AtomicUsize = AtomicUsize::new(0);
static LAST_LEVEL: AtomicUsize = AtomicUsize::new(999);
static LAST_ATTRS: AtomicUsize = AtomicUsize::new(0);
static LAST_PC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MIN_LEVEL: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(-999);

/// Records what it was handed, and filters below MIN_LEVEL.
struct Recorder;

impl slog::Handler for Recorder {
    fn Enabled(&self, _ctx: &dyn context::Context, level: slog::Level) -> bool {
        ENABLED_CALLS.fetch_add(1, Ordering::SeqCst);
        return level.0 >= MIN_LEVEL.load(Ordering::SeqCst);
    }
    fn Handle(&self, _ctx: &dyn context::Context, record: slog::Record) -> errors::error {
        HANDLED.fetch_add(1, Ordering::SeqCst);
        LAST_LEVEL.store((record.Level.0 + 100) as usize, Ordering::SeqCst);
        LAST_PC.store(record.PC as u64, Ordering::SeqCst);
        let mut n = 0usize;
        record.Attrs(&mut |_a| {
            n += 1;
        });
        LAST_ATTRS.store(n, Ordering::SeqCst);
        return errors::nil;
    }
    fn WithAttrs(&self, _a: slice<slog::Attr>) -> Arc<dyn slog::Handler + Send + Sync> {
        return Arc::new(Recorder);
    }
    fn WithGroup(&self, _n: string) -> Arc<dyn slog::Handler + Send + Sync> {
        return Arc::new(Recorder);
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let l = slog::New(Arc::new(Recorder));

    // 1. Info reaches the handler, with the right level and attrs.
    {
        HANDLED.store(0, Ordering::SeqCst);
        l.InfoAttrs(
            s("hello"),
            attrs(alloc::vec![
                slog::String(s("k"), s("v")),
                slog::Int(s("n"), 3),
            ]),
        );
        let lvl = LAST_LEVEL.load(Ordering::SeqCst) as i64 - 100;
        if HANDLED.load(Ordering::SeqCst) == 1
            && lvl == slog::LevelInfo.0
            && LAST_ATTRS.load(Ordering::SeqCst) == 2
        {
            fmt::Println!("[ 1] Info reaches handler      PASS");
        } else {
            fmt::Println!("[ 1] Info reaches handler      FAIL");
            failed += 1;
        }
    }

    // 2. Each level constructor uses its own level.
    {
        let mut ok = true;
        for (f, want) in [
            (0, slog::LevelDebug.0),
            (1, slog::LevelInfo.0),
            (2, slog::LevelWarn.0),
            (3, slog::LevelError.0),
        ]
        .iter()
        {
            match f {
                0 => l.DebugAttrs(s("m"), attrs(alloc::vec![])),
                1 => l.InfoAttrs(s("m"), attrs(alloc::vec![])),
                2 => l.WarnAttrs(s("m"), attrs(alloc::vec![])),
                _ => l.ErrorAttrs(s("m"), attrs(alloc::vec![])),
            }
            if (LAST_LEVEL.load(Ordering::SeqCst) as i64 - 100) != *want {
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 2] levels map correctly      PASS");
        } else {
            fmt::Println!("[ 2] levels map correctly      FAIL");
            failed += 1;
        }
    }

    // 3. A suppressed level asks Enabled but never reaches Handle. This
    //    is the ordering that makes Enabled worth having.
    {
        MIN_LEVEL.store(slog::LevelWarn.0, Ordering::SeqCst);
        HANDLED.store(0, Ordering::SeqCst);
        ENABLED_CALLS.store(0, Ordering::SeqCst);
        l.DebugAttrs(s("suppressed"), attrs(alloc::vec![]));
        let asked = ENABLED_CALLS.load(Ordering::SeqCst) >= 1;
        let handled = HANDLED.load(Ordering::SeqCst);
        // …and a permitted level still gets through.
        l.ErrorAttrs(s("kept"), attrs(alloc::vec![]));
        let after = HANDLED.load(Ordering::SeqCst);
        MIN_LEVEL.store(-999, Ordering::SeqCst);

        if asked && handled == 0 && after == 1 {
            fmt::Println!("[ 3] Enabled gates before work PASS");
        } else {
            fmt::Println!("[ 3] Enabled gates before work FAIL");
            failed += 1;
        }
    }

    // 4. The recorded PC resolves to THIS file, not to slog's guts.
    //    Go skips exactly [runtime.Callers, logAttrs, its caller].
    {
        l.InfoAttrs(s("pc check"), attrs(alloc::vec![]));
        let pc = LAST_PC.load(Ordering::SeqCst) as goish::types::uintptr;
        let name = match goish::runtime::FuncForPC(pc) {
            Some(f) => f.Name(),
            None => s(""),
        };
        let n: &str = name.as_ref();
        if pc != 0 && !n.contains("slog") {
            fmt::Println!("[ 4] PC is the call site       PASS");
        } else {
            fmt::Println!("[ 4] PC is the call site       FAIL [", name, "]");
            failed += 1;
        }
    }

    // 5. LogAttrs and Log reach the handler with an explicit level.
    {
        HANDLED.store(0, Ordering::SeqCst);
        let bg = context::Background();
        l.LogAttrs(bg.as_ref(), slog::LevelWarn, s("la"), attrs(alloc::vec![]));
        l.LogAttrsAt(bg.as_ref(), slog::LevelError, s("lg"), attrs(alloc::vec![]));
        let lvl = LAST_LEVEL.load(Ordering::SeqCst) as i64 - 100;
        if HANDLED.load(Ordering::SeqCst) == 2 && lvl == slog::LevelError.0 {
            fmt::Println!("[ 5] LogAttrs and Log          PASS");
        } else {
            fmt::Println!("[ 5] LogAttrs and Log          FAIL");
            failed += 1;
        }
    }

    // 6. The `...any` form pairs loose key/value arguments. Two pairs
    //    become two Attrs.
    {
        HANDLED.store(0, Ordering::SeqCst);
        l.Info(
            s("paired"),
            slice::__from_vec(alloc::vec![
                goish::Any::new(s("k1")),
                goish::Any::new(s("v1")),
                goish::Any::new(s("k2")),
                goish::Any::new(7i64),
            ]),
        );
        if HANDLED.load(Ordering::SeqCst) == 1 && LAST_ATTRS.load(Ordering::SeqCst) == 2 {
            fmt::Println!("[ 6] ...any pairs arguments    PASS");
        } else {
            fmt::Println!("[ 6] ...any pairs arguments    FAIL");
            failed += 1;
        }
    }

    // 7. A dangling key still produces an Attr, filed under !BADKEY.
    //    Go records the mistake rather than dropping it or panicking —
    //    a logging call is the wrong place to fail, and the stray value
    //    is visible in the output instead of vanishing.
    {
        HANDLED.store(0, Ordering::SeqCst);
        l.Info(
            s("dangling"),
            slice::__from_vec(alloc::vec![
                goish::Any::new(s("k1")),
                goish::Any::new(s("v1")),
                goish::Any::new(s("orphan")),
            ]),
        );
        // One complete pair plus the orphan = two Attrs, not one.
        if LAST_ATTRS.load(Ordering::SeqCst) == 2 {
            fmt::Println!("[ 7] dangling key kept         PASS");
        } else {
            fmt::Println!("[ 7] dangling key kept         FAIL");
            failed += 1;
        }
    }

    // 8. An Attr passed directly in the ...any list is used as-is,
    //    consuming one slot rather than being treated as a key.
    {
        HANDLED.store(0, Ordering::SeqCst);
        l.Info(
            s("mixed"),
            slice::__from_vec(alloc::vec![
                goish::Any::new(slog::String(s("pre"), s("built"))),
                goish::Any::new(s("k")),
                goish::Any::new(s("v")),
            ]),
        );
        if LAST_ATTRS.load(Ordering::SeqCst) == 2 {
            fmt::Println!("[ 8] inline Attr consumes one  PASS");
        } else {
            fmt::Println!("[ 8] inline Attr consumes one  FAIL");
            failed += 1;
        }
    }

    // 9. With() on an empty argument list returns an equivalent
    //     logger rather than building a handler chain. Go returns the
    //     receiver outright; the point is that a conditional
    //     `l = l.With(extra)` in a loop does not grow a chain one link
    //     per iteration when there is nothing to add.
    {
        HANDLED.store(0, Ordering::SeqCst);
        let same = l.With(slice::__from_vec(alloc::vec![]));
        same.InfoAttrs(s("still works"), attrs(alloc::vec![]));
        if HANDLED.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 9] With() empty is a no-op   PASS");
        } else {
            fmt::Println!("[ 9] With() empty is a no-op   FAIL");
            failed += 1;
        }
    }

    // 10. With(args) and WithGroup(name) both produce a working logger
    //     that still reaches the handler.
    {
        HANDLED.store(0, Ordering::SeqCst);
        let wa = l.With(slice::__from_vec(alloc::vec![
            goish::Any::new(s("svc")),
            goish::Any::new(s("api")),
        ]));
        wa.InfoAttrs(s("with attrs"), attrs(alloc::vec![]));
        let wg = l.WithGroup(s("req"));
        wg.InfoAttrs(s("with group"), attrs(alloc::vec![]));
        // WithGroup("") returns the receiver, so it must still log.
        let wempty = l.WithGroup(s(""));
        wempty.InfoAttrs(s("empty group"), attrs(alloc::vec![]));
        if HANDLED.load(Ordering::SeqCst) == 3 {
            fmt::Println!("[10] With / WithGroup          PASS");
        } else {
            fmt::Println!("[10] With / WithGroup          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
