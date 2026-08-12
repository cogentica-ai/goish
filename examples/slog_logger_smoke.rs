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
        l.Info(s("hello"), attrs(alloc::vec![
            slog::String(s("k"), s("v")),
            slog::Int(s("n"), 3),
        ]));
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
                0 => l.Debug(s("m"), attrs(alloc::vec![])),
                1 => l.Info(s("m"), attrs(alloc::vec![])),
                2 => l.Warn(s("m"), attrs(alloc::vec![])),
                _ => l.Error(s("m"), attrs(alloc::vec![])),
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
        l.Debug(s("suppressed"), attrs(alloc::vec![]));
        let asked = ENABLED_CALLS.load(Ordering::SeqCst) >= 1;
        let handled = HANDLED.load(Ordering::SeqCst);
        // …and a permitted level still gets through.
        l.Error(s("kept"), attrs(alloc::vec![]));
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
        l.Info(s("pc check"), attrs(alloc::vec![]));
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
        l.Log(bg.as_ref(), slog::LevelError, s("lg"), attrs(alloc::vec![]));
        let lvl = LAST_LEVEL.load(Ordering::SeqCst) as i64 - 100;
        if HANDLED.load(Ordering::SeqCst) == 2 && lvl == slog::LevelError.0 {
            fmt::Println!("[ 5] LogAttrs and Log          PASS");
        } else {
            fmt::Println!("[ 5] LogAttrs and Log          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
