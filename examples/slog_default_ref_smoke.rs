// slog_default_ref_smoke — the package-level functions against Go.
// (log/slog/logger.go, log/slog/handler.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_slog_default_ref.go` run in `package
// slog` by `scripts/goref.sh`, with `log.SetFlags(0)` so there is no
// timestamp and the bytes are deterministic.
//
// `slog.Info("msg", "k", "v")` is how slog is normally used, and goish
// had no package-level functions at all — no `Info`, `Debug`, `Warn`,
// `Error`, no `*Context` variants, no `Log`/`LogAttrs`/`With`, and no
// `Default`/`SetDefault`/`SetLogLoggerLevel`. Only the methods on a
// Logger you had already built yourself.
//
// The default logger's handler is NOT a TextHandler, which is the thing
// a port is most likely to get wrong here. It writes
//
//     LEVEL message key=value…
//
// through the `log` package — a bare level name, no `time=` field (the
// log package owns the timestamp), and no `level=` key. Wiring the
// default to a TextHandler would change the shape of every
// package-level call.
//
// Two more behaviours that are easy to miss: `slog.Debug` is SILENT by
// default, because the default handler's threshold is the package-level
// `logLoggerLevel` rather than any HandlerOptions.Level; and
// `SetLogLoggerLevel` returns the PREVIOUS level, so it can be restored.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goany::Any;
use goish::goslice::slice;
use goish::gostring::string;
use goish::log::slog;
use goish::types::{byte, int};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn args(v: alloc::vec::Vec<Any>) -> slice<Any> {
    return slice::__from_vec(v);
}

// go: none — goish idiom: the Go reference points the `log` package at
//     a buffer and reads it back; this is that buffer.
#[derive(Clone)]
struct SharedBuf(Arc<goish::sync::Mutex<Vec<byte>>>);

impl goish::io::Writer for SharedBuf {
    fn Write(&mut self, p: slice<byte>) -> (int, goish::errors::error) {
        let v = p.clone().__into_vec();
        let n = v.len() as i64;
        self.0.Lock().extend_from_slice(&v);
        return (n, goish::errors::nil);
    }
}

impl SharedBuf {
    fn new() -> Self {
        return SharedBuf(Arc::new(goish::sync::Mutex::new(Vec::new())));
    }
    fn take(&self) -> string {
        let out = string::from_bytes(&self.0.Lock().clone());
        self.0.Lock().clear();
        return out;
    }
}

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!(
        "[!!] %s FAIL\n     got  %q\n     want %q\n",
        s(what),
        got,
        s(want)
    );
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let buf = SharedBuf::new();
    // Go: log.SetOutput(&buf); log.SetFlags(0)
    goish::log::SetOutput(Box::new(buf.clone()));
    goish::log::SetFlags(0);
    let ctx = goish::context::Background();

    // 1. The default handler's shape: a bare LEVEL, the message, then
    //    the attrs — no `time=` and no `level=` key.
    slog::Info("hello", args(alloc::vec![]));
    eq(&mut failed, buf.take(), "INFO hello\n", "info");

    slog::Info(
        "hello",
        args(alloc::vec![
            Any::new(s("k")),
            Any::new(s("v")),
            Any::new(s("n")),
            Any::new(7 as int),
        ]),
    );
    eq(
        &mut failed,
        buf.take(),
        "INFO hello k=v n=7\n",
        "info-attrs",
    );

    // 2. Debug is SILENT by default — nothing reaches the log package.
    slog::Debug("hidden", args(alloc::vec![]));
    eq(&mut failed, buf.take(), "", "debug-default-off");

    slog::Warn(
        "careful",
        args(alloc::vec![Any::new(s("why")), Any::new(s("reasons"))]),
    );
    eq(
        &mut failed,
        buf.take(),
        "WARN careful why=reasons\n",
        "warn",
    );

    slog::Error(
        "bad",
        args(alloc::vec![
            Any::new(s("err")),
            Any::new(goish::errors::New("boom")),
        ]),
    );
    eq(&mut failed, buf.take(), "ERROR bad err=boom\n", "error");

    // 3. An odd trailing argument becomes !BADKEY rather than being
    //    dropped — the caller's mistake stays visible in the output.
    slog::Info("m", args(alloc::vec![Any::new(s("dangling"))]));
    eq(
        &mut failed,
        buf.take(),
        "INFO m !BADKEY=dangling\n",
        "odd-args",
    );

    // An Attr passed among the args is taken as-is.
    slog::Info("m", args(alloc::vec![Any::new(slog::String("k", "v"))]));
    eq(&mut failed, buf.take(), "INFO m k=v\n", "attr-arg");

    // 4. Log / LogAttrs / the Context variants / With.
    slog::Log(
        ctx.as_ref(),
        slog::LevelWarn,
        "m",
        args(alloc::vec![Any::new(s("k")), Any::new(s("v"))]),
    );
    eq(&mut failed, buf.take(), "WARN m k=v\n", "log-explicit");

    slog::LogAttrs(
        ctx.as_ref(),
        slog::LevelError,
        "m",
        slice::__from_vec(alloc::vec![slog::String("k", "v")]),
    );
    eq(&mut failed, buf.take(), "ERROR m k=v\n", "logattrs");

    slog::InfoContext(
        ctx.as_ref(),
        "m",
        args(alloc::vec![Any::new(s("k")), Any::new(s("v"))]),
    );
    eq(&mut failed, buf.take(), "INFO m k=v\n", "context-variants");

    // A level with no name renders as name+offset here too.
    slog::Log(ctx.as_ref(), slog::Level(2), "m", args(alloc::vec![]));
    eq(&mut failed, buf.take(), "INFO+2 m\n", "level-offset");

    // A group flattens to a dotted prefix, as in the text handler.
    slog::Info(
        "m",
        args(alloc::vec![Any::new(slog::Group(
            "g",
            slice::__from_vec(alloc::vec![slog::String("a", "1")])
        ))]),
    );
    eq(&mut failed, buf.take(), "INFO m g.a=1\n", "group-attr");

    slog::With(args(alloc::vec![Any::new(s("svc")), Any::new(s("api"))]))
        .Info("m", args(alloc::vec![Any::new(s("k")), Any::new(s("v"))]));
    eq(&mut failed, buf.take(), "INFO m svc=api k=v\n", "with");

    // 5. SetLogLoggerLevel moves the DEFAULT handler's threshold and
    //    returns the previous level, so it can be put back.
    {
        let old = slog::SetLogLoggerLevel(slog::LevelDebug);
        eq(&mut failed, old.String(), "INFO", "setlevel old");
        slog::Debug(
            "now visible",
            args(alloc::vec![Any::new(s("k")), Any::new(s("v"))]),
        );
        eq(
            &mut failed,
            buf.take(),
            "DEBUG now visible k=v\n",
            "debug-after-enable",
        );
        let back = slog::SetLogLoggerLevel(old);
        eq(&mut failed, back.String(), "DEBUG", "setlevel back");
        slog::Debug("hidden again", args(alloc::vec![]));
        eq(&mut failed, buf.take(), "", "debug-off-again");
    }

    // Go: enabled debug=false info=true warn=true
    {
        let d = slog::Default();
        let mut ok = true;
        if d.Enabled(ctx.as_ref(), slog::LevelDebug) {
            ok = false;
        }
        if !d.Enabled(ctx.as_ref(), slog::LevelInfo) {
            ok = false;
        }
        if !d.Enabled(ctx.as_ref(), slog::LevelWarn) {
            ok = false;
        }
        if !ok {
            fmt::Println!("[!!] Default().Enabled FAIL");
            failed += 1;
        }
    }

    // 6. SetDefault swaps the logger the package functions use — after
    //    it, `slog.Info` goes out as JSON.
    {
        let jbuf = SharedBuf::new();
        let mut o = slog::HandlerOptions::default();
        o.ReplaceAttr = Some(Arc::new(|g: &[string], a: slog::Attr| {
            if g.is_empty() && a.Key == s(slog::TimeKey) {
                return slog::Attr::default();
            }
            return a;
        }));
        slog::SetDefault(slog::New(slog::NewJSONHandler(jbuf.clone(), Some(o))));
        slog::Info(
            "through json",
            args(alloc::vec![Any::new(s("k")), Any::new(s("v"))]),
        );
        eq(
            &mut failed,
            jbuf.take(),
            "{\"level\":\"INFO\",\"msg\":\"through json\",\"k\":\"v\"}\n",
            "after-setdefault",
        );
    }

    if failed == 0 {
        fmt::Println!("ok - slog package-level functions match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
