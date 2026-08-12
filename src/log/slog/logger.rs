// go: file log/slog/logger.go decls: Logger.Enabled, Logger.Log, Logger.LogAttrs, Logger.Debug, Logger.Info, Logger.Warn, Logger.Error, Logger.logAttrs
//
// log/slog/logger.go — the Logger's emitting surface.
//
// Until this landed, goish's `Logger` had exactly one method,
// `Handler()`. Nothing could produce a Record, which meant
// testing/slogtest — whose whole design is to drive a Logger and
// inspect what the Handler received — had nothing to drive.
//
// **Partial port.** The package-level `Default()`/`SetDefault`/`Info`/
// `Warn`… convenience wrappers and `With`/`WithGroup` are not here;
// they hang off a package-global default Logger that goish does not
// have. `l.log` (the `...any` variadic form) is not ported either —
// pairing loose key/value arguments needs Go's `any` type switch, and
// `LogAttrs` covers the same ground with Attrs the caller built.
//
// goishlint:ignore GOISH018 New, With, WithGroup, Handler, Default, SetDefault, Debug, Info, Warn, Error, Log, LogAttrs, DebugContext, InfoContext, WarnContext, ErrorContext, log, argsToAttrSlice, SetLogLoggerLevel, NewLogLogger, Value, LogValue, Handle, Enabled, WithAttrs, Write, clone, init — the package-level wrappers and the `...any` form are not ported; see the note above.
// goishlint:ignore GOISH021 Logger, LogValuer, defaultLogger, logLoggerLevel, handlerWriter — same. handlerWriter bridges log.Logger's io.Writer onto a slog Handler, which needs the package-level default this file does not carry.

#![allow(non_snake_case)]

extern crate alloc;

use super::{Level, LevelDebug, LevelError, LevelInfo, LevelWarn, Logger, NewRecord};
use super::Attr;
use crate::context;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::uintptr;

impl Logger {
    // go: sdk 1.25.5 log/slog/logger.go:164-169 Logger.Enabled
    /// Go: "Enabled reports whether l emits log records at the given
    /// context and level."
    ///
    /// Deviation: Go accepts a nil ctx and substitutes
    /// `context.Background()`. goish takes a reference, so a nil ctx is
    /// not expressible and the substitution is the caller's to make.
    pub fn Enabled(&self, ctx: &dyn context::Context, level: Level) -> bool {
        return self.Handler().Enabled(ctx, level);
    }

    // go: sdk 1.25.5 log/slog/logger.go:260-277 Logger.logAttrs
    /// Go: the shared emit path — check Enabled, capture the caller's
    /// PC, build a Record, hand it to the Handler.
    ///
    /// The `Enabled` check comes *before* the PC capture and Record
    /// construction, which is the whole reason it exists: a disabled
    /// level must cost almost nothing, so a handler that filters at
    /// Debug does not pay for a stack walk and an allocation per call.
    ///
    /// The PC is captured with `Callers(3, …)` — Go's comment: "skip
    /// [runtime.Callers, this function, this function's caller]" — so
    /// the recorded PC is the user's call site, not slog's internals.
    /// That count is load-bearing: one off, and every log line is
    /// attributed to slog itself.
    fn logAttrs(
        &self,
        ctx: &dyn context::Context,
        level: Level,
        msg: string,
        attrs: slice<Attr>,
    ) {
        if !self.Enabled(ctx, level) {
            return;
        }
        let mut pcs: slice<crate::types::uintptr> = crate::make!([]uintptr, 1);
        // Go: skip [runtime.Callers, this function, this function's caller]
        crate::runtime::Callers(3, &mut pcs);
        let pc = pcs[0];

        let mut r = NewRecord(crate::time::Now(), level, msg, pc);
        for i in 0..attrs.Len() {
            r.AddAttrs(attrs[i].clone());
        }
        let _ = self.Handler().Handle(ctx, r);
    }

    // go: sdk 1.25.5 log/slog/logger.go:193-195 Logger.LogAttrs
    /// Go: "LogAttrs is a more efficient version of [Logger.Log] that
    /// accepts only Attrs."
    pub fn LogAttrs(
        &self,
        ctx: &dyn context::Context,
        level: Level,
        msg: impl Into<string>,
        attrs: slice<Attr>,
    ) {
        self.logAttrs(ctx, level, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:188-190 Logger.Log
    /// Go: "Log emits a log record with the current time and the given
    /// level and message."
    ///
    /// Deviation: Go's is variadic over `...any` and pairs loose
    /// key/value arguments through `argsToAttrSlice`. goish takes Attrs
    /// directly, which is `LogAttrs`'s shape — the pairing helper needs
    /// Go's `any` type switch.
    pub fn Log(
        &self,
        ctx: &dyn context::Context,
        level: Level,
        msg: impl Into<string>,
        attrs: slice<Attr>,
    ) {
        self.logAttrs(ctx, level, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:198-200 Logger.Debug
    /// Go: "Debug logs at [LevelDebug]."
    pub fn Debug(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelDebug, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:208-210 Logger.Info
    /// Go: "Info logs at [LevelInfo]."
    pub fn Info(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelInfo, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:218-220 Logger.Warn
    /// Go: "Warn logs at [LevelWarn]."
    pub fn Warn(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelWarn, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:228-230 Logger.Error
    /// Go: "Error logs at [LevelError]."
    pub fn Error(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelError, msg.into(), attrs);
    }
}
