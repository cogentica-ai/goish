// go: file log/slog/logger.go decls: Logger.With, Logger.WithGroup, Logger.Enabled, Logger.log, Logger.Log, Logger.LogAttrs, Logger.Debug, Logger.Info, Logger.Warn, Logger.Error, Logger.logAttrs, logLoggerLevel, Default, SetDefault, SetLogLoggerLevel, With, Debug, DebugContext, Info, InfoContext, Warn, WarnContext, Error, ErrorContext, Log, LogAttrs
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
// goishlint:ignore GOISH018 New, Handler, Default, SetDefault, Debug, Info, Warn, Error, LogAttrs, DebugContext, InfoContext, WarnContext, ErrorContext, log, argsToAttrSlice, SetLogLoggerLevel, NewLogLogger, Value, LogValue, Handle, Enabled, WithAttrs, Write, clone, init — the package-level wrappers and the `...any` form are not ported; see the note above.
// goishlint:ignore GOISH021 Logger, LogValuer, defaultLogger, logLoggerLevel, handlerWriter — same. handlerWriter bridges log.Logger's io.Writer onto a slog Handler, which needs the package-level default this file does not carry.

#![allow(non_snake_case)]

extern crate alloc;

use super::Attr;
use super::{Level, LevelDebug, LevelError, LevelInfo, LevelWarn, Logger, NewRecord};
use crate::context;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::uintptr;

impl Logger {
    // go: sdk 1.25.5 log/slog/logger.go:126-133 Logger.With
    /// Go: "With returns a Logger that includes the given attributes in
    /// each output operation. Arguments are converted to attributes as
    /// if by [Logger.Log]."
    ///
    /// The empty-args early return is Go's and matters: `With()` with
    /// nothing to add returns the SAME logger rather than cloning, so a
    /// conditional `l = l.With(extra...)` in a loop does not allocate a
    /// handler chain one link deep per iteration.
    pub fn With(&self, args: slice<crate::goany::Any>) -> Logger {
        // Go: if len(args) == 0 { return l }
        if args.Len() == 0 {
            return self.clone();
        }
        return super::New(self.Handler().WithAttrs(super::argsToAttrSlice(args)));
    }

    // go: sdk 1.25.5 log/slog/logger.go:141-148 Logger.WithGroup
    /// Go: "WithGroup returns a Logger that starts a group, if name is
    /// non-empty. The keys of all attributes added to the Logger will
    /// be qualified by the given name. […] If name is empty, WithGroup
    /// returns the receiver."
    ///
    /// Same early return, same reason.
    pub fn WithGroup(&self, name: impl Into<string>) -> Logger {
        let name: string = name.into();
        // Go: if name == "" { return l }
        if name.Len() == 0 {
            return self.clone();
        }
        return super::New(self.Handler().WithGroup(name));
    }

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
    fn logAttrs(&self, ctx: &dyn context::Context, level: Level, msg: string, attrs: slice<Attr>) {
        if !self.Enabled(ctx, level) {
            return;
        }
        let mut pcs: slice<crate::types::uintptr> = crate::make!([]uintptr, 1);
        // Go: skip [runtime.Callers, this function, this function's caller]
        crate::runtime::Callers(3, &mut pcs);
        let pc = pcs[0];

        let mut r = NewRecord(crate::time::Now(), level, msg, pc);
        // Go: r.AddAttrs(attrs...) — one variadic call, which is also
        // what skips the empty groups.
        r.AddAttrs(&attrs.clone().__into_vec());
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

    // go: sdk 1.25.5 log/slog/logger.go:240-257 Logger.log
    /// Go: the `...any` emit path — same shape as `logAttrs`, but the
    /// arguments are a loose key/value list paired by
    /// `argsToAttrSlice` rather than Attrs the caller built.
    ///
    /// Go's `Record.Add` does the pairing after constructing the
    /// Record; goish pairs first and reuses `logAttrs`, which keeps the
    /// Enabled-before-work ordering in exactly one place instead of
    /// two. The observable behaviour is the same.
    fn log(
        &self,
        ctx: &dyn context::Context,
        level: Level,
        msg: string,
        args: slice<crate::goany::Any>,
    ) {
        self.logAttrs(ctx, level, msg, super::argsToAttrSlice(args));
    }

    // go: sdk 1.25.5 log/slog/logger.go:188-190 Logger.Log
    /// Go: "Log emits a log record with the current time and the given
    /// level and message."
    ///
    /// Deviation: Go is variadic; goish takes the argument list as a
    /// slice, which is how every `...any` port in the tree spells it.
    pub fn Log(
        &self,
        ctx: &dyn context::Context,
        level: Level,
        msg: impl Into<string>,
        args: slice<crate::goany::Any>,
    ) {
        self.log(ctx, level, msg.into(), args);
    }

    // go: none — goish-only: the Attr-taking form of `Log`. Go reaches
    // it as `LogAttrs`; this exists because `Log` is now the `...any`
    // form and callers that already have Attrs should not round-trip
    // them through `Any`.
    pub fn LogAttrsAt(
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
    pub fn Debug(&self, msg: impl Into<string>, args: slice<crate::goany::Any>) {
        let bg = context::Background();
        self.log(bg.as_ref(), LevelDebug, msg.into(), args);
    }

    // go: none — goish-only: the Attr-taking form of `Debug`, for
    // callers that already built Attrs.
    pub fn DebugAttrs(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelDebug, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:208-210 Logger.Info
    /// Go: "Info logs at [LevelInfo]."
    pub fn Info(&self, msg: impl Into<string>, args: slice<crate::goany::Any>) {
        let bg = context::Background();
        self.log(bg.as_ref(), LevelInfo, msg.into(), args);
    }

    // go: none — goish-only: the Attr-taking form of `Info`, for
    // callers that already built Attrs.
    pub fn InfoAttrs(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelInfo, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:218-220 Logger.Warn
    /// Go: "Warn logs at [LevelWarn]."
    pub fn Warn(&self, msg: impl Into<string>, args: slice<crate::goany::Any>) {
        let bg = context::Background();
        self.log(bg.as_ref(), LevelWarn, msg.into(), args);
    }

    // go: none — goish-only: the Attr-taking form of `Warn`, for
    // callers that already built Attrs.
    pub fn WarnAttrs(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelWarn, msg.into(), attrs);
    }

    // go: sdk 1.25.5 log/slog/logger.go:228-230 Logger.Error
    /// Go: "Error logs at [LevelError]."
    pub fn Error(&self, msg: impl Into<string>, args: slice<crate::goany::Any>) {
        let bg = context::Background();
        self.log(bg.as_ref(), LevelError, msg.into(), args);
    }

    // go: none — goish-only: the Attr-taking form of `Error`, for
    // callers that already built Attrs.
    pub fn ErrorAttrs(&self, msg: impl Into<string>, attrs: slice<Attr>) {
        let bg = context::Background();
        self.logAttrs(bg.as_ref(), LevelError, msg.into(), attrs);
    }
}

// ─── The default Logger (logger.go:74) ──────────────────────────────

// go: sdk 1.25.5 log/slog/logger.go:20-20 logLoggerLevel
/// Go: `var logLoggerLevel LevelVar` — the threshold the DEFAULT
/// handler consults, distinct from any `HandlerOptions.Level`. Its zero
/// value is LevelInfo, which is why `slog.Debug` prints nothing until
/// `SetLogLoggerLevel` is called.
pub(crate) fn logLoggerLevel() -> &'static super::LevelVar {
    static LEVEL: crate::lazy::Lazy<super::LevelVar> =
        crate::lazy::Lazy::new(|| super::LevelVar::new());
    return LEVEL.get();
}

// go: none — goish idiom: Go holds the default in an
//     `atomic.Pointer[Logger]`; goish holds it behind the same mutex
//     that guards every other swappable global here, since a `Logger`
//     is two words rather than a pointer.
fn defaultLoggerCell() -> &'static crate::sync::Mutex<Logger> {
    static DEFAULT: crate::lazy::Lazy<crate::sync::Mutex<Logger>> = crate::lazy::Lazy::new(|| {
        // Go: `defaultLogger.Store(New(newDefaultHandler(log.Print)))`
        crate::sync::Mutex::new(super::New(alloc::sync::Arc::new(
            super::handler::newDefaultHandler(),
        )))
    });
    return DEFAULT.get();
}

// go: sdk 1.25.5 log/slog/logger.go:55-55 Default
/// Go: "Default returns the default [Logger]."
pub fn Default() -> Logger {
    return defaultLoggerCell().Lock().clone();
}

// go: sdk 1.25.5 log/slog/logger.go:62-75 SetDefault
/// Go: "SetDefault makes l the default [Logger], which is used by the
/// top-level functions [Info], [Debug] and so on."
///
/// Go additionally re-points the `log` package's own output at the new
/// handler, so `log.Print` flows through slog. goish does not: its
/// `log` package has no `handlerWriter` counterpart, and wiring one
/// would need the deadlock guard Go documents right there — "If the
/// default's handler is a defaultHandler, then don't use a
/// handleWriter, or we'll deadlock as they both try to acquire the log
/// default mutex." What IS ported is the half that matters to slog
/// callers: the package-level functions below use the new logger.
pub fn SetDefault(l: Logger) {
    *defaultLoggerCell().Lock() = l;
}

// go: sdk 1.25.5 log/slog/logger.go:44-48 SetLogLoggerLevel
/// Go: "SetLogLoggerLevel controls the level for the bridge to the
/// [log] package. … It returns the previous value."
pub fn SetLogLoggerLevel(level: Level) -> Level {
    let oldLevel = logLoggerLevel().Level();
    logLoggerLevel().Set(level);
    return oldLevel;
}

// go: sdk 1.25.5 log/slog/logger.go:159-161 With
/// Go: "With calls [Logger.With] on the default logger."
pub fn With(args: slice<crate::goany::Any>) -> Logger {
    return Default().With(args);
}

// go: sdk 1.25.5 log/slog/logger.go:280-282 Debug
/// Go: "Debug calls [Logger.Debug] on the default logger."
pub fn Debug<S: Into<string>>(msg: S, args: slice<crate::goany::Any>) {
    Default().log(
        context::Background().as_ref(),
        super::LevelDebug,
        msg.into(),
        args,
    );
}

// go: sdk 1.25.5 log/slog/logger.go:285-287 DebugContext
/// Go: "DebugContext calls [Logger.DebugContext] on the default logger."
pub fn DebugContext<S: Into<string>>(
    ctx: &dyn context::Context,
    msg: S,
    args: slice<crate::goany::Any>,
) {
    Default().log(ctx, super::LevelDebug, msg.into(), args);
}

// go: sdk 1.25.5 log/slog/logger.go:290-292 Info
/// Go: "Info calls [Logger.Info] on the default logger."
pub fn Info<S: Into<string>>(msg: S, args: slice<crate::goany::Any>) {
    Default().log(
        context::Background().as_ref(),
        super::LevelInfo,
        msg.into(),
        args,
    );
}

// go: sdk 1.25.5 log/slog/logger.go:295-297 InfoContext
/// Go: "InfoContext calls [Logger.InfoContext] on the default logger."
pub fn InfoContext<S: Into<string>>(
    ctx: &dyn context::Context,
    msg: S,
    args: slice<crate::goany::Any>,
) {
    Default().log(ctx, super::LevelInfo, msg.into(), args);
}

// go: sdk 1.25.5 log/slog/logger.go:300-302 Warn
/// Go: "Warn calls [Logger.Warn] on the default logger."
pub fn Warn<S: Into<string>>(msg: S, args: slice<crate::goany::Any>) {
    Default().log(
        context::Background().as_ref(),
        super::LevelWarn,
        msg.into(),
        args,
    );
}

// go: sdk 1.25.5 log/slog/logger.go:305-307 WarnContext
/// Go: "WarnContext calls [Logger.WarnContext] on the default logger."
pub fn WarnContext<S: Into<string>>(
    ctx: &dyn context::Context,
    msg: S,
    args: slice<crate::goany::Any>,
) {
    Default().log(ctx, super::LevelWarn, msg.into(), args);
}

// go: sdk 1.25.5 log/slog/logger.go:310-312 Error
/// Go: "Error calls [Logger.Error] on the default logger."
pub fn Error<S: Into<string>>(msg: S, args: slice<crate::goany::Any>) {
    Default().log(
        context::Background().as_ref(),
        super::LevelError,
        msg.into(),
        args,
    );
}

// go: sdk 1.25.5 log/slog/logger.go:315-317 ErrorContext
/// Go: "ErrorContext calls [Logger.ErrorContext] on the default logger."
pub fn ErrorContext<S: Into<string>>(
    ctx: &dyn context::Context,
    msg: S,
    args: slice<crate::goany::Any>,
) {
    Default().log(ctx, super::LevelError, msg.into(), args);
}

// go: sdk 1.25.5 log/slog/logger.go:320-322 Log
/// Go: "Log calls [Logger.Log] on the default logger."
pub fn Log<S: Into<string>>(
    ctx: &dyn context::Context,
    level: Level,
    msg: S,
    args: slice<crate::goany::Any>,
) {
    Default().log(ctx, level, msg.into(), args);
}

// go: sdk 1.25.5 log/slog/logger.go:325-327 LogAttrs
/// Go: "LogAttrs calls [Logger.LogAttrs] on the default logger."
pub fn LogAttrs<S: Into<string>>(
    ctx: &dyn context::Context,
    level: Level,
    msg: S,
    attrs: slice<Attr>,
) {
    Default().logAttrs(ctx, level, msg.into(), attrs);
}
