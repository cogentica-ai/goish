// go: file log/slog/logger.go decls: Logger.With, Logger.WithGroup, Logger.Enabled, Logger.log, Logger.Log, Logger.LogAttrs, Logger.Debug, Logger.Info, Logger.Warn, Logger.Error, Logger.logAttrs
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

use super::{Level, LevelDebug, LevelError, LevelInfo, LevelWarn, Logger, NewRecord};
use super::Attr;
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
