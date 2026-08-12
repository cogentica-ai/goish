// go: file log/slog/handler.go decls:
//
// log/slog/handler.go — the keys the built-in handlers use.
//
// **Partial port.** Handler, HandlerOptions, TextHandler, JSONHandler
// and commonHandler are not here; only the four well-known attribute
// keys, which slogtest and any custom handler need to agree on.
//
// goishlint:ignore GOISH018 Enabled, Handle, WithAttrs, WithGroup, appendAttr, appendAttrs, appendError, appendKey, appendNonBuiltIns, appendRFC3339Millis, appendString, appendTime, appendTwoStrings, appendValue, attrSep, clone, closeGroup, enabled, free, handle, newDefaultHandler, newHandleState, openGroup, openGroups, withAttrs, withGroup — not ported; only the declarations in this file are.
// goishlint:ignore GOISH021 DiscardHandler, Handler, HandlerOptions, commonHandler, defaultHandler, discardHandler, groupPool, handleState, keyComponentSep — same.

#![allow(non_snake_case)]

// ─── built-in attribute keys ─────────────────────────────────────────

// go: sdk 1.25.5 log/slog/handler.go:176-189 TimeKey
/// Go: "TimeKey is the key used by the built-in handlers for the time
/// when the log method is called. The associated Value is a
/// [time.Time]."
pub const TimeKey: &str = "time";

// go: sdk 1.25.5 log/slog/handler.go:176-189 LevelKey
/// Go: "LevelKey is the key used by the built-in handlers for the level
/// of the log call. The associated value is a [Level]."
pub const LevelKey: &str = "level";

// go: sdk 1.25.5 log/slog/handler.go:176-189 MessageKey
/// Go: "MessageKey is the key used by the built-in handlers for the
/// message of the log call. The associated value is a string."
pub const MessageKey: &str = "msg";

// go: sdk 1.25.5 log/slog/handler.go:176-189 SourceKey
/// Go: "SourceKey is the key used by the built-in handlers for the
/// source file and line of the log call. The associated value is a
/// *[Source]."
pub const SourceKey: &str = "source";
