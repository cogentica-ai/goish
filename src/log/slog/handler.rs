// go: file log/slog/handler.go decls: commonHandler.clone, commonHandler.enabled, commonHandler.withAttrs, commonHandler.withGroup, commonHandler.handle, commonHandler.attrSep, handleState.openGroups, handleState.openGroup, handleState.closeGroup, handleState.appendAttrs, handleState.appendAttr, handleState.appendNonBuiltIns, handleState.appendKey, handleState.appendString, handleState.appendTwoStrings, handleState.appendValue, handleState.appendTime, appendRFC3339Millis,
//
// log/slog/handler.go — the keys the built-in handlers use.
//
// The four well-known attribute keys, `HandlerOptions`, and the
// `commonHandler`/`handleState` machinery that both built-in handlers
// share. `TextHandler` and `JSONHandler` themselves live one file each,
// as in Go.
//
// goishlint:ignore GOISH018 Enabled, Handle, WithAttrs, WithGroup, appendError, free, newDefaultHandler, newHandleState — `Enabled`/`Handle`/`WithAttrs`/`WithGroup` are the Handler impls, which live on TextHandler and JSONHandler in their own files; `free`/`newHandleState` are Go's buffer-pool lifecycle, which goish has no pool for; `appendError` and `newDefaultHandler` belong to the default handler, which is not ported.
// goishlint:ignore GOISH021 DiscardHandler, Handler, defaultHandler, discardHandler, groupPool — `Handler` and `discardHandler` are declared in the module root; `groupPool` is Go's sync.Pool, which goish allocates instead; `DiscardHandler` and `defaultHandler` are not ported.

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

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{Attr, Level, LevelInfo, Leveler, Record, Value};
use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// ─── HandlerOptions (handler.go:99) ─────────────────────────────────

// go: sdk 1.25.5 log/slog/handler.go:135-173 HandlerOptions
/// Go: "HandlerOptions are options for a [TextHandler] or
/// [JSONHandler]. A zero HandlerOptions consists entirely of default
/// values."
///
/// Go's `Level` is a `Leveler` interface, nil meaning LevelInfo, and
/// `ReplaceAttr` is a closure. goish spells the first as an `Option<Arc<dyn
/// Leveler>>` — the same nil — and the second as an `Option<Arc<dyn Fn>>`,
/// which is what lets a caller pass a closure that captures.
#[derive(Clone, Default)]
pub struct HandlerOptions {
    /// Go: "AddSource causes the handler to compute the source code
    /// position of the log statement and add a SourceKey attribute to
    /// the output."
    pub AddSource: bool,
    /// Go: "Level reports the minimum record level that will be logged.
    /// The handler discards records with lower levels. If Level is nil,
    /// the handler assumes LevelInfo."
    pub Level: Option<Arc<dyn Leveler + Send + Sync>>,
    /// Go: "ReplaceAttr is called to rewrite each non-group attribute
    /// before it is logged. … If ReplaceAttr returns a zero Attr, the
    /// attribute is discarded. … The first argument is a list of
    /// currently open groups that contain the Attr. … ReplaceAttr is
    /// never called for Group attributes, only their contents."
    pub ReplaceAttr: Option<Arc<dyn Fn(&[string], Attr) -> Attr + Send + Sync>>,
}

// go: sdk 1.25.5 log/slog/handler.go:429-429 keyComponentSep
/// Go: `const keyComponentSep = '.'` — what joins a group prefix to a
/// key in the TEXT output, where JSON nests objects instead.
const keyComponentSep: byte = b'.';

// ─── commonHandler (handler.go:257) ─────────────────────────────────

// go: sdk 1.25.5 log/slog/handler.go:191-204 commonHandler
/// The state both built-in handlers share. `json` selects the output
/// form; everything else is the accumulated result of `WithAttrs` and
/// `WithGroup`.
///
/// Go pre-formats the attrs added by `WithAttrs` into a byte buffer so
/// each record does not re-render them, and remembers how many groups
/// that buffer already opened. goish keeps that design rather than
/// re-rendering, because it is also what makes the OUTPUT right: a
/// group opened during `WithAttrs` must not be opened a second time
/// when a record is handled.
// goishlint:ignore GOISH019 — Go holds `mu *sync.Mutex` and `w io.Writer`
//     as two fields and shares the mutex across clones; goish's
//     `Arc<Mutex<Box<dyn Writer>>>` is both at once, so the pair
//     collapses into `w`.
pub struct commonHandler {
    /// Go: "true => output JSON; false => output text"
    pub(crate) json: bool,
    pub(crate) opts: HandlerOptions,
    pub(crate) preformattedAttrs: Vec<byte>,
    /// Go: "groupPrefix is for the text handler only. It holds the
    /// prefix for groups that were already pre-formatted."
    pub(crate) groupPrefix: string,
    /// Go: "all groups started from WithGroup"
    pub(crate) groups: Vec<string>,
    /// Go: "the number of groups opened in preformattedAttrs"
    pub(crate) nOpenGroups: int,
    /// Go holds `mu *sync.Mutex` and `w io.Writer` separately and shares
    /// the mutex across clones. goish's `Arc<Mutex<W>>` is already both:
    /// the mutex travels with the writer, and cloning the Arc shares it.
    pub(crate) w: Arc<crate::sync::Mutex<alloc::boxed::Box<dyn io::Writer + Send>>>,
}

impl commonHandler {
    // go: sdk 1.25.5 log/slog/handler.go:206-218 commonHandler.clone
    /// Go: "We can't use assignment because we can't copy the mutex."
    pub(crate) fn clone(&self) -> commonHandler {
        return commonHandler {
            json: self.json,
            opts: self.opts.clone(),
            preformattedAttrs: self.preformattedAttrs.clone(),
            groupPrefix: self.groupPrefix.clone(),
            groups: self.groups.clone(),
            nOpenGroups: self.nOpenGroups,
            // Go: "mutex shared among all clones of this handler"
            w: self.w.clone(),
        };
    }

    // go: sdk 1.25.5 log/slog/handler.go:222-228 commonHandler.enabled
    pub(crate) fn enabled(&self, l: Level) -> bool {
        // Go: minLevel := LevelInfo; if h.opts.Level != nil { … }
        let mut minLevel = LevelInfo;
        if let Some(lv) = &self.opts.Level {
            minLevel = lv.Level();
        }
        return l >= minLevel;
    }

    // go: sdk 1.25.5 log/slog/handler.go:230-260 commonHandler.withAttrs
    pub(crate) fn withAttrs(&self, as_: &[Attr]) -> commonHandler {
        // Go: "We are going to ignore empty groups, so if the entire
        // slice consists of them, there is nothing to do."
        let sl = slice::__from_vec(as_.to_vec());
        if super::countEmptyGroups(&sl) == sl.Len() {
            return self.clone();
        }
        let mut h2 = self.clone();
        // Go pre-formats the attributes as an optimization, writing
        // straight into h2.preformattedAttrs.
        let mut buf: Vec<byte> = core::mem::take(&mut h2.preformattedAttrs);
        let mut prefix: Vec<byte> = self.groupPrefix.as_bytes().to_vec();
        let mut groups: Vec<string> = Vec::new();
        let mut sep = string::from_static("");
        if !buf.is_empty() {
            sep = h2.attrSep();
            if h2.json && buf[buf.len() - 1] == b'{' {
                sep = string::from_static("");
            }
        }
        // Go: "Remember the position in the buffer, in case all attrs
        // are empty."
        let pos = buf.len();
        {
            let mut st = handleState {
                h: &h2,
                buf: &mut buf,
                sep,
                prefix: &mut prefix,
                groups: Some(&mut groups),
            };
            st.openGroups();
            if !st.appendAttrs(as_) {
                st.buf.truncate(pos);
                h2.preformattedAttrs = buf;
                return h2;
            }
        }
        // Go: "Remember the new prefix for later keys."
        h2.groupPrefix = string::__from_vec(prefix);
        // Go: "Remember how many opened groups are in
        // preformattedAttrs, so we don't open them again when we handle
        // a Record."
        h2.nOpenGroups = crate::int64(h2.groups.len());
        h2.preformattedAttrs = buf;
        return h2;
    }

    // go: sdk 1.25.5 log/slog/handler.go:262-266 commonHandler.withGroup
    pub(crate) fn withGroup(&self, name: string) -> commonHandler {
        let mut h2 = self.clone();
        h2.groups.push(name);
        return h2;
    }

    // go: sdk 1.25.5 log/slog/handler.go:270-324 commonHandler.handle
    /// Go: "handle is the internal implementation of Handler.Handle used
    /// by TextHandler and JSONHandler."
    ///
    /// Note the built-in attrs are emitted with `state.groups` set to
    /// None, so a ReplaceAttr sees an EMPTY group path for them even
    /// when the handler is inside a WithGroup — and the real groups are
    /// restored before the record's own attrs.
    pub(crate) fn handle(&self, r: &Record) -> error {
        let mut buf: Vec<byte> = Vec::new();
        let mut prefix: Vec<byte> = Vec::new();
        let mut groups: Vec<string> = Vec::new();
        if self.json {
            buf.push(b'{');
        }
        {
            // Go: stateGroups := state.groups; state.groups = nil — "So
            // ReplaceAttrs sees no groups instead of the pre groups."
            let mut st = handleState {
                h: self,
                buf: &mut buf,
                sep: string::from_static(""),
                prefix: &mut prefix,
                groups: None,
            };
            let rep = self.opts.ReplaceAttr.clone();

            // Go: time
            if !r.Time.IsZero() {
                // Go: r.Time.Round(0) — strip monotonic to match Attr
                // behaviour.
                let val = r.Time.Round(crate::time::Duration(0));
                if rep.is_none() {
                    st.appendKey(string::from_bytes(super::TimeKey.as_bytes()));
                    st.appendTime(val);
                } else {
                    st.appendAttr(&super::Time(
                        string::from_bytes(super::TimeKey.as_bytes()),
                        val,
                    ));
                }
            }
            // Go: level
            if rep.is_none() {
                st.appendKey(string::from_bytes(super::LevelKey.as_bytes()));
                st.appendString(r.Level.String());
            } else {
                st.appendAttr(&Attr {
                    Key: string::from_bytes(super::LevelKey.as_bytes()),
                    Value: super::StringValue(r.Level.String()),
                });
            }
            // Go: source
            if self.opts.AddSource {
                // Go: src := r.Source(); if src == nil { src = &Source{} }
                let src = r.Source().unwrap_or_default();
                st.appendAttr(&super::Any(
                    string::from_bytes(super::SourceKey.as_bytes()),
                    crate::goany::Any::new(src),
                ));
            }

            // Go: msg
            if rep.is_none() {
                st.appendKey(string::from_bytes(super::MessageKey.as_bytes()));
                st.appendString(r.Message.clone());
            } else {
                st.appendAttr(&super::String(
                    string::from_bytes(super::MessageKey.as_bytes()),
                    r.Message.clone(),
                ));
            }
            // Go: state.groups = stateGroups — restore the groups
            // passed to ReplaceAttrs.
            st.groups = Some(&mut groups);
            st.appendNonBuiltIns(r);
            st.buf.push(b'\n');
        }

        // Go: h.mu.Lock(); defer h.mu.Unlock(); h.w.Write(*state.buf)
        let (_, err) = self.w.Lock().Write(slice::__from_vec(buf));
        return err;
    }

    // go: sdk 1.25.5 log/slog/handler.go:372-377 commonHandler.attrSep
    pub(crate) fn attrSep(&self) -> string {
        if self.json {
            return string::from_static(",");
        }
        return string::from_static(" ");
    }
}

// ─── handleState (handler.go:390) ───────────────────────────────────

// go: sdk 1.25.5 log/slog/handler.go:382-389 handleState
/// Go pools the buffers this holds; goish allocates them, so there is
/// no `freeBuf` and no `free`. Everything else is Go's: the separator
/// still owed before the next key, the text-mode key prefix, and the
/// open-group path that ReplaceAttr is shown.
// goishlint:ignore GOISH019 — Go's `freeBuf` drives its buffer POOL,
//     returning the buffer on `free()`. goish allocates the buffer and
//     drops it, so there is no flag and no `free`.
pub(crate) struct handleState<'a> {
    h: &'a commonHandler,
    buf: &'a mut Vec<byte>,
    /// Go: "separator to write before next key"
    sep: string,
    /// Go: "for text: key prefix"
    prefix: &'a mut Vec<byte>,
    /// Go: "pool-allocated slice of active groups, for ReplaceAttr".
    /// `None` is Go's nil, which is how `handle` hides the pre-groups
    /// from ReplaceAttr while it emits the built-ins.
    groups: Option<&'a mut Vec<string>>,
}

impl<'a> handleState<'a> {
    // go: sdk 1.25.5 log/slog/handler.go:422-426 handleState.openGroups
    fn openGroups(&mut self) {
        // Go: for _, n := range s.h.groups[s.h.nOpenGroups:]
        let start = self.h.nOpenGroups.unsigned_abs() as usize;
        let names: Vec<string> = self.h.groups[start..].to_vec();
        for n in names {
            self.openGroup(n);
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:433-446 handleState.openGroup
    /// Go: "openGroup starts a new group of attributes with the given
    /// name."
    fn openGroup(&mut self, name: string) {
        if self.h.json {
            self.appendKey(name.clone());
            self.buf.push(b'{');
            self.sep = string::from_static("");
        } else {
            self.prefix.extend_from_slice(name.as_bytes());
            self.prefix.push(keyComponentSep);
        }
        // Go: "Collect group names for ReplaceAttr."
        if let Some(g) = self.groups.as_mut() {
            g.push(name);
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:449-459 handleState.closeGroup
    /// Go: "closeGroup ends the group with the given name."
    fn closeGroup(&mut self, name: string) {
        if self.h.json {
            self.buf.push(b'}');
        } else {
            // Go: (*s.prefix) = (*s.prefix)[:len(*s.prefix)-len(name)-1]
            let n = self.prefix.len() - name.as_bytes().len() - 1;
            self.prefix.truncate(n);
        }
        self.sep = self.h.attrSep();
        if let Some(g) = self.groups.as_mut() {
            g.pop();
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:463-471 handleState.appendAttrs
    /// Go: "appendAttrs appends the slice of Attrs. It reports whether
    /// something was appended."
    fn appendAttrs(&mut self, as_: &[Attr]) -> bool {
        let mut nonEmpty = false;
        for a in as_ {
            if self.appendAttr(a) {
                nonEmpty = true;
            }
        }
        return nonEmpty;
    }

    // go: sdk 1.25.5 log/slog/handler.go:476-531 handleState.appendAttr
    /// Go: "appendAttr appends the Attr's key and value. It handles
    /// replacement and checking for an empty key. It reports whether
    /// something was appended."
    fn appendAttr(&mut self, a: &Attr) -> bool {
        let mut a = Attr {
            Key: a.Key.clone(),
            Value: super::Resolve(&a.Value),
        };
        // Go: if rep != nil && a.Value.Kind() != KindGroup
        if a.Value.Kind() != super::KindGroup {
            if let Some(rep) = self.h.opts.ReplaceAttr.clone() {
                let empty: Vec<string> = Vec::new();
                let gs: &[string] = match self.groups.as_ref() {
                    Some(g) => g.as_slice(),
                    None => empty.as_slice(),
                };
                a = rep(gs, a);
                // Go: "The ReplaceAttr function may return an unresolved
                // Attr."
                a.Value = super::Resolve(&a.Value);
            }
        }
        // Go: "Elide empty Attrs."
        if a.isEmpty() {
            return false;
        }
        // Go: "Special case: Source." An `any`-kinded Source renders as
        // a nested group in JSON and as "file:line" in text, and an
        // EMPTY one is elided entirely rather than printed as "{}" or
        // ":0".
        if a.Value.Kind() == super::KindAny {
            let src = a.Value.Any().As::<super::Source>().cloned();
            if let Some(src) = src {
                if src.isEmpty() {
                    return false;
                }
                if self.h.json {
                    a.Value = src.group();
                } else {
                    a.Value = super::StringValue(crate::fmt::Sprintf!(
                        "%s:%d",
                        src.File.clone(),
                        src.Line
                    ));
                }
            }
        }
        if a.Value.Kind() == super::KindGroup {
            let attrs = super::__group_attrs(&a.Value);
            // Go: "Output only non-empty groups."
            if attrs.Len() > 0 {
                // Go: "The group may turn out to be empty even though it
                // has attrs (for example, ReplaceAttr may delete all the
                // attrs). So remember where we are in the buffer, to
                // restore the position later if necessary."
                let pos = self.buf.len();
                // Go: "Inline a group with an empty key."
                if a.Key.Len() != 0 {
                    self.openGroup(a.Key.clone());
                }
                if !self.appendAttrs(&attrs.clone().__into_vec()) {
                    self.buf.truncate(pos);
                    return false;
                }
                if a.Key.Len() != 0 {
                    self.closeGroup(a.Key.clone());
                }
            }
        } else {
            self.appendKey(a.Key.clone());
            self.appendValue(&a.Value);
        }
        return true;
    }

    // go: sdk 1.25.5 log/slog/handler.go:326-369 handleState.appendNonBuiltIns
    fn appendNonBuiltIns(&mut self, r: &Record) {
        // Go: preformatted Attrs
        if !self.h.preformattedAttrs.is_empty() {
            let sep = self.sep.clone();
            self.buf.extend_from_slice(sep.as_bytes());
            let pfa = self.h.preformattedAttrs.clone();
            self.buf.extend_from_slice(&pfa);
            self.sep = self.h.attrSep();
            if self.h.json && pfa[pfa.len() - 1] == b'{' {
                self.sep = string::from_static("");
            }
        }
        // Go: "Attrs in Record -- unlike the built-in ones, they are in
        // groups started from WithGroup. If the record has no Attrs,
        // don't output any groups."
        let mut nOpenGroups = self.h.nOpenGroups;
        if r.NumAttrs() > 0 {
            let gp = self.h.groupPrefix.clone();
            self.prefix.extend_from_slice(gp.as_bytes());
            let pos = self.buf.len();
            self.openGroups();
            nOpenGroups = crate::int64(self.h.groups.len());
            let mut empty = true;
            // Go: r.Attrs(func(a Attr) bool { … })
            let mut attrs: Vec<Attr> = Vec::new();
            r.Attrs(|a| {
                attrs.push(a.clone());
                return true;
            });
            for a in &attrs {
                if self.appendAttr(a) {
                    empty = false;
                }
            }
            if empty {
                self.buf.truncate(pos);
                nOpenGroups = self.h.nOpenGroups;
            }
        }
        if self.h.json {
            // Go: "Close all open groups."
            let mut i: int = 0;
            while i < nOpenGroups {
                self.buf.push(b'}');
                i += 1;
            }
            // Go: "Close the top-level object."
            self.buf.push(b'}');
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:537-550 handleState.appendKey
    fn appendKey(&mut self, key: string) {
        let sep = self.sep.clone();
        self.buf.extend_from_slice(sep.as_bytes());
        if !self.prefix.is_empty() {
            // Go: s.appendTwoStrings(string(*s.prefix), key)
            let p = string::from_bytes(&self.prefix.clone());
            self.appendTwoStrings(p, key);
        } else {
            self.appendString(key);
        }
        if self.h.json {
            self.buf.push(b':');
        } else {
            self.buf.push(b'=');
        }
        self.sep = self.h.attrSep();
    }

    // go: sdk 1.25.5 log/slog/handler.go:570-583 handleState.appendString
    fn appendString(&mut self, str_: string) {
        if self.h.json {
            self.buf.push(b'"');
            super::__appendEscapedTo(self, &str_);
            self.buf.push(b'"');
        } else {
            // Go: text
            if super::needsQuoting(&str_) {
                let q = crate::strconv::Quote(str_);
                self.buf.extend_from_slice(q.as_bytes());
            } else {
                self.buf.extend_from_slice(str_.as_bytes());
            }
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:553-568 handleState.appendTwoStrings
    /// Go: "appendTwoStrings implements a fast path for concatenating
    /// two strings."
    fn appendTwoStrings(&mut self, x: string, y: string) {
        if self.h.json {
            self.buf.push(b'"');
            super::__appendEscapedTo(self, &x);
            super::__appendEscapedTo(self, &y);
            self.buf.push(b'"');
        } else if !super::needsQuoting(&x) && !super::needsQuoting(&y) {
            self.buf.extend_from_slice(x.as_bytes());
            self.buf.extend_from_slice(y.as_bytes());
        } else {
            let q = crate::strconv::Quote(x + y);
            self.buf.extend_from_slice(q.as_bytes());
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:585-611 handleState.appendValue
    /// Go guards this with a `recover()` so a panicking TextMarshaler
    /// renders as "<nil>" or "!PANIC: …" rather than taking the process
    /// down. goish's value rendering cannot call user code that panics
    /// — there is no TextMarshaler dispatch here — so there is nothing
    /// to recover from, and the guard has no counterpart.
    fn appendValue(&mut self, v: &Value) {
        if self.h.json {
            super::appendJSONValue(self, v);
        } else {
            super::appendTextValue(self, v);
        }
    }

    // go: sdk 1.25.5 log/slog/handler.go:613-619 handleState.appendTime
    fn appendTime(&mut self, t: crate::time::Time) {
        if self.h.json {
            super::appendJSONTime(self, t);
        } else {
            appendRFC3339Millis(self.buf, t);
        }
    }

    // go: none — goish idiom: the two per-format value appenders live in
    //     text_handler.rs and json_handler.rs, as in Go, and reach the
    //     buffer and the string/quoting helpers through these.
    pub(crate) fn __buf(&mut self) -> &mut Vec<byte> {
        return self.buf;
    }
    // go: none — goish idiom: see `__buf`.
    pub(crate) fn __appendString(&mut self, s: string) {
        self.appendString(s);
    }
    // go: none — goish idiom: see `__buf`.
    pub(crate) fn __appendTime(&mut self, t: crate::time::Time) {
        self.appendTime(t);
    }
    // go: none — goish idiom: see `__buf`.
    pub(crate) fn __json(&self) -> bool {
        return self.h.json;
    }
}

// go: none — goish idiom: `handleState` is file-private in Go too, but
//     Go's text/json appenders sit in the same package and can name it.
//     goish's are sibling modules, so the type is re-exported inside
//     the crate under a spellable alias.
pub(crate) type HandleState<'a> = handleState<'a>;

// go: none — goish idiom: Go stores `w io.Writer` — already an
//     interface value — beside a shared `*sync.Mutex`. goish's writers
//     are owned, so the pair is one `Arc<Mutex<Box<dyn Writer>>>`, and
//     this is what boxes a concrete writer into it.
pub(crate) fn __boxed_writer<W: io::Writer + Send + 'static>(
    w: W,
) -> Arc<crate::sync::Mutex<alloc::boxed::Box<dyn io::Writer + Send>>> {
    let boxed: alloc::boxed::Box<dyn io::Writer + Send> = alloc::boxed::Box::new(w);
    return Arc::new(crate::sync::Mutex::new(boxed));
}

// go: sdk 1.25.5 log/slog/handler.go:621-632 appendRFC3339Millis
/// Go: "Format according to time.RFC3339Nano since it is highly
/// optimized, but truncate it to use millisecond resolution."
///
/// This is why the TEXT output carries three fractional digits where
/// the JSON output carries nine: text truncates to the millisecond,
/// JSON does not.
fn appendRFC3339Millis(b: &mut Vec<byte>, t: crate::time::Time) {
    // Go: "Unfortunately, that format trims trailing 0s, so add 1/10
    // millisecond to guarantee that there are exactly 4 digits after
    // the period", then drops the fourth.
    const prefixLen: usize = "2006-01-02T15:04:05.000".len();
    let n = b.len();
    let t = t
        .Truncate(crate::time::Millisecond)
        .Add(crate::time::Duration(crate::time::Millisecond.0 / 10));
    b.extend_from_slice(t.Format(crate::time::RFC3339Nano).as_bytes());
    // Go: b = append(b[:n+prefixLen], b[n+prefixLen+1:]...) — drop the
    // 4th digit.
    b.remove(n + prefixLen);
}
