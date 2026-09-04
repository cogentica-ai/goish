// go: file log/slog/json_handler.go decls: NewJSONHandler, JSONHandler.Enabled, JSONHandler.WithAttrs, JSONHandler.WithGroup, JSONHandler.Handle, appendJSONTime, appendJSONValue, appendEscapedJSONString, safeSet
//
// json_handler.go — the line-delimited JSON output.
//
// Two things here differ from the text handler in ways that are easy to
// miss: a Duration is written as an INTEGER of nanoseconds rather than
// Go's duration syntax ("do what json.Marshal does"), and a Time keeps
// full RFC 3339 nanosecond resolution where the text handler truncates
// to milliseconds.

#![allow(non_snake_case)]
// goishlint:ignore GOISH018 appendJSONMarshal — Go routes a Float64 and an arbitrary `any` through `encoding/json.Marshal`; goish has no reflective marshaller here, so those two kinds render through `Value::append` and `Value::String` instead, which produce the same bytes for every payload slog can hold.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::handler::{commonHandler, HandlerOptions};
use super::{Attr, Handler, Level, Record, Value};
use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::byte;
use crate::unicode::utf8;

// go: sdk 1.25.5 log/slog/json_handler.go:23-25 JSONHandler
/// Go: "JSONHandler is a [Handler] that writes Records to an [io.Writer]
/// as line-delimited JSON objects."
pub struct JSONHandler(pub(crate) commonHandler);

// go: sdk 1.25.5 log/slog/json_handler.go:30-42 NewJSONHandler
/// Go: "NewJSONHandler creates a [JSONHandler] that writes to w, using
/// the given options. If opts is nil, the default options are used."
pub fn NewJSONHandler<W: io::Writer + Send + 'static>(
    w: W,
    opts: Option<HandlerOptions>,
) -> Arc<dyn Handler + Send + Sync> {
    let opts = opts.unwrap_or_default();
    return Arc::new(JSONHandler(commonHandler {
        json: true,
        w: super::handler::__boxed_writer(w),
        opts,
        preformattedAttrs: Vec::new(),
        groupPrefix: string::from_static(""),
        groups: Vec::new(),
        nOpenGroups: 0,
    }));
}

impl Handler for JSONHandler {
    // go: sdk 1.25.5 log/slog/json_handler.go:46-48 JSONHandler.Enabled
    fn Enabled(&self, _ctx: &dyn crate::context::Context, level: Level) -> bool {
        return self.0.enabled(level);
    }

    // go: sdk 1.25.5 log/slog/json_handler.go:52-54 JSONHandler.WithAttrs
    fn WithAttrs(&self, attrs: slice<Attr>) -> Arc<dyn Handler + Send + Sync> {
        return Arc::new(JSONHandler(self.0.withAttrs(&attrs.clone().__into_vec())));
    }

    // go: sdk 1.25.5 log/slog/json_handler.go:56-58 JSONHandler.WithGroup
    fn WithGroup(&self, name: string) -> Arc<dyn Handler + Send + Sync> {
        return Arc::new(JSONHandler(self.0.withGroup(name)));
    }

    // go: sdk 1.25.5 log/slog/json_handler.go:88-90 JSONHandler.Handle
    /// Go: "Handle formats its argument Record as a JSON object on a
    /// single line."
    fn Handle(&self, _ctx: &dyn crate::context::Context, record: Record) -> error {
        return self.0.handle(&record);
    }
}

// go: sdk 1.25.5 log/slog/json_handler.go:93-102 appendJSONTime
pub(crate) fn appendJSONTime(s: &mut super::handler::HandleState, t: crate::time::Time) {
    // Go raises an error for a year outside [0,9999] — "RFC 3339 is
    // clear that years are 4 digits exactly."
    s.__buf().push(b'"');
    let f = t.Format(crate::time::RFC3339Nano);
    let b = s.__buf();
    b.extend_from_slice(f.as_bytes());
    b.push(b'"');
}

// go: sdk 1.25.5 log/slog/json_handler.go:104-138 appendJSONValue
pub(crate) fn appendJSONValue(s: &mut super::handler::HandleState, v: &Value) {
    let k = v.Kind();
    if k == super::KindString {
        s.__appendString(v.String());
        return;
    }
    if k == super::KindTime {
        if let Some(t) = v.Any().As::<crate::time::Time>() {
            s.__appendTime(*t);
            return;
        }
    }
    if k == super::KindDuration {
        // Go: "Do what json.Marshal does" — the integer nanosecond
        // count, NOT the duration syntax the text handler writes.
        if let Some(d) = v.Any().As::<crate::time::Duration>() {
            let n = crate::strconv::FormatInt(d.0, 10);
            s.__buf().extend_from_slice(n.as_bytes());
            return;
        }
    }
    if k == super::KindAny {
        // Go: an `error` that is not a json.Marshaler is written as its
        // Error() text; anything else goes through json.Marshal. goish
        // has no reflective Marshal here, so an Any renders as the same
        // text `Value::String` gives, quoted as a JSON string — which
        // for the payloads slog can hold is the same output, except
        // that a nil Any is JSON `null` rather than the string "<nil>".
        if v.Any().IsNil() {
            s.__buf().extend_from_slice(b"null");
            return;
        }
        s.__appendString(v.String());
        return;
    }
    // Go: Int64, Uint64, Float64 and Bool go out as bare JSON numbers
    // and literals, which is what `Value::append` already produces.
    v.append(s.__buf());
}

// go: sdk 1.25.5 log/slog/json_handler.go:227-227 hex
/// Go: `const hex = "0123456789abcdef"` — the digits a `\u00XX` escape
/// is built from.
const hex: &[u8; 16] = b"0123456789abcdef";

// go: none — goish idiom: Go's `appendEscapedJSONString` takes the
//     `[]byte` buffer directly, because the escaper and the handler
//     share a package there. goish's sit in sibling modules, so the
//     crate-visible entry point takes the handle state and the
//     raw-buffer form below stays private to this file.
pub(crate) fn __appendEscapedTo(s: &mut super::handler::HandleState, x: &string) {
    appendEscapedJSONString(s.__buf(), x);
}

// go: sdk 1.25.5 log/slog/json_handler.go:158-225 appendEscapedJSONString
/// Go: escape a string into a JSON string body (without the quotes).
fn appendEscapedJSONString(buf: &mut Vec<byte>, s: &string) {
    let b = s.as_bytes();
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < b.len() {
        let c = b[i];
        if c < utf8::RuneSelf {
            if super::safeSet(c) {
                i += 1;
                continue;
            }
            if start < i {
                buf.extend_from_slice(&b[start..i]);
            }
            buf.push(b'\\');
            if c == b'\\' || c == b'"' {
                buf.push(c);
            } else if c == b'\n' {
                buf.push(b'n');
            } else if c == b'\r' {
                buf.push(b'r');
            } else if c == b'\t' {
                buf.push(b't');
            } else {
                // Go: "This encodes bytes < 0x20 except for \t, \n and \r."
                buf.extend_from_slice(b"u00");
                buf.push(hex[(c >> 4) as usize]);
                buf.push(hex[(c & 0xF) as usize]);
            }
            i += 1;
            start = i;
            continue;
        }
        let (r, size) = utf8::DecodeRune(&b[i..]);
        let size = size.unsigned_abs() as usize;
        if r == utf8::RuneError && size == 1 {
            if start < i {
                buf.extend_from_slice(&b[start..i]);
            }
            buf.extend_from_slice(b"\\ufffd");
            i += size;
            start = i;
            continue;
        }
        // Go: "U+2028 is LINE SEPARATOR. U+2029 is PARAGRAPH SEPARATOR.
        // … It is valid JSON to escape them, so we do so
        // unconditionally."
        if r == 0x2028 || r == 0x2029 {
            if start < i {
                buf.extend_from_slice(&b[start..i]);
            }
            buf.extend_from_slice(b"\\u202");
            buf.push(hex[(r & 0xF) as usize]);
            i += size;
            start = i;
            continue;
        }
        i += size;
    }
    if start < b.len() {
        buf.extend_from_slice(&b[start..]);
    }
}

// go: sdk 1.25.5 log/slog/json_handler.go:237-334 safeSet
/// Go's `safeSet` table, as a predicate. Go writes it as a
/// `[utf8.RuneSelf]bool` array with one entry per character; the
/// contents are: every printable ASCII except the double quote and the
/// backslash, and no control byte.
pub(crate) fn safeSet(c: byte) -> bool {
    if c < 0x20 {
        return false;
    }
    if c == b'"' || c == b'\\' {
        return false;
    }
    // Go's table stops at utf8.RuneSelf; 0x7f (DEL) is absent from it,
    // which makes it unsafe.
    if c >= utf8::RuneSelf {
        return false;
    }
    if c == 0x7f {
        return false;
    }
    return true;
}
