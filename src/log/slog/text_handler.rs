// go: file log/slog/text_handler.go decls: NewTextHandler, TextHandler.Enabled, TextHandler.WithAttrs, TextHandler.WithGroup, TextHandler.Handle, appendTextValue, needsQuoting
//
// text_handler.go — the logfmt-ish output.
//
// The quoting rule is the whole file. A value is written bare unless it
// would be ambiguous, and "ambiguous" is a precise set: empty, or
// containing a space, an '=', a quote, a control byte, or a non-ASCII
// rune that is not printable. A backslash notably does NOT force
// quoting on its own — Go's test is `b != '\\' && (…)`, which excludes
// it — so a lone backslash is emitted raw.

#![allow(non_snake_case)]
// goishlint:ignore GOISH018 byteSlice — Go's `[]byte` fast path in `appendTextValue` reflects over the boxed `any` to spot a byte slice; goish's `Value` cannot hold one, so there is nothing for the path to match.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::handler::{commonHandler, HandlerOptions};
use super::{Attr, Handler, Level, Record, Value};
use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::unicode::utf8;

// go: sdk 1.25.5 log/slog/text_handler.go:21-23 TextHandler
/// Go: "TextHandler is a [Handler] that writes Records to an [io.Writer]
/// as a sequence of key=value pairs separated by spaces and followed by
/// a newline."
pub struct TextHandler(pub(crate) commonHandler);

// go: sdk 1.25.5 log/slog/text_handler.go:28-40 NewTextHandler
/// Go: "NewTextHandler creates a [TextHandler] that writes to w, using
/// the given options. If opts is nil, the default options are used."
pub fn NewTextHandler<W: io::Writer + Send + 'static>(
    w: W,
    opts: Option<HandlerOptions>,
) -> Arc<dyn Handler + Send + Sync> {
    // Go: if opts == nil { opts = &HandlerOptions{} }
    let opts = opts.unwrap_or_default();
    return Arc::new(TextHandler(commonHandler {
        json: false,
        w: super::handler::__boxed_writer(w),
        opts,
        preformattedAttrs: Vec::new(),
        groupPrefix: string::from_static(""),
        groups: Vec::new(),
        nOpenGroups: 0,
    }));
}

impl Handler for TextHandler {
    // go: sdk 1.25.5 log/slog/text_handler.go:44-46 TextHandler.Enabled
    /// Go: "Enabled reports whether the handler handles records at the
    /// given level. The handler ignores records whose level is lower."
    fn Enabled(&self, _ctx: &dyn crate::context::Context, level: Level) -> bool {
        return self.0.enabled(level);
    }

    // go: sdk 1.25.5 log/slog/text_handler.go:50-52 TextHandler.WithAttrs
    /// Go: "WithAttrs returns a new [TextHandler] whose attributes
    /// consists of h's attributes followed by attrs."
    fn WithAttrs(&self, attrs: slice<Attr>) -> Arc<dyn Handler + Send + Sync> {
        return Arc::new(TextHandler(self.0.withAttrs(&attrs.clone().__into_vec())));
    }

    // go: sdk 1.25.5 log/slog/text_handler.go:54-56 TextHandler.WithGroup
    fn WithGroup(&self, name: string) -> Arc<dyn Handler + Send + Sync> {
        return Arc::new(TextHandler(self.0.withGroup(name)));
    }

    // go: sdk 1.25.5 log/slog/text_handler.go:92-94 TextHandler.Handle
    /// Go: "Handle formats its argument Record as a single line of space-
    /// separated key=value items."
    fn Handle(&self, _ctx: &dyn crate::context::Context, record: Record) -> error {
        return self.0.handle(&record);
    }
}

// go: sdk 1.25.5 log/slog/text_handler.go:96-122 appendTextValue
/// Go dispatches a `KindAny` payload through `encoding.TextMarshaler`,
/// then a `[]byte` fast path, then `fmt.Sprintf("%+v", …)`. goish has no
/// TextMarshaler dispatch at this point, so a `KindAny` renders through
/// the same `Value::String` the other kinds use — which for the payloads
/// slog can hold (an error, a string, a number, nil) is the same text
/// Go's `%+v` produces.
pub(crate) fn appendTextValue(s: &mut super::handler::HandleState, v: &Value) {
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
    if k == super::KindAny {
        s.__appendString(v.String());
        return;
    }
    // Go: default: *s.buf = v.append(*s.buf)
    v.append(s.__buf());
}

// go: sdk 1.25.5 log/slog/text_handler.go:139-161 needsQuoting
/// Go: quote anything that would be ambiguous unquoted.
///
/// Note the backslash exemption: Go's test is
/// `b != '\\' && (b == ' ' || b == '=' || !safeSet[b])`, so a backslash
/// does not force quoting even though it is not in `safeSet`.
pub(crate) fn needsQuoting(s: &string) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return true;
    }
    let mut i: usize = 0;
    while i < b.len() {
        let c = b[i];
        if c < utf8::RuneSelf {
            // Go: "Quote anything except a backslash that would need
            // quoting in a JSON string, as well as space and '='"
            if c != b'\\' && (c == b' ' || c == b'=' || !super::safeSet(c)) {
                return true;
            }
            i += 1;
            continue;
        }
        let (r, size) = utf8::DecodeRune(&b[i..]);
        if r == utf8::RuneError || crate::unicode::IsSpace(r) || !crate::unicode::IsPrint(r) {
            return true;
        }
        i += size.unsigned_abs() as usize;
    }
    return false;
}
