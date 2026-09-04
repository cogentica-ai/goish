// slog_handler_ref_smoke — TextHandler and JSONHandler against Go.
// (log/slog/handler.go, text_handler.go, json_handler.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_slog_handler_ref.go` run in `package
// slog` by `scripts/goref.sh`.
//
// The built-in handlers ARE slog's output, and goish had neither. The
// package carried a `Handler` trait and a discard implementation, so
// `slog.New(...)` had nothing to log with: text_handler.go and
// json_handler.go had no counterpart file, and handler.go had only the
// four well-known key names.
//
// Everything here is a formatting decision that a port either
// reproduces byte for byte or silently changes, and the differences
// between the two handlers are the easy ones to get wrong:
//
//   * TEXT truncates the timestamp to MILLISECONDS ("…05.123Z"); JSON
//     keeps full nanosecond RFC 3339 ("…05.123456789Z").
//   * A Duration is "1.5s" in text and the integer 1500000000 in JSON,
//     because Go's JSON path does "what json.Marshal does".
//   * Groups become dotted key prefixes in text ("g.a=1") and nested
//     objects in JSON ({"g":{"a":1}}).
//   * An EMPTY group is elided entirely in both — including a group
//     opened by WithGroup that no attr ever lands in, which must not
//     leave a dangling "{" behind in the JSON.
//   * Text quotes a value only when it would be ambiguous, and a lone
//     BACKSLASH is not ambiguous: Go's test is `b != '\\' && (…)`.
//
// ReplaceAttr is pinned in four ways because it is the part with real
// state behind it: it sees the built-in time/level/msg attrs with an
// EMPTY group path even when the handler is inside a WithGroup, it can
// drop an attr by returning the zero Attr, it can rename a built-in
// key, and inside a group it is shown that group's path.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::log::slog;
use goish::types::{byte, int, uintptr};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: Go hands the handler `&buf` and reads the
//     same buffer afterwards, because a Go interface value is already a
//     pointer. goish's writers are owned, so sharing one takes an Arc
//     the caller keeps a clone of — this is that writer.
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
        return string::from_bytes(&self.0.Lock().clone());
    }
}

// go: none — goish idiom: the fixed instant the Go reference used.
fn fixed() -> goish::time::Time {
    return goish::time::Date(2024, 1, 2, 3, 4, 5, 123_456_789, goish::time::UTC);
}

fn g1(a: slog::Attr) -> slice<slog::Attr> {
    return slice::__from_vec(alloc::vec![a]);
}
fn g2(a: slog::Attr, b: slog::Attr) -> slice<slog::Attr> {
    return slice::__from_vec(alloc::vec![a, b]);
}

fn rec(msg: &str, level: slog::Level, attrs: &[slog::Attr]) -> slog::Record {
    let mut r = slog::NewRecord(fixed(), level, msg, 0);
    r.AddAttrs(attrs);
    return r;
}

fn opts_addsource() -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.AddSource = true;
    return o;
}
fn opts_pin_source(src: Option<slog::Source>) -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.AddSource = true;
    o.ReplaceAttr = Some(Arc::new(move |g: &[string], mut a: slog::Attr| {
        if g.is_empty() && a.Key == s(slog::SourceKey) {
            match &src {
                None => return slog::Attr::default(),
                Some(v) => {
                    a.Value = slog::AnyValue(goish::goany::Any::new(v.clone()));
                }
            }
        }
        return a;
    }));
    return o;
}
fn opts_level_warn() -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.Level = Some(Arc::new(slog::LevelWarn));
    return o;
}
fn opts_drop_time() -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.ReplaceAttr = Some(Arc::new(|g: &[string], a: slog::Attr| {
        if g.is_empty() && a.Key == s(slog::TimeKey) {
            return slog::Attr::default();
        }
        return a;
    }));
    return o;
}
fn opts_replace_value() -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.ReplaceAttr = Some(Arc::new(|_g: &[string], mut a: slog::Attr| {
        if a.Key == s("k") {
            a.Value = slog::StringValue("REPLACED");
        }
        return a;
    }));
    return o;
}
fn opts_rename_level() -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.ReplaceAttr = Some(Arc::new(|g: &[string], mut a: slog::Attr| {
        if g.is_empty() && a.Key == s(slog::LevelKey) {
            a.Key = s("sev");
        }
        return a;
    }));
    return o;
}
fn opts_see_groups() -> slog::HandlerOptions {
    let mut o = slog::HandlerOptions::default();
    o.ReplaceAttr = Some(Arc::new(|g: &[string], mut a: slog::Attr| {
        if a.Key == s("a") {
            let mut out = string::from_static("groups=[");
            let mut i = 0usize;
            while i < g.len() {
                if i > 0 {
                    out = out + s(" ");
                }
                out = out + g[i].clone();
                i += 1;
            }
            a.Value = slog::StringValue(out + s("]"));
        }
        return a;
    }));
    return o;
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

    let ctx = goish::context::Background();

    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("hello", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=hello\n",
            "plain text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("hello", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"hello\"}\n",
            "plain json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelWarn, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=WARN msg=m\n",
            "levels-warn text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelWarn, &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"WARN\",\"msg\":\"m\"}\n",
            "levels-warn json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::Level(2), &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO+2 msg=m\n",
            "level-offset text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::Level(2), &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO+2\",\"msg\":\"m\"}\n",
            "level-offset json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[
                    slog::String("s", "v"),
                    slog::Int("n", 7),
                    slog::Bool("b", true),
                ],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m s=v n=7 b=true\n",
            "attrs-basic text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[
                    slog::String("s", "v"),
                    slog::Int("n", 7),
                    slog::Bool("b", true),
                ],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"s\":\"v\",\"n\":7,\"b\":true}\n", "attrs-basic json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Float64("f", 1.5), slog::Float64("neg", -0.25)],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m f=1.5 neg=-0.25\n",
            "attrs-float text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Float64("f", 1.5), slog::Float64("neg", -0.25)],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"f\":1.5,\"neg\":-0.25}\n", "attrs-float json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[
                    slog::Duration("d", goish::time::Duration(1_500_000_000)),
                    slog::Time("t", fixed()),
                ],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m d=1.5s t=2024-01-02T03:04:05.123Z\n",
            "attrs-dur-time text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[
                    slog::Duration("d", goish::time::Duration(1_500_000_000)),
                    slog::Time("t", fixed()),
                ],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"d\":1500000000,\"t\":\"2024-01-02T03:04:05.123456789Z\"}\n", "attrs-dur-time json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[
                    slog::String("plain", "abc"),
                    slog::String("space", "a b"),
                    slog::String("empty", ""),
                    slog::String("quote", "he said \"hi\""),
                    slog::String("eq", "a=b"),
                ],
            ),
        );
        eq(&mut failed, b.take(), "time=2024-01-02T03:04:05.123Z level=INFO msg=m plain=abc space=\"a b\" empty=\"\" quote=\"he said \\\"hi\\\"\" eq=\"a=b\"\n", "value-quoting text");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[
                    slog::String("plain", "abc"),
                    slog::String("space", "a b"),
                    slog::String("empty", ""),
                    slog::String("quote", "he said \"hi\""),
                    slog::String("eq", "a=b"),
                ],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"plain\":\"abc\",\"space\":\"a b\",\"empty\":\"\",\"quote\":\"he said \\\"hi\\\"\",\"eq\":\"a=b\"}\n", "value-quoting json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("has space", "v"), slog::String("has=eq", "v")],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m \"has space\"=v \"has=eq\"=v\n",
            "key-quoting text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("has space", "v"), slog::String("has=eq", "v")],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"has space\":\"v\",\"has=eq\":\"v\"}\n", "key-quoting json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("needs quoting", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=\"needs quoting\"\n",
            "msg-quoting text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("needs quoting", slog::LevelInfo, &[]));
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"needs quoting\"}\n", "msg-quoting json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("nl", "a\nb"), slog::String("tab", "a\tb")],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m nl=\"a\\nb\" tab=\"a\\tb\"\n",
            "newline text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("nl", "a\nb"), slog::String("tab", "a\tb")],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"nl\":\"a\\nb\",\"tab\":\"a\\tb\"}\n", "newline json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("u", "Jörg"), slog::String("emoji", "x")],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m u=Jörg emoji=x\n",
            "unicode text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("u", "Jörg"), slog::String("emoji", "x")],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"u\":\"Jörg\",\"emoji\":\"x\"}\n", "unicode json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Any("a", goish::goany::Any::default())],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m a=<nil>\n",
            "nil-any text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Any("a", goish::goany::Any::default())],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"a\":null}\n", "nil-any json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Any(
                    "e",
                    goish::goany::Any::new(goish::errors::New("boom")),
                )],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m e=boom\n",
            "err-any text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Any(
                    "e",
                    goish::goany::Any::new(goish::errors::New("boom")),
                )],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"e\":\"boom\"}\n", "err-any json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group(
                    "g",
                    g2(slog::String("a", "1"), slog::Int("b", 2)),
                )],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m g.a=1 g.b=2\n",
            "group-attr text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group(
                    "g",
                    g2(slog::String("a", "1"), slog::Int("b", 2)),
                )],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"g\":{\"a\":\"1\",\"b\":2}}\n", "group-attr json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group("g", goish::goslice::slice::new())],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "group-empty text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group("g", goish::goslice::slice::new())],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "group-empty json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group(
                    "g",
                    g1(slog::Group("h", g1(slog::String("a", "1")))),
                )],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m g.h.a=1\n",
            "group-nested text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group(
                    "g",
                    g1(slog::Group("h", g1(slog::String("a", "1")))),
                )],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"g\":{\"h\":{\"a\":\"1\"}}}\n", "group-nested json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithAttrs(g2(slog::String("svc", "api"), slog::Int("v", 1)));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m svc=api v=1 k=v\n",
            "with-attrs text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithAttrs(g2(slog::String("svc", "api"), slog::Int("v", 1)));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"svc\":\"api\",\"v\":1,\"k\":\"v\"}\n", "with-attrs json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("req"));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("id", "7"), slog::Int("n", 1)],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m req.id=7 req.n=1\n",
            "with-group text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("req"));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("id", "7"), slog::Int("n", 1)],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"req\":{\"id\":\"7\",\"n\":1}}\n", "with-group json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("req")).WithAttrs(g1(slog::String("id", "7")));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m req.id=7 req.k=v\n",
            "with-group-attrs text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("req")).WithAttrs(g1(slog::String("id", "7")));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"req\":{\"id\":\"7\",\"k\":\"v\"}}\n", "with-group-attrs json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("a")).WithGroup(s("b"));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m a.b.k=v\n",
            "with-group-twice text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("a")).WithGroup(s("b"));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"a\":{\"b\":{\"k\":\"v\"}}}\n", "with-group-twice json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("empty"));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "with-group-none text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let h = h.WithGroup(s("empty"));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "with-group-none json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_level_warn()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "opts-level-warn text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_level_warn()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "opts-level-warn json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_drop_time()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(
            &mut failed,
            b.take(),
            "level=INFO msg=m k=v\n",
            "replace-drop-time text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_drop_time()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(
            &mut failed,
            b.take(),
            "{\"level\":\"INFO\",\"msg\":\"m\",\"k\":\"v\"}\n",
            "replace-drop-time json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_replace_value()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m k=REPLACED\n",
            "replace-value text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_replace_value()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec("m", slog::LevelInfo, &[slog::String("k", "v")]),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"k\":\"REPLACED\"}\n", "replace-value json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_rename_level()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z sev=INFO msg=m\n",
            "replace-level-key text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_rename_level()));
        let _ = h.Handle(ctx.as_ref(), rec("m", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"sev\":\"INFO\",\"msg\":\"m\"}\n",
            "replace-level-key json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_see_groups()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group("g", g1(slog::String("a", "1")))],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m g.a=\"groups=[g]\"\n",
            "replace-sees-groups text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_see_groups()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::Group("g", g1(slog::String("a", "1")))],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"g\":{\"a\":\"groups=[g]\"}}\n", "replace-sees-groups json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("", "v"), slog::String("k", "")],
            ),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m \"\"=v k=\"\"\n",
            "empty-key text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            rec(
                "m",
                slog::LevelInfo,
                &[slog::String("", "v"), slog::String("k", "")],
            ),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\",\"\":\"v\",\"k\":\"\"}\n", "empty-key json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=\"\"\n",
            "empty-msg text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(ctx.as_ref(), rec("", slog::LevelInfo, &[]));
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"\"}\n",
            "empty-msg json",
        );
    }

    // 4. AddSource. The two handlers render a Source differently: text
    //    flattens it to "file:line" — always both, so a Source with no
    //    line prints "a.go:0" — while JSON nests it and OMITS the empty
    //    fields. An empty Source is elided entirely rather than printed
    //    as ":0" or "{}", which is also what a zero PC produces.
    //
    //    The real file and line differ between a Go build and a goish
    //    one, so ReplaceAttr pins a fixed Source. That leaves the
    //    handler's own conversion as the only thing under test.
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s("pkg.Fn"),
                File: s("a.go"),
                Line: 42,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO source=a.go:42 msg=m\n",
            "source full text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s("pkg.Fn"),
                File: s("a.go"),
                Line: 42,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"source\":{\"function\":\"pkg.Fn\",\"file\":\"a.go\",\"line\":42},\"msg\":\"m\"}\n", "source full json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s(""),
                File: s("a.go"),
                Line: 42,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO source=a.go:42 msg=m\n",
            "source no-function text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s(""),
                File: s("a.go"),
                Line: 42,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"source\":{\"file\":\"a.go\",\"line\":42},\"msg\":\"m\"}\n", "source no-function json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s(""),
                File: s("a.go"),
                Line: 0,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO source=a.go:0 msg=m\n",
            "source file-only text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s(""),
                File: s("a.go"),
                Line: 0,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"source\":{\"file\":\"a.go\"},\"msg\":\"m\"}\n", "source file-only json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s(""),
                File: s(""),
                Line: 42,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO source=:42 msg=m\n",
            "source line-only text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source {
                Function: s(""),
                File: s(""),
                Line: 42,
            }))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(&mut failed, b.take(), "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"source\":{\"line\":42},\"msg\":\"m\"}\n", "source line-only json");
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source::default()))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "source empty-source text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(
            b.clone(),
            Some(opts_pin_source(Some(slog::Source::default()))),
        );
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "source empty-source json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_pin_source(None)));
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "source dropped text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_pin_source(None)));
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "source dropped json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(opts_addsource()));
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 0),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "source zero-pc text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(opts_addsource()));
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 0),
        );
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "source zero-pc json",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewTextHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "time=2024-01-02T03:04:05.123Z level=INFO msg=m\n",
            "source addsource-off text",
        );
    }
    {
        let b = SharedBuf::new();
        let h = slog::NewJSONHandler(b.clone(), Some(slog::HandlerOptions::default()));
        let _ = h.Handle(
            ctx.as_ref(),
            slog::NewRecord(fixed(), slog::LevelInfo, "m", 1),
        );
        eq(
            &mut failed,
            b.take(),
            "{\"time\":\"2024-01-02T03:04:05.123456789Z\",\"level\":\"INFO\",\"msg\":\"m\"}\n",
            "source addsource-off json",
        );
    }
    // Record::Source itself: None for a zero PC, and for a real one a
    //    resolved frame — goish has a symboliser, so this is not a stub.
    {
        let r0 = slog::NewRecord(fixed(), slog::LevelInfo, "m", 0);
        if r0.Source().is_some() {
            fmt::Println!("[!!] Source() on a zero PC should be None");
            failed += 1;
        }
        let mut pcs: slice<goish::types::uintptr> = goish::make!([]uintptr, 1);
        goish::runtime::Callers(1, &mut pcs);
        let r1 = slog::NewRecord(fixed(), slog::LevelInfo, "m", pcs[0]);
        // A non-zero PC always yields a Source. Whether its File and
        // Line are FILLED IN depends on the binary carrying a symbol
        // table, and the release profile in Cargo.toml sets
        // `strip = true` — so asserting they resolve would pass under
        // `make e2e` (which builds debug) and fail under a release
        // build, which is a property of the build and not of this port.
        if r1.Source().is_none() {
            fmt::Println!("[!!] Source() on a real PC should be Some");
            failed += 1;
        }
    }
    fmt::Println!("[  4 ] AddSource renders and elides like Go");

    if failed == 0 {
        fmt::Println!("ok - slog handlers match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
