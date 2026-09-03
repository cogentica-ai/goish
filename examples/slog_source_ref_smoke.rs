// slog_source_ref_smoke — how a Source attribute renders, and when it
// disappears.
//
// Reference: Go 1.25.5 log/slog, measured by
// tools/gen_slog_source_ref.go. Every GO[] line is Go's verbatim
// output, from both built-in handlers.
//
// The last of six generators that no example named. goish matches Go
// on all 16 lines.
//
// The two handlers render the same Source DIFFERENTLY and that is not
// a bug in either: text collapses it to "file:line", JSON emits a
// nested object with only the fields that are set. So the same
// partially-filled Source has two correct spellings, and a port has to
// get both right independently. "file-only" is where they diverge
// most — text prints "a.go:0", inventing a zero line number, while
// JSON simply omits the line key. "line-only" is the mirror: text
// prints ":42" with an empty file.
//
// The rest of the cases are about ELISION, which is the part that is
// easy to get subtly wrong because the output is a missing key rather
// than a wrong value:
//
//   empty-source — a Source with every field zero is dropped entirely,
//   so no source key appears. Not "source=:0", not an empty object.
//
//   dropped — a ReplaceAttr returning the zero Attr removes the key,
//   which is the documented way to suppress an attribute.
//
//   zero-pc — AddSource is ON and the Record's PC is 0, so
//   Record.Source() is nil, Go substitutes an empty Source, and the
//   empty check above elides it. Three steps to arrive at "no key",
//   and a port that skipped any one of them would print something.
//
//   addsource-off — no source key even with a valid PC.
//
// Five different routes to "the source key is absent", one route to
// each of two spellings when it is present.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::log::slog;
use goish::types::{byte, int};
use goish::{string, time};

// Go's verbatim output.
const GO: [&str; 16] = [
    "full               text \"time=2024-01-02T03:04:05.123Z level=INFO source=a.go:42 msg=m\\n\"",
    "full               json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"source\\\":{\\\"function\\\":\\\"pkg.Fn\\\",\\\"file\\\":\\\"a.go\\\",\\\"line\\\":42},\\\"msg\\\":\\\"m\\\"}\\n\"",
    "no-function        text \"time=2024-01-02T03:04:05.123Z level=INFO source=a.go:42 msg=m\\n\"",
    "no-function        json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"source\\\":{\\\"file\\\":\\\"a.go\\\",\\\"line\\\":42},\\\"msg\\\":\\\"m\\\"}\\n\"",
    "file-only          text \"time=2024-01-02T03:04:05.123Z level=INFO source=a.go:0 msg=m\\n\"",
    "file-only          json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"source\\\":{\\\"file\\\":\\\"a.go\\\"},\\\"msg\\\":\\\"m\\\"}\\n\"",
    "line-only          text \"time=2024-01-02T03:04:05.123Z level=INFO source=:42 msg=m\\n\"",
    "line-only          json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"source\\\":{\\\"line\\\":42},\\\"msg\\\":\\\"m\\\"}\\n\"",
    "empty-source       text \"time=2024-01-02T03:04:05.123Z level=INFO msg=m\\n\"",
    "empty-source       json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"msg\\\":\\\"m\\\"}\\n\"",
    "dropped            text \"time=2024-01-02T03:04:05.123Z level=INFO msg=m\\n\"",
    "dropped            json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"msg\\\":\\\"m\\\"}\\n\"",
    "zero-pc            text \"time=2024-01-02T03:04:05.123Z level=INFO msg=m\\n\"",
    "zero-pc            json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"msg\\\":\\\"m\\\"}\\n\"",
    "addsource-off      text \"time=2024-01-02T03:04:05.123Z level=INFO msg=m\\n\"",
    "addsource-off      json \"{\\\"time\\\":\\\"2024-01-02T03:04:05.123456789Z\\\",\\\"level\\\":\\\"INFO\\\",\\\"msg\\\":\\\"m\\\"}\\n\"",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

fn pin(src: Option<slog::Source>) -> slog::HandlerOptions {
    slog::HandlerOptions {
        AddSource: true,
        ReplaceAttr: Some(Arc::new(move |g: &[goish::string], a: slog::Attr| {
            if g.is_empty() && a.Key == slog::SourceKey {
                match &src {
                    None => return slog::Attr::default(),
                    Some(s) => {
                        let mut a2 = a.clone();
                        a2.Value = slog::AnyValue(goish::goany::Any::new(s.clone()));
                        return a2;
                    }
                }
            }
            a
        })),
        ..Default::default()
    }
}

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
        SharedBuf(Arc::new(goish::sync::Mutex::new(Vec::new())))
    }
    fn take(&self) -> goish::string {
        goish::string::from_bytes(&self.0.Lock().clone())
    }
}

fn run(tag: &'static str, opts: slog::HandlerOptions, r: slog::Record) {
    let ctx = goish::context::Background();
    for kind in ["text", "json"].iter() {
        let b = SharedBuf::new();
        if *kind == "text" {
            let h = slog::NewTextHandler(b.clone(), Some(opts.clone()));
            let _ = h.Handle(ctx.as_ref(), r.clone());
        } else {
            let h = slog::NewJSONHandler(b.clone(), Some(opts.clone()));
            let _ = h.Handle(ctx.as_ref(), r.clone());
        }
        chk(fmt::Sprintf!(
            "%-18s %-4s %q",
            string(tag),
            string(*kind),
            b.take()
        ));
    }
}

#[goish::main]
fn main() {
    let fixed = time::Date(2024, time::January, 2, 3, 4, 5, 123456789, time::UTC);
    let rec = |pc: goish::uintptr| slog::NewRecord(fixed.clone(), slog::LevelInfo, string("m"), pc);

    let src = |f: &str, file: &str, line: goish::int| slog::Source {
        Function: goish::string::from_bytes(f.as_bytes()),
        File: goish::string::from_bytes(file.as_bytes()),
        Line: line,
    };

    run("full", pin(Some(src("pkg.Fn", "a.go", 42))), rec(1));
    run("no-function", pin(Some(src("", "a.go", 42))), rec(1));
    run("file-only", pin(Some(src("", "a.go", 0))), rec(1));
    run("line-only", pin(Some(src("", "", 42))), rec(1));
    run("empty-source", pin(Some(src("", "", 0))), rec(1));
    run("dropped", pin(None), rec(1));
    run(
        "zero-pc",
        slog::HandlerOptions {
            AddSource: true,
            ..Default::default()
        },
        rec(0),
    );
    run("addsource-off", slog::HandlerOptions::default(), rec(1));

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
