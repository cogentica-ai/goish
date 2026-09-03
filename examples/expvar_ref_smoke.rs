// expvar_ref_smoke — expvar against a running Go.
// (expvar/expvar.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_expvar_ref.go` run in
// `package expvar` by `scripts/goref.sh`. goish matched Go on all 46
// lines — no defects found.
//
// expvar publishes process state as JSON at /debug/vars, and the names
// and values it publishes are often built from data the process did not
// choose: a URL path, a peer's identity, a header. Everything it emits
// therefore has to be VALID JSON whatever it is handed, because one
// unescaped quote turns the document into something a monitoring
// system cannot parse — and a document nobody can parse is a metric
// nobody sees.
//
// What is pinned:
//
//   * Every string is JSON-quoted on the way out, MAP KEYS included —
//     and keys are what a caller most often builds from input. A key
//     containing a quote, a backslash, a newline, a tab or a control
//     character survives as one key, and the empty key is a key.
//   * U+2028 is escaped as  . It is legal in JSON and illegal in
//     JavaScript source, so a document containing it raw parses
//     everywhere except in the one place dashboards evaluate it. Go
//     escapes it; so does goish. (This line first looked like a
//     divergence and was not — the probe's own literal had lost the
//     character.)
//   * Map output is SORTED by key and Do walks in the same order, so
//     two scrapes are comparable and a diff between them means
//     something.
//   * The non-finite floats are the interesting ones, because JSON has
//     no syntax for them: NaN and ±Inf each have a pinned rendering
//     rather than a crash or an empty field.
//   * int64 at both extremes, and Add across zero.
//
// One documented deviation, and the reason this smoke calls Init():
// Go publishes `cmdline` and registers /debug/vars from `init()`,
// which runs whether or not anyone asks. goish has no package init, so
// `Init()` is the explicit equivalent — a caller that never calls it
// gets a /debug/vars without cmdline. `memstats` is dropped outright,
// because runtime.MemStats is not ported, and is not compared here.
//
// Map.Add and Map.AddFloat are likewise absent: Go upgrades an empty
// entry through a runtime type assertion that static dispatch cannot
// spell, and Set is the documented replacement. The reference uses Set
// on both sides so it measures the OUTPUT rather than the constructor.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::expvar;
use goish::expvar::Var;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::math;
use goish::net::http;
use goish::net::http::httptest;
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::types::{float64, int, int64};
const GO: [&str; 46] = [
    "int zero=0",
    "int set=42 value=42",
    "int add=50",
    "int negative=-50",
    "int max=9223372036854775807",
    "int min=-9223372036854775808",
    "float 0                        -> 0",
    "float 1                        -> 1",
    "float -1                       -> -1",
    "float 0.5                      -> 0.5",
    "float 1e+20                    -> 1e+20",
    "float 1e-20                    -> 1e-20",
    "float 0.3333333333333333       -> 0.3333333333333333",
    "float 1.7976931348623157e+308  -> 1.7976931348623157e+308",
    "float 5e-324                   -> 5e-324",
    "float +Inf                     -> +Inf",
    "float -Inf                     -> -Inf",
    "float NaN                      -> NaN",
    "float add -> 1.75 value=1.75",
    "string \"\"                     -> \"\" value=\"\"",
    "string \"plain\"                -> \"plain\" value=\"plain\"",
    "string \"with \\\"quotes\\\"\"      -> \"with \\\"quotes\\\"\" value=\"with \\\"quotes\\\"\"",
    "string \"back\\\\slash\"          -> \"back\\\\slash\" value=\"back\\\\slash\"",
    "string \"new\\nline\"            -> \"new\\nline\" value=\"new\\nline\"",
    "string \"tab\\there\"            -> \"tab\\there\" value=\"tab\\there\"",
    "string \"\\x00nul\"              -> \"\\u0000nul\" value=\"\\x00nul\"",
    "string \"\\x1f-unit-sep\"        -> \"\\u001f-unit-sep\" value=\"\\x1f-unit-sep\"",
    "string \"del\\x7f\"              -> \"del\u{7f}\" value=\"del\\x7f\"",
    "string \"unicode: héllo\"       -> \"unicode: héllo\" value=\"unicode: héllo\"",
    "string \"emoji: 🙂\"             -> \"emoji: 🙂\" value=\"emoji: 🙂\"",
    "string \"<html>&amp;</html>\"   -> \"\\u003chtml\\u003e\\u0026amp;\\u003c/html\\u003e\" value=\"<html>&amp;</html>\"",
    "string \"line\\u2028sep\"        -> \"line\\u2028sep\" value=\"line\\u2028sep\"",
    "string \"\\ufeffbom\"            -> \"﻿bom\" value=\"\\ufeffbom\"",
    "map empty -> {}",
    "map sorted -> {\"123numeric\": 4, \"Mixed\": 3, \"alpha\": 2, \"zeta\": 1}",
    "map quoted -> {\"\": \"v\", \"\\u0001ctl\": \"v\", \"back\\\\slash\": \"v\", \"new\\nline\": \"v\", \"quo\\\"te\": \"v\", \"sp ace\": \"v\", \"tab\\there\": \"v\", \"unicode-é\": \"v\"}",
    "map nested -> {\"f\": 2.5, \"m\": {\"deep\": 7}, \"n\": 1, \"s\": \"str\"}",
    "map do -> [f m n s] sorted=true",
    "map get-missing-nil=true",
    "map after-delete -> {\"f\": 2.5, \"m\": {\"deep\": 7}, \"s\": \"str\"}",
    "get published=true missing=true",
    "handler code=200 ctype=\"application/json; charset=utf-8\"",
    "handler starts=\"{\\n\" ends=\"}\\n\"",
    "handler contains \"\\\"goish.int\\\": 7\"       -> true",
    "handler contains \"\\\"goish.str\\\": \\\"a\\\\\\\"b\\\"\" -> true",
    "handler multiline=true has-cmdline=true",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn mkInt(n: int64) -> Arc<expvar::Int> {
    let v = Arc::new(expvar::Int::new());
    v.Set(n);
    return v;
}
fn mkFloat(f: float64) -> Arc<expvar::Float> {
    let v = Arc::new(expvar::Float::new());
    v.Set(f);
    return v;
}
fn mkString(x: &str) -> Arc<expvar::String> {
    let v = Arc::new(expvar::String::new());
    v.Set(s(x));
    return v;
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    {
        let v = expvar::Int::new();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("int zero=%s", v.String()),
        );
        v.Set(42);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("int set=%s value=%d", v.String(), v.Value()),
        );
        v.Add(8);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("int add=%s", v.String()),
        );
        v.Add(-100);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("int negative=%s", v.String()),
        );
        v.Set(math::MaxInt64);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("int max=%s", v.String()),
        );
        v.Set(math::MinInt64);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("int min=%s", v.String()),
        );
    }
    {
        let floats: [float64; 12] = [
            0.0,
            1.0,
            -1.0,
            0.5,
            1e20,
            1e-20,
            1.0 / 3.0,
            math::MaxFloat64,
            math::SmallestNonzeroFloat64,
            math::Inf(1),
            math::Inf(-1),
            math::NaN(),
        ];
        for f in floats.iter() {
            let v = expvar::Float::new();
            v.Set(*f);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("float %-24g -> %s", *f, v.String()),
            );
        }
        let v = expvar::Float::new();
        v.Set(1.5);
        v.Add(0.25);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("float add -> %s value=%g", v.String(), v.Value()),
        );
    }
    {
        let strs: [&str; 14] = [
            "",
            "plain",
            r#"with "quotes""#,
            r#"back\slash"#,
            "new\nline",
            "tab\there",
            "\u{0}nul",
            "\u{1f}-unit-sep",
            "del\u{7f}",
            "unicode: héllo",
            "emoji: 🙂",
            "<html>&amp;</html>",
            "line\u{2028}sep",
            "\u{feff}bom",
        ];
        for x in strs.iter() {
            let v = expvar::String::new();
            v.Set(s(x));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("string %-22q -> %s value=%q", s(x), v.String(), v.Value()),
            );
        }
    }
    {
        let m = Arc::new(expvar::Map::new());
        m.Init();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map empty -> %s", m.String()),
        );
        m.Set(s("zeta"), mkInt(1));
        m.Set(s("alpha"), mkInt(2));
        m.Set(s("Mixed"), mkInt(3));
        m.Set(s("123numeric"), mkInt(4));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map sorted -> %s", m.String()),
        );
        let m2 = Arc::new(expvar::Map::new());
        m2.Init();
        for k in [
            r#"quo"te"#,
            r#"back\slash"#,
            "new\nline",
            "",
            "sp ace",
            "tab\there",
            "unicode-é",
            "\u{1}ctl",
        ] {
            m2.Set(s(k), mkString("v"));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map quoted -> %s", m2.String()),
        );
        let m3 = Arc::new(expvar::Map::new());
        m3.Init();
        m3.Set(s("n"), mkInt(1));
        m3.Set(s("f"), mkFloat(2.5));
        m3.Set(s("s"), mkString("str"));
        let inner = Arc::new(expvar::Map::new());
        inner.Init();
        inner.Set(s("deep"), mkInt(7));
        m3.Set(s("m"), inner);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map nested -> %s", m3.String()),
        );
        let keys = Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
        let kc = keys.clone();
        m3.Do(|kv: expvar::KeyValue| {
            kc.Lock().push(kv.Key.clone());
        });
        let mut kv = slice::<string>::__from_vec(keys.Lock().clone());
        let before = kv.clone();
        sort::Strings(&mut kv);
        let mut same = before.Len() == kv.Len();
        for i in 0..kv.Len() {
            if before[i] != kv[i] {
                same = false;
            }
        }
        let mut shown = string::from("[");
        for i in 0..before.Len() {
            if i > 0 {
                shown = shown + " ";
            }
            shown = shown + before[i].clone();
        }
        shown = shown + "]";
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map do -> %s sorted=%v", shown, same),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map get-missing-nil=%v", m3.Get(&s("nope")).is_none()),
        );
        m3.Delete(&s("n"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("map after-delete -> %s", m3.String()),
        );
    }
    {
        // Go publishes cmdline and registers /debug/vars from init();
        // goish has no package init, so Init() is the explicit
        // equivalent and has to be called for the comparison to be
        // like for like.
        expvar::Init();
        expvar::Publish(s("goish.int"), mkInt(7));
        expvar::Publish(s("goish.str"), mkString(r#"a"b"#));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "get published=%v missing=%v",
                expvar::Get(&s("goish.int")).is_some(),
                expvar::Get(&s("goish.nope")).is_none()
            ),
        );
        let r = httptest::NewRequest(s("GET"), s("/debug/vars"), ());
        let w = httptest::NewRecorder();
        expvar::Handler().ServeHTTP(&w, &r);
        let body = string::from_bytes(&w.Body().to_vec());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "handler code=%d ctype=%q",
                w.Code(),
                w.HeaderMap().Get(s("Content-Type"))
            ),
        );
        let b = body.as_bytes();
        let first2 = if b.len() < 2 {
            body.clone()
        } else {
            string::from_bytes(&b[..2])
        };
        let last2 = if b.len() < 2 {
            body.clone()
        } else {
            string::from_bytes(&b[b.len() - 2..])
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("handler starts=%q ends=%q", first2, last2),
        );
        for want in [r#""goish.int": 7"#, r#""goish.str": "a\"b""#] {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "handler contains %-24q -> %v",
                    s(want),
                    strings::Contains(body.clone(), s(want))
                ),
            );
        }
        let lines = strings::Count(body.clone(), s("\n"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "handler multiline=%v has-cmdline=%v",
                lines > 2,
                strings::Contains(body.clone(), s(r#""cmdline""#))
            ),
        );
    }
    let _ = http::StatusOK;
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
