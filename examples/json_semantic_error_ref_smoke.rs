// json_semantic_error_ref_smoke — what a v2 decode error SAYS
// (issue #10).
//
// goish's scalar codecs used to say
//
//     json: cannot unmarshal non-string into string
//
// which names neither what arrived nor where. Go names three things a
// caller routes on:
//
//     json: cannot unmarshal JSON number into Go string within "/trigger"
//                             ^^^^^^      ^^^^^^        ^^^^^^^^^
//                             kind        Go type       JSON pointer
//
// The pointer is the part a consumer cannot reconstruct for itself —
// nested objects, arrays, escaped names and streaming decodes all need
// decoder state — which is why it is built in the runtime. The
// `repro_*` rows are issue #10's own reproducer, verbatim.
//
// TWO ROWS BELOW ARE NOT GO'S TEXT, and are pinned as goish's with
// Go's quoted beside them so the gap is visible rather than absent:
//
//   div_int       Go says `into Go int`; goish says `int64`. goish's
//                 `int` IS `i64` — an alias, not a distinct type — so
//                 the codec cannot tell a Go `int` field from an
//                 `int64` one. Same for `byte`/`uint8`, `rune`/`int32`.
//                 Closing it needs newtypes for the aliases.
//   div_slice     and div_map: only the ELEMENT name differs, for the
//                 same alias reason. The composition itself is Go's —
//                 `[]string`, `[][]string`, `map[string][]int64` — via
//                 a defaulted `__go_type_name` on `UnmarshalerFrom`,
//                 which composites override to build from their
//                 element's. Defaulted rather than a new bound, so an
//                 existing implementor that says nothing still
//                 compiles and reports `value`.
//
// Everything else — every kind word, every pointer including RFC 6901
// escaping, the `within` clause's presence at a field and absence at
// the root, the literal-and-cause form for `1.5` into an integer — is
// byte-for-byte Go, from tools/gen_json_semerr_ref.go.
//
// The `field_custom` / `custom_is` pair is the last of issue #10's six
// requirements: an adapter wrapping a custom pointee error at the
// decoder's current path "without parsing or replacing the cause
// text". The cause keeps its own words, gains the kind, the Go type
// and the pointer, and `errors::Is` still finds the sentinel through
// the wrap — so a caller can route on the error AND report where it
// happened.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::jsontext;
use goish::encoding::json::v2 as json;
use goish::errors::{error, nil};
use goish::fmt;
use goish::gomap::map;
use goish::gostring::string;
use goish::slice;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 20] = [
    "root_num_str       json: cannot unmarshal JSON number into Go string",
    "root_bool_str      json: cannot unmarshal JSON boolean into Go string",
    "root_arr_str       json: cannot unmarshal JSON array into Go string",
    "root_obj_str       json: cannot unmarshal JSON object into Go string",
    "root_num_bool      json: cannot unmarshal JSON number into Go bool",
    "root_str_bool      json: cannot unmarshal JSON string into Go bool",
    "root_str_float     json: cannot unmarshal JSON string into Go float64",
    // Go: `json: cannot unmarshal JSON string into Go int` — see the
    // header; goish's `int` is an alias of `i64`.
    "div_int            json: cannot unmarshal JSON string into Go int64",
    // Go: `json: cannot unmarshal JSON number 1.5 into Go int: invalid syntax`
    "div_frac_int       json: cannot unmarshal JSON number 1.5 into Go int64: invalid syntax",
    // Go: `... into Go []int` / `map[string]int`. The STRUCTURE is
    // Go's now; only the element name carries the same int alias, so
    // a slice of any other type is byte-exact — `slice_string` proves
    // that, and it is the row that would catch the composition
    // regressing.
    "div_slice          json: cannot unmarshal JSON object into Go []int64",
    "div_map            json: cannot unmarshal JSON array into Go map[string]int64",
    "slice_string       json: cannot unmarshal JSON object into Go []string",
    "nested_slice       json: cannot unmarshal JSON object into Go [][]string",
    "field_nested_str   json: cannot unmarshal JSON number into Go string within \"/in/s\"",
    "field_slice_deep   json: cannot unmarshal JSON number into Go string within \"/sl/0/s\"",
    "escaped_name       json: cannot unmarshal JSON number into Go string within \"/a~1b\"",
    "repro_text         json: cannot unmarshal JSON number into Go string within \"/trigger\"",
    "repro_nonnil       true",
    // Go: `... into Go json_test.Custom within "/c": Custom: expected
    // string or object, got number`. The type name is whatever the
    // adapter passes, so this one says api.Custom the way the
    // downstream port's would.
    "field_custom       json: cannot unmarshal JSON number into Go api.Custom within \"/c\": Custom: expected string or object, got number",
    "custom_is          true",
];

#[goish::reflect]
#[derive(Default, Clone, PartialEq)]
struct Inner {
    #[tag(r#"json:"s""#)]
    S: string,
}

#[goish::reflect]
#[derive(Default, Clone, PartialEq)]
struct Outer {
    #[tag(r#"json:"in""#)]
    In: Inner,
    #[tag(r#"json:"sl""#)]
    Sl: slice<Inner>,
}

/// A process-wide sentinel the caller routes on, the way a Go package
/// exports `var ErrX = errors.New(...)`.
static SENTINEL: goish::sync::Mutex<Option<error>> = goish::sync::Mutex::new(None);
fn err_custom() -> error {
    let mut g = SENTINEL.Lock();
    if g.is_none() {
        *g = Some(goish::errors::New(string::from_static(
            "Custom: expected string or object, got number",
        )));
    }
    return g.as_ref().unwrap().clone();
}

/// A custom pointee decoder that rejects with its OWN error, then asks
/// the runtime to attach the kind, the Go type and the path — issue
/// #10's fourth requirement, "without parsing or replacing the cause
/// text".
#[derive(Default, Clone, PartialEq)]
struct Custom {
    N: int,
}

impl json::UnmarshalerFrom for Custom {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        // Peek BEFORE consuming (the kind is gone afterwards) and wrap
        // AFTER (StackPointer names the value just read).
        let kind = dec.PeekKind();
        let (_, e) = dec.ReadValue();
        if e != nil {
            return e;
        }
        if kind != '"' && kind != '{' {
            return json::NewSemanticError(
                dec,
                kind,
                string::from_static("api.Custom"),
                err_custom(),
            );
        }
        return nil;
    }
}

/// A hand-written object adapter holding one — the shape the
/// downstream generator emits.
#[derive(Default)]
struct HasCustom {
    c: Option<Custom>,
}

impl json::UnmarshalerFrom for HasCustom {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (_, e) = dec.ReadToken(); // {
        if e != nil {
            return e;
        }
        let (_, e) = dec.ReadToken(); // "c"
        if e != nil {
            return e;
        }
        return self.c.UnmarshalJSONFrom(dec);
    }
}

/// Issue #10's reproducer, verbatim: an object adapter that delegates
/// a nullable field to goish's own pointer/string codec.
#[derive(Default)]
struct Request {
    trigger: Option<string>,
}

impl json::UnmarshalerFrom for Request {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> error {
        let (_, err) = dec.ReadToken(); // {
        if err != nil {
            return err;
        }
        let (_, err) = dec.ReadToken(); // "trigger"
        if err != nil {
            return err;
        }
        return self.trigger.UnmarshalJSONFrom(dec);
    }
}

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    *ln += 1;
}

fn row(ln: &mut usize, name: &'static str, e: error) {
    let text = if e.IsNil() {
        string::from_static("<nil>")
    } else {
        e.Error()
    };
    chk(ln, &fmt::Sprintf!("%-18s %s", string::from_static(name), text));
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let mut v = string::new();
    row(&mut ln, "root_num_str", json::Unmarshal(&b"1"[..], &mut v, []));
    let mut v = string::new();
    row(&mut ln, "root_bool_str", json::Unmarshal(&b"true"[..], &mut v, []));
    let mut v = string::new();
    row(&mut ln, "root_arr_str", json::Unmarshal(&b"[]"[..], &mut v, []));
    let mut v = string::new();
    row(&mut ln, "root_obj_str", json::Unmarshal(&b"{}"[..], &mut v, []));
    let mut v = false;
    row(&mut ln, "root_num_bool", json::Unmarshal(&b"1"[..], &mut v, []));
    let mut v = false;
    row(&mut ln, "root_str_bool", json::Unmarshal(&b"\"x\""[..], &mut v, []));
    let mut v: f64 = 0.0;
    row(&mut ln, "root_str_float", json::Unmarshal(&b"\"x\""[..], &mut v, []));

    let mut v: int = int::from(0);
    row(&mut ln, "div_int", json::Unmarshal(&b"\"x\""[..], &mut v, []));
    let mut v: int = int::from(0);
    row(&mut ln, "div_frac_int", json::Unmarshal(&b"1.5"[..], &mut v, []));
    let mut v: slice<int> = slice::new();
    row(&mut ln, "div_slice", json::Unmarshal(&b"{}"[..], &mut v, []));
    let mut v: map<string, int> = map::new();
    row(&mut ln, "div_map", json::Unmarshal(&b"[]"[..], &mut v, []));
    // Byte-exact: no int in sight, so the composition alone is on show.
    let mut v: slice<string> = slice::new();
    row(&mut ln, "slice_string", json::Unmarshal(&b"{}"[..], &mut v, []));
    let mut v: slice<slice<string>> = slice::new();
    row(&mut ln, "nested_slice", json::Unmarshal(&b"{}"[..], &mut v, []));

    // The pointer, which is the whole point.
    let mut o = Outer::default();
    row(
        &mut ln,
        "field_nested_str",
        json::Unmarshal(&b"{\"in\":{\"s\":1}}"[..], &mut o, []),
    );
    let mut o = Outer::default();
    row(
        &mut ln,
        "field_slice_deep",
        json::Unmarshal(&b"{\"sl\":[{\"s\":1}]}"[..], &mut o, []),
    );
    // RFC 6901: a `/` in a member name must not fake a path separator.
    let mut m: map<string, string> = map::new();
    row(
        &mut ln,
        "escaped_name",
        json::Unmarshal(&b"{\"a/b\":1}"[..], &mut m, []),
    );

    // Issue #10's reproducer.
    let mut value = Request::default();
    let err = json::Unmarshal(&br#"{"trigger":1}"#[..], &mut value, []);
    row(&mut ln, "repro_text", err);
    // The already-fixed pointer-state contract must survive: a nil
    // pointer is allocated before decoding, so it is non-nil and
    // zero-valued after the error.
    chk(
        &mut ln,
        &fmt::Sprintf!(
            "%-18s %v",
            string::from_static("repro_nonnil"),
            value.trigger.is_some()
        ),
    );

    // A custom pointee error, wrapped with the runtime's context.
    let mut hc = HasCustom::default();
    let e = json::Unmarshal(&b"{\"c\":5}"[..], &mut hc, []);
    row(&mut ln, "field_custom", e.clone());
    // The cause survives wrapping, so a caller routes on the sentinel
    // AND reads the path. Go: errors.Is(err, errCustom) == true.
    chk(
        &mut ln,
        &fmt::Sprintf!(
            "%-18s %v",
            string::from_static("custom_is"),
            goish::errors::Is(e, err_custom())
        ),
    );

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
}
