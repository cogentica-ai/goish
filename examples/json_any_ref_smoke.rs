// json_any_ref_smoke — `goish::Any` (Go's `interface{}`) under
// encoding/json/v2, both directions. Issue #15.
//
// Go marshals an interface by dispatching on its DYNAMIC value, which
// reflection makes free: the interface header already carries the type
// descriptor. goish erases into `Arc<dyn AnyVal>`, and `AnyVal`'s
// blanket impl cannot conjure a `MarshalerTo` for a `T` that may not
// have one — so the codec is DECLARED to survive the wrap, through the
// same per-trait registry `#[goish::interface]` uses for everything
// else.
//
// Two rows carry the design:
//
//   m_struct   a `#[goish::reflect]` struct, marshaled through an Any
//              with NO registration written by anyone. The macro emits
//              it into .init_array. This is the case a port actually
//              hits — a generated LSP message inside an `any` field —
//              and needing a manual call per type would be a footgun
//              whose symptom is a runtime error on one field of one
//              message.
//   m_custom   a hand-written codec, registered explicitly. This is
//              why a fixed downcast table over the built-in scalars
//              cannot serve: Go accepts arbitrary dynamic types with
//              their own marshalers, and a table would silently refuse
//              exactly the values a port puts in an `any`.
//
// `m_nil` is first in the implementation as well as here: the nil
// marker is a concrete type like any other, so it has to be answered
// before the registry is consulted or it would miss and be reported
// unsupported.
//
// The DECODE rows are the other half, and the `type=` column is their
// point: a JSON number is ALWAYS float64, never an int. Storing an int
// for `1` round-trips perfectly and diverges the moment anything reads
// the dynamic type or does arithmetic, so the value alone proves
// nothing.
//
// The `into_*` rows decode into an interface that ALREADY holds a
// value, which is six distinct behaviours in Go and where an
// implementation is most likely to be quietly wrong. `into_struct_part`
// is the one that pins the design: `{"x":1}` over a held `Point{9,9}`
// gives `{1 9}`, NOT `{1 0}` — Go copies the held value and decodes
// into the copy, so fields the document omits survive. A decoder that
// built a fresh zero would pass `into_struct_obj` identically and fail
// only here.
//
// `into_struct_*` needs `RegisterAnyUnmarshaler`, which unlike the
// marshal side is NOT emitted by `#[goish::reflect]`: it needs `Clone +
// PartialEq` to copy the held value and put it back, and a generated
// struct is not required to have either.
//
// GO[] comes from tools/gen_json_any_ref.go under
//   GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …
// with two columns RE-SPELLED, which is the one thing here that is not
// byte-for-byte Go and so is worth stating plainly:
//
//   type=  Go prints its own names — `[]interface {}`,
//          `map[string]interface {}`, `json_test.Point`. goish prints
//          Rust paths, so `go_type` maps them to `[]any`, `map`,
//          `Point`. The MEANING is identical and every row's type was
//          compared against Go's by hand; the spelling is not.
//   got=   Go prints `%v` (`{1 2}`, `map[k:1]`). This re-MARSHALS the
//          decoded value instead, which is a stronger check — it goes
//          back through the codec — but prints JSON, so `{1 9}` reads
//          as `{"x":1,"y":9}`.
//
// The Go transcript is in the generator's own output; run it to check
// the mapping rather than trusting this comment.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::v2::{self as json, MarshalerTo};
use goish::encoding::json::jsontext;
use goish::errors::error;
use goish::fmt;
use goish::gomap::map;
use goish::gostring::string;
use goish::types::int;
use goish::Any;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 27] = [
    "m_nil                err=false got=null",
    "m_bool               err=false got=true",
    "m_string             err=false got=\"hi\"",
    "m_float              err=false got=1.5",
    "m_int                err=false got=7",
    "m_slice              err=false got=[1,\"a\",null,true]",
    "m_map                err=false got={\"k\":1}",
    "m_nested             err=false got=[[1],{\"m\":[null]}]",
    "m_struct             err=false got={\"x\":1,\"y\":2}",
    "m_custom             err=false got=\"odd-3\"",
    "d_null               err=false type=<nil>      got=null",
    "d_true               err=false type=bool       got=true",
    "d_string             err=false type=string     got=\"hi\"",
    "d_int_lit            err=false type=float64    got=1",
    "d_float              err=false type=float64    got=1.5",
    "d_array              err=false type=[]any      got=[1,\"a\",null,true]",
    "d_object             err=false type=map        got={\"k\":1}",
    "d_nested             err=false type=[]any      got=[[1],{\"m\":[null]}]",
    "into_struct_obj      err=false type=Point      got={\"x\":1,\"y\":2}",
    "into_struct_part     err=false type=Point      got={\"x\":1,\"y\":9}",
    "into_struct_num      err=true  type=Point      got={\"x\":9,\"y\":9}",
    "into_string_num      err=true  type=string     got=\"old\"",
    "into_struct_null     err=false type=<nil>      got=null",
    "into_map_obj         err=false type=map        got={\"keep\":1,\"x\":1}",
    "into_slice_arr       err=false type=[]any      got=[9]",
    "cmd_roundtrip        err=false got={\"arguments\":[1,\"a\",null]}",
    "cmd_absent           err=false got={}",
];

#[goish::reflect]
#[derive(Default, Clone, PartialEq)]
struct Point {
    #[tag(r#"json:"x""#)]
    X: int,
    #[tag(r#"json:"y""#)]
    Y: int,
}

/// A type whose JSON form is nothing like its fields — Go's
/// `MarshalJSON` on a dynamically held value. Reachable only through
/// the interface, which is the case a downcast table cannot cover.
#[derive(Default, Clone, PartialEq)]
struct Odd(int);

impl MarshalerTo for Odd {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        return enc.WriteToken(jsontext::String(fmt::Sprintf!("odd-%d", self.0)));
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

fn row<T: MarshalerTo>(ln: &mut usize, name: &'static str, v: &T) {
    let (out, err) = json::Marshal(v, []);
    chk(
        ln,
        &fmt::Sprintf!(
            "%-20s err=%-5v got=%s",
            string::from_static(name),
            !err.IsNil(),
            string::from_bytes(out.as_ref())
        ),
    );
}

/// A decode row prints what Go's `%T` column does — the DYNAMIC type —
/// alongside the value re-marshaled, so a wrong type shows even when
/// the value looks right.
fn dec_row(ln: &mut usize, name: &'static str, doc: &[u8], dst: &mut Any) {
    let err = json::Unmarshal(doc, dst, []);
    let (out, merr) = json::Marshal(dst, []);
    let shown = if merr.IsNil() {
        string::from_bytes(out.as_ref())
    } else {
        string::from_static("<unmarshalable>")
    };
    chk(
        ln,
        &fmt::Sprintf!(
            "%-20s err=%-5v type=%-10s got=%s",
            string::from_static(name),
            !err.IsNil(),
            go_type(dst),
            shown
        ),
    );
}

/// Go's `%T` for the dynamic value, in Go's spelling rather than
/// Rust's path — the transcript says `float64`, not `f64`.
fn go_type(v: &Any) -> string {
    let t = fmt::Sprintf!("%T", v.clone());
    let s: &str = t.as_ref();
    return string::from_static(match s {
        "goish::nilval::Nil" => "<nil>",
        "bool" => "bool",
        "goish::gostring::string" => "string",
        "f64" => "float64",
        _ => {
            if goish::strings::Contains(&t, "slice") {
                "[]any"
            } else if goish::strings::Contains(&t, "map") {
                "map"
            } else if goish::strings::Contains(&t, "Point") {
                "Point"
            } else {
                "?"
            }
        }
    });
}

#[goish::reflect]
#[derive(Default, Clone, PartialEq)]
struct Command {
    #[tag(r#"json:"arguments,omitzero""#)]
    Arguments: Option<goish::slice<Any>>,
}

fn anyslice(items: alloc::vec::Vec<Any>) -> goish::slice<Any> {
    let mut s = goish::make!([]Any, 0);
    for it in items {
        s = goish::append!(s, it);
    }
    return s;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    row(&mut ln, "m_nil", &Any::default());
    row(&mut ln, "m_bool", &Any::new(true));
    row(&mut ln, "m_string", &Any::new(string::from_static("hi")));
    row(&mut ln, "m_float", &Any::new(1.5f64));
    row(&mut ln, "m_int", &Any::new(7i64));

    row(
        &mut ln,
        "m_slice",
        &Any::new(anyslice(alloc::vec![
            Any::new(1.0f64),
            Any::new(string::from_static("a")),
            Any::default(),
            Any::new(true),
        ])),
    );

    let mut mp: map<string, Any> = map::new();
    mp.Set(string::from_static("k"), Any::new(1.0f64));
    row(&mut ln, "m_map", &Any::new(mp));

    // [[1], {"m": [null]}]
    let inner = anyslice(alloc::vec![Any::new(1.0f64)]);
    let mut m2: map<string, Any> = map::new();
    m2.Set(
        string::from_static("m"),
        Any::new(anyslice(alloc::vec![Any::default()])),
    );
    row(
        &mut ln,
        "m_nested",
        &Any::new(anyslice(alloc::vec![Any::new(inner), Any::new(m2)])),
    );

    // No registration written anywhere for Point — the reflect macro
    // emitted one into .init_array.
    row(
        &mut ln,
        "m_struct",
        &Any::new(Point {
            X: int::from(1),
            Y: int::from(2),
        }),
    );

    // A hand-written codec has to say so. One line, and the error it
    // replaces names the exact type to add it for.
    json::RegisterAnyMarshaler::<Odd>();
    row(&mut ln, "m_custom", &Any::new_opaque(Odd(int::from(3))));

    // An unregistered type must FAIL, and the message must name it —
    // that is the difference between a one-line fix and a bisect.
    #[derive(Default, Clone, PartialEq)]
    struct Unknown(int);
    let (_, err) = json::Marshal(&Any::new_opaque(Unknown(int::from(1))), []);
    if err.IsNil() {
        fmt::Printf!("[!!] unregistered type marshaled without error\n");
        FAILED.fetch_add(1, Ordering::Relaxed);
    } else if goish::strings::Contains(&err.Error(), "Unknown") {
        fmt::Printf!("[ok] unregistered         names the type\n");
    } else {
        fmt::Printf!("[!!] unregistered error does not name the type: %s\n", err.Error());
        FAILED.fetch_add(1, Ordering::Relaxed);
    }

    // ── decode ─────────────────────────────────────────────────────
    for (name, doc) in [
        ("d_null", &b"null"[..]),
        ("d_true", &b"true"[..]),
        ("d_string", &b"\"hi\""[..]),
        ("d_int_lit", &b"1"[..]),
        ("d_float", &b"1.5"[..]),
        ("d_array", &b"[1,\"a\",null,true]"[..]),
        ("d_object", &b"{\"k\":1}"[..]),
        ("d_nested", &b"[[1],{\"m\":[null]}]"[..]),
    ] {
        let mut dst = Any::default();
        dec_row(&mut ln, name, doc, &mut dst);
    }

    // ── decode into a HELD value ───────────────────────────────────
    json::RegisterAnyUnmarshaler::<Point>();
    let held = || Point { X: int::from(9), Y: int::from(9) };
    let mut a = Any::new(held());
    dec_row(&mut ln, "into_struct_obj", b"{\"x\":1,\"y\":2}", &mut a);
    let mut a = Any::new(held());
    dec_row(&mut ln, "into_struct_part", b"{\"x\":1}", &mut a);
    let mut a = Any::new(held());
    dec_row(&mut ln, "into_struct_num", b"5", &mut a);
    let mut a = Any::new(string::from_static("old"));
    dec_row(&mut ln, "into_string_num", b"5", &mut a);
    let mut a = Any::new(held());
    dec_row(&mut ln, "into_struct_null", b"null", &mut a);
    let mut mp2: map<string, Any> = map::new();
    mp2.Set(string::from_static("keep"), Any::new(1.0f64));
    let mut a = Any::new(mp2);
    dec_row(&mut ln, "into_map_obj", b"{\"x\":1}", &mut a);
    let mut a = Any::new(anyslice(alloc::vec![
        Any::new(1.0f64),
        Any::new(2.0f64),
        Any::new(3.0f64)
    ]));
    dec_row(&mut ln, "into_slice_arr", b"[9]", &mut a);

    // The field the issue is blocked on, end to end.
    let mut cmd = Command::default();
    let err = json::Unmarshal(&b"{\"arguments\":[1,\"a\",null]}"[..], &mut cmd, []);
    let (out, _) = json::Marshal(&cmd, []);
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%-5v got=%s",
        string::from_static("cmd_roundtrip"), !err.IsNil(),
        string::from_bytes(out.as_ref())));
    let (out, err) = json::Marshal(&Command::default(), []);
    chk(&mut ln, &fmt::Sprintf!("%-20s err=%-5v got=%s",
        string::from_static("cmd_absent"), !err.IsNil(),
        string::from_bytes(out.as_ref())));

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
