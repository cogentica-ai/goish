// json_any_marshal_ref_smoke — marshaling `goish::Any` (Go's
// `interface{}`) under encoding/json/v2. Issue #15, marshal half.
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
// NOT here, and both tracked in ROADMAP §2s with issue #15 left open:
//
//   - the UNMARSHAL half, the larger one — decoding into an interface
//     that already holds a value is six distinct behaviours in Go.
//   - `Command.Arguments *[]any` itself. A `#[goish::reflect]` struct
//     with an `Option<slice<Any>>` field still does not compile,
//     because the macro also emits the v1 codec and that needs
//     `Any: encoding::json::FromValue`. The v2 codec landing does not
//     reach it, which is worth knowing before anyone reads this file
//     as "the blocked field works now".
//
// GO[] is the marshal half of tools/gen_json_any_ref.go under
//   GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …

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

const GO: [&str; 10] = [
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
