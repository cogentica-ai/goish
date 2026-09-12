// json_marshal_error_ref_smoke — partial bytes and the error text when
// a marshaler fails mid-object (issue #13, and #10's encoder half).
//
// Two separate contracts, and the issue is filed about the first:
//
//   1. WHAT BYTES COME BACK. Go returns the prefix the encoder already
//      accepted, so a caller can see how far it got — the member name
//      is written, its value is not:
//
//          {"jsonrpc":"2.0","method":"test/deferred","params"
//
//   2. WHAT THE ERROR SAYS. `json: cannot marshal from Go T within
//      "/params": <cause>`. Note `from Go`, not `into Go`, and no JSON
//      kind — nothing arrived. Go's SemanticError carries an `action`
//      field for exactly this, so goish's does too rather than
//      special-casing the wording at one call site.
//
// (1) already held. (2) needed `Encoder::StackPointer`, which in turn
// needed the encoder to remember member names as it writes them — the
// decoder had that field, the encoder did not.
//
// The `enc_*` rows walk an encoder token by token, for the same reason
// the decoder's pointer smoke does: the timing is what a port gets
// wrong, and it comes out identical on both sides —
//
//   after `{`       the parent
//   after a NAME    already `/name`
//   after its value still `/name`
//   after `[`       the parent; after the first element `/0`
//
// `is` is pinned because it is what makes the error usable: the cause
// keeps its identity through the wrap, so a caller routes on the
// sentinel AND reports the member.
//
// GO[] is from tools/gen_json_marshalerr_ref.go under
//   GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …
// The Go type name in the error is whatever the marshaler passes, so
// this says `lsproto.Params` where the generator said
// `json_test.Failing`.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::jsontext;
use goish::encoding::json::v2 as json;
use goish::errors::{self, error, nil};
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 14] = [
    "bytes  {\"jsonrpc\":\"2.0\",\"method\":\"test/deferred\",\"params\"",
    "err    json: cannot marshal from Go lsproto.Params within \"/params\": deferred params failure",
    "is     true",
    "enc start      ptr=\"\" depth=0",
    "enc {          ptr=\"\" depth=1",
    "enc a          ptr=\"/a\" depth=1",
    "enc 1          ptr=\"/a\" depth=1",
    "enc b          ptr=\"/b\" depth=1",
    "enc [          ptr=\"/b\" depth=2",
    "enc 7          ptr=\"/b/0\" depth=2",
    "enc ]          ptr=\"/b\" depth=1",
    "enc }          ptr=\"\" depth=0",
    // A string VALUE must not be mistaken for a member name. This row
    // exists because perturbing the name-position test to "record
    // every string" broke NOTHING in the rows above — in a normal
    // object every value is followed by the next name before anyone
    // reads the pointer, so the bug is invisible until the last thing
    // written is a value. Then `/a` becomes `/x`.
    "enc strval     ptr=\"/a\" depth=1",
    "nested_err    json: cannot marshal from Go lsproto.Params within \"/a/params\": deferred params failure",
];

/// A package-level sentinel, the way a Go package exports
/// `var ErrX = errors.New(...)`.
static SENT: goish::sync::Mutex<Option<error>> = goish::sync::Mutex::new(None);
fn err_deferred() -> error {
    let mut g = SENT.Lock();
    if g.is_none() {
        *g = Some(errors::New(string::from_static("deferred params failure")));
    }
    return g.as_ref().unwrap().clone();
}

/// A params value whose marshaler fails, asking the runtime to attach
/// the type and the pointer.
#[derive(Default, Clone, PartialEq)]
struct Failing;

impl json::MarshalerTo for Failing {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        return json::NewMarshalSemanticError(
            enc,
            string::from_static("lsproto.Params"),
            err_deferred(),
        );
    }
}

/// The hand-written request marshaler from the issue: head, then the
/// params value that fails.
struct Request;

impl json::MarshalerTo for Request {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        let _ = enc.WriteToken(jsontext::BeginObject);
        let _ = enc.WriteToken(jsontext::String(string::from_static("jsonrpc")));
        let _ = enc.WriteToken(jsontext::String(string::from_static("2.0")));
        let _ = enc.WriteToken(jsontext::String(string::from_static("method")));
        let _ = enc.WriteToken(jsontext::String(string::from_static("test/deferred")));
        let _ = enc.WriteToken(jsontext::String(string::from_static("params")));
        return Failing.MarshalJSONTo(enc);
    }
}

/// One level deeper, so the pointer has to grow: `/a/params`.
struct Outer;

impl json::MarshalerTo for Outer {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> error {
        let _ = enc.WriteToken(jsontext::BeginObject);
        let _ = enc.WriteToken(jsontext::String(string::from_static("a")));
        return Request.MarshalJSONTo(enc);
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

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let (out, err) = json::Marshal(&Request, []);
    chk(
        &mut ln,
        &fmt::Sprintf!("bytes  %s", string::from_bytes(out.as_ref())),
    );
    chk(&mut ln, &fmt::Sprintf!("err    %s", err.Error()));
    chk(
        &mut ln,
        &fmt::Sprintf!("is     %v", errors::Is(err, err_deferred())),
    );

    // Encoder.StackPointer, token by token.
    let sink = goish::bytes::Buffer::default();
    let mut enc = jsontext::NewEncoder(sink, []);
    macro_rules! show {
        ($what:expr) => {
            chk(
                &mut ln,
                &fmt::Sprintf!(
                    "enc %-10s ptr=%q depth=%d",
                    string::from_static($what),
                    enc.StackPointer().String(),
                    enc.StackDepth()
                ),
            )
        };
    }
    show!("start");
    let _ = enc.WriteToken(jsontext::BeginObject);
    show!("{");
    let _ = enc.WriteToken(jsontext::String(string::from_static("a")));
    show!("a");
    let _ = enc.WriteToken(jsontext::Int(int::from(1)));
    show!("1");
    let _ = enc.WriteToken(jsontext::String(string::from_static("b")));
    show!("b");
    let _ = enc.WriteToken(jsontext::BeginArray);
    show!("[");
    let _ = enc.WriteToken(jsontext::Int(int::from(7)));
    show!("7");
    let _ = enc.WriteToken(jsontext::EndArray);
    show!("]");
    let _ = enc.WriteToken(jsontext::EndObject);
    show!("}");

    // A string value is not a name.
    let sink2 = goish::bytes::Buffer::default();
    let mut enc2 = jsontext::NewEncoder(sink2, []);
    let _ = enc2.WriteToken(jsontext::BeginObject);
    let _ = enc2.WriteToken(jsontext::String(string::from_static("a")));
    let _ = enc2.WriteToken(jsontext::String(string::from_static("x")));
    chk(
        &mut ln,
        &fmt::Sprintf!(
            "enc %-10s ptr=%q depth=%d",
            string::from_static("strval"),
            enc2.StackPointer().String(),
            enc2.StackDepth()
        ),
    );

    // Nested: the pointer grows with the frames.
    let (_, err) = json::Marshal(&Outer, []);
    chk(&mut ln, &fmt::Sprintf!("nested_err    %s", err.Error()));

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
