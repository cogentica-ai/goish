// jsontext_pointer_ref_smoke — `Decoder.StackPointer()` token by token
// (issue #10).
//
// A decode error that cannot say WHERE it happened is the gap issue
// #10 is about, and every other requirement on it sits on this one: a
// consumer cannot reconstruct the pointer from the original bytes,
// because nested objects, arrays, escaped member names and streaming
// `UnmarshalDecode` all need decoder state.
//
// goish already built this pointer privately, for duplicate-name
// errors. What it did not do is expose it.
//
// The transcript prints the pointer after EVERY token because the
// happy path is not where a port goes wrong — the timing is:
//
//   after `{`        the parent; the frame is open but empty
//   after a NAME     already `/name`, before its value is read
//   after its value  still `/name`
//   after `}`        the parent again
//   after `[`        the parent; after the FIRST element `/0`
//
// So an array reports the index of the element just read, not the one
// coming next, and a freshly opened container reports its own position
// rather than anything inside it. Each of those is a place an
// off-by-one would still produce plausible-looking pointers.
//
// The `escape` rows are RFC 6901: `/` -> `~1` and `~` -> `~0`. Without
// them a member name containing `/` fakes a path separator and the
// error points at a field that does not exist.
//
// GO[] is the verbatim output of tools/gen_jsontext_pointer_ref.go
// under GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/jsontext,
// transcribed programmatically from the bytes rather than retyped.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::jsontext;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 44] = [
    "flat       {\"a\":1,\"b\":2}",
    "           start      ptr=\"\" depth=0",
    "           {          ptr=\"\" depth=1",
    "           a          ptr=\"/a\" depth=1",
    "           1          ptr=\"/a\" depth=1",
    "           b          ptr=\"/b\" depth=1",
    "           2          ptr=\"/b\" depth=1",
    "           }          ptr=\"\" depth=0",
    "nested     {\"a\":{\"b\":[10,20]}}",
    "           start      ptr=\"\" depth=0",
    "           {          ptr=\"\" depth=1",
    "           a          ptr=\"/a\" depth=1",
    "           {          ptr=\"/a\" depth=2",
    "           b          ptr=\"/a/b\" depth=2",
    "           [          ptr=\"/a/b\" depth=3",
    "           10         ptr=\"/a/b/0\" depth=3",
    "           20         ptr=\"/a/b/1\" depth=3",
    "           ]          ptr=\"/a/b\" depth=2",
    "           }          ptr=\"/a\" depth=1",
    "           }          ptr=\"\" depth=0",
    "array      [1,[2,3]]",
    "           start      ptr=\"\" depth=0",
    "           [          ptr=\"\" depth=1",
    "           1          ptr=\"/0\" depth=1",
    "           [          ptr=\"/1\" depth=2",
    "           2          ptr=\"/1/0\" depth=2",
    "           3          ptr=\"/1/1\" depth=2",
    "           ]          ptr=\"/1\" depth=1",
    "           ]          ptr=\"\" depth=0",
    "escape     {\"a/b\":1,\"c~d\":2}",
    "           start      ptr=\"\" depth=0",
    "           {          ptr=\"\" depth=1",
    "           a/b        ptr=\"/a~1b\" depth=1",
    "           1          ptr=\"/a~1b\" depth=1",
    "           c~d        ptr=\"/c~0d\" depth=1",
    "           2          ptr=\"/c~0d\" depth=1",
    "           }          ptr=\"\" depth=0",
    "root       5",
    "           start      ptr=\"\" depth=0",
    "           5          ptr=\"\" depth=0",
    "emptyobj   {}",
    "           start      ptr=\"\" depth=0",
    "           {          ptr=\"\" depth=1",
    "           }          ptr=\"\" depth=0",
];

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

fn walk(ln: &mut usize, label: &'static str, doc: &'static str) {
    let mut dec = jsontext::NewDecoder(
        goish::strings::NewReader(string::from_static(doc)),
        [],
    );
    chk(ln, &fmt::Sprintf!("%-10s %s", string::from_static(label), string::from_static(doc)));
    chk(
        ln,
        &fmt::Sprintf!(
            "           start      ptr=%q depth=%d",
            dec.StackPointer().String(),
            dec.StackDepth()
        ),
    );
    loop {
        let (tok, err) = dec.ReadToken();
        if !err.IsNil() {
            break;
        }
        chk(
            ln,
            &fmt::Sprintf!(
                "           %-10s ptr=%q depth=%d",
                tok.String(),
                dec.StackPointer().String(),
                dec.StackDepth()
            ),
        );
    }
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    walk(&mut ln, "flat", r#"{"a":1,"b":2}"#);
    walk(&mut ln, "nested", r#"{"a":{"b":[10,20]}}"#);
    walk(&mut ln, "array", "[1,[2,3]]");
    walk(&mut ln, "escape", r#"{"a/b":1,"c~d":2}"#);
    walk(&mut ln, "root", "5");
    walk(&mut ln, "emptyobj", "{}");

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
