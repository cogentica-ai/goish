// map_nil_write_probe — writing to a nil map must panic with Go's
// message (#7).
//
// A separate PROCESS because goish's `recover!()` does not resume
// execution, so a smoke cannot catch this and carry on. Driven by
// map_nil_ref_smoke, which asserts the exit status and the text;
// excluded from the e2e set because dying is the point.
//
// Go: "assignment to entry in nil map", measured in
// tools/gen_map_alias_ref.go (`nil_write_panic_msg`).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::map;
use goish::types::int;

#[goish::main]
fn main() {
    let mut z: map<string, int> = goish::nil.into();
    // Reads first, so a failure to panic below cannot be mistaken for
    // the process dying on something earlier.
    let (v, ok) = z.Get(string::from_static("missing"));
    fmt::Printf!("read v=%d ok=%v len=%d\n", v, ok, goish::len(&z));
    fmt::Println!("about to write to a nil map");
    z.Set(string::from_static("k"), 1);
    // Unreachable in Go.
    fmt::Println!("WROTE TO A NIL MAP WITHOUT PANICKING");
}
