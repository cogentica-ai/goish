// url.Values Get/Set/Add/Del/Has against Go 1.25.5.
// Expected values from a goref run.
//
// The distinctions worth pinning:
//   Set REPLACES the value list; Add APPENDS to it
//   Get returns the FIRST value, ignoring the rest
//   Get cannot tell absent from present-but-empty — a key mapped to
//   an EMPTY slice has Get()=="" but Has()==true
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::net::http::url;
use goish::{fmt, slice, string, syscall};

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", want);
        *bad += 1;
    }
}

fn eqb(got: bool, want: bool, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        *bad += 1;
    }
}

fn joined(v: &map<string, slice<string>>, k: &'static str) -> string {
    let (vs, _) = v.Get(string(k));
    let mut out = string::new();
    for i in 0..vs.len() {
        if i > 0 {
            out = out + string(",");
        }
        out = out + vs[i].clone();
    }
    return out;
}

#[goish::main]
fn main() {
    let mut bad = 0i32;
    let mut v: map<string, slice<string>> = map::new();

    eq(url::ValuesGet(&v, string("a")), "", "empty Get", &mut bad);
    eqb(url::ValuesHas(&v, string("a")), false, "empty Has", &mut bad);

    url::ValuesSet(&mut v, string("a"), string("1"));
    eq(url::ValuesGet(&v, string("a")), "1", "after Set", &mut bad);
    eqb(url::ValuesHas(&v, string("a")), true, "Has after Set", &mut bad);
    eq(joined(&v, "a"), "1", "list after Set", &mut bad);

    // Add APPENDS; Get still returns the first.
    url::ValuesAdd(&mut v, string("a"), string("2"));
    eq(url::ValuesGet(&v, string("a")), "1", "Get after Add is first", &mut bad);
    eq(joined(&v, "a"), "1,2", "list after Add", &mut bad);

    // Set REPLACES the whole list.
    url::ValuesSet(&mut v, string("a"), string("3"));
    eq(joined(&v, "a"), "3", "Set replaces", &mut bad);

    url::ValuesAdd(&mut v, string("b"), string("x"));
    eq(url::ValuesEncode(v.clone()), "a=3&b=x", "encode", &mut bad);

    url::ValuesDel(&mut v, string("a"));
    eq(url::ValuesGet(&v, string("a")), "", "Get after Del", &mut bad);
    eqb(url::ValuesHas(&v, string("a")), false, "Has after Del", &mut bad);
    eq(url::ValuesEncode(v.clone()), "b=x", "encode after Del", &mut bad);

    // present-but-empty: Get is "" but Has is TRUE.
    {
        let mut v2: map<string, slice<string>> = map::new();
        v2.Set(string("e"), slice::<string>::new());
        eq(url::ValuesGet(&v2, string("e")), "", "empty slice Get", &mut bad);
        eqb(url::ValuesHas(&v2, string("e")), true, "empty slice Has", &mut bad);
    }

    if bad == 0 {
        fmt::Println!("URL_VALUES_OK 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
