// json_depth_limit_smoke — a JSON document may not decide how deep
// this process recurses.
//
// TWO parsers, two limits, and they are DIFFERENT NUMBERS on purpose. `jsontext` is the token layer and
// `encoding/json` the semantic one, each with its own recursive
// descent and each unbounded before this. Fixing one said nothing
// about the other, which is why both are pinned here: the second was
// found by asking whether the first was the only place.
//
// jsontext refuses past 10000, which is Go's number for it. The v1
// parser refuses past 2000, which is NOT Go's 10000, and the reason is
// measured rather than chosen: Go's v1 scanner keeps an explicit
// parseState stack and does not recurse, while this one does, so its
// own ceiling in a debug build on an 8 MiB stack is near 8200 — below
// Go's limit. A limit of 10000 there would mean a document Go accepts
// crashes the process. See the constant in encoding/json/mod.rs for
// the measurements and ROADMAP.md for the real fix.
//
// `jsontext`'s `scan_whole_value` recursed once per nested composite
// with NO limit, so a document made of nothing but `[` chose the stack
// depth. Measured before the fix: 100000 parsed fine, 500000 printed
//
//     goish: runtime error: stack overflow
//
// The runtime catches it and prints a diagnostic rather than
// corrupting anything, but the process is gone either way, and roughly
// a megabyte of open brackets does it to any program parsing untrusted
// JSON.
//
// Go caps at maxNestingDepth = 10000 (jsontext/state.go:53) and
// returns errMaxDepth. The boundary here was MEASURED against a
// running Go 1.25.5 rather than derived: 10000 nested arrays parse,
// 10001 does not, and an earlier version of the fix refused one level
// too late.
//
// One deliberate difference, not hidden: Go's message wraps errMaxDepth
// with a JSON pointer and byte offset —
//
//     jsontext: exceeded max depth within "/0/0/…" after offset 10000
//
// — which this layer has no pointer tracking to reproduce. goish
// returns the bare "exceeded max depth". The boundary is what this
// file pins.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::encoding::json::jsontext;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int};


fn nested(n: usize) -> Vec<byte> {
    let mut v: Vec<byte> = Vec::new();
    for _ in 0..n { v.push(b'['); }
    for _ in 0..n { v.push(b']'); }
    return v;
}

const GO: [&str; 11] = [
    "depth=10     len=20 err=<nil>",
    "depth=1000   len=2000 err=<nil>",
    "depth=9999   len=19998 err=<nil>",
    "depth=10000  len=20000 err=<nil>",
    "depth=10001  len=0 err=exceeded max depth",
    "depth=500000 len=0 err=exceeded max depth",
    "v1 depth=10     err=<nil>",
    "v1 depth=1999   err=<nil>",
    "v1 depth=2000   err=<nil>",
    "v1 depth=2001   err=invalid character '[' exceeded max depth",
    "v1 depth=500000 err=invalid character '[' exceeded max depth",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    for n in [10usize, 1000, 9999, 10000, 10001, 500000].iter() {
        let data = nested(*n);
        let src = bytes::NewReader(slice::__from_vec(data));
        let mut d = jsontext::NewDecoder(src, []);
        let (v, err) = d.ReadValue();
        chk(&mut ln, &fmt::Sprintf!("depth=%-6d len=%d err=%v", *n as int, v.Len() as int, err));
    }
    // The v1 semantic layer has its OWN parser and its own limit
    // (encoding/json/scanner.go:148), and it recursed unbounded too.
    for n in [10usize, 1999, 2000, 2001, 500000].iter() {
        let data = nested(*n);
        let mut v = goish::encoding::json::Value::default();
        let err = goish::encoding::json::Unmarshal(&data, &mut v);
        chk(&mut ln, &fmt::Sprintf!("v1 depth=%-6d err=%v", *n as int, err));
    }

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
