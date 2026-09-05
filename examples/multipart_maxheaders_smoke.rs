// multipart_maxheaders_smoke — one part may not carry unbounded
// headers.
//
// Reference: Go 1.25.5 mime/multipart, tools/gen_multipart_headers_ref.go.
//
// Go bounds a part's headers at maxMIMEHeaders (multipart.go:355,
// default 10000) and answers ErrMessageTooLarge past it. goish's part
// parser had no bound at all: it looped adding to the Header map until
// the blank line, so ONE part could carry as many headers as the body
// had room for.
//
// The amplification is what makes that a defect rather than a
// curiosity. `a:b\r\n` is four bytes on the wire and becomes a map
// entry with a key string, a value slice and the map's own overhead —
// a large multiple. goish already caps parts at 1000, matching Go, so
// the ceiling was 1000 parts times unbounded headers where Go's is
// 1000 times 10000.
//
// The two middle rows straddle the boundary and are the point: 9998
// X-P headers plus the Content-Disposition is 9999 and passes, 10001
// plus one is 10002 and does not. A bound placed one off — counting
// before the add, or allowing 10001 — moves exactly one of them.
//
// Go's GODEBUG override (multipartmaxheaders) has nothing to read
// here: goish has no internal/godebug, so the default IS the value.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String;
use goish::gostring::string;
use goish::mime::multipart;
use goish::types::int;
use goish::fmt;

const GO: [&str; 4] = [
    "headers=5      ok values=1",
    "headers=9998   ok values=1",
    "headers=10001  err=multipart: message too large",
    "headers=50000  err=multipart: message too large",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
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
    for n in [5i64, 9998, 10001, 50000].iter() {
        let mut b = String::new();
        b.push_str("--B\r\n");
        b.push_str("Content-Disposition: form-data; name=\"f\"\r\n");
        for i in 0..*n {
            b.push_str("X-P");
            b.push_str(goish::strconv::Itoa(i).as_ref());
            b.push_str(": v\r\n");
        }
        b.push_str("\r\nBODY\r\n--B--\r\n");

        let mut r = multipart::NewReader(
            goish::goslice::slice::__from_vec(b.as_bytes().to_vec()),
            string::from("B"),
        );
        let (form, err) = r.ReadForm(1 << 20);
        if !err.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("headers=%-6d err=%v", *n, err));
            continue;
        }
        let vals = form.Value.Get(string::from("f")).0;
        chk(&mut ln, &fmt::Sprintf!("headers=%-6d ok values=%d", *n, goish::len(&vals)));
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
