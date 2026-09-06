// jsontext_utf8_ref_smoke — a JSON string must be valid UTF-8, against
// Go 1.25.5 (GOEXPERIMENT=jsonv2).
//
// RFC 7493 §2.1 and RFC 8259 §8.1 require it, and Go rejects invalid
// UTF-8 unless AllowInvalidUTF8 is set — its doc says the option
// "causes the encoder or decoder to break compliance" with both RFCs
// (jsontext/options.go:62-65).
//
// goish stored that option and never read it. The field was set,
// merged and ignored, so the decoder behaved as AllowInvalidUTF8(true)
// unconditionally: every malformed sequence passed through. The file
// header called this a "v1 simplification" on the grounds that the
// target workload sets the option globally — the same reasoning the
// same note already records as WRONG once, for AllowDuplicateNames,
// where a repeated key was being accepted where tsc rejects it.
//
// What it costs is a parser differential: a document goish accepts and
// Go refuses. That matters most where goish validates or forwards JSON
// to something written in Go, which is the usual reason to have a
// syntax layer at all.
//
// Each input is run twice, with the option off and on, because the
// off/on pair is what distinguishes "validates" from "rejects
// everything". The four malformed cases are the standard families —
// a lone continuation byte, a truncated two-byte sequence, a raw
// surrogate half, and an overlong encoding — since a validator that
// catches only one of them is a validator that can be walked around.
//
// Reference: tools/gen_jsontext_utf8_ref.go via scripts/goref.sh with
// GOEXPERIMENT=jsonv2 (the package is behind that experiment in 1.25).

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::encoding::json::jsontext;
use goish::gostring::string;
use goish::{bytes, fmt};

const GO: [&str; 14] = [
    "plain-ascii          allow=false ok",
    "plain-ascii          allow=true  ok",
    "valid-utf8           allow=false ok",
    "valid-utf8           allow=true  ok",
    "lone-continuation    allow=false ERR",
    "lone-continuation    allow=true  ok",
    "truncated-2byte      allow=false ERR",
    "truncated-2byte      allow=true  ok",
    "surrogate-half-raw   allow=false ERR",
    "surrogate-half-raw   allow=true  ok",
    "overlong             allow=false ERR",
    "overlong             allow=true  ok",
    "escaped-ok           allow=false ok",
    "escaped-ok           allow=true  ok",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let cases: [(&str, &[u8]); 7] = [
        ("plain-ascii", b"{\"a\":\"hello\"}"),
        ("valid-utf8", b"{\"a\":\"h\xc3\xa9llo\"}"),
        ("lone-continuation", b"{\"a\":\"h\x80llo\"}"),
        ("truncated-2byte", b"{\"a\":\"h\xc3\"}"),
        ("surrogate-half-raw", b"{\"a\":\"\xed\xa0\x80\"}"),
        ("overlong", b"{\"a\":\"\xc0\xaf\"}"),
        ("escaped-ok", "{\"a\":\"é\"}".as_bytes()),
    ];
    for (name, raw) in cases.iter() {
        for allow in [false, true].iter() {
            let rdr = bytes::NewReader(goish::slice::<goish::byte>::__from_vec(raw.to_vec()));
            let mut opts: Vec<jsontext::Options> = Vec::new();
            if *allow {
                opts.push(jsontext::AllowInvalidUTF8(true));
            }
            let mut d = jsontext::NewDecoder(rdr, &opts);
            let mut bad = false;
            loop {
                let (_, e) = d.ReadToken();
                if !e.IsNil() {
                    let em = e.Error();
                    let es: &str = em.as_ref();
                    if es != "EOF" { bad = true; }
                    break;
                }
            }
            chk(&mut ln, &fmt::Sprintf!("%-20s allow=%-5v %s", string::from(*name), *allow,
                string::from(if bad { "ERR" } else { "ok" })));
        }
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
    }
    goish::os::Exit(0);
}
