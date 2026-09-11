// json_array_ref_smoke — a Go FIXED ARRAY under encoding/json/v2
// (issue #18).
//
// A slice takes whatever length the document has. An array's length is
// part of its type, so the codec has to decide what a disagreeing
// document means — and JSON v2 REJECTS both directions, which is the
// opposite of v1, where a short array left the tail zeroed and a long
// one dropped the excess. A port that reused the slice codec would
// accept both silently, which is why every length row below is here.
//
// The `got=` column is the point of the file. After a rejection the
// destination is not untouched and not left alone:
//
//   [1]     into [2]uint32  ->  error, and the array is [1 0]
//   [1,2,3] into [2]uint32  ->  error, and the array is [1 2]
//   []      into [2]uint32  ->  error, and the array is [0 0]
//   "x"     into [2]uint32  ->  error, and the array is UNTOUCHED
//
// So committing to the array branch zeroes the destination; a wrong
// outer KIND never touches it. Every destination below starts at
// {7,8} so the difference is visible rather than indistinguishable
// from a zero value. `null` is the other surprise: not an error, and
// not a no-op — it zeroes.
//
// NOT asserted: the error TEXT. Go says
//   "json: unable to unmarshal JSON array into Go [2]uint32 after
//    offset 2: too few array elements"
// and goish says "json: too few array elements". That gap is issue
// #10 (JSON Pointer and Go type in semantic errors) and belongs to
// it; pinning the text here would make this file fail for that
// reason instead.
//
// GO[] is the output of tools/gen_json_array_ref.go under
//   GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 …
// with the two err_* text lines dropped for the reason above.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::encoding::json::v2 as json;
use goish::fmt;
use goish::gostring::string;
use goish::types::{int, uint32};
use goish::array;

static FAILED: AtomicUsize = AtomicUsize::new(0);

const GO: [&str; 15] = [
    "marshal_2      [0 4]        err=false got=[0,4]",
    "marshal_0      []           err=false got=[]",
    "dec_2          [0,4]        err=false got=[0 4]",
    "dec_2          [1]          err=true  got=[1 0]",
    "dec_2          [1,2,3]      err=true  got=[1 2]",
    "dec_2          null         err=false got=[0 0]",
    "dec_2          []           err=true  got=[0 0]",
    "dec_2          \"x\"          err=true  got=[7 8]",
    "dec_2          {}           err=true  got=[7 8]",
    "dec_2          [1,\"a\"]      err=true  got=[1 0]",
    "dec_0          []           err=false got=[]",
    "dec_0          [1]          err=true  got=[]",
    "dec_0          null         err=false got=[]",
    "dec_ptr        [9,10]       err=false got=[9 10]",
    "dec_nested     [[1,2],[3,4]] err=false got=[[1 2] [3 4]]",
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

/// `[a b]` — Go's `%v` for an array, which is what the reference
/// transcript prints.
fn show2(a: &array<uint32, 2>) -> string {
    return fmt::Sprintf!("[%d %d]", a[0], a[1]);
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let input: array<uint32, 2> = goish::array!([2]uint32{0u32, 4u32});
    let (data, err) = json::Marshal(&input, []);
    chk(&mut ln, &fmt::Sprintf!("%-14s %-12s err=%-5v got=%s",
        string::from_static("marshal_2"), string::from_static("[0 4]"),
        !err.IsNil(), string::from_bytes(data.as_ref())));

    let zero: array<uint32, 0> = goish::array!([0]uint32);
    let (data, err) = json::Marshal(&zero, []);
    chk(&mut ln, &fmt::Sprintf!("%-14s %-12s err=%-5v got=%s",
        string::from_static("marshal_0"), string::from_static("[]"),
        !err.IsNil(), string::from_bytes(data.as_ref())));

    for input in [
        &b"[0,4]"[..], &b"[1]"[..], &b"[1,2,3]"[..], &b"null"[..],
        &b"[]"[..], &b"\"x\""[..], &b"{}"[..], &b"[1,\"a\"]"[..],
    ] {
        let mut got: array<uint32, 2> = goish::array!([2]uint32{7u32, 8u32});
        let err = json::Unmarshal(input, &mut got, []);
        chk(&mut ln, &fmt::Sprintf!("%-14s %-12s err=%-5v got=%s",
            string::from_static("dec_2"), string::from_bytes(input),
            !err.IsNil(), show2(&got)));
    }

    for input in [&b"[]"[..], &b"[1]"[..], &b"null"[..]] {
        let mut got: array<uint32, 0> = goish::array!([0]uint32);
        let err = json::Unmarshal(input, &mut got, []);
        chk(&mut ln, &fmt::Sprintf!("%-14s %-12s err=%-5v got=[]",
            string::from_static("dec_0"), string::from_bytes(input),
            !err.IsNil()));
    }

    // The shape the downstream union actually holds it in.
    let mut p: Option<array<uint32, 2>> = None;
    let err = json::Unmarshal(&b"[9,10]"[..], &mut p, []);
    let shown = match &p {
        Some(a) => show2(a),
        None => string::from_static("<nil>"),
    };
    chk(&mut ln, &fmt::Sprintf!("%-14s %-12s err=%-5v got=%s",
        string::from_static("dec_ptr"), string::from_static("[9,10]"),
        !err.IsNil(), shown));

    let mut nested: array<array<uint32, 2>, 2> = Default::default();
    let err = json::Unmarshal(&b"[[1,2],[3,4]]"[..], &mut nested, []);
    chk(&mut ln, &fmt::Sprintf!("%-14s %-12s err=%-5v got=[%s %s]",
        string::from_static("dec_nested"), string::from_static("[[1,2],[3,4]]"),
        !err.IsNil(), show2(&nested[0]), show2(&nested[1])));

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
