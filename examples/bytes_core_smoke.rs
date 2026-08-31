// bytes_core_smoke — the free functions of bytes.go against a running Go.
// (bytes/bytes.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_bytes_core_ref.go` run in
// `package bytes_test` by `scripts/goref.sh`, converted to byte
// literals so nothing depends on goish's own `%q`.
//
// These functions were "covered" by a name match long before anything
// checked what they returned — they lived unanchored in the module root
// while `Replacer` and the cutset trims, two files over, turned out to
// be wrong. The vectors are picked for the places a byte-wise port and
// a rune-wise one disagree: an empty separator (which splits into
// runes, not bytes, and makes Count the rune count plus one), a
// separator longer than the input, a lone continuation byte, an
// overlapping needle, a negative or zero `n`, and the boundary between
// "found at 0" and "not found".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::{byte, int, rune};
use goish::unicode;

fn sl(b: &[u8]) -> slice<byte> {
    return slice::<byte>::__from_vec(b.to_vec());
}

fn raw(s: &slice<byte>) -> Vec<byte> {
    let r: &[byte] = s;
    return r.to_vec();
}

fn rawlist(s: &slice<slice<byte>>) -> Vec<Vec<byte>> {
    let mut out: Vec<Vec<byte>> = Vec::new();
    let mut i: int = 0;
    while i < s.Len() {
        out.push(raw(&s[i as usize]));
        i += 1;
    }
    return out;
}

fn same(got: &Vec<Vec<byte>>, want: &[&[u8]]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    let mut i = 0usize;
    while i < got.len() {
        if got[i].as_slice() != want[i] {
            return false;
        }
        i += 1;
    }
    return true;
}

const IDX: [(&[u8], &[u8], int, int, int, bool, bool, bool); 13] = [
    (b"", b"", 0, 0, 1, true, true, true),
    (b"", b"\x61", -1, -1, 0, false, false, false),
    (b"\x61", b"", 0, 1, 2, true, true, true),
    (b"\x61\x62\x63", b"\x62", 1, 1, 1, true, false, false),
    (b"\x61\x62\x63", b"\x61\x62\x63", 0, 0, 1, true, true, true),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        -1,
        -1,
        0,
        false,
        false,
        false,
    ),
    (b"\x61\x61\x61", b"\x61\x61", 0, 1, 1, true, true, true),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        1,
        3,
        1,
        true,
        false,
        true,
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        1,
        1,
        1,
        true,
        false,
        false,
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        1,
        1,
        1,
        true,
        false,
        false,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        3,
        3,
        1,
        true,
        false,
        false,
    ),
    (b"\xff\xfe", b"\xfe", 1, 1, 1, true, false, true),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        2,
        5,
        2,
        true,
        false,
        true,
    ),
];

const CUT: [(&[u8], &[u8], &[u8], &[u8], bool, &[u8], bool, &[u8], bool); 13] = [
    (b"", b"", b"", b"", true, b"", true, b"", true),
    (b"", b"\x61", b"", b"", false, b"", false, b"", false),
    (
        b"\x61", b"", b"", b"\x61", true, b"\x61", true, b"\x61", true,
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        b"\x61",
        b"\x63",
        true,
        b"\x61\x62\x63",
        false,
        b"\x61\x62\x63",
        false,
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        b"",
        b"",
        true,
        b"",
        true,
        b"",
        true,
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        b"\x61\x62\x63",
        b"",
        false,
        b"\x61\x62\x63",
        false,
        b"\x61\x62\x63",
        false,
    ),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        b"",
        b"\x61",
        true,
        b"\x61",
        true,
        b"\x61",
        true,
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x62",
        b"\x6e\x61",
        true,
        b"\x62\x61\x6e\x61\x6e\x61",
        false,
        b"\x62\x61\x6e",
        true,
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        b"\x68",
        b"\x6c\x6c\x6f",
        true,
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        false,
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        false,
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        b"\x68",
        b"\xa9\x6c\x6c\x6f",
        true,
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        false,
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        false,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        b"\xe6\x97\xa5",
        b"\xe8\xaa\x9e",
        true,
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        false,
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        false,
    ),
    (
        b"\xff\xfe",
        b"\xfe",
        b"\xff",
        b"",
        true,
        b"\xff\xfe",
        false,
        b"\xff",
        true,
    ),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        b"\x61\x62",
        b"\x61\x62\x63",
        true,
        b"\x61\x62\x63\x61\x62\x63",
        false,
        b"\x61\x62\x63\x61\x62",
        true,
    ),
];

const EQ: [(&[u8], &[u8], bool, bool, int); 13] = [
    (b"", b"", true, true, 0),
    (b"", b"\x61", false, false, -1),
    (b"\x61", b"", false, false, 1),
    (b"\x61\x62\x63", b"\x62", false, false, -1),
    (b"\x61\x62\x63", b"\x61\x62\x63", true, true, 0),
    (b"\x61\x62\x63", b"\x61\x62\x63\x64", false, false, -1),
    (b"\x61\x61\x61", b"\x61\x61", false, false, 1),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        false,
        false,
        1,
    ),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xc3\xa9", false, false, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xc3", false, false, -1),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        false,
        false,
        -1,
    ),
    (b"\xff\xfe", b"\xfe", false, false, 1),
    (b"\x61\x62\x63\x61\x62\x63", b"\x63", false, false, -1),
];

const FOLD: [(&[u8], &[u8], bool); 9] = [
    (b"\x47\x6f", b"\x47\x4f", true),
    (b"\xc3\x9f", b"\x73\x73", false),
    (b"\x4b", b"\xe2\x84\xaa", true),
    (b"\xcf\x83", b"\xce\xa3", true),
    (b"\xcf\x83", b"\xcf\x82", true),
    (b"\xc4\xb0", b"\x69", false),
    (b"\xc4\xb1", b"\x49", false),
    (b"\xff", b"\xff", true),
    (b"\x61\xff\x62", b"\x41\xff\x42", true),
];

const IBYTE: [(&[u8], byte, int, int); 20] = [
    (b"", 0x61, -1, -1),
    (b"", 0x62, -1, -1),
    (b"", 0xff, -1, -1),
    (b"", 0xc3, -1, -1),
    (b"\x61\x62\x63", 0x61, 0, 0),
    (b"\x61\x62\x63", 0x62, 1, 1),
    (b"\x61\x62\x63", 0xff, -1, -1),
    (b"\x61\x62\x63", 0xc3, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 0x61, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 0x62, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 0xff, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 0xc3, 1, 1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 0x61, -1, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 0x62, -1, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 0xff, -1, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 0xc3, -1, -1),
    (b"\xff\xfe", 0x61, -1, -1),
    (b"\xff\xfe", 0x62, -1, -1),
    (b"\xff\xfe", 0xff, 0, 0),
    (b"\xff\xfe", 0xc3, -1, -1),
];

const IRUNE: [(&[u8], rune, int); 30] = [
    (b"", 97, -1),
    (b"", 233, -1),
    (b"", 26412, -1),
    (b"", 65533, -1),
    (b"", -1, -1),
    (b"", 1114112, -1),
    (b"\x61\x62\x63", 97, 0),
    (b"\x61\x62\x63", 233, -1),
    (b"\x61\x62\x63", 26412, -1),
    (b"\x61\x62\x63", 65533, -1),
    (b"\x61\x62\x63", -1, -1),
    (b"\x61\x62\x63", 1114112, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 97, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 233, 1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 26412, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 65533, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", 1114112, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 97, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 233, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 26412, 3),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 65533, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", -1, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", 1114112, -1),
    (b"\xff\xfe", 97, -1),
    (b"\xff\xfe", 233, -1),
    (b"\xff\xfe", 26412, -1),
    (b"\xff\xfe", 65533, 0),
    (b"\xff\xfe", -1, -1),
    (b"\xff\xfe", 1114112, -1),
];

const ANY: [(&[u8], &[u8], bool, int, int); 42] = [
    (b"", b"", false, -1, -1),
    (b"", b"\x61", false, -1, -1),
    (b"", b"\x78\x79\x7a", false, -1, -1),
    (b"", b"\xc3\xa9", false, -1, -1),
    (b"", b"\xe6\x9c\xac\xe8\xaa\x9e", false, -1, -1),
    (b"", b"\xef\xbf\xbd", false, -1, -1),
    (b"", b"\xff", false, -1, -1),
    (b"\x61\x62\x63", b"", false, -1, -1),
    (b"\x61\x62\x63", b"\x61", true, 0, 0),
    (b"\x61\x62\x63", b"\x78\x79\x7a", false, -1, -1),
    (b"\x61\x62\x63", b"\xc3\xa9", false, -1, -1),
    (b"\x61\x62\x63", b"\xe6\x9c\xac\xe8\xaa\x9e", false, -1, -1),
    (b"\x61\x62\x63", b"\xef\xbf\xbd", false, -1, -1),
    (b"\x61\x62\x63", b"\xff", false, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"", false, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\x61", false, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\x78\x79\x7a", false, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xc3\xa9", true, 1, 1),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xe6\x9c\xac\xe8\xaa\x9e",
        false,
        -1,
        -1,
    ),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xef\xbf\xbd", false, -1, -1),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xff", false, -1, -1),
    (b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", b"", false, -1, -1),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\x61",
        false,
        -1,
        -1,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\x78\x79\x7a",
        false,
        -1,
        -1,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xc3\xa9",
        false,
        -1,
        -1,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac\xe8\xaa\x9e",
        true,
        3,
        6,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xef\xbf\xbd",
        false,
        -1,
        -1,
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xff",
        false,
        -1,
        -1,
    ),
    (b"\xff\xfe", b"", false, -1, -1),
    (b"\xff\xfe", b"\x61", false, -1, -1),
    (b"\xff\xfe", b"\x78\x79\x7a", false, -1, -1),
    (b"\xff\xfe", b"\xc3\xa9", false, -1, -1),
    (b"\xff\xfe", b"\xe6\x9c\xac\xe8\xaa\x9e", false, -1, -1),
    (b"\xff\xfe", b"\xef\xbf\xbd", true, 0, 1),
    (b"\xff\xfe", b"\xff", true, 0, 1),
    (b"\x61\xff\x62", b"", false, -1, -1),
    (b"\x61\xff\x62", b"\x61", true, 0, 0),
    (b"\x61\xff\x62", b"\x78\x79\x7a", false, -1, -1),
    (b"\x61\xff\x62", b"\xc3\xa9", false, -1, -1),
    (b"\x61\xff\x62", b"\xe6\x9c\xac\xe8\xaa\x9e", false, -1, -1),
    (b"\x61\xff\x62", b"\xef\xbf\xbd", true, 1, 1),
    (b"\x61\xff\x62", b"\xff", true, 1, 1),
];

const FUNC: [(&[u8], int, int, bool, bool); 6] = [
    (b"", -1, -1, false, false),
    (b"\x61\x62\x63", -1, -1, false, false),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", -1, -1, false, true),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        -1,
        -1,
        false,
        false,
    ),
    (b"\xff\xfe", -1, -1, false, false),
    (b"\x61\xff\x62", -1, -1, false, false),
];

const SPLITN: [(&[u8], &[u8], int, &[&[u8]], &[&[u8]]); 78] = [
    (b"", b"", -1, &[], &[]),
    (b"", b"", 0, &[], &[]),
    (b"", b"", 1, &[], &[]),
    (b"", b"", 2, &[], &[]),
    (b"", b"", 3, &[], &[]),
    (b"", b"", 100, &[], &[]),
    (b"", b"\x61", -1, &[b""], &[b""]),
    (b"", b"\x61", 0, &[], &[]),
    (b"", b"\x61", 1, &[b""], &[b""]),
    (b"", b"\x61", 2, &[b""], &[b""]),
    (b"", b"\x61", 3, &[b""], &[b""]),
    (b"", b"\x61", 100, &[b""], &[b""]),
    (b"\x61", b"", -1, &[b"\x61"], &[b"\x61"]),
    (b"\x61", b"", 0, &[], &[]),
    (b"\x61", b"", 1, &[b"\x61"], &[b"\x61"]),
    (b"\x61", b"", 2, &[b"\x61"], &[b"\x61"]),
    (b"\x61", b"", 3, &[b"\x61"], &[b"\x61"]),
    (b"\x61", b"", 100, &[b"\x61"], &[b"\x61"]),
    (
        b"\x61\x62\x63",
        b"\x62",
        -1,
        &[b"\x61", b"\x63"],
        &[b"\x61\x62", b"\x63"],
    ),
    (b"\x61\x62\x63", b"\x62", 0, &[], &[]),
    (
        b"\x61\x62\x63",
        b"\x62",
        1,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        2,
        &[b"\x61", b"\x63"],
        &[b"\x61\x62", b"\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        3,
        &[b"\x61", b"\x63"],
        &[b"\x61\x62", b"\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        100,
        &[b"\x61", b"\x63"],
        &[b"\x61\x62", b"\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        -1,
        &[b"", b""],
        &[b"\x61\x62\x63", b""],
    ),
    (b"\x61\x62\x63", b"\x61\x62\x63", 0, &[], &[]),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        1,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        2,
        &[b"", b""],
        &[b"\x61\x62\x63", b""],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        3,
        &[b"", b""],
        &[b"\x61\x62\x63", b""],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        100,
        &[b"", b""],
        &[b"\x61\x62\x63", b""],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        -1,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (b"\x61\x62\x63", b"\x61\x62\x63\x64", 0, &[], &[]),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        1,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        2,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        3,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        100,
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        -1,
        &[b"", b"\x61"],
        &[b"\x61\x61", b"\x61"],
    ),
    (b"\x61\x61\x61", b"\x61\x61", 0, &[], &[]),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        1,
        &[b"\x61\x61\x61"],
        &[b"\x61\x61\x61"],
    ),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        2,
        &[b"", b"\x61"],
        &[b"\x61\x61", b"\x61"],
    ),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        3,
        &[b"", b"\x61"],
        &[b"\x61\x61", b"\x61"],
    ),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        100,
        &[b"", b"\x61"],
        &[b"\x61\x61", b"\x61"],
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        -1,
        &[b"\x62", b"\x6e\x61"],
        &[b"\x62\x61\x6e\x61", b"\x6e\x61"],
    ),
    (b"\x62\x61\x6e\x61\x6e\x61", b"\x61\x6e\x61", 0, &[], &[]),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        1,
        &[b"\x62\x61\x6e\x61\x6e\x61"],
        &[b"\x62\x61\x6e\x61\x6e\x61"],
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        2,
        &[b"\x62", b"\x6e\x61"],
        &[b"\x62\x61\x6e\x61", b"\x6e\x61"],
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        3,
        &[b"\x62", b"\x6e\x61"],
        &[b"\x62\x61\x6e\x61", b"\x6e\x61"],
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        100,
        &[b"\x62", b"\x6e\x61"],
        &[b"\x62\x61\x6e\x61", b"\x6e\x61"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        -1,
        &[b"\x68", b"\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9", b"\x6c\x6c\x6f"],
    ),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xc3\xa9", 0, &[], &[]),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        1,
        &[b"\x68\xc3\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        2,
        &[b"\x68", b"\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9", b"\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        3,
        &[b"\x68", b"\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9", b"\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        100,
        &[b"\x68", b"\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9", b"\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        -1,
        &[b"\x68", b"\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3", b"\xa9\x6c\x6c\x6f"],
    ),
    (b"\x68\xc3\xa9\x6c\x6c\x6f", b"\xc3", 0, &[], &[]),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        1,
        &[b"\x68\xc3\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        2,
        &[b"\x68", b"\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3", b"\xa9\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        3,
        &[b"\x68", b"\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3", b"\xa9\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        100,
        &[b"\x68", b"\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3", b"\xa9\x6c\x6c\x6f"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        -1,
        &[b"\xe6\x97\xa5", b"\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        0,
        &[],
        &[],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        1,
        &[b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        2,
        &[b"\xe6\x97\xa5", b"\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        3,
        &[b"\xe6\x97\xa5", b"\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        100,
        &[b"\xe6\x97\xa5", b"\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (
        b"\xff\xfe",
        b"\xfe",
        -1,
        &[b"\xff", b""],
        &[b"\xff\xfe", b""],
    ),
    (b"\xff\xfe", b"\xfe", 0, &[], &[]),
    (b"\xff\xfe", b"\xfe", 1, &[b"\xff\xfe"], &[b"\xff\xfe"]),
    (
        b"\xff\xfe",
        b"\xfe",
        2,
        &[b"\xff", b""],
        &[b"\xff\xfe", b""],
    ),
    (
        b"\xff\xfe",
        b"\xfe",
        3,
        &[b"\xff", b""],
        &[b"\xff\xfe", b""],
    ),
    (
        b"\xff\xfe",
        b"\xfe",
        100,
        &[b"\xff", b""],
        &[b"\xff\xfe", b""],
    ),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        -1,
        &[b"\x61\x62", b"\x61\x62", b""],
        &[b"\x61\x62\x63", b"\x61\x62\x63", b""],
    ),
    (b"\x61\x62\x63\x61\x62\x63", b"\x63", 0, &[], &[]),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        1,
        &[b"\x61\x62\x63\x61\x62\x63"],
        &[b"\x61\x62\x63\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        2,
        &[b"\x61\x62", b"\x61\x62\x63"],
        &[b"\x61\x62\x63", b"\x61\x62\x63"],
    ),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        3,
        &[b"\x61\x62", b"\x61\x62", b""],
        &[b"\x61\x62\x63", b"\x61\x62\x63", b""],
    ),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        100,
        &[b"\x61\x62", b"\x61\x62", b""],
        &[b"\x61\x62\x63", b"\x61\x62\x63", b""],
    ),
];

const SPLIT: [(&[u8], &[u8], &[&[u8]], &[&[u8]]); 13] = [
    (b"", b"", &[], &[]),
    (b"", b"\x61", &[b""], &[b""]),
    (b"\x61", b"", &[b"\x61"], &[b"\x61"]),
    (
        b"\x61\x62\x63",
        b"\x62",
        &[b"\x61", b"\x63"],
        &[b"\x61\x62", b"\x63"],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63",
        &[b"", b""],
        &[b"\x61\x62\x63", b""],
    ),
    (
        b"\x61\x62\x63",
        b"\x61\x62\x63\x64",
        &[b"\x61\x62\x63"],
        &[b"\x61\x62\x63"],
    ),
    (
        b"\x61\x61\x61",
        b"\x61\x61",
        &[b"", b"\x61"],
        &[b"\x61\x61", b"\x61"],
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        &[b"\x62", b"\x6e\x61"],
        &[b"\x62\x61\x6e\x61", b"\x6e\x61"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3\xa9",
        &[b"\x68", b"\x6c\x6c\x6f"],
        &[b"\x68\xc3\xa9", b"\x6c\x6c\x6f"],
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\xc3",
        &[b"\x68", b"\xa9\x6c\x6c\x6f"],
        &[b"\x68\xc3", b"\xa9\x6c\x6c\x6f"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x9c\xac",
        &[b"\xe6\x97\xa5", b"\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
    ),
    (b"\xff\xfe", b"\xfe", &[b"\xff", b""], &[b"\xff\xfe", b""]),
    (
        b"\x61\x62\x63\x61\x62\x63",
        b"\x63",
        &[b"\x61\x62", b"\x61\x62", b""],
        &[b"\x61\x62\x63", b"\x61\x62\x63", b""],
    ),
];

const JOIN: [(&[&[u8]], &[u8], &[u8]); 28] = [
    (&[], b"", b""),
    (&[], b"\x2c", b""),
    (&[], b"\x2c\x20", b""),
    (&[], b"\xe6\x97\xa5", b""),
    (&[b""], b"", b""),
    (&[b""], b"\x2c", b""),
    (&[b""], b"\x2c\x20", b""),
    (&[b""], b"\xe6\x97\xa5", b""),
    (&[b"\x61"], b"", b"\x61"),
    (&[b"\x61"], b"\x2c", b"\x61"),
    (&[b"\x61"], b"\x2c\x20", b"\x61"),
    (&[b"\x61"], b"\xe6\x97\xa5", b"\x61"),
    (&[b"\x61", b"\x62"], b"", b"\x61\x62"),
    (&[b"\x61", b"\x62"], b"\x2c", b"\x61\x2c\x62"),
    (&[b"\x61", b"\x62"], b"\x2c\x20", b"\x61\x2c\x20\x62"),
    (
        &[b"\x61", b"\x62"],
        b"\xe6\x97\xa5",
        b"\x61\xe6\x97\xa5\x62",
    ),
    (&[b"", b"\x61", b""], b"", b"\x61"),
    (&[b"", b"\x61", b""], b"\x2c", b"\x2c\x61\x2c"),
    (&[b"", b"\x61", b""], b"\x2c\x20", b"\x2c\x20\x61\x2c\x20"),
    (
        &[b"", b"\x61", b""],
        b"\xe6\x97\xa5",
        b"\xe6\x97\xa5\x61\xe6\x97\xa5",
    ),
    (&[b"", b""], b"", b""),
    (&[b"", b""], b"\x2c", b"\x2c"),
    (&[b"", b""], b"\x2c\x20", b"\x2c\x20"),
    (&[b"", b""], b"\xe6\x97\xa5", b"\xe6\x97\xa5"),
    (
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac"],
        b"",
        b"\xe6\x97\xa5\xe6\x9c\xac",
    ),
    (
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac"],
        b"\x2c",
        b"\xe6\x97\xa5\x2c\xe6\x9c\xac",
    ),
    (
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac"],
        b"\x2c\x20",
        b"\xe6\x97\xa5\x2c\x20\xe6\x9c\xac",
    ),
    (
        &[b"\xe6\x97\xa5", b"\xe6\x9c\xac"],
        b"\xe6\x97\xa5",
        b"\xe6\x97\xa5\xe6\x97\xa5\xe6\x9c\xac",
    ),
];

const FIELDS: [(&[u8], &[&[u8]], &[&[u8]]); 11] = [
    (b"", &[], &[]),
    (b"\x20\x20\x20", &[], &[b"\x20\x20\x20"]),
    (b"\x61", &[b"\x61"], &[b"\x61"]),
    (
        b"\x61\x20\x62\x20\x63",
        &[b"\x61", b"\x62", b"\x63"],
        &[b"\x61\x20\x62\x20\x63"],
    ),
    (
        b"\x20\x20\x61\x20\x20\x62\x20\x20",
        &[b"\x61", b"\x62"],
        &[b"\x20\x20\x61\x20\x20\x62\x20\x20"],
    ),
    (
        b"\x09\x0a\x0b\x0c\x0d\x20\x61\x20\x0d\x0c\x0b\x0a\x09",
        &[b"\x61"],
        &[b"\x09\x0a\x0b\x0c\x0d\x20\x61\x20\x0d\x0c\x0b\x0a\x09"],
    ),
    (
        b"\x61\xc2\xa0\x62",
        &[b"\x61", b"\x62"],
        &[b"\x61\xc2\xa0\x62"],
    ),
    (
        b"\x61\xe3\x80\x80\x62",
        &[b"\x61", b"\x62"],
        &[b"\x61\xe3\x80\x80\x62"],
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\x20\xe8\xaa\x9e",
        &[b"\xe6\x97\xa5\xe6\x9c\xac", b"\xe8\xaa\x9e"],
        &[b"\xe6\x97\xa5\xe6\x9c\xac\x20\xe8\xaa\x9e"],
    ),
    (b"\xff\x20\xfe", &[b"\xff", b"\xfe"], &[b"\xff\x20\xfe"]),
    (
        b"\x61\xff\x62\x20\x63",
        &[b"\x61\xff\x62", b"\x63"],
        &[b"\x61\xff\x62\x20\x63"],
    ),
];

const REPLACE: [(&[u8], &[u8], &[u8], int, &[u8]); 50] = [
    (b"", b"", b"\x78", -1, b"\x78"),
    (b"", b"", b"\x78", 0, b""),
    (b"", b"", b"\x78", 1, b"\x78"),
    (b"", b"", b"\x78", 2, b"\x78"),
    (b"", b"", b"\x78", 100, b"\x78"),
    (
        b"\x61\x62\x63",
        b"",
        b"\x2d",
        -1,
        b"\x2d\x61\x2d\x62\x2d\x63\x2d",
    ),
    (b"\x61\x62\x63", b"", b"\x2d", 0, b"\x61\x62\x63"),
    (b"\x61\x62\x63", b"", b"\x2d", 1, b"\x2d\x61\x62\x63"),
    (b"\x61\x62\x63", b"", b"\x2d", 2, b"\x2d\x61\x2d\x62\x63"),
    (
        b"\x61\x62\x63",
        b"",
        b"\x2d",
        100,
        b"\x2d\x61\x2d\x62\x2d\x63\x2d",
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        b"\x58\x59",
        -1,
        b"\x61\x58\x59\x63",
    ),
    (b"\x61\x62\x63", b"\x62", b"\x58\x59", 0, b"\x61\x62\x63"),
    (
        b"\x61\x62\x63",
        b"\x62",
        b"\x58\x59",
        1,
        b"\x61\x58\x59\x63",
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        b"\x58\x59",
        2,
        b"\x61\x58\x59\x63",
    ),
    (
        b"\x61\x62\x63",
        b"\x62",
        b"\x58\x59",
        100,
        b"\x61\x58\x59\x63",
    ),
    (b"\x61\x62\x63", b"\x62", b"", -1, b"\x61\x63"),
    (b"\x61\x62\x63", b"\x62", b"", 0, b"\x61\x62\x63"),
    (b"\x61\x62\x63", b"\x62", b"", 1, b"\x61\x63"),
    (b"\x61\x62\x63", b"\x62", b"", 2, b"\x61\x63"),
    (b"\x61\x62\x63", b"\x62", b"", 100, b"\x61\x63"),
    (
        b"\x61\x61\x61",
        b"\x61",
        b"\x61\x61",
        -1,
        b"\x61\x61\x61\x61\x61\x61",
    ),
    (b"\x61\x61\x61", b"\x61", b"\x61\x61", 0, b"\x61\x61\x61"),
    (
        b"\x61\x61\x61",
        b"\x61",
        b"\x61\x61",
        1,
        b"\x61\x61\x61\x61",
    ),
    (
        b"\x61\x61\x61",
        b"\x61",
        b"\x61\x61",
        2,
        b"\x61\x61\x61\x61\x61",
    ),
    (
        b"\x61\x61\x61",
        b"\x61",
        b"\x61\x61",
        100,
        b"\x61\x61\x61\x61\x61\x61",
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x58",
        -1,
        b"\x62\x58\x6e\x61",
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x58",
        0,
        b"\x62\x61\x6e\x61\x6e\x61",
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x58",
        1,
        b"\x62\x58\x6e\x61",
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x58",
        2,
        b"\x62\x58\x6e\x61",
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x58",
        100,
        b"\x62\x58\x6e\x61",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        b"\x2e",
        -1,
        b"\x2e\x68\x2e\xc3\xa9\x2e\x6c\x2e\x6c\x2e\x6f\x2e",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        b"\x2e",
        0,
        b"\x68\xc3\xa9\x6c\x6c\x6f",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        b"\x2e",
        1,
        b"\x2e\x68\xc3\xa9\x6c\x6c\x6f",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        b"\x2e",
        2,
        b"\x2e\x68\x2e\xc3\xa9\x6c\x6c\x6f",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        b"\x2e",
        100,
        b"\x2e\x68\x2e\xc3\xa9\x2e\x6c\x2e\x6c\x2e\x6f\x2e",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"",
        b"\x2e",
        -1,
        b"\x2e\xe6\x97\xa5\x2e\xe6\x9c\xac\x2e",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"",
        b"\x2e",
        0,
        b"\xe6\x97\xa5\xe6\x9c\xac",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"",
        b"\x2e",
        1,
        b"\x2e\xe6\x97\xa5\xe6\x9c\xac",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"",
        b"\x2e",
        2,
        b"\x2e\xe6\x97\xa5\x2e\xe6\x9c\xac",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"",
        b"\x2e",
        100,
        b"\x2e\xe6\x97\xa5\x2e\xe6\x9c\xac\x2e",
    ),
    (b"\x61\x62\x63", b"\x64", b"\x58", -1, b"\x61\x62\x63"),
    (b"\x61\x62\x63", b"\x64", b"\x58", 0, b"\x61\x62\x63"),
    (b"\x61\x62\x63", b"\x64", b"\x58", 1, b"\x61\x62\x63"),
    (b"\x61\x62\x63", b"\x64", b"\x58", 2, b"\x61\x62\x63"),
    (b"\x61\x62\x63", b"\x64", b"\x58", 100, b"\x61\x62\x63"),
    (b"\xff\xfe", b"", b"\x2e", -1, b"\x2e\xff\x2e\xfe\x2e"),
    (b"\xff\xfe", b"", b"\x2e", 0, b"\xff\xfe"),
    (b"\xff\xfe", b"", b"\x2e", 1, b"\x2e\xff\xfe"),
    (b"\xff\xfe", b"", b"\x2e", 2, b"\x2e\xff\x2e\xfe"),
    (b"\xff\xfe", b"", b"\x2e", 100, b"\x2e\xff\x2e\xfe\x2e"),
];

const REPLACEALL: [(&[u8], &[u8], &[u8], &[u8]); 10] = [
    (b"", b"", b"\x78", b"\x78"),
    (
        b"\x61\x62\x63",
        b"",
        b"\x2d",
        b"\x2d\x61\x2d\x62\x2d\x63\x2d",
    ),
    (b"\x61\x62\x63", b"\x62", b"\x58\x59", b"\x61\x58\x59\x63"),
    (b"\x61\x62\x63", b"\x62", b"", b"\x61\x63"),
    (
        b"\x61\x61\x61",
        b"\x61",
        b"\x61\x61",
        b"\x61\x61\x61\x61\x61\x61",
    ),
    (
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x61\x6e\x61",
        b"\x58",
        b"\x62\x58\x6e\x61",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"",
        b"\x2e",
        b"\x2e\x68\x2e\xc3\xa9\x2e\x6c\x2e\x6c\x2e\x6f\x2e",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"",
        b"\x2e",
        b"\x2e\xe6\x97\xa5\x2e\xe6\x9c\xac\x2e",
    ),
    (b"\x61\x62\x63", b"\x64", b"\x58", b"\x61\x62\x63"),
    (b"\xff\xfe", b"", b"\x2e", b"\x2e\xff\x2e\xfe\x2e"),
];

const REPEAT: [(&[u8], int, &[u8]); 12] = [
    (b"", 0, b""),
    (b"", 1, b""),
    (b"", 3, b""),
    (b"\x61", 0, b""),
    (b"\x61", 1, b"\x61"),
    (b"\x61", 3, b"\x61\x61\x61"),
    (b"\x61\x62", 0, b""),
    (b"\x61\x62", 1, b"\x61\x62"),
    (b"\x61\x62", 3, b"\x61\x62\x61\x62\x61\x62"),
    (b"\xe6\x97\xa5", 0, b""),
    (b"\xe6\x97\xa5", 1, b"\xe6\x97\xa5"),
    (b"\xe6\x97\xa5", 3, b"\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5"),
];

const MAP: [(&str, &[u8], &[u8]); 24] = [
    ("upper", b"", b""),
    ("upper", b"\x68\x65\x6c\x6c\x6f", b"\x48\x45\x4c\x4c\x4f"),
    (
        "upper",
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\x48\xc3\x89\x4c\x4c\x4f",
    ),
    (
        "upper",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
    ),
    ("upper", b"\xff\xfe", b"\xef\xbf\xbd\xef\xbf\xbd"),
    ("upper", b"\x61\xff\x62", b"\x41\xef\xbf\xbd\x42"),
    ("drop-vowel", b"", b""),
    ("drop-vowel", b"\x68\x65\x6c\x6c\x6f", b"\x68\x6c\x6c"),
    (
        "drop-vowel",
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\x68\xc3\xa9\x6c\x6c",
    ),
    (
        "drop-vowel",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
    ),
    ("drop-vowel", b"\xff\xfe", b"\xef\xbf\xbd\xef\xbf\xbd"),
    ("drop-vowel", b"\x61\xff\x62", b"\xef\xbf\xbd\x62"),
    ("ident", b"", b""),
    ("ident", b"\x68\x65\x6c\x6c\x6f", b"\x68\x65\x6c\x6c\x6f"),
    (
        "ident",
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\x68\xc3\xa9\x6c\x6c\x6f",
    ),
    (
        "ident",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
    ),
    ("ident", b"\xff\xfe", b"\xef\xbf\xbd\xef\xbf\xbd"),
    ("ident", b"\x61\xff\x62", b"\x61\xef\xbf\xbd\x62"),
    ("neg", b"", b""),
    ("neg", b"\x68\x65\x6c\x6c\x6f", b""),
    ("neg", b"\x68\xc3\xa9\x6c\x6c\x6f", b""),
    ("neg", b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e", b""),
    ("neg", b"\xff\xfe", b""),
    ("neg", b"\x61\xff\x62", b""),
];

const RUNES: [(&[u8], &[rune], &[u8], &[u8]); 6] = [
    (b"", &[], b"", b""),
    (
        b"\x68\x65\x6c\x6c\x6f",
        &[104, 101, 108, 108, 111],
        b"\x68\x65\x6c\x6c\x6f",
        b"\x68\x65\x6c\x6c\x6f",
    ),
    (
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        &[104, 233, 108, 108, 111],
        b"\x68\xc3\xa9\x6c\x6c\x6f",
        b"\x68\xc3\xa9\x6c\x6c\x6f",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        &[26085, 26412, 35486],
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
    ),
    (b"\xff\xfe", &[65533, 65533], b"\x3f", b"\xff\xfe"),
    (
        b"\x61\xff\x62",
        &[97, 65533, 98],
        b"\x61\x3f\x62",
        b"\x61\xff\x62",
    ),
];

const TITLE: [(&[u8], &[u8]); 7] = [
    (b"", b""),
    (
        b"\x68\x65\x72\x20\x72\x6f\x79\x61\x6c\x20\x68\x69\x67\x68\x6e\x65\x73\x73",
        b"\x48\x65\x72\x20\x52\x6f\x79\x61\x6c\x20\x48\x69\x67\x68\x6e\x65\x73\x73",
    ),
    (
        b"\x62\x72\x6f\x77\x6e\x20\x66\x6f\x78",
        b"\x42\x72\x6f\x77\x6e\x20\x46\x6f\x78",
    ),
    (b"\x61", b"\x41"),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\x20\xe8\xaa\x9e",
        b"\xe6\x97\xa5\xe6\x9c\xac\x20\xe8\xaa\x9e",
    ),
    (b"\x78\x27\x79", b"\x58\x27\x59"),
    (b"\x31\x61", b"\x31\x61"),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Index / LastIndex / Count / Contains / HasPrefix / HasSuffix.
    //    The empty separator is the interesting row: Index is 0,
    //    LastIndex is len(s), and Count is the RUNE count plus one, so
    //    Count("héllo", "") is 6 and not 7.
    {
        let mut ok = true;
        let mut i = 0;
        while i < IDX.len() {
            let (s, sep, idx, last, count, contains, hasp, hass) = IDX[i];
            if bytes::Index(sl(s), sl(sep)) != idx {
                ok = false;
            }
            if bytes::LastIndex(sl(s), sl(sep)) != last {
                ok = false;
            }
            if bytes::Count(sl(s), sl(sep)) != count {
                ok = false;
            }
            if bytes::Contains(sl(s), sl(sep)) != contains {
                ok = false;
            }
            if bytes::HasPrefix(sl(s), sl(sep)) != hasp {
                ok = false;
            }
            if bytes::HasSuffix(sl(s), sl(sep)) != hass {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Index/Last/Count x13");
    }

    // 2. Cut / CutPrefix / CutSuffix. `found` is not `before != s`:
    //    Cut(s, "") finds the empty separator at 0 and returns ("", s).
    {
        let mut ok = true;
        let mut i = 0;
        while i < CUT.len() {
            let (s, sep, before, after, found, pre, pre_ok, suf, suf_ok) = CUT[i];
            let (b, a, f) = bytes::Cut(sl(s), sl(sep));
            if raw(&b) != before.to_vec() || raw(&a) != after.to_vec() || f != found {
                ok = false;
            }
            let (p, po) = bytes::CutPrefix(sl(s), sl(sep));
            if raw(&p) != pre.to_vec() || po != pre_ok {
                ok = false;
            }
            let (u, uo) = bytes::CutSuffix(sl(s), sl(sep));
            if raw(&u) != suf.to_vec() || uo != suf_ok {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "Cut/CutPrefix/CutSuffix");
    }

    // 3. Equal / EqualFold / Compare.
    {
        let mut ok = true;
        let mut i = 0;
        while i < EQ.len() {
            let (a, b, equal, fold, cmp) = EQ[i];
            if bytes::Equal(sl(a), sl(b)) != equal {
                ok = false;
            }
            if bytes::EqualFold(sl(a), sl(b)) != fold {
                ok = false;
            }
            if bytes::Compare(sl(a), sl(b)) != cmp {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Equal/EqualFold/Compare");
    }

    // 4. EqualFold is Unicode simple folding, not an ASCII tolower:
    //    K (U+212A) folds to k, σ and ς fold together, and ß does NOT
    //    fold to "ss" — that is full folding, which Go does not do here.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FOLD.len() {
            let (a, b, want) = FOLD[i];
            if bytes::EqualFold(sl(a), sl(b)) != want {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "EqualFold is Unicode");
    }

    // 5. IndexByte / LastIndexByte, including bytes that are only ever
    //    part of a multi-byte encoding.
    {
        let mut ok = true;
        let mut i = 0;
        while i < IBYTE.len() {
            let (s, c, idx, last) = IBYTE[i];
            if bytes::IndexByte(sl(s), c) != idx {
                ok = false;
            }
            if bytes::LastIndexByte(sl(s), c) != last {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "IndexByte/LastIndexByte");
    }

    // 6. IndexRune. RuneError is the special one: it matches both a
    //    literal U+FFFD and any byte that is an invalid encoding. An
    //    out-of-range rune is -1, never a panic.
    {
        let mut ok = true;
        let mut i = 0;
        while i < IRUNE.len() {
            let (s, r, idx) = IRUNE[i];
            if bytes::IndexRune(sl(s), r) != idx {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "IndexRune x30");
    }

    // 7. ContainsAny / IndexAny / LastIndexAny — `chars` is a rune set,
    //    so a lone 0xFF in the haystack decodes to RuneError and is
    //    found only by a cutset that actually holds U+FFFD.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ANY.len() {
            let (s, chars, contains, idx, last) = ANY[i];
            if bytes::ContainsAny(sl(s), sl(chars)) != contains {
                ok = false;
            }
            if bytes::IndexAny(sl(s), sl(chars)) != idx {
                ok = false;
            }
            if bytes::LastIndexAny(sl(s), sl(chars)) != last {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 7", "ContainsAny/IndexAny x42");
    }

    // 8. IndexFunc / LastIndexFunc / ContainsFunc / ContainsRune.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FUNC.len() {
            let (s, digit, lastdigit, containsdigit, containse) = FUNC[i];
            if bytes::IndexFunc(sl(s), unicode::IsDigit) != digit {
                ok = false;
            }
            if bytes::LastIndexFunc(sl(s), unicode::IsDigit) != lastdigit {
                ok = false;
            }
            if bytes::ContainsFunc(sl(s), unicode::IsDigit) != containsdigit {
                ok = false;
            }
            if bytes::ContainsRune(sl(s), 0xE9) != containse {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 8", "Index/LastIndex/ContainsFunc");
    }

    // 9. SplitN / SplitAfterN across n = -1, 0, 1, 2, 3, 100. n == 0
    //    yields nil, n == 1 yields the whole input, and an empty
    //    separator splits into runes.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SPLITN.len() {
            let (s, sep, n, want, want_after) = SPLITN[i];
            if !same(&rawlist(&bytes::SplitN(sl(s), sl(sep), n)), want) {
                ok = false;
            }
            if !same(&rawlist(&bytes::SplitAfterN(sl(s), sl(sep), n)), want_after) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 9", "SplitN/SplitAfterN x78");
    }

    // 10. Split / SplitAfter, and Join round-tripping them.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SPLIT.len() {
            let (s, sep, want, want_after) = SPLIT[i];
            if !same(&rawlist(&bytes::Split(sl(s), sl(sep))), want) {
                ok = false;
            }
            if !same(&rawlist(&bytes::SplitAfter(sl(s), sl(sep))), want_after) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "10", "Split/SplitAfter");
    }

    // 11. Join. A one-element slice never sees the separator, so
    //     Join([""], ",") is "" and not ",".
    {
        let mut ok = true;
        let mut i = 0;
        while i < JOIN.len() {
            let (parts, sep, want) = JOIN[i];
            let mut v: Vec<slice<byte>> = Vec::new();
            let mut j = 0usize;
            while j < parts.len() {
                v.push(sl(parts[j]));
                j += 1;
            }
            let elems: slice<slice<byte>> = slice::<slice<byte>>::__from_vec(v);
            if raw(&bytes::Join(elems, sl(sep))) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "11", "Join x28");
    }

    // 12. Fields and FieldsFunc. The space set is `unicode.IsSpace`, so
    //     the ideographic space U+3000 separates; an all-space input
    //     yields nothing rather than one empty field.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FIELDS.len() {
            let (s, want, want_digit) = FIELDS[i];
            if !same(&rawlist(&bytes::Fields(sl(s))), want) {
                ok = false;
            }
            if !same(
                &rawlist(&bytes::FieldsFunc(sl(s), unicode::IsDigit)),
                want_digit,
            ) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "12", "Fields/FieldsFunc");
    }

    // 13. Replace / ReplaceAll. n < 0 means every occurrence; an empty
    //     `old` inserts `new` at each rune boundary AND at both ends,
    //     which is len(runes)+1 insertions.
    {
        let mut ok = true;
        let mut i = 0;
        while i < REPLACE.len() {
            let (s, old, new_, n, want) = REPLACE[i];
            if raw(&bytes::Replace(sl(s), sl(old), sl(new_), n)) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        i = 0;
        while i < REPLACEALL.len() {
            let (s, old, new_, want) = REPLACEALL[i];
            if raw(&bytes::ReplaceAll(sl(s), sl(old), sl(new_))) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "13", "Replace/ReplaceAll x60");
    }

    // 14. Repeat.
    {
        let mut ok = true;
        let mut i = 0;
        while i < REPEAT.len() {
            let (s, n, want) = REPEAT[i];
            if raw(&bytes::Repeat(sl(s), n)) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "14", "Repeat");
    }

    // 15. Map. A negative result drops the rune; an invalid byte is
    //     handed to the mapping as RuneError and, if kept, is re-encoded
    //     as the three-byte U+FFFD — so `ident` is not the identity on
    //     invalid input.
    {
        let mut ok = true;
        let mut i = 0;
        while i < MAP.len() {
            let (name, s, want) = MAP[i];
            let got = match name {
                "upper" => bytes::Map(unicode::ToUpper, sl(s)),
                "drop-vowel" => bytes::Map(
                    |r: rune| -> rune {
                        if r == 0x61 || r == 0x65 || r == 0x69 || r == 0x6F || r == 0x75 {
                            return -1;
                        }
                        return r;
                    },
                    sl(s),
                ),
                "ident" => bytes::Map(|r: rune| -> rune { return r }, sl(s)),
                _ => bytes::Map(|_r: rune| -> rune { return -1 }, sl(s)),
            };
            if raw(&got) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "15", "Map (drop, RuneError)");
    }

    // 16. Runes / ToValidUTF8 / Clone.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RUNES.len() {
            let (s, want, valid, clone) = RUNES[i];
            let got = bytes::Runes(sl(s));
            if got.Len() as usize != want.len() {
                ok = false;
            } else {
                let mut j = 0usize;
                while j < want.len() {
                    if got[j] != want[j] {
                        ok = false;
                    }
                    j += 1;
                }
            }
            if raw(&bytes::ToValidUTF8(sl(s), sl(b"?"))) != valid.to_vec() {
                ok = false;
            }
            if raw(&bytes::Clone(sl(s))) != clone.to_vec() {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "16", "Runes/ToValidUTF8/Clone");
    }

    // 17. Title. Deprecated upstream and kept for parity: it uppercases
    //     the letter after every non-letter, so "x'y" becomes "X'Y" and
    //     "1a" becomes "1A".
    {
        let mut ok = true;
        let mut i = 0;
        while i < TITLE.len() {
            let (s, want) = TITLE[i];
            #[allow(deprecated)]
            let got = bytes::Title(sl(s));
            if raw(&got) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, "17", "Title (word boundaries)");
    }

    if failed == 0 {
        fmt::Println!("ok 17/17");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 17");
        syscall::Exit(1);
    }
}

// go: none — goish idiom: the smokes all print one PASS/FAIL line per
//     numbered check; this is that line, hoisted so seventeen checks do
//     not repeat it seventeen times.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}
