// strings_replacer_smoke — strings.Replacer against a running Go.
// (strings/replace.go, strings/search.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_replacer_ref.go` run in
// `package strings_test` by `scripts/goref.sh`.
//
// `NewReplacer` picks one of four algorithms from the shape of its
// arguments — Boyer-Moore for a single multi-byte pattern, a 256-byte
// translation table when every old and new is one byte, a table of
// slices when only the olds are, and a trie otherwise. They agree only
// because each implements the same rule: replacements happen in the
// order they appear in the target string, without overlapping, and the
// old strings are compared in argument order.
//
// The trie is where "argument order" gets interesting. Keys are matched
// neither shortest- nor longest-first: `lookup` walks the whole path
// and takes the highest-priority complete key it passes, priority being
// higher for an earlier argument. So ("a","1","ab","2") turns "ab" into
// "1b" while ("ab","2","a","1") turns it into "2", and
// ("abc","1","abd","2","ab","3") turns "abc" into "1" but "abe" into
// "3e".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string as gostring;
use goish::strings;
use goish::syscall;
use goish::types::byte;

fn gb(s: &gostring) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

/// The sixteen argument lists, in the order the vectors index them.
const SETS: [&[&[u8]]; 16] = [
    // single
    &[b"\x61\x62", b"\x58"],
    // single-empty-new
    &[b"\x61\x62\x63", b""],
    // single-longer-new
    &[b"\x61", b"\x61\x61"],
    // bytes
    &[b"\x61", b"\x31", b"\x62", b"\x32", b"\x63", b"\x33"],
    // bytes-dup
    &[b"\x61", b"\x31", b"\x61", b"\x32"],
    // bytestring
    &[b"\x61", b"\x41\x41", b"\x62", b"", b"\x63", b"\x43"],
    // bytestring-dup
    &[b"\x61", b"\x58\x58", b"\x61", b"\x59\x59"],
    // generic-prefix
    &[b"\x61", b"\x31", b"\x61\x62", b"\x32"],
    // generic-prefix-rev
    &[b"\x61\x62", b"\x32", b"\x61", b"\x31"],
    // generic-overlap
    &[b"\x61\x61", b"\x58", b"\x61\x61\x61", b"\x59"],
    // generic-doc
    &[
        b"\x61\x78",
        b"\x31",
        b"\x61\x79",
        b"\x32",
        b"\x62\x63\x62\x63",
        b"\x33",
        b"\x78",
        b"\x34",
        b"\x78\x79",
        b"\x35",
    ],
    // generic-empty-old
    &[b"", b"\x58"],
    // generic-empty-and-more
    &[b"", b"\x58", b"\x61", b"\x31"],
    // generic-html
    &[
        b"\x26",
        b"\x26\x61\x6d\x70\x3b",
        b"\x3c",
        b"\x26\x6c\x74\x3b",
        b"\x3e",
        b"\x26\x67\x74\x3b",
        b"\x22",
        b"\x26\x23\x33\x34\x3b",
        b"\x27",
        b"\x26\x23\x33\x39\x3b",
    ],
    // generic-multibyte
    &[
        b"\xc3\xa9",
        b"\x65",
        b"\xe6\x97\xa5\xe6\x9c\xac",
        b"\x4a\x50",
    ],
    // generic-same-first-byte
    &[
        b"\x61\x62\x63",
        b"\x31",
        b"\x61\x62\x64",
        b"\x32",
        b"\x61\x62",
        b"\x33",
    ],
];

/// (set index, input, Replace output, WriteString byte count)
const VECTORS: [(usize, &[u8], &[u8], i64); 70] = [
    (0, b"", b"", 0),
    (0, b"\x61", b"\x61", 1),
    (0, b"\x61\x62", b"\x58", 1),
    (0, b"\x61\x61\x62", b"\x61\x58", 2),
    (0, b"\x61\x62\x61\x62", b"\x58\x58", 2),
    (0, b"\x78\x61\x62\x79", b"\x78\x58\x79", 3),
    (0, b"\x61\x61\x61\x62", b"\x61\x61\x58", 3),
    (0, b"\x61\x62\x61\x62\x61\x62", b"\x58\x58\x58", 3),
    (0, b"\x62\x61", b"\x62\x61", 2),
    (1, b"\x61\x62\x63\x61\x62\x63", b"", 0),
    (1, b"\x61\x61\x62\x63\x62", b"\x61\x62", 2),
    (1, b"\x61\x62\x63", b"", 0),
    (2, b"\x61", b"\x61\x61", 2),
    (2, b"\x61\x61", b"\x61\x61\x61\x61", 4),
    (
        2,
        b"\x62\x61\x6e\x61\x6e\x61",
        b"\x62\x61\x61\x6e\x61\x61\x6e\x61\x61",
        9,
    ),
    (3, b"", b"", 0),
    (3, b"\x61\x62\x63", b"\x31\x32\x33", 3),
    (3, b"\x63\x62\x61", b"\x33\x32\x31", 3),
    (3, b"\x78\x79\x7a", b"\x78\x79\x7a", 3),
    (3, b"\x61\x61\x61", b"\x31\x31\x31", 3),
    (4, b"\x61\x61\x61", b"\x31\x31\x31", 3),
    (4, b"\x62\x61\x62", b"\x62\x31\x62", 3),
    (5, b"", b"", 0),
    (5, b"\x61\x62\x63", b"\x41\x41\x43", 3),
    (5, b"\x61\x61\x61", b"\x41\x41\x41\x41\x41\x41", 6),
    (5, b"\x62\x62\x62", b"", 0),
    (
        5,
        b"\x61\x62\x63\x61\x62\x63",
        b"\x41\x41\x43\x41\x41\x43",
        6,
    ),
    (6, b"\x61\x61\x61", b"\x58\x58\x58\x58\x58\x58", 6),
    (6, b"\x62\x61\x62", b"\x62\x58\x58\x62", 4),
    (7, b"\x61\x62", b"\x31\x62", 2),
    (7, b"\x61\x61\x62", b"\x31\x31\x62", 3),
    (7, b"\x61\x62\x61\x62", b"\x31\x62\x31\x62", 4),
    (7, b"\x61", b"\x31", 1),
    (7, b"\x62", b"\x62", 1),
    (8, b"\x61\x62", b"\x32", 1),
    (8, b"\x61\x61\x62", b"\x31\x32", 2),
    (8, b"\x61\x62\x61\x62", b"\x32\x32", 2),
    (8, b"\x61", b"\x31", 1),
    (8, b"\x62", b"\x62", 1),
    (9, b"\x61\x61", b"\x58", 1),
    (9, b"\x61\x61\x61", b"\x58\x61", 2),
    (9, b"\x61\x61\x61\x61", b"\x58\x58", 2),
    (9, b"\x61\x61\x61\x61\x61", b"\x58\x58\x61", 3),
    (10, b"\x61\x78", b"\x31", 1),
    (10, b"\x61\x79", b"\x32", 1),
    (10, b"\x62\x63\x62\x63", b"\x33", 1),
    (10, b"\x78", b"\x34", 1),
    (10, b"\x78\x79", b"\x34\x79", 2),
    (10, b"\x61\x78\x79", b"\x31\x79", 2),
    (10, b"\x62\x63\x62\x63\x62\x63", b"\x33\x62\x63", 3),
    (10, b"\x7a\x7a\x7a", b"\x7a\x7a\x7a", 3),
    (11, b"", b"\x58", 1),
    (11, b"\x61", b"\x58\x61\x58", 3),
    (11, b"\x61\x62", b"\x58\x61\x58\x62\x58", 5),
    (12, b"", b"\x58", 1),
    (12, b"\x61", b"\x58\x31\x58", 3),
    (12, b"\x61\x62", b"\x58\x31\x58\x62\x58", 5),
    (12, b"\x62\x61", b"\x58\x62\x58\x31\x58", 5),
    (13, b"", b"", 0),
    (
        13,
        b"\x61\x3c\x62\x3e\x26\x63",
        b"\x61\x26\x6c\x74\x3b\x62\x26\x67\x74\x3b\x26\x61\x6d\x70\x3b\x63",
        16,
    ),
    (
        13,
        b"\x22\x27",
        b"\x26\x23\x33\x34\x3b\x26\x23\x33\x39\x3b",
        10,
    ),
    (
        13,
        b"\x3c\x3c\x3e\x3e",
        b"\x26\x6c\x74\x3b\x26\x6c\x74\x3b\x26\x67\x74\x3b\x26\x67\x74\x3b",
        16,
    ),
    (14, b"\x63\x61\x66\xc3\xa9", b"\x63\x61\x66\x65", 4),
    (
        14,
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\x4a\x50\xe8\xaa\x9e",
        5,
    ),
    (
        14,
        b"\xc3\xa9\xe6\x97\xa5\xe6\x9c\xac\xc3\xa9",
        b"\x65\x4a\x50\x65",
        4,
    ),
    (15, b"\x61\x62\x63", b"\x31", 1),
    (15, b"\x61\x62\x64", b"\x32", 1),
    (15, b"\x61\x62\x65", b"\x33\x65", 2),
    (15, b"\x61\x62", b"\x33", 1),
    (15, b"\x61\x62\x63\x61\x62\x64", b"\x31\x32", 2),
];

fn mk(pairs: &[&[u8]]) -> strings::Replacer {
    let mut v: Vec<gostring> = Vec::new();
    let mut i = 0;
    while i < pairs.len() {
        v.push(gostring::from_bytes(pairs[i]));
        i += 1;
    }
    return strings::NewReplacer(slice::<gostring>::__from_vec(v));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Replace over all 70 Go vectors, across all four algorithms.
    {
        let mut ok = true;
        let mut i = 0;
        while i < VECTORS.len() {
            let (si, input, want, _) = VECTORS[i];
            let r = mk(SETS[si]);
            let got = r.Replace(gostring::from_bytes(input));
            if gb(&got) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] Replace 70 Go vectors    PASS");
        } else {
            fmt::Println!("[ 1] Replace 70 Go vectors    FAIL");
            failed += 1;
        }
    }

    // 2. WriteString writes the same bytes and reports the same count.
    {
        let mut ok = true;
        let mut i = 0;
        while i < VECTORS.len() {
            let (si, input, want, want_n) = VECTORS[i];
            let r = mk(SETS[si]);
            let mut buf = bytes::NewBuffer(slice::<byte>::__from_vec(Vec::new()));
            let (n, err) = r.WriteString(&mut buf, gostring::from_bytes(input));
            if !err.IsNil() || n != want_n || gb(&buf.String()) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] WriteString + count      PASS");
        } else {
            fmt::Println!("[ 2] WriteString + count      FAIL");
            failed += 1;
        }
    }

    // 3. The trie's priority rule, stated directly. Reversing the
    //    argument order changes the answer, and a longer pattern wins
    //    only when it comes first.
    {
        let mut ok = true;
        let a = mk(&[b"a", b"1", b"ab", b"2"]);
        let b = mk(&[b"ab", b"2", b"a", b"1"]);
        if gb(&a.Replace(gostring::from_bytes(b"ab"))) != b"1b".to_vec() {
            ok = false;
        }
        if gb(&b.Replace(gostring::from_bytes(b"ab"))) != b"2".to_vec() {
            ok = false;
        }
        let c = mk(&[b"abc", b"1", b"abd", b"2", b"ab", b"3"]);
        if gb(&c.Replace(gostring::from_bytes(b"abc"))) != b"1".to_vec() {
            ok = false;
        }
        if gb(&c.Replace(gostring::from_bytes(b"abe"))) != b"3e".to_vec() {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 3] trie priority rule       PASS");
        } else {
            fmt::Println!("[ 3] trie priority rule       FAIL");
            failed += 1;
        }
    }

    // 4. An empty old string matches between every byte and at both
    //    ends — the case the previous implementation dropped entirely.
    {
        let r = mk(&[b"", b"X"]);
        let s = mk(&[b"", b"X", b"a", b"1"]);
        if gb(&r.Replace(gostring::from_bytes(b"ab"))) == b"XaXbX".to_vec()
            && gb(&r.Replace(gostring::from_bytes(b""))) == b"X".to_vec()
            && gb(&s.Replace(gostring::from_bytes(b"ba"))) == b"XbX1X".to_vec()
        {
            fmt::Println!("[ 4] empty old string         PASS");
        } else {
            fmt::Println!("[ 4] empty old string         FAIL");
            failed += 1;
        }
    }

    // 5. When the same old appears twice, the first pair wins — in the
    //    byte table and in the byte-string table alike.
    {
        let a = mk(&[b"a", b"1", b"a", b"2"]);
        let b = mk(&[b"a", b"XX", b"a", b"YY"]);
        if gb(&a.Replace(gostring::from_bytes(b"aaa"))) == b"111".to_vec()
            && gb(&b.Replace(gostring::from_bytes(b"aaa"))) == b"XXXXXX".to_vec()
        {
            fmt::Println!("[ 5] first pair wins          PASS");
        } else {
            fmt::Println!("[ 5] first pair wins          FAIL");
            failed += 1;
        }
    }

    // 6. Matches never overlap: with ("aa","X","aaa","Y"), "aaaaa" is
    //    "XXa", not "XY" or "YX".
    {
        let r = mk(&[b"aa", b"X", b"aaa", b"Y"]);
        if gb(&r.Replace(gostring::from_bytes(b"aaa"))) == b"Xa".to_vec()
            && gb(&r.Replace(gostring::from_bytes(b"aaaa"))) == b"XX".to_vec()
            && gb(&r.Replace(gostring::from_bytes(b"aaaaa"))) == b"XXa".to_vec()
        {
            fmt::Println!("[ 6] no overlapping matches   PASS");
        } else {
            fmt::Println!("[ 6] no overlapping matches   FAIL");
            failed += 1;
        }
    }

    // 7. A Replacer is reusable: the same one gives the same answer
    //    every time, and a swap does not compose with itself.
    {
        let r = mk(&[b"a", b"b", b"b", b"a"]);
        let mut ok = true;
        let mut i = 0;
        while i < 3 {
            if gb(&r.Replace(gostring::from_bytes(b"abab"))) != b"baba".to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 7] reusable                 PASS");
        } else {
            fmt::Println!("[ 7] reusable                 FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
