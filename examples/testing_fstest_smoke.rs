// testing_fstest_smoke — pin MapFS's Seek and ReadAt against Go 1.25.5.
//
// Ground truth, from running the real Go code over
// MapFS{"a.txt": {Data: []byte("hello world")}}:
//
//   scripts/goref.sh testing/fstest mapfs_ref.go
//     Seek(0,0)  = 0        Seek(0,2)  = 11
//     Seek(5,0)  = 5        Seek(-3,2) = 8
//     Seek(11,0) = 11       Seek(-12,2)= 0, "seek a.txt: invalid argument"
//     Seek(12,0) = 0, "seek a.txt: invalid argument"
//     Seek(-1,0) = 0, "seek a.txt: invalid argument"
//     Seek(4,0) then Seek(3,1) = 7        (whence 1 accumulates)
//     ReadAt(len=5,off=0)  = 5, "hello",       err=nil
//     ReadAt(len=5,off=6)  = 5, "world",       err=nil
//     ReadAt(len=5,off=8)  = 3, "rld",         err=EOF   (short read)
//     ReadAt(len=20,off=0) = 11,"hello world", err=EOF
//     ReadAt(len=1,off=11) = 0, "",            err=EOF   (at end)
//     ReadAt(len=1,off=12) = 0, "", "read a.txt: invalid argument"
//     ReadAt(len=1,off=-1) = 0, "", "read a.txt: invalid argument"
//     after Seek(3,0) + ReadAt(off=9), position is still 3
//
// Note off=11 (exactly len) is EOF while off=12 is an error: the
// boundary is `offset > len`, not `>=`, so seeking or reading at the
// very end is legal and simply yields nothing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::gostring::string;
use goish::testing::fstest::{
    MapFile, MapFS, __shim_open_read_at, __shim_open_seek, __shim_open_seek2,
};
use goish::types::byte;
use goish::{errors, fmt, make, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, alloc::sync::Arc<MapFile>> = goish::map::new();
    let mut f = MapFile::default();
    f.Data = slice::__from_vec(b"hello world".to_vec());
    m.Set(s("a.txt"), alloc::sync::Arc::new(f));
    return MapFS(m);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Seek with whence 0 and 2, including both out-of-range ends.
    {
        let fsys = newfs();
        let cases: &[(i64, i64, i64, bool)] = &[
            // (offset, whence, want_pos, want_err)
            (0, 0, 0, false),
            (5, 0, 5, false),
            (11, 0, 11, false), // exactly len is legal
            (12, 0, 0, true),   // one past is not
            (-1, 0, 0, true),
            (0, 2, 11, false),
            (-3, 2, 8, false),
            (-12, 2, 0, true),
        ];
        let mut ok = true;
        for (off, whence, want, want_err) in cases.iter() {
            let (got, err) = __shim_open_seek(&fsys, s("a.txt"), *off, *whence);
            let got_err = err != errors::nil;
            if got != *want || got_err != *want_err {
                fmt::Println!(
                    "    Seek(", *off, ",", *whence, ") = ", got, " err=", got_err
                );
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 1] Seek whence 0 and 2       PASS");
        } else {
            fmt::Println!("[ 1] Seek whence 0 and 2       FAIL");
            failed += 1;
        }
    }

    // 2. whence 1 accumulates from the current position.
    {
        let fsys = newfs();
        // Both seeks on ONE handle: Seek(4,0) lands at 4, then
        // Seek(3,1) adds to the current position and lands at 7. A
        // fresh handle per call would start at 0 and hide the bug this
        // is meant to catch.
        let (a, b, e) = __shim_open_seek2(&fsys, s("a.txt"), 4, 0, 3, 1);
        if a == 4 && b == 7 && e == errors::nil {
            fmt::Println!("[ 2] Seek whence 1 relative    PASS");
        } else {
            fmt::Println!("[ 2] Seek whence 1 relative    FAIL");
            failed += 1;
        }
    }

    // 3. ReadAt: full reads, short reads at EOF, and the boundary
    //    between "at the end" (EOF) and "past the end" (error).
    {
        let fsys = newfs();
        let cases: &[(i64, i64, &str, bool, bool)] = &[
            // (buflen, offset, want_data, want_eof, want_err)
            (5, 0, "hello", false, false),
            (5, 6, "world", false, false),
            (5, 8, "rld", true, false),
            (20, 0, "hello world", true, false),
            (1, 11, "", true, false),
            (1, 12, "", false, true),
            (1, -1, "", false, true),
        ];
        let mut ok = true;
        for (buflen, off, want, want_eof, want_err) in cases.iter() {
            let mut buf: slice<byte> = make!([]byte, *buflen);
            let (n, err) = __shim_open_read_at(&fsys, s("a.txt"), &mut buf, *off);
            let mut got: Vec<u8> = Vec::new();
            let mut i: i64 = 0;
            while i < n {
                got.push(buf[i]);
                i += 1;
            }
            let got_s = string::from_bytes(&got);
            let eof: errors::error = goish::io::EOF.clone().into();
            let is_eof = err == eof;
            let is_err = err != errors::nil && !is_eof;
            if got_s != s(want) || is_eof != *want_eof || is_err != *want_err {
                fmt::Println!(
                    "    ReadAt(len=", *buflen, ",off=", *off, ") = ", n,
                    " [", got_s, "] eof=", is_eof, " err=", is_err
                );
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 3] ReadAt data and EOF       PASS");
        } else {
            fmt::Println!("[ 3] ReadAt data and EOF       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
