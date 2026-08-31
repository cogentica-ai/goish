// io_fs_format_smoke — io/fs.FormatFileInfo and FormatDirEntry, plus
// fstest's mapFileInfo.String which is built on the first.
//
//   scripts/goref.sh io/fs format_ref.go
//     FormatFileInfo(hello.go) = "-rw-r--r-- 100 0001-01-01 00:00:00 hello.go"
//     FormatFileInfo(subdir)   = "dr-xr-xr-x 0 0001-01-01 00:00:00 subdir/"
//     FormatDirEntry(hello.go) = "- hello.go"
//     FormatDirEntry(subdir)   = "d subdir/"
//
// This file used to carry a KNOWN DIVERGENCE: the timestamps read 1970
// rather than 0001, because goish's `Time` stored `sec` as UNIX seconds
// and its zero was the epoch. `time` now counts from the absolute zero
// year as Go's does, so these lines are byte-for-byte Go's and the
// divergence is gone.
//
// The detail worth pinning is FormatDirEntry's nine-character
// truncation. Type() returns only the type bits, but its String() still
// renders nine permission positions as dashes — so without the strip a
// directory would print as "d--------- subdir/" instead of "d subdir/".
// Both a directory and a regular file are checked, because the strip is
// only visible against the full-width rendering FormatFileInfo gives.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{__shim_map_file_info_string, MapFS, MapFile};
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    let mut a = MapFile::default();
    a.Data = slice::__from_vec(alloc::vec![0u8; 100]);
    a.Mode = fs::FileMode(0o644);
    m.Set(s("hello.go"), Arc::new(a));
    let mut b = MapFile::default();
    b.Data = slice::__from_vec(b"y".to_vec());
    b.Mode = fs::FileMode(0o600);
    m.Set(s("subdir/x"), Arc::new(b));
    return MapFS(m);
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let fsys = newfs();

    // 1. FormatFileInfo on a regular file: mode, size, mtime, name.
    //    Timestamp is goish's zero (1970), not Go's (0001) — see above.
    {
        let (st, err) = fs::Stat(&fsys, s("hello.go"));
        if err != errors::nil {
            fmt::Println!("[ 1] FormatFileInfo file       FAIL (stat)");
            failed += 1;
        } else {
            let got = fs::FormatFileInfo(st.as_ref());
            if got == s("-rw-r--r-- 100 0001-01-01 00:00:00 hello.go") {
                fmt::Println!("[ 1] FormatFileInfo file       PASS");
            } else {
                fmt::Println!("[ 1] FormatFileInfo file       FAIL [", got, "]");
                failed += 1;
            }
        }
    }

    // 2. A directory gets a trailing slash, and the synthesised dir
    //    mode Go reports for a MapFS parent.
    {
        let (st, err) = fs::Stat(&fsys, s("subdir"));
        if err != errors::nil {
            fmt::Println!("[ 2] FormatFileInfo dir        FAIL (stat)");
            failed += 1;
        } else {
            let got = fs::FormatFileInfo(st.as_ref());
            if got == s("dr-xr-xr-x 0 0001-01-01 00:00:00 subdir/") {
                fmt::Println!("[ 2] FormatFileInfo dir        PASS");
            } else {
                fmt::Println!("[ 2] FormatFileInfo dir        FAIL [", got, "]");
                failed += 1;
            }
        }
    }

    // 3. FormatDirEntry strips the nine permission positions. Without
    //    the strip a directory renders "d--------- subdir/".
    {
        let (entries, err) = fs::ReadDir(&fsys, s("."));
        if err != errors::nil {
            fmt::Println!("[ 3] FormatDirEntry            FAIL (readdir)");
            failed += 1;
        } else {
            let mut got_file = s("");
            let mut got_dir = s("");
            for i in 0..entries.Len() {
                let e = entries[i].clone();
                let line = fs::FormatDirEntry(e.as_ref());
                if e.Name() == s("hello.go") {
                    got_file = line;
                } else if e.Name() == s("subdir") {
                    got_dir = line;
                }
            }
            if got_file == s("- hello.go") && got_dir == s("d subdir/") {
                fmt::Println!("[ 3] FormatDirEntry strips 9   PASS");
            } else {
                fmt::Println!(
                    "[ 3] FormatDirEntry            FAIL [",
                    got_file,
                    "] [",
                    got_dir,
                    "]"
                );
                failed += 1;
            }
        }
    }

    // 4. mapFileInfo.String is FormatFileInfo of itself.
    {
        let (got, ok) = __shim_map_file_info_string(&fsys, s("hello.go"));
        if ok && got == s("-rw-r--r-- 100 0001-01-01 00:00:00 hello.go") {
            fmt::Println!("[ 4] mapFileInfo.String        PASS");
        } else {
            fmt::Println!("[ 4] mapFileInfo.String        FAIL [", got, "]");
            failed += 1;
        }
    }

    // 5. MapFS.Sub yields a filesystem rooted at the subdirectory.
    {
        let arc = alloc::sync::Arc::new(newfs());
        let (sub, err) = arc.Sub(s("subdir"));
        if err != errors::nil {
            fmt::Println!("[ 5] MapFS.Sub                 FAIL (sub)");
            failed += 1;
        } else {
            let (data, rerr) = fs::ReadFile(sub.as_ref(), s("x"));
            if rerr == errors::nil && string::from_bytes(data.as_ref()) == s("y") {
                fmt::Println!("[ 5] MapFS.Sub reroots         PASS");
            } else {
                fmt::Println!("[ 5] MapFS.Sub reroots         FAIL");
                failed += 1;
            }
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
