// testing_fstest_format_smoke — pin fstest's conformance formatters
// against Go 1.25.5.
//
// These three exist so a mismatch prints as two directly comparable
// lines, and formatEntry/formatInfoEntry exist as a *pair*: a DirEntry
// and the FileInfo its Info() returns must render identically, and the
// TestFS conformance check compares exactly those two strings. Check 2
// is that pairing, which is the only reason both functions exist.
//
//   scripts/goref.sh testing/fstest fmtinfo_ref.go
//     formatEntry:     a.txt IsDir=false Type=----------
//     formatInfoEntry: a.txt IsDir=false Type=----------
//     formatEntry:     sub   IsDir=true  Type=d---------
//     formatInfoEntry: sub   IsDir=true  Type=d---------
//     formatInfo(a.txt): name="a.txt" isdir=false mode=-rw-r--r-- size=5
//     errorf x2 -> errors=2, "boom 42", "again x"
//
// Note Type= renders the *type bits only*, so a 0644 regular file shows
// "----------" rather than its permissions, while Mode= in formatInfo
// shows "-rw-r--r--". Conflating the two is the mistake this pins.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{formatEntry, formatInfo, formatInfoEntry, fsTester, MapFile, MapFS};
use goish::{errors, fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, alloc::sync::Arc<MapFile>> = goish::map::new();
    let mut a = MapFile::default();
    a.Data = goish::slice::__from_vec(b"hello".to_vec());
    a.Mode = fs::FileMode(0o644);
    m.Set(s("a.txt"), alloc::sync::Arc::new(a));
    let mut b = MapFile::default();
    b.Data = goish::slice::__from_vec(b"xy".to_vec());
    b.Mode = fs::FileMode(0o600);
    m.Set(s("sub/b.txt"), alloc::sync::Arc::new(b));
    return MapFS(m);
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let fsys = newfs();

    let (entries, err) = fs::ReadDir(&fsys, s("."));
    if err != errors::nil {
        fmt::Println!("ReadDir failed: ", err.Error());
        syscall::Exit(1);
    }

    // 1. formatEntry renders name, IsDir and the TYPE bits — not the
    //    permission bits. A 0644 regular file is "----------".
    {
        let mut got_file = string::from_static("");
        let mut got_dir = string::from_static("");
        for i in 0..entries.Len() {
            let e = &entries[i];
            let line = formatEntry(e.as_ref());
            if e.Name() == s("a.txt") {
                got_file = line;
            } else if e.Name() == s("sub") {
                got_dir = line;
            }
        }
        if got_file == s("a.txt IsDir=false Type=----------")
            && got_dir == s("sub IsDir=true Type=d---------")
        {
            fmt::Println!("[ 1] formatEntry type bits     PASS");
        } else {
            fmt::Println!("[ 1] formatEntry               FAIL [", got_file, "] [", got_dir, "]");
            failed += 1;
        }
    }

    // 2. The pairing that justifies both functions existing: an entry
    //    and its own Info() must format to the same string.
    {
        let mut ok = true;
        for i in 0..entries.Len() {
            let e = &entries[i];
            let (info, ierr) = e.Info();
            if ierr != errors::nil {
                ok = false;
                continue;
            }
            if formatEntry(e.as_ref()) != formatInfoEntry(info.as_ref()) {
                fmt::Println!(
                    "    mismatch [", formatEntry(e.as_ref()),
                    "] vs [", formatInfoEntry(info.as_ref()), "]"
                );
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[ 2] entry and Info() agree    PASS");
        } else {
            fmt::Println!("[ 2] entry and Info() agree    FAIL");
            failed += 1;
        }
    }

    // 3. formatInfo carries the full mode and size — permissions this
    //    time, unlike Type= above.
    {
        let (st, serr) = fs::Stat(&fsys, s("a.txt"));
        if serr != errors::nil {
            fmt::Println!("[ 3] formatInfo                FAIL (stat)");
            failed += 1;
        } else {
            let line = formatInfo(st.as_ref());
            let l: &str = line.as_ref();
            // ModTime is a zero Time here and renders per RFC3339Nano,
            // so match on the stable prefix rather than the timestamp.
            if l.starts_with("a.txt IsDir=false Mode=-rw-r--r-- Size=5 ModTime=") {
                fmt::Println!("[ 3] formatInfo mode+size      PASS");
            } else {
                fmt::Println!("[ 3] formatInfo                FAIL [", line, "]");
                failed += 1;
            }
        }
    }

    // 4. errorf accumulates in order, and Errors() reads them back.
    {
        let mut t = fsTester::default();
        t.errorf(s("boom 42"));
        t.errorf(s("again x"));
        let errs = t.Errors();
        if errs.Len() == 2
            && errs[0].Error() == s("boom 42")
            && errs[1].Error() == s("again x")
        {
            fmt::Println!("[ 4] errorf accumulates        PASS");
        } else {
            fmt::Println!("[ 4] errorf accumulates        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
