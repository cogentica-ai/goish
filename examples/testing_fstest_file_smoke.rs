// testing_fstest_file_smoke — fstest's checkFile and openDir.
//
// checkFile does three things beyond "the bytes come back", and each is
// a real failure mode:
//
//  * Closing twice must not crash. Go says so explicitly and discards
//    the second return value. An FS that double-frees on a second Close
//    breaks every `defer f.Close()` written next to an explicit one.
//  * fs.ReadFile must agree with Open + read-to-end — two code paths,
//    one answer.
//  * Mutating the slice ReadFile returned must not change what the next
//    call returns. An implementation handing out its internal buffer
//    passes every other check here and lets a reader corrupt the
//    filesystem from the outside. Check 3 is that one, and it is the
//    reason this check exists at all.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs;
use goish::testing::fstest::{fsTester, MapFile, MapFS};
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    let mut a = MapFile::default();
    a.Data = slice::__from_vec(b"hello world".to_vec());
    m.Set(s("a.txt"), Arc::new(a));
    let mut b = MapFile::default();
    b.Data = slice::__from_vec(b"nested".to_vec());
    m.Set(s("sub/b.txt"), Arc::new(b));
    return MapFS(m);
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let fsys = newfs();

    // 1. A conforming file passes every part of checkFile.
    {
        let mut t = fsTester::default();
        t.checkFile(&fsys, s("a.txt"));
        if t.Errors().Len() == 0 {
            fmt::Println!("[ 1] conforming file           PASS");
        } else {
            fmt::Println!("[ 1] conforming file           FAIL ", t.Errors()[0].Error());
            failed += 1;
        }
    }

    // 2. Closing twice does not crash — reaching this line at all is
    //    the assertion, since a double-free would have aborted above.
    {
        let (f, err) = fs::FS::Open(&fsys, s("a.txt"));
        if err == errors::nil {
            f.Close();
            f.Close();
            f.Close();
            fmt::Println!("[ 2] triple Close survives     PASS");
        } else {
            fmt::Println!("[ 2] triple Close survives     FAIL");
            failed += 1;
        }
    }

    // 3. Mutating what ReadFile returned must not affect the next call.
    //    This is the aliasing bug checkFile exists to catch.
    {
        let (mut d1, e1) = fs::ReadFile(&fsys, s("a.txt"));
        for i in 0..d1.Len() {
            d1[i] = d1[i].wrapping_add(1);
        }
        let (d2, e2) = fs::ReadFile(&fsys, s("a.txt"));
        let intact = e1 == errors::nil
            && e2 == errors::nil
            && string::from_bytes(d2.as_ref()) == s("hello world");
        if intact {
            fmt::Println!("[ 3] ReadFile does not alias   PASS");
        } else {
            fmt::Println!("[ 3] ReadFile does not alias   FAIL");
            failed += 1;
        }
    }

    // 4. Open + read-to-end agrees with fs.ReadFile.
    {
        let (viaread, e1) = fs::ReadFile(&fsys, s("sub/b.txt"));
        let mut t = fsTester::default();
        t.checkFile(&fsys, s("sub/b.txt"));
        if e1 == errors::nil
            && string::from_bytes(viaread.as_ref()) == s("nested")
            && t.Errors().Len() == 0
        {
            fmt::Println!("[ 4] two read paths agree      PASS");
        } else {
            fmt::Println!("[ 4] two read paths agree      FAIL");
            failed += 1;
        }
    }

    // 5. openDir returns a directory's entries, and reports a
    //    non-directory rather than pretending.
    {
        let mut t = fsTester::default();
        let (entries, ok) = t.openDir(&fsys, s("sub"));
        let dir_ok = ok && entries.Len() == 1 && t.Errors().Len() == 0;

        let mut t2 = fsTester::default();
        let (_, ok2) = t2.openDir(&fsys, s("a.txt"));
        // A regular file is not a ReadDirFile, so this must fail loudly.
        let file_rejected = !ok2 && t2.Errors().Len() == 1;

        if dir_ok && file_rejected {
            fmt::Println!("[ 5] openDir dir vs file       PASS");
        } else {
            fmt::Println!("[ 5] openDir dir vs file       FAIL");
            failed += 1;
        }
    }

    // 6. checkFile records the file it visited, which is what the
    //    walk in TestFS accumulates.
    {
        let mut t = fsTester::default();
        t.checkFile(&fsys, s("a.txt"));
        let (_, files) = t.Found();
        if files.Len() == 1 && files[0] == s("a.txt") {
            fmt::Println!("[ 6] visited file recorded     PASS");
        } else {
            fmt::Println!("[ 6] visited file recorded     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
