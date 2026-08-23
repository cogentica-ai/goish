// testing_fstest_stat_smoke — fstest's checkStat.
//
// Four renderings of the same file must agree, and they exist because
// four different code paths produce them: the DirEntry from ReadDir,
// entry.Info(), Open().Stat(), and the free fs.Stat. A filesystem that
// assembles any one of them separately — a very common shortcut —
// drifts here first, and nowhere else.
//
// So the interesting assertion is not "MapFS passes" (check 1) but
// "a filesystem whose paths disagree is caught" (check 3). Without the
// second, a checkStat that compared nothing would pass the first.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs::{self, DirEntry, FileInfo};
use goish::testing::fstest::{fsTester, MapFS, MapFile};
use goish::types::int;
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    for n in ["a.txt", "b.txt"].iter() {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(b"hello".to_vec());
        f.Mode = fs::FileMode(0o644);
        m.Set(s(n), Arc::new(f));
    }
    return MapFS(m);
}

/// A FileInfo that reports a size nobody else agrees with.
struct WrongSizeInfo {
    name: string,
}

impl FileInfo for WrongSizeInfo {
    fn Name(&self) -> string {
        return self.name.clone();
    }
    fn Size(&self) -> int {
        return 9999; // the lie
    }
    fn Mode(&self) -> fs::FileMode {
        return fs::FileMode(0o644);
    }
    fn ModTime(&self) -> goish::time::Time {
        return goish::time::Time::default();
    }
    fn IsDir(&self) -> bool {
        return false;
    }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        return Arc::new(());
    }
}

/// A DirEntry whose Info() disagrees with what Open().Stat() will say.
struct DriftingEntry {
    name: string,
}

impl DirEntry for DriftingEntry {
    fn Name(&self) -> string {
        return self.name.clone();
    }
    fn IsDir(&self) -> bool {
        return false;
    }
    fn Type(&self) -> fs::FileMode {
        return fs::FileMode(0);
    }
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, errors::error) {
        return (
            Arc::new(WrongSizeInfo {
                name: self.name.clone(),
            }),
            errors::nil,
        );
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let fsys = newfs();
    let (entries, err) = fs::ReadDir(&fsys, s("."));
    if err != errors::nil {
        fmt::Println!("ReadDir failed");
        syscall::Exit(1);
    }

    // 1. MapFS's four paths agree for every entry.
    {
        let mut t = fsTester::default();
        for i in 0..entries.Len() {
            let e = entries[i].clone();
            t.checkStat(&fsys, e.Name(), e.as_ref());
        }
        if t.Errors().Len() == 0 {
            fmt::Println!("[ 1] MapFS paths agree         PASS");
        } else {
            fmt::Println!(
                "[ 1] MapFS paths agree         FAIL ",
                t.Errors()[0].Error()
            );
            failed += 1;
        }
    }

    // 2. A path that does not exist is reported as an Open failure,
    //    and checkStat returns rather than pressing on into a nil Stat.
    {
        let mut t = fsTester::default();
        let e = entries[0].clone();
        t.checkStat(&fsys, s("nope.txt"), e.as_ref());
        let errs = t.Errors();
        let msg: &str = if errs.Len() > 0 {
            // Only the Open error, not a cascade.
            "ok"
        } else {
            "none"
        };
        if errs.Len() == 1 && msg == "ok" {
            fmt::Println!("[ 2] missing path: one error   PASS");
        } else {
            fmt::Println!(
                "[ 2] missing path: one error   FAIL got ",
                errs.Len() as i64
            );
            failed += 1;
        }
    }

    // 3. An entry whose Info() disagrees with Open().Stat() is caught.
    //    This is the direction that proves checkStat compares at all.
    {
        let drift: Arc<dyn DirEntry + Send + Sync> = Arc::new(DriftingEntry { name: s("a.txt") });
        let mut t = fsTester::default();
        t.checkStat(&fsys, s("a.txt"), drift.as_ref());
        if t.Errors().Len() >= 1 {
            fmt::Println!("[ 3] drifting entry caught     PASS");
        } else {
            fmt::Println!("[ 3] drifting entry caught     FAIL");
            failed += 1;
        }
    }

    // 4. fs.Stat and Open().Stat() agree on a real file — the last of
    //    the four paths, checked directly so a failure here is
    //    distinguishable from a DirEntry problem.
    {
        let (a, e1) = fs::Stat(&fsys, s("a.txt"));
        let (f, e2) = fs::FS::Open(&fsys, s("a.txt"));
        if e1 != errors::nil || e2 != errors::nil {
            fmt::Println!("[ 4] fs.Stat vs Open().Stat()  FAIL (open)");
            failed += 1;
        } else {
            let (b, e3) = f.Stat();
            f.Close();
            if e3 == errors::nil && a.Size() == b.Size() && a.Name() == b.Name() {
                fmt::Println!("[ 4] fs.Stat vs Open().Stat()  PASS");
            } else {
                fmt::Println!("[ 4] fs.Stat vs Open().Stat()  FAIL");
                failed += 1;
            }
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
