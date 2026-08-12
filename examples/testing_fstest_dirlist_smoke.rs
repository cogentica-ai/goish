// testing_fstest_dirlist_smoke — fstest's checkDirList.
//
// Two independent jobs, both asserted:
//
//  1. Every entry's IsDir() must agree with Type() & ModeDir. An entry
//     that claims to be a directory through one accessor and not the
//     other is internally inconsistent, and callers pick one or the
//     other — so half of them would silently be wrong with no way to
//     tell which half.
//
//  2. Two listings are diffed by name and rendered as +/- lines, sorted
//     by name with '+' before '-' so a rename reads as an adjacent
//     pair instead of two entries scattered apart.
//
// The lying entry in check 3 is a hand-built DirEntry rather than
// anything MapFS produces — MapFS is consistent, which is exactly why
// it cannot exercise the check.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::fs::{self, DirEntry, FileInfo};
use goish::testing::fstest::{fsTester, MapFile, MapFS};
use goish::types::int;
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// A DirEntry whose IsDir() and Type() deliberately disagree.
struct LyingEntry {
    name: string,
    says_dir: bool,
    type_bits: fs::FileMode,
}

impl DirEntry for LyingEntry {
    fn Name(&self) -> string {
        return self.name.clone();
    }
    fn IsDir(&self) -> bool {
        return self.says_dir;
    }
    fn Type(&self) -> fs::FileMode {
        return self.type_bits;
    }
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, errors::error) {
        // checkDirList never calls Info(); this exists only to satisfy
        // the trait, and reports the error a real entry would.
        return (
            Arc::new(NoInfo {}),
            errors::New(s("Info not available")),
        );
    }
}

/// Placeholder FileInfo for LyingEntry::Info, which is never reached.
struct NoInfo {}

impl FileInfo for NoInfo {
    fn Name(&self) -> string {
        return s("");
    }
    fn Size(&self) -> int {
        return 0;
    }
    fn Mode(&self) -> fs::FileMode {
        return fs::FileMode(0);
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

fn newfs() -> MapFS {
    let mut m: goish::map<string, Arc<MapFile>> = goish::map::new();
    for n in ["a.txt", "b.txt", "sub/c.txt"].iter() {
        let mut f = MapFile::default();
        f.Data = slice::__from_vec(b"x".to_vec());
        m.Set(s(n), Arc::new(f));
    }
    return MapFS(m);
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

    // 1. A listing compared against itself produces no diff.
    {
        let mut t = fsTester::default();
        t.checkDirList(s("."), "self", &entries, &entries);
        if t.Errors().Len() == 0 {
            fmt::Println!("[ 1] identical lists agree     PASS");
        } else {
            fmt::Println!("[ 1] identical lists agree     FAIL ", t.Errors()[0].Error());
            failed += 1;
        }
    }

    // 2. A missing entry on either side is reported.
    {
        let mut shorter: slice<Arc<dyn DirEntry + Send + Sync>> = slice::new();
        for i in 0..(entries.Len() - 1) {
            shorter = goish::append!(shorter, entries[i].clone());
        }
        let mut t = fsTester::default();
        t.checkDirList(s("."), "shorter", &entries, &shorter);
        let one_way = t.Errors().Len() == 1;

        let mut t2 = fsTester::default();
        t2.checkDirList(s("."), "longer", &shorter, &entries);
        let other_way = t2.Errors().Len() == 1;

        if one_way && other_way {
            fmt::Println!("[ 2] missing entry both ways   PASS");
        } else {
            fmt::Println!("[ 2] missing entry both ways   FAIL");
            failed += 1;
        }
    }

    // 3. An entry whose IsDir() contradicts its Type() bits is caught,
    //    in both directions of the contradiction.
    {
        // Claims directory, but carries no ModeDir bit.
        let liar_a: Arc<dyn DirEntry + Send + Sync> = Arc::new(LyingEntry {
            name: s("liar"),
            says_dir: true,
            type_bits: fs::FileMode(0),
        });
        let mut la: slice<Arc<dyn DirEntry + Send + Sync>> = slice::new();
        la = goish::append!(la, liar_a);
        let mut t = fsTester::default();
        t.checkDirList(s("."), "liar-a", &la, &la);
        let caught_a = t.Errors().Len() >= 1;

        // Claims file, but carries ModeDir.
        let liar_b: Arc<dyn DirEntry + Send + Sync> = Arc::new(LyingEntry {
            name: s("liar"),
            says_dir: false,
            type_bits: fs::ModeDir,
        });
        let mut lb: slice<Arc<dyn DirEntry + Send + Sync>> = slice::new();
        lb = goish::append!(lb, liar_b);
        let mut t2 = fsTester::default();
        t2.checkDirList(s("."), "liar-b", &lb, &lb);
        let caught_b = t2.Errors().Len() >= 1;

        if caught_a && caught_b {
            fmt::Println!("[ 3] IsDir/Type mismatch caught PASS");
        } else {
            fmt::Println!("[ 3] IsDir/Type mismatch caught FAIL");
            failed += 1;
        }
    }

    // 4. MapFS's own entries are internally consistent — the check
    //    finds nothing to complain about on a real filesystem.
    {
        let (sub, serr) = fs::ReadDir(&fsys, s("sub"));
        let mut t = fsTester::default();
        if serr == errors::nil {
            t.checkDirList(s("sub"), "consistency", &sub, &sub);
        }
        let _n: int = 0;
        if serr == errors::nil && t.Errors().Len() == 0 {
            fmt::Println!("[ 4] MapFS entries consistent  PASS");
        } else {
            fmt::Println!("[ 4] MapFS entries consistent  FAIL");
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
