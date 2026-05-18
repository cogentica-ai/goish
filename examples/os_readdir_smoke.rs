// os_readdir_smoke — exercise os::ReadDir + DirEntry
// (slim line-by-line port of os/dir.go:114).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::os;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Create a fresh tmp directory to read.
    let dir = string("/tmp/goish-readdir-smoke");
    // Best-effort cleanup-then-recreate using mkdir via writing files.
    // We can't mkdir yet; rely on writing a few files into an existing dir.
    // Use /tmp directly for readdir, but assert specific files exist
    // after creating them.
    let f1 = string("/tmp/goish-readdir-smoke-file-a.txt");
    let f2 = string("/tmp/goish-readdir-smoke-file-b.txt");
    let _ = os::WriteFile(f1.clone(), bytes("a"), 0o644);
    let _ = os::WriteFile(f2.clone(), bytes("b"), 0o644);

    // 1. ReadDir on /tmp returns entries; ours are present.
    {
        let (entries, err) = os::ReadDir(string("/tmp"));
        if !err.IsNil() {
            Println!("[ 1] ReadDir /tmp              FAIL err");
            failed += 1;
        } else {
            let mut found_a = false;
            let mut found_b = false;
            for i in 0..entries.Len() {
                let e = entries[i].clone();
                if e.Name() == "goish-readdir-smoke-file-a.txt" {
                    found_a = true;
                }
                if e.Name() == "goish-readdir-smoke-file-b.txt" {
                    found_b = true;
                }
            }
            if found_a && found_b {
                Println!("[ 1] ReadDir /tmp              PASS", entries.Len(), "entries");
            } else {
                Println!(
                    "[ 1] ReadDir /tmp              FAIL a={} b={}",
                    found_a, found_b
                );
                failed += 1;
            }
        }
    }

    // 2. Entries are sorted by name.
    {
        let (entries, _) = os::ReadDir(string("/tmp"));
        let mut sorted = true;
        let mut prev = string::new();
        for i in 0..entries.Len() {
            let e = entries[i].clone();
            if i > 0 && !(prev < e.Name()) && prev != e.Name() {
                sorted = false;
                break;
            }
            prev = e.Name();
        }
        if sorted {
            Println!("[ 2] entries sorted            PASS");
        } else {
            Println!("[ 2] entries sorted            FAIL");
            failed += 1;
        }
    }

    // 3. ReadDir on a non-existent path → error.
    {
        let (_e, err) = os::ReadDir(string("/tmp/goish-no-such-dir-12345"));
        if !err.IsNil() {
            Println!("[ 3] missing dir → err         PASS");
        } else {
            Println!("[ 3] missing dir → err         FAIL");
            failed += 1;
        }
    }

    // 4. "." and ".." are skipped.
    {
        let (entries, _) = os::ReadDir(string("/tmp"));
        let mut has_dot = false;
        let mut has_dotdot = false;
        for i in 0..entries.Len() {
            let e = entries[i].clone();
            if e.Name() == "." {
                has_dot = true;
            }
            if e.Name() == ".." {
                has_dotdot = true;
            }
        }
        if !has_dot && !has_dotdot {
            Println!("[ 4] . and .. skipped          PASS");
        } else {
            Println!("[ 4] . and .. skipped          FAIL dot={} dotdot={}", has_dot, has_dotdot);
            failed += 1;
        }
    }

    // 5. d_type → FileMode mapping: regular files have Type() with no
    //    ModeDir bit set; ../tmp itself when listed as parent has
    //    ModeDir.
    {
        let (entries, _) = os::ReadDir(string("/tmp"));
        let mut reg_ok = false;
        for i in 0..entries.Len() {
            let e = entries[i].clone();
            if e.Name() == "goish-readdir-smoke-file-a.txt" && !e.IsDir() {
                reg_ok = true;
                break;
            }
        }
        if reg_ok {
            Println!("[ 5] regular file !IsDir       PASS");
        } else {
            Println!("[ 5] regular file !IsDir       FAIL");
            failed += 1;
        }
    }

    // 6. DirEntry.Info() lstats the entry — Go-faithful: os.DirEntry is
    //    the fs.DirEntry interface, and unixDirent.Info() re-stats the
    //    path. The reported size must match the file we wrote ("a" = 1).
    {
        let (entries, _) = os::ReadDir(string("/tmp"));
        let mut info_ok = false;
        for i in 0..entries.Len() {
            let e = entries[i].clone();
            if e.Name() == "goish-readdir-smoke-file-a.txt" {
                let (info, ierr) = e.Info();
                if ierr.IsNil() && info.Size() == 1 && !info.IsDir() {
                    info_ok = true;
                }
                break;
            }
        }
        if info_ok {
            Println!("[ 6] DirEntry.Info() lstat      PASS");
        } else {
            Println!("[ 6] DirEntry.Info() lstat      FAIL");
            failed += 1;
        }
    }

    let _ = dir;

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 6", failed);
        syscall::Exit(1);
    }
}
