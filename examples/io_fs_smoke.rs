// io_fs_smoke — exercise io/fs (FileMode, ValidPath, PathError, sentinels).
// (io/fs/fs.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::error;
use goish::errors;
use goish::fmt;
use goish::io::fs;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. FileMode.String for plain file (rw-r--r--).
    {
        let m = fs::FileMode(0o644);
        let s = m.String();
        if s == string("-rw-r--r--") {
            fmt::Println!("[ 1] String 0644             PASS");
        } else {
            fmt::Println!("[ 1] String 0644             FAIL got '{}'", s);
            failed += 1;
        }
    }

    // 2. FileMode.String for directory (drwxr-xr-x).
    {
        let m = fs::FileMode(fs::ModeDir.0 | 0o755);
        let s = m.String();
        if s == string("drwxr-xr-x") {
            fmt::Println!("[ 2] String dir              PASS");
        } else {
            fmt::Println!("[ 2] String dir              FAIL got '{}'", s);
            failed += 1;
        }
    }

    // 3. FileMode.String for symlink (Lrwxrwxrwx).
    {
        let m = fs::FileMode(fs::ModeSymlink.0 | 0o777);
        let s = m.String();
        if s == string("Lrwxrwxrwx") {
            fmt::Println!("[ 3] String symlink          PASS");
        } else {
            fmt::Println!("[ 3] String symlink          FAIL got '{}'", s);
            failed += 1;
        }
    }

    // 4. IsDir / IsRegular / Perm / Type.
    {
        let dir = fs::FileMode(fs::ModeDir.0 | 0o755);
        let reg = fs::FileMode(0o644);
        let sym = fs::FileMode(fs::ModeSymlink.0 | 0o777);
        let ok = dir.IsDir()
            && !reg.IsDir()
            && !reg.IsRegular() == false  // reg IS regular
            && !dir.IsRegular()
            && !sym.IsRegular()
            && reg.Perm() == fs::FileMode(0o644)
            && dir.Perm() == fs::FileMode(0o755)
            && reg.Type() == fs::FileMode(0)
            && dir.Type() == fs::ModeDir;
        if ok {
            fmt::Println!("[ 4] IsDir/IsRegular/Perm    PASS");
        } else {
            fmt::Println!("[ 4] IsDir/IsRegular/Perm    FAIL");
            failed += 1;
        }
    }

    // 5. ValidPath for legal paths.
    {
        let ok = fs::ValidPath(string("."))
            && fs::ValidPath(string("foo"))
            && fs::ValidPath(string("a/b/c"))
            && fs::ValidPath(string("a/b/c.txt"));
        if ok {
            fmt::Println!("[ 5] ValidPath valid         PASS");
        } else {
            fmt::Println!("[ 5] ValidPath valid         FAIL");
            failed += 1;
        }
    }

    // 6. ValidPath rejects illegal paths.
    {
        let bad = !fs::ValidPath(string(""))
            && !fs::ValidPath(string("/abs"))
            && !fs::ValidPath(string("trail/"))
            && !fs::ValidPath(string("a//b"))
            && !fs::ValidPath(string(".."))
            && !fs::ValidPath(string("a/.."))
            && !fs::ValidPath(string("a/./b"));
        if bad {
            fmt::Println!("[ 6] ValidPath invalid       PASS");
        } else {
            fmt::Println!("[ 6] ValidPath invalid       FAIL");
            failed += 1;
        }
    }

    // 7. PathError formats Op + Path + Err.
    {
        let pe = fs::PathError {
            Op: string("open"),
            Path: string("/foo"),
            Err: fs::ErrNotExist.into(),
        };
        let e = errors::Wrap(pe);
        let msg = e.Error();
        if msg == string("open /foo: file does not exist") {
            fmt::Println!("[ 7] PathError Error fmt     PASS");
        } else {
            fmt::Println!("[ 7] PathError Error fmt     FAIL got '{}'", msg);
            failed += 1;
        }
    }

    // 8. PathError.Unwrap chains errors::Is to sentinel.
    {
        let pe = fs::PathError {
            Op: string("open"),
            Path: string("/x"),
            Err: fs::ErrPermission.into(),
        };
        let e = errors::Wrap(pe);
        if errors::Is(e, fs::ErrPermission) {
            fmt::Println!("[ 8] PathError chains Is     PASS");
        } else {
            fmt::Println!("[ 8] PathError chains Is     FAIL");
            failed += 1;
        }
    }

    // 9. Sentinel singletons compare equal across calls.
    {
        let a: error = fs::ErrNotExist.into();
        let b: error = fs::ErrNotExist.into();
        let c: error = fs::ErrInvalid.into();
        if a == b && a != c {
            fmt::Println!("[ 9] Sentinel identity       PASS");
        } else {
            fmt::Println!("[ 9] Sentinel identity       FAIL");
            failed += 1;
        }
    }

    // 10. ModeType masks correctly: combination of bits.
    {
        let mask = fs::ModeType.0;
        let want = fs::ModeDir.0
            | fs::ModeSymlink.0
            | fs::ModeNamedPipe.0
            | fs::ModeSocket.0
            | fs::ModeDevice.0
            | fs::ModeCharDevice.0
            | fs::ModeIrregular.0;
        if mask == want {
            fmt::Println!("[10] ModeType mask           PASS");
        } else {
            fmt::Println!("[10] ModeType mask           FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
