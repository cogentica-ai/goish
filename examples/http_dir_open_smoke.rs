// http_dir_open_smoke — http.Dir as an http.FileSystem
// (net/http/fs.go:77-96), and the os::File -> http::File adapter it
// needs.
//
// Go's Dir.Open returns *os.File, which satisfies http.File outright.
// goish's os::File is two methods short of that shape — Close takes
// &mut self because it owns the fd, and there is no Readdir — and
// http::File hands out &self through an Arc, so fs.rs carries one to
// the other with `osFile`. This checks the carry actually works:
// reading, seeking and stat-ing a real file on disk through the
// interface, not just that it compiles.
//
// It also pins Dir.Open's path safety, which is the reason the
// function is written the way it is:
//
//   * `path.Clean("/" + name)[1:]` collapses any "..", so a request
//     for "../etc/passwd" cannot climb out of the root — it cleans to
//     "etc/passwd" and simply misses.
//   * filepath.Localize rejects a path that is not representable on
//     the local filesystem, answering errInvalidUnsafePath, which
//     toHTTPError maps to 404 rather than 500 so the failure is
//     indistinguishable from a missing file.
//   * A missing file keeps fs.ErrNotExist identity through
//     mapOpenError.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::io::fs as iofs;
use goish::net::http::fs::{FileSystem, NewDir};
use goish::os;
use goish::{errors, fmt, string, syscall};

fn buf(n: usize) -> slice<goish::types::byte> {
    return slice::__from_vec(alloc::vec![0u8; n]);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // Lay down a small tree under a temp root.
    let root = string("/tmp/goish_dir_open_smoke");
    let _ = os::RemoveAll(root.clone());
    let err = os::MkdirAll(root.clone() + "/sub", 0o755);
    if err != goish::nil {
        fmt::Println!("setup: MkdirAll failed: ", err);
        syscall::Exit(1);
    }
    let werr = os::WriteFile(root.clone() + "/hello.txt", goish::convert::bytes(string("Hello, world.")), 0o644);
    if werr != goish::nil {
        fmt::Println!("setup: WriteFile failed: ", werr);
        syscall::Exit(1);
    }
    let _ = os::WriteFile(root.clone() + "/sub/deep.txt", goish::convert::bytes(string("deep")), 0o644);

    let d = NewDir(root.clone());

    // 1. Open + Read a real file through the http::File interface.
    {
        let (f, err) = d.Open(string("/hello.txt"));
        if err != goish::nil {
            fmt::Println!("[1] Open  FAIL err=", err);
            failed += 1;
        } else {
            let mut b = buf(32);
            let (n, _e) = f.Read(&mut b);
            let got = string::from_bytes(&b.slice(0, n));
            let _ = f.Close();
            if got == "Hello, world." {
                fmt::Println!("[1] Dir.Open + Read through http::File  PASS");
            } else {
                fmt::Println!("[1] Read  FAIL got=", got);
                failed += 1;
            }
        }
    }

    // 2. Seek then Read — the adapter's &self Seek reaching os::File.
    {
        let (f, err) = d.Open(string("/hello.txt"));
        if err != goish::nil {
            fmt::Println!("[2] Open  FAIL err=", err);
            failed += 1;
        } else {
            let (pos, serr) = f.Seek(7, goish::io::SeekStart);
            let mut b = buf(32);
            let (n, _e) = f.Read(&mut b);
            let got = string::from_bytes(&b.slice(0, n));
            let _ = f.Close();
            if serr == goish::nil && pos == 7 && got == "world." {
                fmt::Println!("[2] Seek through the adapter  PASS");
            } else {
                fmt::Println!("[2] Seek  FAIL pos=", pos, " got=", got);
                failed += 1;
            }
        }
    }

    // 3. Stat reports the real size.
    {
        let (f, err) = d.Open(string("/hello.txt"));
        if err != goish::nil {
            fmt::Println!("[3] Open  FAIL");
            failed += 1;
        } else {
            let (fi, serr) = f.Stat();
            let ok = serr == goish::nil && fi.Size() == 13 && !fi.IsDir();
            let _ = f.Close();
            if ok {
                fmt::Println!("[3] Stat through the adapter  PASS");
            } else {
                fmt::Println!("[3] Stat  FAIL");
                failed += 1;
            }
        }
    }

    // 4. Readdir over the root — two entries, hello.txt and sub.
    {
        let (f, err) = d.Open(string("/"));
        if err != goish::nil {
            fmt::Println!("[4] Open(/)  FAIL err=", err);
            failed += 1;
        } else {
            let (infos, rerr) = f.Readdir(-1);
            let _ = f.Close();
            if rerr == goish::nil && infos.Len() == 2 {
                fmt::Println!("[4] Readdir over the root  PASS");
            } else {
                fmt::Println!("[4] Readdir  FAIL n=", infos.Len(), " err=", rerr);
                failed += 1;
            }
        }
    }

    // 5. A missing file keeps fs::ErrNotExist through mapOpenError.
    {
        let (_f, err) = d.Open(string("/absent.txt"));
        if err != goish::nil && errors::Is(err.clone(), iofs::ErrNotExist) {
            fmt::Println!("[5] missing file keeps fs::ErrNotExist  PASS");
        } else {
            fmt::Println!("[5] missing file  FAIL err=", err);
            failed += 1;
        }
    }

    // 6. "../" cannot climb out of the root: Clean folds it away, so
    //    the request lands inside the root and simply misses.
    {
        let (_f, err) = d.Open(string("/../../../etc/passwd"));
        if err != goish::nil {
            fmt::Println!("[6] parent traversal is contained  PASS");
        } else {
            fmt::Println!("[6] parent traversal ESCAPED  FAIL");
            failed += 1;
        }
    }

    // 7. Nested path resolves.
    {
        let (f, err) = d.Open(string("/sub/deep.txt"));
        if err != goish::nil {
            fmt::Println!("[7] nested Open  FAIL err=", err);
            failed += 1;
        } else {
            let (fi, _e) = f.Stat();
            let ok = fi.Size() == 4;
            let _ = f.Close();
            if ok {
                fmt::Println!("[7] nested path resolves  PASS");
            } else {
                fmt::Println!("[7] nested path  FAIL");
                failed += 1;
            }
        }
    }

    let _ = os::RemoveAll(root);

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 7");
        syscall::Exit(1);
    }
}
