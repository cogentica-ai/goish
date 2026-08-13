// http_iofs_smoke — net/http's fs.FS adapter: http.FS, ioFS.Open,
// ioFile and mapOpenError, ported from Go 1.25.5 net/http/fs.go.
//
// Covers:
//   1. http::FS(fsys).Open("/hello.txt") — the leading slash is
//      stripped (fs.go:888-892) so an fs.FS rooted at "." resolves,
//      and Stat() reports the right size.
//   2. Open("/") maps to "." — the FS root, a directory.
//   3. A missing file propagates the underlying fs.ErrNotExist
//      unchanged (mapOpenError's early return, fs.go:50-52).
//   4. A path below a regular file — "hello.txt/nope" — still reports
//      fs.ErrNotExist. This exercises mapOpenError's EARLY RETURN
//      (fs.go:50-52), not its prefix walk: MapFS already answers
//      ErrNotExist here. The walk (fs.go:55-66) only runs for a
//      filesystem that reports ENOTDIR instead, which is os.DirFS, not
//      MapFS — so the walk branch is unexercised and stays that way
//      until there is a DirFS-backed case to hang it on.
//   5. A nested path resolves through ioFS.
//
//   6. ioFile.Seek reaches the underlying file. Go asserts
//      f.file.(io.Seeker); goish's io::Seeker takes &mut self, which
//      an Arc<dyn fs::File> cannot give, so the assertion targets
//      fs::SeekableFile — the same capability with the &self receiver
//      this module already uses for Read. A cast! that is not
//      registered is a SILENT miss, so this case exists specifically
//      to prove the success branch is reachable, not just compiled.
//
//   7. ioFile.Readdir over a directory. MapFS's directory handle does
//      implement fs::ReadDirFile and is registered for cast!, so this
//      is the success branch, not the errMissingReadDir one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::goslice::slice;
use goish::io::fs::{self, FileMode};
use goish::net::http;
use goish::testing::fstest::{MapFile, MapFS};
use goish::time;
use goish::{errors, fmt, string, syscall};

fn mf(data: &str) -> Arc<MapFile> {
    return Arc::new(MapFile {
        Data: slice::__from_vec(data.as_bytes().to_vec()),
        Mode: FileMode::default(),
        ModTime: time::Time::default(),
        Sys: None,
    });
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let mut n = 0;

    let mut m = MapFS::new();
    m.0.Set(string("hello.txt"), mf("Hello, world."));
    m.0.Set(string("sub/deep.txt"), mf("deep"));
    let fsys: Arc<dyn fs::FS + Send + Sync> = Arc::new(m);

    let hfs = http::FS(fsys);

    // 1. A rooted request path opens, and Stat sees the real size.
    n += 1;
    {
        let (f, err) = hfs.Open(string("/hello.txt"));
        if err != goish::nil {
            fmt::Println!("[1] Open(/hello.txt)  FAIL err=", err);
            failed += 1;
        } else {
            let (fi, serr) = f.Stat();
            if serr != goish::nil || fi.Size() != 13 {
                fmt::Println!("[1] Stat  FAIL size=", fi.Size());
                failed += 1;
            } else {
                fmt::Println!("[1] http::FS Open + Stat through ioFS/ioFile  PASS");
            }
        }
    }

    // 2. "/" is rewritten to "." — the FS root.
    n += 1;
    {
        let (f, err) = hfs.Open(string("/"));
        if err != goish::nil {
            fmt::Println!("[2] Open(/)  FAIL err=", err);
            failed += 1;
        } else {
            let (fi, serr) = f.Stat();
            if serr != goish::nil || !fi.IsDir() {
                fmt::Println!("[2] Open(/) is not a directory  FAIL");
                failed += 1;
            } else {
                fmt::Println!("[2] Open(\"/\") maps to the FS root  PASS");
            }
        }
    }

    // 3. A genuinely missing file keeps fs.ErrNotExist identity.
    n += 1;
    {
        let (_f, err) = hfs.Open(string("/absent.txt"));
        if err != goish::nil && errors::Is(err.clone(), fs::ErrNotExist) {
            fmt::Println!("[3] missing file keeps fs::ErrNotExist  PASS");
        } else {
            fmt::Println!("[3] missing file  FAIL err=", err);
            failed += 1;
        }
    }

    // 4. A path below a regular file still reports ErrNotExist. See
    //    the header note: this is mapOpenError's early return, not its
    //    prefix walk.
    n += 1;
    {
        let (_f, err) = hfs.Open(string("/hello.txt/nope"));
        if err != goish::nil && errors::Is(err.clone(), fs::ErrNotExist) {
            fmt::Println!("[4] path below a regular file keeps fs::ErrNotExist  PASS");
        } else {
            fmt::Println!("[4] mapOpenError  FAIL err=", err);
            failed += 1;
        }
    }

    // 5. A nested path resolves through ioFS.
    n += 1;
    {
        let (f, err) = hfs.Open(string("/sub/deep.txt"));
        if err != goish::nil {
            fmt::Println!("[5] Open(/sub/deep.txt)  FAIL err=", err);
            failed += 1;
        } else {
            let (fi, _e) = f.Stat();
            if fi.Size() == 4 {
                fmt::Println!("[5] nested path opens through ioFS  PASS");
            } else {
                fmt::Println!("[5] nested path  FAIL size=", fi.Size());
                failed += 1;
            }
        }
    }

    // 6. Seek through the adapter actually reaches the file.
    n += 1;
    {
        let (f, err) = hfs.Open(string("/hello.txt"));
        if err != goish::nil {
            fmt::Println!("[6] Open  FAIL err=", err);
            failed += 1;
        } else {
            // Seek to 7 ("world."), then read the rest.
            let (pos, serr) = f.Seek(7, goish::io::SeekStart);
            let mut buf: slice<goish::types::byte> = slice::__from_vec(alloc::vec![0u8; 16]);
            let (rn, _rerr) = f.Read(&mut buf);
            let got = goish::string::from_bytes(&buf.slice(0, rn));
            if serr == goish::nil && pos == 7 && got == "world." {
                fmt::Println!("[6] ioFile.Seek reaches the file  PASS");
            } else {
                fmt::Println!("[6] ioFile.Seek  FAIL pos=", pos, " got=", got, " err=", serr);
                failed += 1;
            }
        }
    }

    // 7. Readdir over the FS root.
    n += 1;
    {
        let (d, err) = hfs.Open(string("/"));
        if err != goish::nil {
            fmt::Println!("[7] Open(/)  FAIL err=", err);
            failed += 1;
        } else {
            let (infos, rerr) = d.Readdir(-1);
            // MapFS holds hello.txt and sub/deep.txt, so the root has
            // two entries: the file and the synthesized "sub" dir.
            if rerr == goish::nil && infos.Len() == 2 {
                fmt::Println!("[7] ioFile.Readdir lists the root  PASS");
            } else {
                fmt::Println!("[7] ioFile.Readdir  FAIL n=", infos.Len(), " err=", rerr);
                failed += 1;
            }
        }
    }

    if failed == 0 {
        fmt::Println!("ok ", n, "/", n);
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of ", n);
        syscall::Exit(1);
    }
}
