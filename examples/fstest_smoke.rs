// fstest_smoke — testing/fstest MapFS, ported from Go 1.25.5
// testing/fstest/mapfs_test.go (TestFS harness cases replaced with the
// specific walks/reads TestFS performs; expected values verified
// against real Go 1.25.5 semantics).
//
// Covers:
//   1. TestMapFSChmodDot: WalkDir over {"a/b.txt", "."} — explicit
//      "." metadata wins, "a" synthesized as dr-xr-xr-x, exact order
//      and FileMode strings.
//   2. TestMapFSFileInfoName: Stat("path/to/b.txt").Name() == "b.txt".
//   3. TestMapFSSymlink: file behind a symlinked dir readable via
//      fs.ReadFile; MapFS.ReadLink returns the target; Lstat sees the
//      link type; symlink-to-symlink resolution (linklink).
//   4. TestMapFS shape: hello + fortune/k/ken.txt — synthesized
//      intermediate dirs appear in ReadDir sorted; open dir ReadDir
//      chunking hits EOF; Read on dir errors; ErrNotExist identity on
//      a missing file.
//   5. fs::WalkDir through the dyn fs::FS surface.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;
use alloc::sync::Arc;
use goish::goslice::slice;
use goish::io::fs::{self, FileMode, ModeDir, ModeSymlink};
use goish::testing::fstest::{MapFS, MapFile};
use goish::time;
use goish::types::byte;
use goish::{errors, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

fn mf(data: &str, mode: FileMode) -> Arc<MapFile> {
    Arc::new(MapFile {
        Data: slice::__from_vec(data.as_bytes().to_vec()),
        Mode: mode,
        ModTime: time::Time::default(),
        Sys: None,
    })
}

#[goish::main]
fn main() {
    // ─── TestMapFSChmodDot (mapfs_test.go:24) ──────────────────────
    let mut m = MapFS::new();
    m.0.Set("a/b.txt", mf("", FileMode(0o666)));
    m.0.Set(".", mf("", FileMode(0o777 | ModeDir.0)));
    let buf = goish::runtime::spin::SpinLock::new(RustString::new());
    let err = fs::WalkDir(
        &m,
        ".",
        |path: string, d: &(dyn fs::DirEntry + Send + Sync + 'static), err: goish::error| {
            if err != errors::nil {
                return err;
            }
            let (fi, err) = d.Info();
            if err != errors::nil {
                return err;
            }
            let mut g = buf.lock();
            g.push_str(core::str::from_utf8(path.as_bytes()).unwrap());
            g.push_str(": ");
            g.push_str(core::str::from_utf8(fi.Mode().String().as_bytes()).unwrap());
            g.push('\n');
            errors::nil
        },
    );
    check(err == errors::nil, b"chmoddot: walk error\n");
    // Go want: ".: drwxrwxrwx\na: dr-xr-xr-x\na/b.txt: -rw-rw-rw-\n"
    check(
        buf.lock().as_bytes() == b".: drwxrwxrwx\na: dr-xr-xr-x\na/b.txt: -rw-rw-rw-\n",
        b"chmoddot: mode walk mismatch\n",
    );

    // ─── TestMapFSFileInfoName (mapfs_test.go:49) ──────────────────
    let mut m = MapFS::new();
    m.0.Set("path/to/b.txt", mf("", FileMode(0)));
    let (info, err) = m.Stat("path/to/b.txt");
    check(err == errors::nil, b"fileinfoname: stat error\n");
    check(
        info.Name().as_bytes() == b"b.txt",
        b"fileinfoname: want b.txt\n",
    );

    // ─── TestMapFSSymlink (mapfs_test.go:61) ───────────────────────
    let file_content = "If a program is too slow, it must have a loop.\n";
    let mut m = MapFS::new();
    m.0.Set("fortune/k/ken.txt", mf(file_content, FileMode(0)));
    m.0.Set("dirlink", mf("fortune/k", ModeSymlink));
    m.0.Set("linklink", mf("dirlink", ModeSymlink));
    m.0.Set("ken.txt", mf("dirlink/ken.txt", ModeSymlink));
    // Go: fs.ReadFile(m, "ken.txt") == fileContent (via two symlinks)
    let (got, err) = fs::ReadFile(&m, "ken.txt");
    check(err == errors::nil, b"symlink: readfile error\n");
    check(
        got.as_ref() == file_content.as_bytes(),
        b"symlink: content mismatch\n",
    );
    // Go: fs.ReadLink(m, "dirlink") == "fortune/k"
    let (target, err) = m.ReadLink("dirlink");
    check(
        err == errors::nil && target.as_bytes() == b"fortune/k",
        b"symlink: readlink\n",
    );
    // Go: fs.Lstat sees the symlink itself.
    let (li, err) = m.Lstat("linklink");
    check(
        err == errors::nil && li.Mode().Type().0 == ModeSymlink.0,
        b"symlink: lstat type\n",
    );
    // Read through linklink (symlink -> symlink -> dir).
    let (got2, err) = fs::ReadFile(&m, "linklink/ken.txt");
    check(
        err == errors::nil && got2.as_ref() == file_content.as_bytes(),
        b"symlink: linklink read\n",
    );

    // ─── TestMapFS shape (mapfs_test.go:14) ────────────────────────
    let mut m = MapFS::new();
    m.0.Set("hello", mf("hello, world\n", FileMode(0)));
    m.0.Set("fortune/k/ken.txt", mf(file_content, FileMode(0)));
    // Root ReadDir: synthesized "fortune" dir + "hello" file, sorted.
    let (ents, err) = fs::ReadDir(&m, ".");
    check(
        err == errors::nil && goish::len(&ents) == 2,
        b"mapfs: root readdir count\n",
    );
    check(
        ents[0].Name().as_bytes() == b"fortune" && ents[0].IsDir(),
        b"mapfs: fortune synthesized dir\n",
    );
    check(
        ents[1].Name().as_bytes() == b"hello" && !ents[1].IsDir(),
        b"mapfs: hello file\n",
    );
    // Intermediate dir.
    let (ents, err) = fs::ReadDir(&m, "fortune/k");
    check(
        err == errors::nil && goish::len(&ents) == 1 && ents[0].Name().as_bytes() == b"ken.txt",
        b"mapfs: fortune/k listing\n",
    );
    // Open a dir: Read errors, chunked ReadDir then EOF.
    let (dirf, err) = m.Open("fortune");
    check(err == errors::nil, b"mapfs: open dir\n");
    let mut tmp: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
    let (_, err) = dirf.Read(&mut tmp);
    check(err != errors::nil, b"mapfs: dir read must error\n");
    let (rdf, ok) = goish::cast!(&*dirf, fs::ReadDirFile);
    check(ok, b"mapfs: dir is ReadDirFile\n");
    let (chunk, err) = rdf.ReadDir(1);
    check(
        err == errors::nil && goish::len(&chunk) == 1 && chunk[0].Name().as_bytes() == b"k",
        b"mapfs: chunk 1\n",
    );
    let (_, err) = rdf.ReadDir(1);
    check(err == goish::io::EOF, b"mapfs: dir EOF\n");
    // Missing file: fs.ErrNotExist identity through PathError unwrap.
    let (_, err) = m.Open("nope");
    check(
        err != errors::nil && errors::Is(err, fs::ErrNotExist),
        b"mapfs: ErrNotExist identity\n",
    );
    // Plain file read via Open.
    let (f, err) = m.Open("hello");
    check(err == errors::nil, b"mapfs: open hello\n");
    let mut rbuf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 64]);
    let (n, err) = f.Read(&mut rbuf);
    check(
        err == errors::nil && &rbuf.as_ref()[..n as usize] == b"hello, world\n",
        b"mapfs: read hello\n",
    );
    let (info, err) = f.Stat();
    check(
        err == errors::nil && info.Size() == 13 && !info.IsDir(),
        b"mapfs: stat hello\n",
    );

    let msg = b"FSTEST_OK MapFS walk + symlinks + synth dirs vs Go semantics\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
