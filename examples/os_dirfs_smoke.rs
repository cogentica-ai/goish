// os_dirfs_smoke — os.DirFS over a real directory tree + the new
// io/fs entry points: fs.ReadFile (optimized ReadFileFS path and the
// generic Open+Read fallback), fs.Sub, and the os/fs sentinel-error
// identity (os.ErrNotExist IS fs.ErrNotExist, as in Go).
//
// Complements io_fs_walkdir_smoke (WalkDir/ReadDir/Stat over an
// in-memory FS) with the real-filesystem integration.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::io::fs;
use goish::{errors, os, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// ─── minimal custom FS: only Open, no optimized interfaces ──────────
//
// Forces fs::ReadFile down the generic Open + Read-to-EOF path.

struct memFS;

struct memFile {
    data: &'static [u8],
    pos: AtomicUsize,
}

impl fs::File for memFile {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, goish::error) {
        (goish::nil.into(), errors::New("stat not supported"))
    }
    fn Read(&self, p: &mut slice<u8>) -> (goish::int, goish::error) {
        let pos = self.pos.load(Ordering::Relaxed);
        if pos >= self.data.len() {
            return (0, goish::io::EOF.into());
        }
        let dst = p.as_mut();
        let n = dst.len().min(self.data.len() - pos);
        dst[..n].copy_from_slice(&self.data[pos..pos + n]);
        self.pos.store(pos + n, Ordering::Relaxed);
        (n as goish::int, goish::nil.into())
    }
    fn Close(&self) -> goish::error {
        goish::nil.into()
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::FS for memFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, goish::error) {
        if name.as_bytes() == b"hello.txt" {
            (
                Arc::new(memFile {
                    data: b"hello from memFS",
                    pos: AtomicUsize::new(0),
                }),
                goish::nil.into(),
            )
        } else {
            (goish::nil.into(), fs::ErrNotExist.into())
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

#[goish::main]
fn main() {
    // ─── setup: real tree under TempDir ────────────────────────────
    let root = os::TempDir() + "/goish_os_dirfs_smoke";
    let _ = os::RemoveAll(root.clone());
    let err = os::MkdirAll(root.clone() + "/sub", 0o755);
    check(err == goish::nil, b"setup: MkdirAll\n");
    let err = os::WriteFile(root.clone() + "/a.txt", b"alpha", 0o644);
    check(err == goish::nil, b"setup: WriteFile a\n");
    let err = os::WriteFile(root.clone() + "/sub/b.txt", b"bravo!", 0o644);
    check(err == goish::nil, b"setup: WriteFile b\n");
    let err = os::WriteFile(root.clone() + "/sub/c.log", b"charlie", 0o644);
    check(err == goish::nil, b"setup: WriteFile c\n");

    // ─── 1. DirFS: ReadFile (ReadFileFS fast path) + Stat ──────────
    let fsys = os::DirFS(root.clone());
    let (data, err) = fs::ReadFile(&*fsys, "a.txt");
    check(err == goish::nil, b"t1: ReadFile err\n");
    check(data.as_ref() == b"alpha", b"t1: ReadFile content\n");

    let (info, err) = fs::Stat(&*fsys, "sub/b.txt");
    check(err == goish::nil, b"t1b: Stat err\n");
    check(info.Size() == 6 && !info.IsDir(), b"t1b: Stat file\n");
    let (dinfo, err) = fs::Stat(&*fsys, "sub");
    check(err == goish::nil && dinfo.IsDir(), b"t1c: Stat dir\n");
    check(
        dinfo.Mode().IsDir() && !dinfo.Mode().IsRegular(),
        b"t1c: Mode bits\n",
    );

    // ─── 2. DirFS: ReadDir sorted + WalkDir over the real tree ─────
    let (entries, err) = fs::ReadDir(&*fsys, "sub");
    check(err == goish::nil, b"t2: ReadDir err\n");
    check(entries.as_ref().len() == 2, b"t2: ReadDir count\n");
    check(
        entries.as_ref()[0].Name().as_bytes() == b"b.txt"
            && entries.as_ref()[1].Name().as_bytes() == b"c.log",
        b"t2: ReadDir sorted\n",
    );

    let walked: RefCell<alloc::vec::Vec<string>> = RefCell::new(alloc::vec::Vec::new());
    let err = fs::WalkDir(
        &*fsys,
        ".",
        |path: string, _d: &(dyn fs::DirEntry + Send + Sync + 'static), err: goish::error| {
            if err != goish::nil {
                return err;
            }
            walked.borrow_mut().push(path);
            goish::nil.into()
        },
    );
    check(err == goish::nil, b"t2b: WalkDir err\n");
    let walked = walked.into_inner();
    // Lexical: . a.txt sub sub/b.txt sub/c.log
    check(walked.len() == 5, b"t2b: WalkDir count\n");
    check(
        walked[1].as_bytes() == b"a.txt"
            && walked[2].as_bytes() == b"sub"
            && walked[3].as_bytes() == b"sub/b.txt",
        b"t2b: WalkDir lexical order\n",
    );

    // ─── 3. fs.Sub ─────────────────────────────────────────────────
    let (sub, err) = fs::Sub(fsys.clone(), "sub");
    check(err == goish::nil, b"t3: Sub err\n");
    let (data, err) = fs::ReadFile(&*sub, "b.txt");
    check(err == goish::nil, b"t3: sub ReadFile err\n");
    check(data.as_ref() == b"bravo!", b"t3: sub ReadFile content\n");
    let (entries, err) = fs::ReadDir(&*sub, ".");
    check(
        err == goish::nil && entries.as_ref().len() == 2,
        b"t3b: sub ReadDir\n",
    );
    let (same, err) = fs::Sub(fsys.clone(), ".");
    check(err == goish::nil, b"t3c: Sub dot err\n");
    let (data, err) = fs::ReadFile(&*same, "a.txt");
    check(
        err == goish::nil && data.as_ref() == b"alpha",
        b"t3c: Sub dot identity\n",
    );

    // ─── 4. sentinel identity across os / fs ───────────────────────
    let (_, err) = fs::ReadFile(&*fsys, "missing.txt");
    check(err != goish::nil, b"t4: missing file errs\n");
    check(
        errors::Is(err.clone(), fs::ErrNotExist),
        b"t4: errors.Is fs.ErrNotExist\n",
    );
    check(os::IsNotExist(err), b"t4: os.IsNotExist agrees\n");

    // ─── 5. custom FS through the generic ReadFile path ────────────
    let mem = memFS;
    let (data, err) = fs::ReadFile(&mem, "hello.txt");
    check(err == goish::nil, b"t5: memFS ReadFile err\n");
    check(
        data.as_ref() == b"hello from memFS",
        b"t5: memFS ReadFile content\n",
    );
    let (_, err) = fs::ReadFile(&mem, "nope");
    check(
        errors::Is(err, fs::ErrNotExist),
        b"t5: memFS not-exist identity\n",
    );

    // cleanup
    let _ = os::RemoveAll(root);

    let msg = b"OS_DIRFS_OK all 5 test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
