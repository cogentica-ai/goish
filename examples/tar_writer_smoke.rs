// tar_writer_smoke — exercise the archive/tar Writer.
//
// The strong test: write a tar with the Writer, then read it back with
// the already-ported Reader and assert every Next() header + body
// matches what was written.
//
// Coverage:
//   1  round-trip: a regular file (header + body match).
//   2  round-trip: an empty file (size 0).
//   3  round-trip: a long-name file forcing PAX/GNU (>100 bytes).
//   4  round-trip: a directory header (no body).
//   5  round-trip: a file with non-ASCII metadata (PAX).
//   6  Flush after a fully-written file is a no-op success.
//   7  WriteHeader after Close returns ErrWriteAfterClose.
//   8  Write exceeding the declared Size returns ErrWriteTooLong.
//   9  AddFS over a tiny in-memory fs.FS produces a readable archive.
//  10  Go interop: a real Go-produced tar is read by goish's Reader.
//  11  Go interop: a goish-produced tar is written out for the Go
//      toolchain to extract (validation step).

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::archive::tar;
use goish::bytes;
use goish::errors::{self, error};
use goish::fmt;
use goish::io::fs;
use goish::runtime::spin::SpinLock;
use goish::types::{byte, int};
use goish::{io, nil, slice, string, syscall};

const TOTAL: usize = 11;

// Linux open(2) flags not exported by goish::syscall.
const O_WRONLY: i32 = 0o1;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;

// goish -> Go interop file, extracted by the validation step.
const GOISH_PRODUCED: &[u8] = b"/tmp/tar_writer_smoke_goish.tar\0";

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

fn check(cond: bool, name: &[u8]) {
    if cond {
        syscall::Write(syscall::STDOUT, b"  PASS ".as_ptr(), 7);
    } else {
        syscall::Write(syscall::STDOUT, b"  FAIL ".as_ptr(), 7);
        fail();
    }
    syscall::Write(syscall::STDOUT, name.as_ptr(), name.len());
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);
}

// ─── MemReader — an io.Reader over a Vec<u8> ─────────────────────────

struct MemReader {
    data: Vec<u8>,
    pos: usize,
}

impl io::Reader for MemReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.data.len() - self.pos);
        let mut i: int = 0;
        while i < want as int {
            p[i] = self.data[self.pos + i as usize];
            i += 1;
        }
        self.pos += want;
        (want as int, nil.into())
    }
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn drain(buf: bytes::Buffer) -> Vec<u8> {
    let b = buf.Bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i: int = 0;
    while i < b.Len() {
        out.push(b[i]);
        i += 1;
    }
    out
}

// Read the whole body of the current Reader entry into a Vec.
fn read_body(tr: &mut tar::Reader, size: i64) -> Vec<u8> {
    use goish::io::Reader as _;
    let mut out: Vec<u8> = Vec::new();
    let mut buf = from_bytes(&[0u8; 256]);
    let mut remaining = size;
    while remaining > 0 {
        let (n, err) = tr.Read(&mut buf);
        let mut k: int = 0;
        while k < n {
            out.push(buf[k]);
            k += 1;
        }
        remaining -= n as i64;
        if err != nil {
            break;
        }
    }
    out
}

fn eq(a: &[byte], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..b.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn str_eq(s: &string, b: &[u8]) -> bool {
    s.as_bytes() == b
}

// ─── Tests ───────────────────────────────────────────────────────────

// Build one Header for a regular file.
fn reg_header(name: &str, size: i64) -> tar::Header {
    let mut h = tar::Header::new();
    h.Typeflag = tar::TypeReg;
    h.Name = string::from_bytes(name.as_bytes());
    h.Mode = 0o644;
    h.Size = size;
    h
}

fn run_tests() {
    test_roundtrip();
    test_flush();
    test_write_after_close();
    test_write_too_long();
    test_addfs();
    test_go_to_goish();
    test_goish_to_go();
}

// Tests 1..5 — write 5 entries, read them all back.
fn test_roundtrip() {
    let archive = build_five();
    verify_five(&archive);
}

// make_long_name builds a >100-byte path so USTAR cannot encode it.
fn make_long_name() -> string {
    let mut s = alloc::string::String::new();
    for _ in 0..12 {
        s.push_str("longdir/");
    }
    s.push_str("file.txt");
    string::from_bytes(s.as_bytes())
}

// Round-trip helper: build the 5-entry archive and return its bytes.
fn build_five() -> Vec<u8> {
    let long_name = make_long_name();
    let buf = bytes::NewBuffer(slice::new());
    let mut tw = tar::NewWriter(buf);

    let body1: &[u8] = b"hello tar writer\n";
    let _ = tw.WriteHeader(&reg_header("hello.txt", body1.len() as i64));
    let _ = tw.Write(from_bytes(body1));

    let _ = tw.WriteHeader(&reg_header("empty.txt", 0));

    let body3: &[u8] = b"long name body";
    let mut h3 = reg_header("", body3.len() as i64);
    h3.Name = long_name;
    let _ = tw.WriteHeader(&h3);
    let _ = tw.Write(from_bytes(body3));

    let mut h4 = tar::Header::new();
    h4.Typeflag = tar::TypeDir;
    h4.Name = string::from_static("subdir/");
    h4.Mode = 0o755;
    let _ = tw.WriteHeader(&h4);

    let body5: &[u8] = b"pax meta body";
    let mut h5 = reg_header("meta.txt", body5.len() as i64);
    h5.Uname = string::from_bytes("ünïcödé".as_bytes());
    h5.Format = tar::FormatPAX;
    let _ = tw.WriteHeader(&h5);
    let _ = tw.Write(from_bytes(body5));

    let _ = tw.Close();
    drain(tw.into_writer())
}

fn test_flush() {
    // Flush after fully writing a file is a no-op success.
    let buf = bytes::NewBuffer(slice::new());
    let mut tw = tar::NewWriter(buf);
    let body: &[u8] = b"flushme";
    let _ = tw.WriteHeader(&reg_header("f.txt", body.len() as i64));
    let _ = tw.Write(from_bytes(body));
    let ferr = tw.Flush();
    let cerr = tw.Close();
    check(
        ferr == nil && cerr == nil,
        b"Flush after full write succeeds",
    );
}

fn verify_five(archive: &[u8]) {
    let r = MemReader {
        data: archive.to_vec(),
        pos: 0,
    };
    let mut tr = tar::NewReader(alloc::boxed::Box::new(r));

    // 1. regular file
    let (h1, e1) = tr.Next();
    let body1 = read_body(&mut tr, h1.Size);
    check(
        e1 == nil
            && str_eq(&h1.Name, b"hello.txt")
            && h1.Size == 17
            && eq(&body1, b"hello tar writer\n"),
        b"round-trip: regular file",
    );

    // 2. empty file
    let (h2, e2) = tr.Next();
    check(
        e2 == nil && str_eq(&h2.Name, b"empty.txt") && h2.Size == 0,
        b"round-trip: empty file",
    );

    // 3. long-name file
    let (h3, e3) = tr.Next();
    let body3 = read_body(&mut tr, h3.Size);
    let want3 = make_long_name();
    check(
        e3 == nil && h3.Name == want3 && eq(&body3, b"long name body"),
        b"round-trip: long-name file (PAX/GNU)",
    );

    // 4. directory header
    let (h4, e4) = tr.Next();
    check(
        e4 == nil && str_eq(&h4.Name, b"subdir/") && h4.Typeflag == tar::TypeDir,
        b"round-trip: directory header",
    );

    // 5. non-ASCII metadata file
    let (h5, e5) = tr.Next();
    let body5 = read_body(&mut tr, h5.Size);
    check(
        e5 == nil
            && str_eq(&h5.Name, b"meta.txt")
            && str_eq(&h5.Uname, "ünïcödé".as_bytes())
            && eq(&body5, b"pax meta body"),
        b"round-trip: non-ASCII metadata (PAX)",
    );

    // End of archive.
    let (_, e6) = tr.Next();
    check(e6 == io::EOF, b"round-trip: EOF at end of archive");
}

fn test_write_after_close() {
    let buf = bytes::NewBuffer(slice::new());
    let mut tw = tar::NewWriter(buf);
    let _ = tw.WriteHeader(&reg_header("x.txt", 0));
    let _ = tw.Close();
    // WriteHeader after Close must report ErrWriteAfterClose.
    let err = tw.WriteHeader(&reg_header("y.txt", 0));
    check(
        errors::Is(err, tar::ErrWriteAfterClose),
        b"WriteHeader after Close -> ErrWriteAfterClose",
    );
}

fn test_write_too_long() {
    let buf = bytes::NewBuffer(slice::new());
    let mut tw = tar::NewWriter(buf);
    // Declare size 4 but write 10 bytes.
    let _ = tw.WriteHeader(&reg_header("z.txt", 4));
    let (_, err) = tw.Write(from_bytes(b"0123456789"));
    check(
        errors::Is(err, tar::ErrWriteTooLong),
        b"Write exceeding Size -> ErrWriteTooLong",
    );
}

// ─── AddFS test (tiny in-memory fs.FS) ───────────────────────────────

struct mapInfo {
    name: string,
    size: int,
    isDir: bool,
}

impl fs::FileInfo for mapInfo {
    fn Name(&self) -> string {
        self.name.clone()
    }
    fn Size(&self) -> i64 {
        self.size
    }
    fn Mode(&self) -> fs::FileMode {
        if self.isDir {
            fs::ModeDir | fs::FileMode(0o755)
        } else {
            fs::FileMode(0o644)
        }
    }
    fn ModTime(&self) -> goish::time::Time {
        goish::time::Time::default()
    }
    fn IsDir(&self) -> bool {
        self.isDir
    }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        Arc::new(())
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

struct mapDirEntry {
    name: string,
    size: int,
    isDir: bool,
}

impl fs::DirEntry for mapDirEntry {
    fn Name(&self) -> string {
        self.name.clone()
    }
    fn IsDir(&self) -> bool {
        self.isDir
    }
    fn Type(&self) -> fs::FileMode {
        if self.isDir {
            fs::ModeDir
        } else {
            fs::FileMode(0)
        }
    }
    fn Info(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (
            Arc::new(mapInfo {
                name: self.name.clone(),
                size: self.size,
                isDir: self.isDir,
            }),
            errors::nil,
        )
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

struct mapRegularFile {
    name: string,
    content: Vec<u8>,
    pos: SpinLock<usize>,
}

impl fs::File for mapRegularFile {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (
            Arc::new(mapInfo {
                name: self.name.clone(),
                size: self.content.len() as int,
                isDir: false,
            }),
            errors::nil,
        )
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        let mut g = self.pos.lock();
        if *g >= self.content.len() {
            return (0, io::EOF.into());
        }
        let mut n: usize = 0;
        while *g < self.content.len() && n < (p.Len() as usize) {
            p[n] = self.content[*g];
            *g += 1;
            n += 1;
        }
        (n as int, errors::nil)
    }
    fn Close(&self) -> error {
        errors::nil
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

struct mapDir {
    name: string,
    entries: Vec<mapDirEntry>,
}

impl fs::File for mapDir {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (
            Arc::new(mapInfo {
                name: self.name.clone(),
                size: 0,
                isDir: true,
            }),
            errors::nil,
        )
    }
    fn Read(&self, _p: &mut slice<byte>) -> (int, error) {
        (0, errors::New("is a directory"))
    }
    fn Close(&self) -> error {
        errors::nil
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::ReadDirFile for mapDir {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        <Self as fs::File>::Stat(self)
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        <Self as fs::File>::Read(self, p)
    }
    fn Close(&self) -> error {
        <Self as fs::File>::Close(self)
    }
    fn ReadDir(&self, _n: int) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let mut v: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::new();
        for e in self.entries.iter() {
            v.push(Arc::new(mapDirEntry {
                name: e.name.clone(),
                size: e.size,
                isDir: e.isDir,
            }));
        }
        (slice::__from_vec(v), errors::nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

#[derive(Clone)]
struct node {
    path: string,
    content: Vec<u8>,
    isDir: bool,
}

struct mapFS {
    nodes: Vec<node>,
}

impl mapFS {
    fn base_name(p: &string) -> string {
        let b = p.as_bytes();
        let mut start = 0;
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' {
                start = i + 1;
            }
            i += 1;
        }
        string::from_bytes(&b[start..])
    }
    fn parent(p: &string) -> string {
        let b = p.as_bytes();
        let mut cut: isize = -1;
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' {
                cut = i as isize;
            }
            i += 1;
        }
        if cut < 0 {
            string::new()
        } else {
            string::from_bytes(&b[..cut as usize])
        }
    }
    fn dir_entries(&self, dir: &string) -> Vec<mapDirEntry> {
        let mut out: Vec<mapDirEntry> = Vec::new();
        for n in self.nodes.iter() {
            if Self::parent(&n.path) == *dir && n.path != *dir {
                out.push(mapDirEntry {
                    name: Self::base_name(&n.path),
                    size: n.content.len() as int,
                    isDir: n.isDir,
                });
            }
        }
        out
    }
    fn find(&self, name: &string) -> Option<node> {
        for n in self.nodes.iter() {
            if n.path == *name {
                return Some(n.clone());
            }
        }
        None
    }
}

impl fs::FS for mapFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        if name == "." {
            let d = mapDir {
                name: string::from_static("."),
                entries: self.dir_entries(&string::new()),
            };
            return (Arc::new(d), errors::nil);
        }
        match self.find(&name) {
            None => (
                goish::nil.into(),
                errors::Wrap(fs::PathError {
                    Op: string::from_static("open"),
                    Path: name,
                    Err: fs::ErrNotExist.into(),
                }),
            ),
            Some(n) if n.isDir => {
                let d = mapDir {
                    name: mapFS::base_name(&n.path),
                    entries: self.dir_entries(&n.path),
                };
                (Arc::new(d), errors::nil)
            }
            Some(n) => {
                let f = mapRegularFile {
                    name: mapFS::base_name(&n.path),
                    content: n.content.clone(),
                    pos: SpinLock::new(0),
                };
                (Arc::new(f), errors::nil)
            }
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::ReadDirFS for mapFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        <Self as fs::FS>::Open(self, name)
    }
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let dir = if name == "." {
            string::new()
        } else {
            name.clone()
        };
        let mut v: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::new();
        for e in self.dir_entries(&dir) {
            v.push(Arc::new(mapDirEntry {
                name: e.name,
                size: e.size,
                isDir: e.isDir,
            }));
        }
        (slice::__from_vec(v), errors::nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::StatFS for mapFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        <Self as fs::FS>::Open(self, name)
    }
    fn Stat(&self, name: string) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        if name == "." {
            return (
                Arc::new(mapInfo {
                    name: string::from_static("."),
                    size: 0,
                    isDir: true,
                }),
                errors::nil,
            );
        }
        match self.find(&name) {
            None => (
                goish::nil.into(),
                errors::Wrap(fs::PathError {
                    Op: string::from_static("stat"),
                    Path: name,
                    Err: fs::ErrNotExist.into(),
                }),
            ),
            Some(n) => (
                Arc::new(mapInfo {
                    name: mapFS::base_name(&n.path),
                    size: n.content.len() as int,
                    isDir: n.isDir,
                }),
                errors::nil,
            ),
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

fn register_mapfs_impls() {
    fs::__goish_register_FS_impl::<mapFS>();
    fs::__goish_register_ReadDirFS_impl::<mapFS>();
    fs::__goish_register_StatFS_impl::<mapFS>();
    fs::__goish_register_File_impl::<mapRegularFile>();
    fs::__goish_register_File_impl::<mapDir>();
    fs::__goish_register_ReadDirFile_impl::<mapDir>();
}

fn test_addfs() {
    register_mapfs_impls();
    fn n(p: &'static str, content: &str, is_dir: bool) -> node {
        node {
            path: string::from_static(p),
            content: content.as_bytes().to_vec(),
            isDir: is_dir,
        }
    }
    let fsys = mapFS {
        nodes: alloc::vec![
            n("a.txt", "alpha", false),
            n("dir1", "", true),
            n("dir1/b.txt", "bravo", false),
        ],
    };

    let buf = bytes::NewBuffer(slice::new());
    let mut tw = tar::NewWriter(buf);
    let aerr = tw.AddFS(&fsys);
    let cerr = tw.Close();
    let archive = drain(tw.into_writer());

    // Read back: expect a.txt, dir1/, dir1/b.txt (lexical order).
    let r = MemReader {
        data: archive,
        pos: 0,
    };
    let mut tr = tar::NewReader(alloc::boxed::Box::new(r));
    let (h1, _) = tr.Next();
    let b1 = read_body(&mut tr, h1.Size);
    let (h2, _) = tr.Next();
    let (h3, _) = tr.Next();
    let b3 = read_body(&mut tr, h3.Size);
    let (_, e_end) = tr.Next();

    check(
        aerr == nil
            && cerr == nil
            && str_eq(&h1.Name, b"a.txt")
            && eq(&b1, b"alpha")
            && str_eq(&h2.Name, b"dir1/")
            && h2.Typeflag == tar::TypeDir
            && str_eq(&h3.Name, b"dir1/b.txt")
            && eq(&b3, b"bravo")
            && e_end == io::EOF,
        b"AddFS over in-memory fs.FS round-trips",
    );
}

// ─── Go interop ──────────────────────────────────────────────────────

// A real tar archive produced by Go 1.25 `tar.NewWriter` (run via the
// Go toolchain): a single regular file "go.txt" with body "from go\n"
// (mode 0644). 2048 bytes: USTAR header + data block + 1024 trailer.
const GO_TAR: &[u8] = &[
    103, 111, 46, 116, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 48, 48, 48, 48, 54, 52, 52, 0, 48, 48, 48, 48, 48, 48, 48, 0, 48, 48,
    48, 48, 48, 48, 48, 0, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 48, 0, 48, 48, 48, 48, 48, 48,
    48, 48, 48, 48, 48, 0, 48, 49, 48, 51, 52, 50, 0, 32, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 115, 116, 97, 114,
    0, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 48, 48, 48, 48, 48, 48, 48, 0, 48, 48, 48, 48, 48, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    102, 114, 111, 109, 32, 103, 111, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

fn test_go_to_goish() {
    let archive = GO_TAR.to_vec();
    let r = MemReader {
        data: archive,
        pos: 0,
    };
    let mut tr = tar::NewReader(alloc::boxed::Box::new(r));
    let (h, e) = tr.Next();
    let body = read_body(&mut tr, h.Size);
    let (_, e_end) = tr.Next();
    check(
        e == nil
            && str_eq(&h.Name, b"go.txt")
            && h.Size == 8
            && eq(&body, b"from go\n")
            && e_end == io::EOF,
        b"Go -> goish: read a Go-produced tar",
    );
}

fn write_file(path: &[u8], data: &[u8]) -> bool {
    let fd = syscall::Open(path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        return false;
    }
    let mut off = 0usize;
    let mut ok = true;
    while off < data.len() {
        let n = syscall::Write(fd, data[off..].as_ptr(), data.len() - off);
        if n <= 0 {
            ok = false;
            break;
        }
        off += n as usize;
    }
    syscall::Close(fd);
    ok
}

fn test_goish_to_go() {
    // Write a small tar with goish, drop it for the Go toolchain to
    // extract during the validation step. Also locally round-trip it.
    let buf = bytes::NewBuffer(slice::new());
    let mut tw = tar::NewWriter(buf);
    let body: &[u8] = b"goish to go interop\n";
    let _ = tw.WriteHeader(&reg_header("interop.txt", body.len() as i64));
    let _ = tw.Write(from_bytes(body));
    let _ = tw.Close();
    let archive = drain(tw.into_writer());

    let mut ok = write_file(GOISH_PRODUCED, &archive);

    // Local sanity: goish must read its own output.
    if ok {
        let r = MemReader {
            data: archive,
            pos: 0,
        };
        let mut tr = tar::NewReader(alloc::boxed::Box::new(r));
        let (h, e) = tr.Next();
        let got = read_body(&mut tr, h.Size);
        ok = e == nil && str_eq(&h.Name, b"interop.txt") && eq(&got, body);
    }
    check(ok, b"goish -> Go: write a goish tar (Go extracts it)");
}

#[goish::main]
fn main() {
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        let pass = TOTAL - f;
        if f == 0 {
            fmt::Println!("ok 11/11");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", pass as i64, "of", TOTAL as i64);
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}
