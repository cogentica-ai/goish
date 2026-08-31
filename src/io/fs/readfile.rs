// go: file io/fs/readfile.go decls: ReadFile
//
// readfile.go — ReadFileFS and ReadFile.
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::byte;

use super::*;

// ─── ReadFile (readfile.go) ──────────────────────────────────────────

// go: sdk 1.25.5 io/fs/readfile.go:11-22 ReadFileFS
/// `fs.ReadFileFS` (readfile.go:14) — a file system with an optimized
/// `ReadFile` implementation. Embeds [`FS`] in Go (re-declared here;
/// see the interface-embedding note above).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ReadFileFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `ReadFile(name)` — the full contents of the named file. A
    /// successful call returns a nil error, not `io::EOF`.
    fn ReadFile(&self, name: string) -> (slice<byte>, error);
}

// go: sdk 1.25.5 io/fs/readfile.go:32-66 ReadFile
/// `fs.ReadFile(fsys, name)` (readfile.go:24) — read the named file
/// and return its contents. A successful call returns a nil error,
/// not `io::EOF` (reads the whole file).
///
/// If `fsys` implements [`ReadFileFS`], `ReadFile` calls its
/// `ReadFile`. Otherwise it opens the file and reads until EOF.
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
pub fn ReadFile<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: S,
) -> (slice<byte>, error) {
    let name: string = name.into();

    // Go: if fsys, ok := fsys.(ReadFileFS); ok { return fsys.ReadFile(name) }
    let (rffs, ok) = goish::cast!(fsys, ReadFileFS);
    if ok {
        return rffs.ReadFile(name);
    }

    // Go: file, err := fsys.Open(name); if err != nil { return nil, err }
    let (file, err) = fsys.Open(name);
    if err != errors::nil {
        return (slice::new(), err);
    }
    // Go: defer file.Close(); read until error/EOF.
    let mut out: Vec<u8> = Vec::new();
    let mut chunk: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4096]);
    loop {
        let (n, err) = file.Read(&mut chunk);
        if n > 0 {
            out.extend_from_slice(&chunk.as_ref()[..n as usize]);
        }
        if err != errors::nil {
            let _ = file.Close();
            if err == crate::io::EOF {
                return (slice::__from_vec(out), errors::nil);
            }
            return (slice::__from_vec(out), err);
        }
        if n == 0 {
            // A zero-byte, nil-error Read from a well-behaved File
            // only happens at EOF; stop rather than spin.
            let _ = file.Close();
            return (slice::__from_vec(out), errors::nil);
        }
    }
}
