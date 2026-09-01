// go: file os/path.go decls: MkdirAll, RemoveAll, endsWithDot
// goishlint:ignore GOISH018 removeAll, removeAllFrom, openDirAt — Go's
// unix RemoveAll walks the tree with openat(2)/unlinkat(2) relative
// file descriptors so a rename between the stat and the unlink cannot
// redirect it. goish's walks by PATH; it is the same traversal without
// that race guard, and porting the fd-relative walk needs unlinkat and
// AT_REMOVEDIR, which are not wired yet.
//
// path.go — MkdirAll and RemoveAll.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors;
use crate::errors::nil;
use crate::gostring::string;
use crate::int;
use crate::io::fs::FileMode;
use crate::syscall;

use super::{bytes_of, error, IsPathSeparator, Mkdir, PathError, ReadDir, Remove, Stat};

// go: sdk 1.25.5 os/path.go:12-65 MkdirAll
/// Create `path` along with any necessary parents, and return nil, or
/// else the first error. The permission bits `perm` are used for all
/// directories that MkdirAll creates. If `path` is already a directory,
/// MkdirAll does nothing and returns nil.
pub fn MkdirAll<P: Into<string>, M: Into<FileMode>>(path: P, perm: M) -> error {
    let path: string = path.into();
    let perm: FileMode = perm.into();
    // Fast path: if we can tell whether path is a directory or file,
    // stop with success or error.
    let (dir, err) = Stat(path.clone());
    if err.IsNil() {
        if dir.IsDir() {
            return nil;
        }
        // Go: &PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}.
        // goish returned a bare errors.New whose text named neither the
        // path nor the reason.
        return errors::Wrap(PathError {
            Op: string::from("mkdir"),
            Path: path,
            Err: syscall::ENOTDIR.into(),
        });
    }

    // Slow path: make sure the parent exists and then call Mkdir for
    // path. Extract the parent by first removing any trailing path
    // separator and then scanning backward to one.
    let bs = bytes_of(&path);
    let mut i: int = int(bs.len()) - 1;
    while i >= 0 && IsPathSeparator(bs[i as usize]) {
        i -= 1;
    }
    while i >= 0 && !IsPathSeparator(bs[i as usize]) {
        i -= 1;
    }
    if i < 0 {
        i = 0;
    }

    // If there is a parent directory, recurse to ensure it exists.
    if i > 0 {
        let parent = string::from_bytes(&bs[..i as usize]);
        let perr = MkdirAll(parent, perm);
        if !perr.IsNil() {
            return perr;
        }
    }

    // Parent now exists; invoke Mkdir and use its result.
    let merr = Mkdir(path.clone(), perm);
    if !merr.IsNil() {
        // Handle arguments like "foo/." by double-checking that the
        // directory doesn't exist.
        let (d2, err1) = Stat(path);
        if err1.IsNil() && d2.IsDir() {
            return nil;
        }
        return merr;
    }
    return nil;
}

// go: sdk 1.25.5 os/path.go:67-76 RemoveAll
/// Remove `path` and any children it contains. It removes everything it
/// can but returns the first error it encounters. If the path does not
/// exist, RemoveAll returns nil.
pub fn RemoveAll<P: Into<string>>(path: P) -> error {
    let path: string = path.into();

    // Go's `removeAll` opens with two guards, and goish had NEITHER.
    //
    // The empty path is a silent nil, for compatibility with an older
    // RemoveAll (Go issue 28830).
    if path.Len() == 0 {
        return nil;
    }
    // The rmdir system call does not permit removing ".", so Go does
    // not permit it either. Without this guard `RemoveAll(".")` walks
    // the CURRENT DIRECTORY and deletes everything in it before failing
    // to rmdir "." itself — which is what it did here, to this
    // repository's working tree, while this file was being written.
    if endsWithDot(&path) {
        return errors::Wrap(PathError {
            Op: string::from("RemoveAll"),
            Path: path,
            Err: syscall::EINVAL.into(),
        });
    }

    let (fi, err) = Stat(path.clone());
    if !err.IsNil() {
        // Go: a path that does not exist is not an error.
        return nil;
    }
    if !fi.IsDir() {
        return Remove(path);
    }
    let (entries, derr) = ReadDir(path.clone());
    if !derr.IsNil() {
        return derr;
    }
    for i in 0..entries.Len() {
        let e = entries[i].clone();
        let mut child: Vec<u8> = Vec::new();
        child.extend_from_slice(bytes_of(&path));
        child.push(b'/');
        child.extend_from_slice(e.Name().as_bytes());
        let cerr = RemoveAll(string::__from_vec(child));
        if !cerr.IsNil() {
            return cerr;
        }
    }
    return Remove(path);
}

// go: sdk 1.25.5 os/path.go:78-86 endsWithDot
/// Whether the final component of `path` is ".".
fn endsWithDot(path: &string) -> bool {
    let b = bytes_of(path);
    if b == b"." {
        return true;
    }
    if b.len() >= 2 && b[b.len() - 1] == b'.' && IsPathSeparator(b[b.len() - 2]) {
        return true;
    }
    return false;
}
