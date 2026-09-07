// os/root — Go 1.25.5 src/os/root.go, root_unix.go and root_openat.go.
//
// `Root` is directory-limited filesystem access: every path is
// resolved RELATIVE to a directory fd with openat(2), one component at
// a time, so a "..", an absolute path, or a symlink pointing outside
// cannot leave the root even when an attacker chooses the name. It is
// a refusal, not a detection — the walk never opens the thing it would
// have to reject.
//
// INCREMENTAL PORT. What is here is anchored declaration by
// declaration. What is not here is UNPORTED, not waived: Root's
// mutating half (Mkdir, Remove, Rename, Link, Symlink, Chmod, Chown,
// Chtimes, WriteFile), its stat half (Stat, Lstat, Readlink,
// ReadFile), Root.FS and Root.OpenRoot. Those want the same walk with
// a different final operation, which is why the walk below is written
// as `do_in_root` taking the last step as a parameter, exactly as Go's
// doInRoot does.
//
// goishlint:ignore GOISH018 OpenInRoot, Root.Create, Root.OpenRoot, Root.Chmod, Root.Mkdir, Root.MkdirAll, Root.Chown, Root.Lchown, Root.Chtimes, Root.Remove, Root.RemoveAll, Root.Stat, Root.Lstat, Root.Readlink, Root.Rename, Root.Link, Root.Symlink, Root.ReadFile, Root.WriteFile, Root.FS, Root.logOpen, Root.logStat, rootFS.Open, rootFS.ReadDir, rootFS.ReadFile, rootFS.Stat, rootFS.Lstat, rootFS.ReadLink, root.Close, root.Name, root.incref, root.decref, isValidRootFSPath - incremental port; these are unported, NOT waived, and the walk they all share is in root_openat.rs.
// goishlint:ignore GOISH019 — file-wide. `rootFS` is unported (Root.FS is), so the fs.FS adapter has nothing to be; and goish's `Root` holds the fd in an Arc'd inner struct plus the name, where Go's holds one pointer to an unexported `root` carrying both — a different layout for the same two facts, because Name must survive Close and clones must share one fd.
// goishlint:ignore GOISH021 — file-wide. `rootMaxSymlinks` is a local const in the walk (root_openat.rs) rather than a package-level one, and `rootFS` is unported because Root.FS is.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gostring::string;
use crate::gonilable::nilable;
use crate::syscall;
use crate::types::int;

use super::{File, FileMode, PathError};

// go: none — goish-only: Go's `errPathEscapes` is os/file.go:421, a
// package-level `var` in a file goish does not claim. The message is
// verbatim, and it is what a caller matches on.
/// Go: `errors.New("path escapes from parent")`.
pub(crate) fn errPathEscapes() -> error {
    return errors::New(string::from_static("path escapes from parent"));
}

// go: none — goish-only: the fd behind a Root, with the closed flag
// Go keeps on its unexported `root` struct. Separate so that clones of
// a Root share one fd and one close.
pub(crate) struct RootInner {
    pub(crate) fd: crate::sync::Mutex<i32>,
}

// go: sdk 1.25.5 os/root.go:68-70 Root
/// Go: "Root may be used to only access files within a single
/// directory tree."
///
/// `Name` deliberately survives `Close` — Go documents that, and a
/// caller logging which root refused something needs it after the
/// refusal.
#[derive(Clone)]
pub struct Root {
    pub(crate) inner: alloc::sync::Arc<RootInner>,
    name: string,
}

// go: sdk 1.25.5 os/root.go:82-85 OpenRoot
/// Go: "OpenRoot opens the named directory. If there is an error, it
/// will be of type *PathError."
pub fn OpenRoot<N: Into<string>>(name: N) -> (nilable<Root>, error) {
    let name: string = name.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(super::bytes_of(&name));
    buf.push(0);
    let fd = syscall::Open(
        buf.as_ptr(),
        syscall::O_RDONLY | syscall::O_CLOEXEC | syscall::O_DIRECTORY,
        0,
    );
    if fd < 0 {
        // Go's newRoot fstats the fd and reports "not a directory"
        // itself; O_DIRECTORY makes the kernel do it, and ENOTDIR
        // renders identically. The other errnos pass through, so a
        // missing directory still says "no such file or directory".
        return (
            crate::nilval::nil.into(),
            errors::Wrap(PathError {
                Op: string::from_static("open"),
                Path: name,
                Err: syscall::Errno(-fd).into(),
            }),
        );
    }
    return (
        nilable::new(Root {
            inner: alloc::sync::Arc::new(RootInner {
                fd: crate::sync::Mutex::new(fd),
            }),
            name,
        }),
        errors::nil,
    );
}

impl Root {
    // go: sdk 1.25.5 os/root.go:90-92 Root.Name
    /// Go: "Name returns the name of the directory presented to
    /// OpenRoot. It is safe to call Name after Close."
    pub fn Name(&self) -> string {
        return self.name.clone();
    }

    // go: sdk 1.25.5 os/root.go:96-98 Root.Close
    /// Go: "Close closes the Root. After Close is called, methods on
    /// Root return errors."
    pub fn Close(&self) -> error {
        let mut g = self.inner.fd.Lock();
        if *g < 0 {
            return errors::nil;
        }
        let fd = *g;
        *g = -1;
        let r = syscall::Close(fd);
        if r < 0 {
            return errors::Wrap(PathError {
                Op: string::from_static("close"),
                Path: self.name.clone(),
                Err: syscall::Errno(-r).into(),
            });
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 os/root.go:102-104 Root.Open
    /// Go: "Open opens the named file in the root for reading."
    pub fn Open<N: Into<string>>(&self, name: N) -> (nilable<File>, error) {
        return self.OpenFile(name, int::from(0), FileMode(0));
    }

    // go: sdk 1.25.5 os/root.go:117-128 Root.OpenFile
    /// Go: "OpenFile opens the named file in the root. If perm
    /// contains bits other than the nine least-significant bits
    /// (0o777), OpenFile returns an error."
    pub fn OpenFile<N: Into<string>>(
        &self,
        name: N,
        flag: int,
        perm: FileMode,
    ) -> (nilable<File>, error) {
        let name: string = name.into();
        if (perm & FileMode(0o777)) != perm {
            return (
                crate::nilval::nil.into(),
                errors::Wrap(PathError {
                    Op: string::from_static("openat"),
                    Path: name,
                    Err: errors::New(string::from_static("unsupported file mode")),
                }),
            );
        }
        let (fd, err) = self.doInRoot(&name, flag, perm);
        if !err.IsNil() {
            return (crate::nilval::nil.into(), err);
        }
        return (nilable::new(File::NewFile(int::from(i64::from(fd)), name)), errors::nil);
    }
}

// go: sdk 1.25.5 os/root.go:301-351 splitPathInRoot
/// Go: split `s` into path components, appending to `prefix` and then
/// `suffix`. An empty path and an ABSOLUTE path are the two refusals
/// made here, before any syscall — an absolute symlink target reaches
/// this function and is rejected as an escape, which is why
/// `escape -> /tmp/x/secret.txt` fails the same way `../secret.txt`
/// does.
///
/// The returned `suffixSep` is the trailing separator run, kept so
/// that `Open("dir/")` still asks the kernel for a directory.
pub(crate) fn splitPathInRoot(
    s: &string,
    prefix: &[string],
    suffix: &[string],
) -> (Vec<string>, string, error) {
    let b = super::bytes_of(s);
    if b.is_empty() {
        return (
            Vec::new(),
            string::new(),
            errors::New(string::from_static("empty path")),
        );
    }
    if b[0] == b'/' {
        return (Vec::new(), string::new(), errPathEscapes());
    }
    let mut parts: Vec<string> = prefix.to_vec();
    let mut suffix_sep = string::new();
    let (mut i, mut j) = (0usize, 1usize);
    loop {
        if j < b.len() && b[j] != b'/' {
            j += 1;
            continue;
        }
        parts.push(string::from_bytes(&b[i..j]));
        let part_end = j;
        while j < b.len() && b[j] == b'/' {
            j += 1;
        }
        if j == b.len() {
            suffix_sep = string::from_bytes(&b[part_end..]);
            break;
        }
        // Go drops "." components, except at the end.
        if parts[parts.len() - 1].as_ref() as &str == "." {
            parts.pop();
        }
        i = j;
    }
    if !suffix.is_empty() && !parts.is_empty() && (parts[parts.len() - 1].as_ref() as &str) == "." {
        parts.pop();
    }
    parts.extend_from_slice(suffix);
    return (parts, suffix_sep, errors::nil);
}
