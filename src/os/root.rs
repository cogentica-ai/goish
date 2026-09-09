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
// go: waived openRootNolog, newRoot — OpenRoot's body. Go opens the
// directory and then fstats it to reject a non-directory; goish passes
// O_DIRECTORY and lets the kernel answer, which renders identically
// ("not a directory") and is one syscall rather than two
// (examples/os_root_ref_smoke.rs).
// go: waived root.incref, root.decref, root.Close, root.Name — Go's
// unexported `root` refcounts because operations hand its fd out;
// goish's Root holds the fd behind a mutex and never lends it, so
// there is nothing to count. Name and Close are on Root itself.
// go: waived isValidRootFSPath — part of Root.FS, which is unported.

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
        // The final step: openat with the caller's flags. O_NOFOLLOW is
        // not optional — it is what stops the kernel traversing a
        // symlink out of the root — and ELOOP/ENOTDIR from it is the
        // signal to follow the link ourselves, under the walk's rules.
        let flag32 = crate::int32(flag);
        let mode32 = crate::int32(super::syscallMode(perm));
        let (fd, err) = self.__path_op(
            "openat",
            &name,
            |dirfd: i32, comp: &crate::gostring::string| {
                let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
                cb.extend_from_slice(super::bytes_of(comp));
                cb.push(0);
                let fd = syscall::__openat_raw(
                    dirfd,
                    cb.as_ptr(),
                    flag32 | syscall::O_NOFOLLOW | syscall::O_CLOEXEC,
                    mode32,
                );
                if fd >= 0 {
                    return super::root_openat::LastResult::Ok(fd);
                }
                let e = -fd;
                if e == 40 || e == 20 {
                    return super::root_openat::LastResult::Symlink;
                }
                return super::root_openat::LastResult::Err(e);
            },
        );
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

impl Root {
    // go: none — goish-only: Go wraps the walk's error at each call
    // site; one helper does it here because every one-name operation
    // owes the same `PathError{Op, Path}`.
    /// Run the walk and wrap any failure as Go's PathError.
    fn __path_op<T, F>(&self, op: &str, name: &string, f: F) -> (T, error)
    where
        T: Default,
        F: FnMut(i32, &string) -> super::root_openat::LastResult<T>,
    {
        let (v, err) = self.doInRoot(name, f);
        if !err.IsNil() {
            return (
                T::default(),
                errors::Wrap(PathError {
                    Op: string::from(op),
                    Path: name.clone(),
                    Err: err,
                }),
            );
        }
        return (v, errors::nil);
    }

    // go: sdk 1.25.5 os/root.go:108-110 Root.Create
    /// Go: "Create creates or truncates the named file in the root."
    pub fn Create<N: Into<string>>(&self, name: N) -> (nilable<File>, error) {
        return self.OpenFile(
            name,
            super::O_RDWR | super::O_CREATE | super::O_TRUNC,
            FileMode(0o666),
        );
    }

    // go: sdk 1.25.5 os/root.go:132-136 Root.OpenRoot
    /// Go: "OpenRoot opens the named directory in the root."
    ///
    /// The new Root is reached through the SAME walk, so `..` is
    /// refused here exactly as it is by Open — a caller cannot widen
    /// its own root by asking for the parent.
    pub fn OpenRoot<N: Into<string>>(&self, name: N) -> (nilable<Root>, error) {
        let name: string = name.into();
        let (f, err) = self.OpenFile(
            name.clone(),
            super::O_RDONLY | int::from(i64::from(syscall::O_DIRECTORY)),
            FileMode(0),
        );
        if !err.IsNil() {
            return (crate::nilval::nil.into(), err);
        }
        // The fd is taken over by the new Root. `File` has no Drop,
        // so letting it go here closes nothing — the Root owns the
        // descriptor from now on and its Close is what releases it.
        let f = f.MustTake();
        let fd = crate::int32(f.Fd());
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

    // go: sdk 1.25.5 os/root.go:200-207 Root.Stat
    /// Go: "Stat returns a FileInfo describing the named file in the
    /// root." Symlinks are FOLLOWED, so a link pointing outside is
    /// refused rather than described.
    pub fn Stat<N: Into<string>>(&self, name: N) -> (super::FileInfoData, error) {
        return self.__stat(name.into(), false);
    }

    // go: sdk 1.25.5 os/root.go:209-214 Root.Lstat
    /// Go: "Lstat returns a FileInfo describing the named file in the
    /// root. If the file is a symbolic link, the returned FileInfo
    /// describes the symbolic link."
    ///
    /// So this one does NOT follow, and `Lstat` on a link pointing
    /// outside SUCCEEDS — it describes the link, which is inside.
    pub fn Lstat<N: Into<string>>(&self, name: N) -> (super::FileInfoData, error) {
        return self.__stat(name.into(), true);
    }

    // go: sdk 1.25.5 os/root.go:149-155 Root.Mkdir
    /// Go: "Mkdir creates a new directory in the root with the
    /// specified name and permission bits."
    ///
    /// mkdirat never follows the final component, so a name that is
    /// already a symlink answers "file exists" rather than an escape —
    /// the link is in the way before its target is ever considered.
    pub fn Mkdir<N: Into<string>>(&self, name: N, perm: FileMode) -> error {
        let name: string = name.into();
        let mode = crate::int32(super::syscallMode(perm));
        let (_, err) = self.__path_op::<i32, _>("mkdirat", &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            let r = syscall::Mkdirat(dirfd, cb.as_ptr(), crate::uint32(mode));
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        return err;
    }

    // go: sdk 1.25.5 os/root.go:188-192 Root.Remove
    /// Go: "Remove removes the named file or (empty) directory in the
    /// root."
    ///
    /// unlinkat removes the NAME. A symlink pointing outside the root
    /// is deleted here and its target is untouched, which is both
    /// Go's behaviour and the safe one.
    pub fn Remove<N: Into<string>>(&self, name: N) -> error {
        let name: string = name.into();
        let (_, err) = self.__path_op::<i32, _>("removeat", &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            let r = syscall::Unlinkat(dirfd, cb.as_ptr(), 0);
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            // EISDIR (21) and EPERM (1) are how unlink(2) refuses a
            // directory; retry as rmdir, which is the whole of Go's
            // removeat.
            if -r == 21 || -r == 1 {
                let r2 = syscall::Unlinkat(dirfd, cb.as_ptr(), syscall::AT_REMOVEDIR);
                if r2 == 0 {
                    return super::root_openat::LastResult::Ok(0);
                }
                return super::root_openat::LastResult::Err(-r2);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        return err;
    }

    // go: none — goish-only: Go's Root.Stat and Root.Lstat both call
    // `rootStat(r, name, lstat bool)` (os/root_openat.go). Same shape.
    /// The shared body of Stat and Lstat.
    fn __stat(&self, name: string, lstat: bool) -> (super::FileInfoData, error) {
        let op = if lstat { "lstatat" } else { "statat" };
        let (st, err) = self.__path_op::<syscall::Stat_t, _>(op, &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            // ALWAYS AT_SYMLINK_NOFOLLOW, even for the following form.
            // Letting the kernel follow would resolve the link outside
            // the walk, and outside the walk there is no root: a
            // `Stat` of a link pointing out of the root SUCCEEDED that
            // way, describing a file the caller must not be able to
            // see. Stat follows by handing the link back to the walk,
            // which re-resolves it under the escape rules.
            let mut out = syscall::Stat_t::default();
            let r = syscall::Fstatat(
                dirfd,
                cb.as_ptr(),
                &mut out,
                syscall::AT_SYMLINK_NOFOLLOW,
            );
            if r != 0 {
                return super::root_openat::LastResult::Err(-r);
            }
            if !lstat && (out.st_mode & syscall::S_IFMT) == syscall::S_IFLNK {
                return super::root_openat::LastResult::Symlink;
            }
            return super::root_openat::LastResult::Ok(out);
        });
        if !err.IsNil() {
            return (
                super::FileInfoData {
                    name: name.clone(),
                    size: 0,
                    mode: FileMode(0),
                    mod_time: crate::time::Time::default(),
                    is_dir: false,
                    sys: None,
                },
                err,
            );
        }
        return (super::fileinfo_from_stat(super::base_name(&name), &st), errors::nil);
    }
}

// go: sdk 1.25.5 os/root.go:25-33 OpenInRoot
/// Go: "OpenInRoot opens the file name in the directory dir. It is
/// equivalent to OpenRoot(dir) followed by opening the file in the
/// root."
pub fn OpenInRoot<D: Into<string>, N: Into<string>>(
    dir: D,
    name: N,
) -> (nilable<File>, error) {
    let (r, err) = OpenRoot(dir);
    if !err.IsNil() {
        return (crate::nilval::nil.into(), err);
    }
    let r = r.MustTake();
    let out = r.Open(name);
    let _ = r.Close();
    return out;
}

impl Root {
    // go: sdk 1.25.5 os/root.go:216-221 Root.Readlink
    /// Go: "Readlink returns the destination of the named symbolic
    /// link in the root."
    ///
    /// This acts on the LINK, not through it — the same family as
    /// Lstat and Remove — so a link pointing outside the root is READ
    /// rather than refused, and the answer is the path it holds, which
    /// may well be outside. Reading a link is not following one.
    pub fn Readlink<N: Into<string>>(&self, name: N) -> (string, error) {
        let name: string = name.into();
        let (t, err) = self.__path_op::<string, _>("readlinkat", &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            let mut buf: Vec<u8> = alloc::vec![0u8; 4096];
            let n = syscall::Readlinkat(dirfd, cb.as_ptr(), buf.as_mut_ptr(), buf.len());
            if n < 0 {
                return super::root_openat::LastResult::Err(crate::int32(-n));
            }
            return super::root_openat::LastResult::Ok(string::from_bytes(&buf[..n as usize]));
        });
        return (t, err);
    }

    // go: sdk 1.25.5 os/root.go:253-262 Root.ReadFile
    /// Go: "ReadFile reads the named file in the root and returns its
    /// contents."
    ///
    /// Opened through `Open`, so it inherits that walk and its Op
    /// string: a refusal here says `openat`, not `readfile`.
    // goishlint:ignore GOISH023 — the body ends in the read loop, and
    // every exit from it is an explicit `return`.
    pub fn ReadFile<N: Into<string>>(&self, name: N) -> (crate::goslice::slice<super::byte>, error) {
        use crate::io::Reader;
        let (f, err) = self.Open(name);
        if !err.IsNil() {
            return (
                crate::goslice::slice::<super::byte>::__from_vec(Vec::new()),
                err,
            );
        }
        let mut f = f.MustTake();
        let mut out: Vec<super::byte> = Vec::new();
        let mut buf = crate::goslice::slice::<super::byte>::__from_vec(alloc::vec![0u8; 4096]);
        loop {
            let (n, rerr) = f.Read(&mut buf);
            if n > 0 {
                out.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            if !rerr.IsNil() {
                let _ = f.Close();
                if crate::errors::Is(rerr.clone(), crate::io::EOF) {
                    return (crate::goslice::slice::<super::byte>::__from_vec(out), errors::nil);
                }
                return (
                    crate::goslice::slice::<super::byte>::__from_vec(out),
                    rerr,
                );
            }
            if n == 0 {
                let _ = f.Close();
                return (crate::goslice::slice::<super::byte>::__from_vec(out), errors::nil);
            }
        }
    }

    // go: sdk 1.25.5 os/root.go:264-274 Root.WriteFile
    /// Go: "WriteFile writes data to the named file in the root,
    /// creating it if necessary."
    ///
    /// Also through the walk, via OpenFile — which is why writing to a
    /// symlink that points outside is refused rather than following it
    /// and overwriting whatever is there.
    pub fn WriteFile<N: Into<string>, D: AsRef<[super::byte]>>(
        &self,
        name: N,
        data: D,
        perm: FileMode,
    ) -> error {
        use crate::io::Writer;
        let (f, err) = self.OpenFile(
            name,
            super::O_WRONLY | super::O_CREATE | super::O_TRUNC,
            perm,
        );
        if !err.IsNil() {
            return err;
        }
        let mut f = f.MustTake();
        let d = crate::goslice::slice::<super::byte>::__from_vec(data.as_ref().to_vec());
        let (_, werr) = f.Write(d);
        let cerr = f.Close();
        if !werr.IsNil() {
            return werr;
        }
        return cerr;
    }
}

impl Root {
    // go: none — goish-only: Go wraps a two-name failure at each call
    // site; one helper does it here because Rename, Link and Symlink
    // all owe the same `LinkError{Op, Old, New}` — the shape whose
    // message names BOTH paths, which is how a caller tells which end
    // escaped.
    /// Resolve `old` and then `new` through the walk, and run `f` with
    /// both parents. An escape in EITHER position fails.
    fn __link_op<F>(&self, op: &str, old: &string, new: &string, mut f: F) -> error
    where
        F: FnMut(i32, &string, i32, &string) -> i32,
    {
        let mkerr = |e: error| -> error {
            return errors::Wrap(super::LinkError {
                Op: string::from(op),
                Old: old.clone(),
                New: new.clone(),
                Err: e,
            });
        };
        // Nested walks, as Go nests doInRoot inside doInRoot: the outer
        // one holds the old parent open while the inner resolves the
        // new name.
        let (_, err) = self.doInRoot::<i32, _>(old, |oldparent, oldcomp| {
            let oldcomp = oldcomp.clone();
            let (_, inner) = self.doInRoot::<i32, _>(new, |newparent, newcomp| {
                let r = f(oldparent, &oldcomp, newparent, newcomp);
                if r == 0 {
                    return super::root_openat::LastResult::Ok(0);
                }
                return super::root_openat::LastResult::Err(-r);
            });
            if !inner.IsNil() {
                return super::root_openat::LastResult::Errored(inner);
            }
            return super::root_openat::LastResult::Ok(0);
        });
        if !err.IsNil() {
            return mkerr(err);
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 os/root.go:223-233 Root.Rename
    /// Go: "Rename renames (moves) oldname to newname in the root."
    ///
    /// BOTH names go through the walk. Resolving one and taking the
    /// other at face value would pass every single-name test in the
    /// tree and still let a caller move a file out of the root.
    pub fn Rename<O: Into<string>, N: Into<string>>(&self, oldname: O, newname: N) -> error {
        let (o, n) = (oldname.into(), newname.into());
        return self.__link_op("renameat", &o, &n, |op, oc, np, nc| {
            let mut ob: Vec<u8> = Vec::with_capacity(oc.Len() as usize + 1);
            ob.extend_from_slice(super::bytes_of(oc));
            ob.push(0);
            let mut nb: Vec<u8> = Vec::with_capacity(nc.Len() as usize + 1);
            nb.extend_from_slice(super::bytes_of(nc));
            nb.push(0);
            return syscall::Renameat(op, ob.as_ptr(), np, nb.as_ptr());
        });
    }

    // go: sdk 1.25.5 os/root.go:235-245 Root.Link
    /// Go: "Link creates a hard link to oldname in the root."
    ///
    /// Flags are 0: without AT_SYMLINK_FOLLOW a symlink is linked as
    /// itself and never resolved, so linking a link that points
    /// outside copies the LINK, not the file it names.
    pub fn Link<O: Into<string>, N: Into<string>>(&self, oldname: O, newname: N) -> error {
        let (o, n) = (oldname.into(), newname.into());
        return self.__link_op("linkat", &o, &n, |op, oc, np, nc| {
            let mut ob: Vec<u8> = Vec::with_capacity(oc.Len() as usize + 1);
            ob.extend_from_slice(super::bytes_of(oc));
            ob.push(0);
            let mut nb: Vec<u8> = Vec::with_capacity(nc.Len() as usize + 1);
            nb.extend_from_slice(super::bytes_of(nc));
            nb.push(0);
            return syscall::Linkat(op, ob.as_ptr(), np, nb.as_ptr(), 0);
        });
    }

    // go: sdk 1.25.5 os/root.go:247-251 Root.Symlink
    /// Go: "Symlink creates newname as a symbolic link to oldname."
    ///
    /// Only NEWNAME is resolved. The target is bytes stored in the
    /// link and is never checked, so `Symlink("/etc/passwd", …)`
    /// succeeds — and creates a link this same Root then refuses to
    /// follow. That is the whole design: the check belongs at
    /// resolution, not at creation, because a link's meaning depends
    /// on who resolves it.
    pub fn Symlink<O: Into<string>, N: Into<string>>(&self, oldname: O, newname: N) -> error {
        let (o, n) = (oldname.into(), newname.into());
        let mut tb: Vec<u8> = Vec::with_capacity(o.Len() as usize + 1);
        tb.extend_from_slice(super::bytes_of(&o));
        tb.push(0);
        let (_, err) = self.doInRoot::<i32, _>(&n, |dirfd, comp| {
            let mut nb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            nb.extend_from_slice(super::bytes_of(comp));
            nb.push(0);
            let r = syscall::Symlinkat(tb.as_ptr(), dirfd, nb.as_ptr());
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        if !err.IsNil() {
            return errors::Wrap(super::LinkError {
                Op: string::from_static("symlinkat"),
                Old: o,
                New: n,
                Err: err,
            });
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 os/root.go:139-147 Root.Chmod
    /// Go: "Chmod changes the mode of the named file in the root."
    ///
    /// Symlinks are FOLLOWED, so chmod through a link pointing outside
    /// is refused rather than silently changing a file the caller
    /// cannot otherwise reach.
    pub fn Chmod<N: Into<string>>(&self, name: N, mode: FileMode) -> error {
        let name: string = name.into();
        let m = crate::uint32(crate::int32(super::syscallMode(mode)));
        let (_, err) = self.__path_op::<i32, _>("chmodat", &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            // AT_SYMLINK_NOFOLLOW first, purely to LOOK: fchmodat's
            // own NOFOLLOW is unsupported on Linux, so the link has to
            // be handed to the walk instead of chmod'ed through.
            let mut st = syscall::Stat_t::default();
            let sr = syscall::Fstatat(dirfd, cb.as_ptr(), &mut st, syscall::AT_SYMLINK_NOFOLLOW);
            if sr == 0 && (st.st_mode & syscall::S_IFMT) == syscall::S_IFLNK {
                return super::root_openat::LastResult::Symlink;
            }
            let r = syscall::Fchmodat(dirfd, cb.as_ptr(), m, 0);
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        return err;
    }

    // go: sdk 1.25.5 os/root.go:170-174 Root.Chown
    /// Go: "Chown changes the numeric uid and gid of the named file in
    /// the root." Symlinks are followed.
    pub fn Chown<N: Into<string>>(&self, name: N, uid: int, gid: int) -> error {
        return self.__chown(name.into(), uid, gid, false);
    }

    // go: sdk 1.25.5 os/root.go:176-180 Root.Lchown
    /// Go: "Lchown changes the numeric uid and gid of the named file
    /// in the root. If the file is a symbolic link, it changes the uid
    /// and gid of the link itself."
    pub fn Lchown<N: Into<string>>(&self, name: N, uid: int, gid: int) -> error {
        return self.__chown(name.into(), uid, gid, true);
    }

    // go: none — goish-only: Go's Chown and Lchown differ only in the
    // AT_SYMLINK_NOFOLLOW flag and the Op string.
    /// The shared body of Chown and Lchown.
    fn __chown(&self, name: string, uid: int, gid: int, lchown: bool) -> error {
        let op = if lchown { "lchownat" } else { "chownat" };
        let (u, g) = (crate::uint32(crate::int32(uid)), crate::uint32(crate::int32(gid)));
        let (_, err) = self.__path_op::<i32, _>(op, &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            let flags = if lchown { syscall::AT_SYMLINK_NOFOLLOW } else { 0 };
            if !lchown {
                // Following is the walk's job, never the kernel's.
                let mut st = syscall::Stat_t::default();
                let sr =
                    syscall::Fstatat(dirfd, cb.as_ptr(), &mut st, syscall::AT_SYMLINK_NOFOLLOW);
                if sr == 0 && (st.st_mode & syscall::S_IFMT) == syscall::S_IFLNK {
                    return super::root_openat::LastResult::Symlink;
                }
            }
            let r = syscall::Fchownat(dirfd, cb.as_ptr(), u, g, flags);
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        return err;
    }
}

impl Root {
    // go: sdk 1.25.5 os/root.go:182-186 Root.Chtimes
    /// Go: "Chtimes changes the access and modification times of the
    /// named file in the root."
    ///
    /// The Timespec conversion is `os::Chtimes`'s, including the
    /// negative-nsec correction a pre-1970 fractional time needs —
    /// utimensat rejects a tv_nsec outside [0, 1e9) with EINVAL.
    pub fn Chtimes<N: Into<string>>(
        &self,
        name: N,
        atime: crate::time::Time,
        mtime: crate::time::Time,
    ) -> error {
        let name: string = name.into();
        let set = |t: crate::time::Time| -> syscall::Timespec {
            if t.IsZero() {
                return syscall::Timespec {
                    tv_sec: syscall::UTIME_OMIT,
                    tv_nsec: syscall::UTIME_OMIT,
                };
            }
            let ns = crate::int64(t.UnixNano());
            let mut sec = ns / 1_000_000_000;
            let mut nsec = ns % 1_000_000_000;
            if nsec < 0 {
                nsec += 1_000_000_000;
                sec -= 1;
            }
            return syscall::Timespec {
                tv_sec: sec,
                tv_nsec: nsec,
            };
        };
        let utimes = [set(atime), set(mtime)];
        let (_, err) = self.__path_op::<i32, _>("chtimesat", &name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            // Following is the walk's job, never the kernel's — the
            // same rule as Stat and Chmod.
            let mut st = syscall::Stat_t::default();
            let sr = syscall::Fstatat(dirfd, cb.as_ptr(), &mut st, syscall::AT_SYMLINK_NOFOLLOW);
            if sr == 0 && (st.st_mode & syscall::S_IFMT) == syscall::S_IFLNK {
                return super::root_openat::LastResult::Symlink;
            }
            let r = syscall::Utimensat(dirfd, cb.as_ptr(), utimes.as_ptr(), 0);
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        return err;
    }

    // go: none — goish-only: Mkdir's walk without the PathError, so
    // MkdirAll can report the ORIGINAL path rather than the prefix it
    // happened to fail on — Go says `mkdirat ../evil/x: path escapes
    // from parent`, not `mkdirat ..: …` nested inside it.
    /// Mkdir one component, returning the walk's bare error.
    fn __mkdir_bare(&self, name: &string, perm: FileMode) -> error {
        let mode = crate::int32(super::syscallMode(perm));
        let (_, err) = self.doInRoot::<i32, _>(name, |dirfd, comp| {
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(comp));
            cb.push(0);
            let r = syscall::Mkdirat(dirfd, cb.as_ptr(), crate::uint32(mode));
            if r == 0 {
                return super::root_openat::LastResult::Ok(0);
            }
            return super::root_openat::LastResult::Err(-r);
        });
        return err;
    }

    // go: sdk 1.25.5 os/root.go:161-168 Root.MkdirAll
    /// Go: "MkdirAll creates a new directory in the root, along with
    /// any necessary parents."
    ///
    /// Go does this inside ONE walk, with a custom `openDirFunc` that
    /// creates a missing intermediate instead of failing on it
    /// (root_openat.go:170) — the only caller that passes one. goish
    /// walks a prefix at a time instead: each prefix is a full,
    /// independently checked resolution, so an escape anywhere in the
    /// path is refused before anything is created. Slower in syscalls,
    /// identical in what it permits, and it does not need the walk to
    /// grow a parameter for one caller.
    pub fn MkdirAll<N: Into<string>>(&self, name: N, perm: FileMode) -> error {
        let name: string = name.into();
        // Refuse the whole path FIRST, so a rejected MkdirAll leaves
        // nothing behind: `../evil/x` must not create `evil`.
        let (parts, _, serr) = splitPathInRoot(&name, &[], &[]);
        if !serr.IsNil() {
            return errors::Wrap(PathError {
                Op: string::from_static("mkdirat"),
                Path: name,
                Err: serr,
            });
        }
        let mut prefix = string::new();
        for (i, p) in parts.iter().enumerate() {
            if (p.as_ref() as &str) == "." {
                continue;
            }
            if i > 0 && prefix.Len() > 0 {
                prefix = prefix + string::from_static("/");
            }
            prefix = prefix + p.clone();
            let err = self.__mkdir_bare(&prefix, perm);
            if err.IsNil() {
                continue;
            }
            // EEXIST is fine only when what exists is a directory,
            // which is Go's rule for MkdirAll.
            let (fi, serr) = self.Stat(prefix.clone());
            if serr.IsNil() && fi.IsDir() {
                continue;
            }
            return errors::Wrap(PathError {
                Op: string::from_static("mkdirat"),
                Path: name,
                Err: err,
            });
        }
        return errors::nil;
    }
}

impl Root {
    // go: sdk 1.25.5 os/root.go:194-198 Root.RemoveAll
    /// Go: "RemoveAll removes the named file or directory and any
    /// children that it contains."
    ///
    /// Note the Op: a refusal here says `RemoveAll`, not `removeat` —
    /// Go names the operation the caller asked for, not the syscall it
    /// got to.
    ///
    /// Every step goes through the walk, including each child, so a
    /// symlink inside the tree is UNLINKED rather than followed. That
    /// is not a detail: `os::RemoveAll` had the mirror bug — it stat'ed
    /// where Go lstats, followed a link to a directory, and deleted the
    /// target's contents. Inside a Root the same mistake would delete
    /// outside the root, which is the one thing a Root exists to
    /// prevent. The reference pins it with a link to a directory
    /// outside, sitting in the tree being removed.
    pub fn RemoveAll<N: Into<string>>(&self, name: N) -> error {
        let name: string = name.into();
        // Resolve the path through the walk BEFORE removing anything.
        //
        // Not belt and braces: without it this failed OPEN. The escape
        // surfaced as a Remove error, and the "already gone is not an
        // error" branch below then swallowed it and returned nil — a
        // refusal reported as success, which is the worst shape a
        // security check can fail in. The final step is a no-op, so
        // this only resolves; it does not remove.
        let (_, werr) = self.doInRoot::<i32, _>(&name, |_dirfd, _comp| {
            return super::root_openat::LastResult::Ok(0);
        });
        if !werr.IsNil() {
            return errors::Wrap(PathError {
                Op: string::from_static("RemoveAll"),
                Path: name,
                Err: werr,
            });
        }
        return self.__remove_all(name.clone(), &name);
    }

    // go: none — goish-only: the recursion behind RemoveAll, carrying
    // the ORIGINAL name so every error names what the caller asked to
    // remove rather than the child that failed.
    /// Remove `path` and anything under it.
    fn __remove_all(&self, path: string, orig: &string) -> error {
        // Remove first — it unlinks a symlink of any kind without
        // looking through it, which settles every non-directory case
        // before anything can be followed. The same order os::RemoveAll
        // now uses, and for the same reason.
        let err = self.Remove(path.clone());
        if err.IsNil() {
            return errors::nil;
        }
        // Gone already is not an error — but ONLY gone. Go swallows
        // exactly IsNotExist and ENOTDIR here and returns everything
        // else (removeall_noat.go:36-42). Swallowing every Lstat
        // failure would turn a permission error, or a refusal from the
        // walk, into a silent success: the same fail-open shape that
        // made RemoveAll("../victim") answer nil a few commits ago,
        // one level further down.
        let (fi, lerr) = self.Lstat(path.clone());
        if !lerr.IsNil() {
            if super::IsNotExist(lerr.clone()) {
                return errors::nil;
            }
            return lerr;
        }
        if !fi.IsDir() {
            return err;
        }
        // A directory: list it through the root and recurse.
        let (d, derr) = self.OpenFile(
            path.clone(),
            super::O_RDONLY | int::from(i64::from(syscall::O_DIRECTORY)),
            FileMode(0),
        );
        if !derr.IsNil() {
            return derr;
        }
        let mut d = d.MustTake();
        let (names, nerr) = d.Readdirnames(int::from(-1));
        let _ = d.Close();
        if !nerr.IsNil() {
            return nerr;
        }
        for i in 0..names.Len() {
            let child = path.clone() + string::from_static("/") + names[i].clone();
            let cerr = self.__remove_all(child, orig);
            if !cerr.IsNil() {
                return cerr;
            }
        }
        return self.Remove(path);
    }
}
