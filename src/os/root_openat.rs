// os/root_openat — Go 1.25.5 src/os/root_openat.go.
//
// The walk. `doInRoot` is the whole of Root's security property: it
// resolves a path one component at a time against a directory fd, and
// it is written so the FINAL step is a parameter, because Stat, Mkdir,
// Remove and the rest all want this walk with a different last move.
//
// INCREMENTAL PORT. `rootOpenFileNolog`'s share of the walk is here;
// the other operations that ride on it are UNPORTED, not waived.
//
// goishlint:ignore GOISH018 Error, errSymlink, rootChmod, rootChown, rootChtimes, rootLchown, rootMkdir, rootRemove, rootRename, rootLink, rootSymlink, rootReadlink, rootStat, rootOpenDir, rootOpenFileNolog, openRootInRoot, chmodat, chownat, chtimesat, lchownat, linkat, mkdirat, readlinkat, removeat, removedirat, removefileat, renameat, symlinkat, afterResolvingSymlink, checkSymlink, isNoFollowErr, modeAt, doInRoot, Close, Name, incref, decref, rootMkdirAll, rootRemoveAll - incremental port; these are unported, NOT waived.
// goishlint:ignore GOISH021 — file-wide. `errSymlink` and `root` are types goish does not have; see the GOISH019 note.
// goishlint:ignore GOISH019 — file-wide. `errSymlink` is Go's way of returning a link target through an error value; goish's walk gets the target directly from read_link_at, so there is no such type. Go's unexported `root` holds the fd, the name and a refcount behind a mutex; goish's Root holds the fd behind one, in root.rs, and has no refcount because it has no operation that hands the fd out.
// goishlint:ignore GOISH021 rootMaxSymlinks - the limit is a local const in the walk below, not a package-level one.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gostring::string;
use crate::syscall;
use crate::types::int;

use super::root::{errPathEscapes, splitPathInRoot, Root};
use super::{FileMode, PathError};

// go: none — goish-only: Go's `checkSymlink` (os/root_unix.go:139-149)
// answers "was that failure a symlink, and if so what does it point
// at" by calling readlinkat. goish returns the target directly, with
// None meaning "not a symlink".
/// Read the symlink at `parent`/`name`, or None if it is not one.
fn read_link_at(parent: i32, name: &string) -> Option<string> {
    let mut nb: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    nb.extend_from_slice(super::bytes_of(name));
    nb.push(0);
    let mut buf: Vec<u8> = alloc::vec![0u8; 4096];
    let n = syscall::Readlinkat(parent, nb.as_ptr(), buf.as_mut_ptr(), buf.len());
    if n < 0 {
        return None;
    }
    return Some(string::from_bytes(&buf[..n as usize]));
}

impl Root {
    // go: sdk 1.25.5 os/root_openat.go:265-400 doInRoot
    /// Go's walk, with the final step specialised to `openat` — Go
    /// passes it as a function so the same walk serves Stat, Mkdir and
    /// the rest, and this is written to be widened the same way.
    ///
    /// Two rules carry the whole security property, and both are
    /// easy to get subtly wrong:
    ///
    ///   * `..` does NOT `openat(dir, "..")`. The directory may have
    ///     been moved or replaced since it was opened, so walking up
    ///     through it can land somewhere else entirely. Go instead
    ///     REWRITES the path, dropping the component the `..` cancels,
    ///     and restarts from the root fd. If there is nothing left to
    ///     cancel, the path escapes.
    ///   * every open is O_NOFOLLOW, so a symlink cannot be traversed
    ///     by the kernel. When one is found it is read and its target
    ///     spliced into the remaining components — which sends an
    ///     absolute target through splitPathInRoot, where it is
    ///     rejected. A symlink that stays inside is FOLLOWED; Root
    ///     refuses escapes, not indirection.
    ///
    /// The step and restart limits are Go's, and they are why a
    /// hostile path cannot turn one Open into unbounded work.
    // goishlint:ignore GOISH023 — the body ends in the walk loop, and
    // every exit from it is an explicit `return`.
    pub(crate) fn doInRoot(&self, name: &string, flag: int, perm: FileMode) -> (i32, error) {
        const MAX_STEPS: i32 = 255;
        const MAX_RESTARTS: i32 = 8;
        const MAX_SYMLINKS: i32 = 8;

        let wrap = |e: error| -> error {
            return errors::Wrap(PathError {
                Op: string::from_static("openat"),
                Path: name.clone(),
                Err: e,
            });
        };

        let rootfd = *self.inner.fd.Lock();
        if rootfd < 0 {
            return (-1, wrap(super::ErrClosed.into()));
        }

        let (mut parts, mut suffix_sep, err) = splitPathInRoot(name, &[], &[]);
        if !err.IsNil() {
            return (-1, wrap(err));
        }

        let mut dirfd = rootfd;
        let mut i: usize = 0;
        let (mut steps, mut restarts, mut symlinks) = (0i32, 0i32, 0i32);
        loop {
            steps += 1;
            if steps > MAX_STEPS && restarts > MAX_RESTARTS {
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                // ENAMETOOLONG, as Go returns.
                return (-1, wrap(syscall::Errno(36).into()));
            }

            if (parts[i].as_ref() as &str) == ".." {
                restarts += 1;
                let mut end = i + 1;
                while end < parts.len() && (parts[end].as_ref() as &str) == ".." {
                    end += 1;
                }
                let count = end - i;
                if count > i {
                    if dirfd != rootfd {
                        syscall::Close(dirfd);
                    }
                    return (-1, wrap(errPathEscapes()));
                }
                parts.drain(i - count..end);
                if parts.is_empty() {
                    parts.push(string::from_static("."));
                }
                i = 0;
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                dirfd = rootfd;
                continue;
            }

            let last = i == parts.len() - 1;
            let comp = if last {
                parts[i].clone() + suffix_sep.clone()
            } else {
                parts[i].clone()
            };
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(&comp));
            cb.push(0);

            #[allow(clippy::let_and_return)]
            let openflags = if last {
                crate::int32(flag) | syscall::O_NOFOLLOW | syscall::O_CLOEXEC
            } else {
                syscall::O_RDONLY
                    | syscall::O_NOFOLLOW
                    | syscall::O_CLOEXEC
                    | syscall::O_DIRECTORY
            };
            let mode = if last { crate::int32(super::syscallMode(perm)) } else { 0 };
            let fd = syscall::Openat(dirfd, cb.as_ptr(), openflags, mode);
            if fd >= 0 {
                if last {
                    if dirfd != rootfd {
                        syscall::Close(dirfd);
                    }
                    return (fd, errors::nil);
                }
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                dirfd = fd;
                i += 1;
                continue;
            }

            // ELOOP (40) and ENOTDIR (20) are how O_NOFOLLOW reports a
            // symlink — ENOTDIR because a symlink used as a directory
            // component fails that way. Anything else is the real
            // error, reported against the path walked so far.
            let e = -fd;
            if e != 40 && e != 20 {
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                return (-1, wrap(syscall::Errno(e).into()));
            }
            let target = match read_link_at(dirfd, &parts[i]) {
                Some(t) => t,
                None => {
                    if dirfd != rootfd {
                        syscall::Close(dirfd);
                    }
                    return (-1, wrap(syscall::Errno(e).into()));
                }
            };
            symlinks += 1;
            if symlinks > MAX_SYMLINKS {
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                return (-1, wrap(syscall::Errno(40).into()));
            }
            let prefix: Vec<string> = parts[..i].to_vec();
            let rest: Vec<string> = parts[i + 1..].to_vec();
            let (newparts, new_sep, serr) = splitPathInRoot(&target, &prefix, &rest);
            if !serr.IsNil() {
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                return (-1, wrap(serr));
            }
            if last {
                suffix_sep = new_sep;
            }
            // A component already walked has changed: restart, because
            // the fds in hand no longer describe this path.
            let changed = newparts.len() < i || newparts[..i] != parts[..i];
            if changed {
                i = 0;
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                dirfd = rootfd;
            }
            parts = newparts;
        }
        // Unreachable: every exit from the walk is a `return` above.
    }
}
