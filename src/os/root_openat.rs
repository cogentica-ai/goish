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
// Go splits every Root operation into a pair — `rootChmod` calling
// `chmodat`, `rootStat` calling `modeAt`, and so on — because its walk
// takes the last step as a function value and each pair supplies one.
// The `root*` half lives in root_openat.go and the `*at` half in
// root_unix.go; both are waived here because both are one closure in
// goish, and coverage matches waivers by name across the package.
// goish's walk takes a CLOSURE, so each pair is one closure at the
// operation's own definition in root.rs. The behaviour is ported and
// pinned; there is no separate declaration to anchor. Each waiver
// names the closure that replaced it and the smoke that would catch
// its loss.
//
// go: waived rootOpenFileNolog — Root.OpenFile's closure in root.rs
// (examples/os_root_ref_smoke.rs).
// go: waived rootOpenDir — the intermediate-component openat in the
// walk below, which is what Go's default openDirFunc does
// (examples/os_root_ref_smoke.rs).
// go: waived rootStat — Root.__stat's closure, both the following and
// the NOFOLLOW form (examples/os_root2_ref_smoke.rs).
// go: waived modeAt — the S_IFLNK test inside that closure, which is
// what decides whether the walk is asked to follow
// (examples/os_root2_ref_smoke.rs).
// go: waived rootMkdirAll — Root.MkdirAll, which walks a prefix at a
// time rather than taking Go's custom openDirFunc; the divergence is
// argued at the declaration (examples/os_root5_ref_smoke.rs).
// go: waived openRootInRoot — Root.OpenRoot, which reuses OpenFile's
// walk rather than a second entry point
// (examples/os_root2_ref_smoke.rs).
// go: waived rootMkdir — Root.Mkdir's closure (examples/os_root2_ref_smoke.rs).
// go: waived mkdirat — the mkdirat call in Root.Mkdir's closure (examples/os_root2_ref_smoke.rs).
// go: waived rootRemove — Root.Remove's closure (examples/os_root2_ref_smoke.rs).
// go: waived removeat — the unlinkat call in Root.Remove's closure (examples/os_root2_ref_smoke.rs).
// go: waived removedirat — the AT_REMOVEDIR retry in that same closure, which is Go's file-then-directory fallback (examples/os_root2_ref_smoke.rs).
// go: waived removefileat — the first unlinkat of that same pair (examples/os_root2_ref_smoke.rs).
// go: waived rootReadlink — Root.Readlink's closure (examples/os_root3_ref_smoke.rs).
// go: waived readlinkat — the readlinkat call in it (examples/os_root3_ref_smoke.rs).
// go: waived rootRename — Root.Rename's closure (examples/os_root4_ref_smoke.rs).
// go: waived renameat — the renameat call in it (examples/os_root4_ref_smoke.rs).
// go: waived rootLink — Root.Link's closure (examples/os_root4_ref_smoke.rs).
// go: waived linkat — the linkat call in it (examples/os_root4_ref_smoke.rs).
// go: waived rootSymlink — Root.Symlink's closure (examples/os_root4_ref_smoke.rs).
// go: waived symlinkat — the symlinkat call in it (examples/os_root4_ref_smoke.rs).
// go: waived rootChmod — Root.Chmod's closure (examples/os_root4_ref_smoke.rs).
// go: waived chmodat — the fchmodat call in it (examples/os_root4_ref_smoke.rs).
// go: waived rootChown — Root.__chown with lchown=false (examples/os_root4_ref_smoke.rs).
// go: waived rootLchown — Root.__chown with lchown=true — Go's two functions differ only in the AT_SYMLINK_NOFOLLOW flag and the Op string (examples/os_root4_ref_smoke.rs).
// go: waived chownat — the fchownat call in Root.__chown (examples/os_root4_ref_smoke.rs).
// go: waived lchownat — the same call with AT_SYMLINK_NOFOLLOW (examples/os_root4_ref_smoke.rs).
// go: waived rootChtimes — Root.Chtimes's closure (examples/os_root5_ref_smoke.rs).
// go: waived chtimesat — the utimensat call in it (examples/os_root5_ref_smoke.rs).
// go: waived rootRemoveAll — Root.__remove_all (examples/os_root5_ref_smoke.rs).
// go: waived removeAllFrom — the child recursion inside Root.__remove_all (examples/os_root5_ref_smoke.rs).
// go: waived isNoFollowErr — the ELOOP/ENOTDIR test in the walk below.
// go: waived isErrNoFollow — the same test.
// go: waived checkSymlink — read_link_at below, which answers the same
// question ("was that a symlink, and what does it point at") by
// returning the target instead of an error carrying it.
// go: waived afterResolvingSymlink — goish resolves the link inline in
// the walk rather than through a callback.

// goishlint:ignore GOISH021 — file-wide. `errSymlink` and `root` are types goish does not have; see the GOISH019 note.
// goishlint:ignore GOISH019 — file-wide. `errSymlink` is Go's way of returning a link target through an error value; goish's walk gets the target directly from read_link_at, so there is no such type. Go's unexported `root` holds the fd, the name and a refcount behind a mutex; goish's Root holds the fd behind one, in root.rs, and has no refcount because it has no operation that hands the fd out.
// goishlint:ignore GOISH021 rootMaxSymlinks - the limit is a local const in the walk below, not a package-level one.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gostring::string;
use crate::syscall;

use super::root::{errPathEscapes, splitPathInRoot, Root};

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
    // goishlint:ignore GOISH020 — Go takes four parameters: the Root,
    // the name, an `openDirFunc` for the INTERMEDIATE components, and
    // `f` for the last one. goish takes three: `self` is the Root, and
    // openDirFunc is not a parameter here because the one operation
    // that needs a custom one is not ported. Every caller but
    // `rootMkdirAll` passes nil (meaning `rootOpenDir`, which the walk
    // does inline below); rootMkdirAll passes a variant that CREATES a
    // missing intermediate directory instead of failing on it, at
    // root_openat.go:170. Porting MkdirAll means restoring this
    // parameter — it is not an accident of shape.
    /// The error returned is BARE — `path escapes from parent`, an
    /// errno — with no PathError around it. Wrapping is the caller's,
    /// because a one-name operation owes a `PathError{Op, Path}` and a
    /// two-name one owes a `LinkError{Op, Old, New}`, and only the
    /// caller knows which it is.
    pub(crate) fn doInRoot<T, F>(&self, name: &string, mut last: F) -> (T, error)
    where
        T: Default,
        F: FnMut(i32, &string) -> LastResult<T>,
    {
        const MAX_STEPS: i32 = 255;
        const MAX_RESTARTS: i32 = 8;
        const MAX_SYMLINKS: i32 = 8;

        let rootfd = *self.inner.fd.Lock();
        if rootfd < 0 {
            return (T::default(), super::ErrClosed.into());
        }

        let (mut parts, mut suffix_sep, err) = splitPathInRoot(name, &[], &[]);
        if !err.IsNil() {
            return (T::default(), err);
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
                return (T::default(), syscall::Errno(36).into());
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
                    return (T::default(), errPathEscapes());
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

            let is_last = i == parts.len() - 1;
            let comp = if is_last {
                parts[i].clone() + suffix_sep.clone()
            } else {
                parts[i].clone()
            };
            let mut cb: Vec<u8> = Vec::with_capacity(comp.Len() as usize + 1);
            cb.extend_from_slice(super::bytes_of(&comp));
            cb.push(0);

            // The final component is the caller's business; every
            // component before it is a directory this walk must open
            // itself, always with O_NOFOLLOW so the kernel cannot
            // traverse a link on our behalf.
            let e: i32;
            if is_last {
                match last_step(&mut last, dirfd, &comp) {
                    LastResult::Ok(v) => {
                        if dirfd != rootfd {
                            syscall::Close(dirfd);
                        }
                        return (v, errors::nil);
                    }
                    LastResult::Err(errno) => {
                        if dirfd != rootfd {
                            syscall::Close(dirfd);
                        }
                        return (T::default(), syscall::Errno(errno).into());
                    }
                    LastResult::Errored(e) => {
                        if dirfd != rootfd {
                            syscall::Close(dirfd);
                        }
                        return (T::default(), e);
                    }
                    // The step wants the link followed: fall through to
                    // the splice below, exactly as Go's errSymlink does.
                    LastResult::Symlink => {
                        e = 40;
                    }
                }
            } else {
                let fd = syscall::__openat_raw(
                    dirfd,
                    cb.as_ptr(),
                    syscall::O_RDONLY
                        | syscall::O_NOFOLLOW
                        | syscall::O_CLOEXEC
                        | syscall::O_DIRECTORY,
                    0,
                );
                if fd >= 0 {
                    if dirfd != rootfd {
                        syscall::Close(dirfd);
                    }
                    dirfd = fd;
                    i += 1;
                    continue;
                }
                // ELOOP (40) and ENOTDIR (20) are how O_NOFOLLOW reports
                // a symlink — ENOTDIR because a symlink used as a
                // directory component fails that way. Anything else is
                // the real error.
                e = -fd;
                if e != 40 && e != 20 {
                    if dirfd != rootfd {
                        syscall::Close(dirfd);
                    }
                    return (T::default(), syscall::Errno(e).into());
                }
            }
            let target = match read_link_at(dirfd, &parts[i]) {
                Some(t) => t,
                None => {
                    if dirfd != rootfd {
                        syscall::Close(dirfd);
                    }
                    return (T::default(), syscall::Errno(e).into());
                }
            };
            symlinks += 1;
            if symlinks > MAX_SYMLINKS {
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                return (T::default(), syscall::Errno(40).into());
            }
            let prefix: Vec<string> = parts[..i].to_vec();
            let rest: Vec<string> = parts[i + 1..].to_vec();
            let (newparts, new_sep, serr) = splitPathInRoot(&target, &prefix, &rest);
            if !serr.IsNil() {
                if dirfd != rootfd {
                    syscall::Close(dirfd);
                }
                return (T::default(), serr);
            }
            if is_last {
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

// go: none — goish-only: Go's final step returns `(T, error)` and
// signals "follow this symlink" with a distinguished `errSymlink`
// error carrying the target. goish has no error type carrying a
// payload the walk can read back, so the three outcomes are an enum
// and the target is read by the walk itself.
/// What a walk's final step can answer.
pub(crate) enum LastResult<T> {
    /// Done — this is the value.
    Ok(T),
    /// Failed, with a positive errno.
    Err(i32),
    /// Failed with an error already shaped by an inner walk — a
    /// two-name operation nests one walk inside another, and the
    /// inner failure must reach the caller unchanged rather than
    /// being flattened to an errno.
    Errored(error),
    /// The final component is a symlink and this operation FOLLOWS it.
    /// An operation that acts on the link itself — Lstat, Remove,
    /// Mkdir — never answers this, which is why `remove escape`
    /// deletes the link and `lstat escape` describes it.
    Symlink,
}

// go: none — goish-only: a named call so the walk's borrow of the
// closure ends before the loop continues.
fn last_step<T, F>(f: &mut F, dirfd: i32, comp: &string) -> LastResult<T>
where
    F: FnMut(i32, &string) -> LastResult<T>,
{
    return f(dirfd, comp);
}
