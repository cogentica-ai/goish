// go: file os/dir.go decls: CopyFS
//
// dir.go — CopyFS.
//
// Go's dir.go also holds the readdir modes and `File.ReadDir`, which
// this tree keeps in os/mod.rs alongside the rest of the File methods;
// only CopyFS is ported here, and the manifest says so.
//
// goishlint:ignore GOISH021 readdirMode, readdirName, readdirDirEntry, readdirFileInfo, DirEntry — the mode enum `readdir` switches on, which goish's ReadDir does not need because it has three separate entry points; `DirEntry` is Go's alias for `fs.DirEntry`, and goish uses `io::fs::DirEntry` directly.
// goishlint:ignore GOISH018 ReadDir, Readdirnames, readdir, testingForceReadDirLstat — `ReadDir`, `Readdirnames` and their worker live on `File` in os/mod.rs with the other File methods; `testingForceReadDirLstat` is a test hook Go's own tests set.

#![allow(non_snake_case)]

extern crate alloc;

use super::{FileMode, MkdirAll, OpenFile, PathError, Symlink, O_CREATE, O_EXCL, O_WRONLY};
use crate::errors::{self, error, nil};
use crate::gostring::string;
use crate::io;
use crate::io::fs;
use crate::types::int;

// go: sdk 1.25.5 os/dir.go:145-194 CopyFS
/// Go: "CopyFS copies the file system fsys into the directory dir,
/// creating dir if necessary."
///
/// Three edges are worth knowing, and the reference smoke pins all
/// three:
///
///   * It REFUSES to overwrite. Files are opened `O_CREATE|O_EXCL`, so
///     copying twice into the same destination fails with ErrExist
///     rather than clobbering — "Files are created with mode
///     0o666&^umask|(perm&0o777)" and existing ones are not touched.
///   * A symlink is RECREATED as a symlink, not followed. Go added
///     that in 1.24; before it, a link was silently replaced by a copy
///     of its target.
///   * The mode written is `0o666 | (source perm & 0o777)`, not the
///     source mode — so a 0o600 source lands 0o666 (before umask) and
///     only the EXECUTE bits actually carry across.
pub fn CopyFS<D: Into<string>>(dir: D, fsys: &(dyn fs::FS + Send + Sync + 'static)) -> error {
    let dir: string = dir.into();
    return fs::WalkDir(
        fsys,
        ".",
        move |path: string, d: &(dyn fs::DirEntry + Send + Sync + 'static), err: error| -> error {
            if err != nil {
                return err;
            }
            // Go: fpath, err := filepathlite.Localize(path)
            let (fpath, lerr) = crate::path::filepath::Localize(path.clone());
            if lerr != nil {
                return lerr;
            }
            // Go: newPath := joinPath(dir, fpath)
            let newPath =
                crate::path::filepath::Join(crate::goslice::slice::__from_vec(alloc::vec![
                    dir.clone(),
                    fpath
                ]));

            let ty = d.Type();
            if ty & super::ModeDir != FileMode(0) {
                // Go: return MkdirAll(newPath, 0777)
                return MkdirAll(newPath, FileMode(0o777));
            }
            if ty & super::ModeSymlink != FileMode(0) {
                // Go: target, err := fs.ReadLink(fsys, path)
                let (target, rerr) = fs::ReadLink(fsys, path.clone());
                if rerr != nil {
                    return rerr;
                }
                return Symlink(target, newPath);
            }
            if ty != FileMode(0) {
                // Go: default — anything that is not a regular file, a
                // directory or a symlink. A device or a socket cannot
                // be copied, and Go says so rather than producing
                // something that looks like it worked.
                return errors::Wrap(PathError {
                    Op: string::from_static("CopyFS"),
                    Path: path,
                    Err: super::ErrInvalid.into(),
                });
            }

            // Go: case 0 — a regular file.
            let (r, oerr) = fsys.Open(path.clone());
            if oerr != nil {
                return oerr;
            }
            let (info, serr) = r.Stat();
            if serr != nil {
                return serr;
            }
            // Go: OpenFile(newPath, O_CREATE|O_EXCL|O_WRONLY,
            //     0666|info.Mode()&0777)
            let perm = FileMode(0o666) | (info.Mode() & FileMode(0o777));
            let (w, werr) = OpenFile(newPath.clone(), O_CREATE | O_EXCL | O_WRONLY, perm);
            if werr != nil {
                return werr;
            }
            let mut w = w;
            let mut rr = __fs_file_reader(r);
            let (_, cerr) = io::Copy(w.MustMut(), &mut rr);
            if cerr != nil {
                let _ = w.MustMut().Close();
                return errors::Wrap(PathError {
                    Op: string::from_static("Copy"),
                    Path: newPath,
                    Err: cerr,
                });
            }
            return w.MustMut().Close();
        },
    );
}

// go: none — goish idiom: `io::Copy` wants a `&mut dyn io::Reader`, and
//     an `fs::File` is an `Arc<dyn fs::File>` whose Read takes `&self`.
//     This is the shim between the two; Go needs none because its
//     `fs.File` already satisfies `io.Reader`.
struct __FsFileReader(alloc::sync::Arc<dyn fs::File + Send + Sync>);

impl io::Reader for __FsFileReader {
    // go: none — goish idiom: see `__FsFileReader`.
    fn Read(&mut self, p: &mut crate::goslice::slice<crate::types::byte>) -> (int, error) {
        return self.0.Read(p);
    }
}

// go: none — goish idiom: see `__FsFileReader`.
pub(crate) fn __fs_file_reader(f: alloc::sync::Arc<dyn fs::File + Send + Sync>) -> impl io::Reader {
    return __FsFileReader(f);
}
