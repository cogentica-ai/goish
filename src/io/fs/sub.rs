// go: file io/fs/sub.go decls: Sub, subFS.fullName, subFS.shorten, subFS.fixErr, subFS.Open, subFS.ReadDir, subFS.ReadFile, subFS.ReadLink, subFS.Lstat, subFS.Glob, subFS.Sub
//
// sub.go — SubFS, Sub and subFS.
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int};

use super::*;

// ─── Sub (sub.go) ────────────────────────────────────────────────────

// go: sdk 1.25.5 io/fs/sub.go:13-18 SubFS
/// `fs.SubFS` (sub.go:12) — a file system with an optimized `Sub`
/// implementation. Embeds [`FS`] in Go (re-declared; see note above).
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait SubFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `Sub(dir)` — an FS corresponding to the subtree rooted at dir.
    fn Sub(&self, dir: string) -> (Arc<dyn FS + Send + Sync>, error);
}

// go: sdk 1.25.5 io/fs/sub.go:35-46 Sub
/// `fs.Sub(fsys, dir)` (sub.go:25) — an FS corresponding to the
/// subtree rooted at `fsys`'s `dir`.
///
/// If `dir` is `.`, `Sub` returns `fsys` unchanged. If `fsys`
/// implements [`SubFS`], `Sub` calls its `Sub`. Otherwise it returns
/// a wrapper that translates paths (the wrapper forwards optimized
/// `ReadDir` / `ReadFile` / `Stat` through the free functions; Go's
/// error-path shortening inside the wrapper is not replicated).
pub fn Sub<S: Into<string>>(
    fsys: Arc<dyn FS + Send + Sync>,
    dir: S,
) -> (Arc<dyn FS + Send + Sync>, error) {
    let dir: string = dir.into();
    // Go: if !ValidPath(dir) { return nil, &PathError{...} }
    if !ValidPath(dir.clone()) {
        return (
            crate::nil.into(),
            errors::Wrap(PathError {
                Op: string::from_static("sub"),
                Path: dir,
                Err: ErrInvalid.into(),
            }),
        );
    }
    // Go: if dir == "." { return fsys, nil }
    if dir.as_bytes() == b"." {
        return (fsys, errors::nil);
    }
    // Go: if fsys, ok := fsys.(SubFS); ok { return fsys.Sub(dir) }
    let (sfs, ok) = goish::cast!(&*fsys, SubFS);
    if ok {
        return sfs.Sub(dir);
    }
    register_subfs_impls();
    return (Arc::new(subFS { fsys, dir }), errors::nil);
}

// go: sdk 1.25.5 io/fs/sub.go:54-57 subFS
// Go: `type subFS struct { fsys FS; dir string }`
struct subFS {
    fsys: Arc<dyn FS + Send + Sync>,
    dir: string,
}

impl subFS {
    // go: sdk 1.25.5 io/fs/sub.go:60-65 subFS.fullName
    /// Maps `name` to the fully-qualified name `dir/name`.
    ///
    /// The rejection used to be `errors.New("invalid name")`. Go's is
    /// `ErrInvalid`, which is the whole point — a caller writes
    /// `errors.Is(err, fs.ErrInvalid)`, and a fresh error answers no.
    fn fullName(&self, op: &'static str, name: &string) -> (string, error) {
        if !ValidPath(name.clone()) {
            return (
                string::new(),
                errors::Wrap(PathError {
                    Op: string::from_static(op),
                    Path: name.clone(),
                    Err: ErrInvalid.into(),
                }),
            );
        }
        return (
            crate::path::Join(slice::__from_vec(alloc::vec![
                self.dir.clone(),
                name.clone()
            ])),
            errors::nil,
        );
    }

    // go: sdk 1.25.5 io/fs/sub.go:68-77 subFS.shorten
    /// Maps `name`, which should start with `f.dir`, back to the suffix
    /// after `f.dir`.
    fn shorten(&self, name: &string) -> (string, bool) {
        if name.as_bytes() == self.dir.as_bytes() {
            return (string::from_static("."), true);
        }
        let (n, d) = (name.as_bytes(), self.dir.as_bytes());
        if n.len() >= d.len() + 2 && n[d.len()] == b'/' && &n[..d.len()] == d {
            return (string::from_bytes(&n[d.len() + 1..]), true);
        }
        return (string::new(), false);
    }

    // go: sdk 1.25.5 io/fs/sub.go:79-86 subFS.fixErr
    /// Shortens any reported names in `PathError`s by stripping `f.dir`.
    ///
    /// Without this a sub-filesystem leaks its parent's paths into every
    /// error it reports — `open sub/dir/x: …` where the caller only ever
    /// named `x`. Go mutates the `PathError` in place; goish's `error`
    /// is a shared handle, so this rebuilds it.
    fn fixErr(&self, err: error) -> error {
        if err == errors::nil {
            return err;
        }
        // Go: e, ok := err.(*PathError)
        let pe = match errors::As::<PathError>(err.clone()) {
            Some(pe) => pe,
            None => return err,
        };
        let (short, ok) = self.shorten(&pe.Path);
        if !ok {
            return err;
        }
        return errors::Wrap(PathError {
            Op: pe.Op.clone(),
            Path: short,
            Err: pe.Err.clone(),
        });
    }
}

impl FS for subFS {
    // go: sdk 1.25.5 io/fs/sub.go:88-95 subFS.Open
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        let (full, err) = self.fullName("open", &name);
        if err != errors::nil {
            return (crate::nil.into(), err);
        }
        // Go: file, err := f.fsys.Open(full); return file, f.fixErr(err)
        let (file, err) = self.fsys.Open(full);
        return (file, self.fixErr(err));
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl ReadDirFS for subFS {
    // go: sdk 1.25.5 io/fs/sub.go:88-95 subFS.Open
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return FS::Open(self, name);
    }
    // go: sdk 1.25.5 io/fs/sub.go:97-104 subFS.ReadDir
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        // Go's op here is "read", not "readdir" — the two directory and
        // file readers share it, and a caller matching on the op text
        // would not have found what this used to report.
        let (full, err) = self.fullName("read", &name);
        if err != errors::nil {
            return (slice::new(), err);
        }
        let (dir, err) = ReadDir(&*self.fsys, full);
        return (dir, self.fixErr(err));
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl ReadFileFS for subFS {
    // go: sdk 1.25.5 io/fs/sub.go:88-95 subFS.Open
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return FS::Open(self, name);
    }
    // go: sdk 1.25.5 io/fs/sub.go:106-113 subFS.ReadFile
    fn ReadFile(&self, name: string) -> (slice<byte>, error) {
        // Go's op is "read" — see the note on ReadDir above.
        let (full, err) = self.fullName("read", &name);
        if err != errors::nil {
            return (slice::new(), err);
        }
        let (data, err) = ReadFile(&*self.fsys, full);
        return (data, self.fixErr(err));
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl StatFS for subFS {
    // go: sdk 1.25.5 io/fs/sub.go:88-95 subFS.Open
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return FS::Open(self, name);
    }
    // go: none — goish idiom: Go's `subFS` does not implement `StatFS`;
    //     the top-level `Stat` falls through to `Open` + `File.Stat`,
    //     which a `subFS` already translates. goish keeps the direct
    //     path because its `Stat` fallback costs an `Open` on a
    //     filesystem that may have a cheaper answer.
    fn Stat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        let (full, err) = self.fullName("stat", &name);
        if err != errors::nil {
            return (crate::nil.into(), err);
        }
        let (info, err) = Stat(&*self.fsys, full);
        return (info, self.fixErr(err));
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl ReadLinkFS for subFS {
    // go: none — goish idiom: `#[goish::interface]` does not model Go's
    //     interface embedding, so every composite interface re-declares
    //     the inherited method and the concrete type forwards it.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return FS::Open(self, name);
    }

    // go: sdk 1.25.5 io/fs/sub.go:115-125 subFS.ReadLink
    fn ReadLink(&self, name: string) -> (string, error) {
        let (full, err) = self.fullName("readlink", &name);
        if err != errors::nil {
            return (string::new(), err);
        }
        let (target, err) = ReadLink(&*self.fsys, full);
        if err != errors::nil {
            return (string::new(), self.fixErr(err));
        }
        return (target, errors::nil);
    }

    // go: sdk 1.25.5 io/fs/sub.go:127-137 subFS.Lstat
    fn Lstat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        let (full, err) = self.fullName("lstat", &name);
        if err != errors::nil {
            return (crate::nil.into(), err);
        }
        let (info, err) = Lstat(&*self.fsys, full);
        if err != errors::nil {
            return (crate::nil.into(), self.fixErr(err));
        }
        return (info, errors::nil);
    }

    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl GlobFS for subFS {
    // go: none — goish idiom: see the note on `ReadLinkFS::Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return FS::Open(self, name);
    }

    // go: sdk 1.25.5 io/fs/sub.go:139-158 subFS.Glob
    fn Glob(&self, pattern: string) -> (slice<string>, error) {
        // Go: check pattern is well-formed.
        let (_, err) = crate::path::Match(pattern.clone(), string::from_static(""));
        if err != errors::nil {
            return (slice::new(), err);
        }
        if pattern.as_bytes() == b"." {
            return (
                slice::__from_vec(alloc::vec![string::from_static(".")]),
                errors::nil,
            );
        }

        let mut full: Vec<u8> = Vec::new();
        full.extend_from_slice(self.dir.as_bytes());
        full.push(b'/');
        full.extend_from_slice(pattern.as_bytes());
        let (list, err) = Glob(&*self.fsys, string::from_bytes(&full));

        let mut out: Vec<string> = Vec::new();
        let mut i: int = 0;
        while i < list.Len() {
            let (short, ok) = self.shorten(&list[i as usize]);
            if !ok {
                // Go: "can't use fmt in this package".
                let mut msg: Vec<u8> = Vec::new();
                msg.extend_from_slice(b"invalid result from inner fsys Glob: ");
                msg.extend_from_slice(list[i as usize].as_bytes());
                msg.extend_from_slice(b" not in ");
                msg.extend_from_slice(self.dir.as_bytes());
                return (slice::new(), errors::New(string::from_bytes(&msg)));
            }
            out.push(short);
            i += 1;
        }
        return (slice::__from_vec(out), self.fixErr(err));
    }

    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl SubFS for subFS {
    // go: none — goish idiom: see the note on `ReadLinkFS::Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return FS::Open(self, name);
    }

    // go: sdk 1.25.5 io/fs/sub.go:160-168 subFS.Sub
    /// A nested `Sub` collapses: `Sub(Sub(fsys, "a"), "b")` is one
    /// `subFS` rooted at `a/b`, not two wrappers.
    fn Sub(&self, dir: string) -> (Arc<dyn FS + Send + Sync>, error) {
        if dir.as_bytes() == b"." {
            register_subfs_impls();
            return (
                Arc::new(subFS {
                    fsys: self.fsys.clone(),
                    dir: self.dir.clone(),
                }),
                errors::nil,
            );
        }
        let (full, err) = self.fullName("sub", &dir);
        if err != errors::nil {
            return (crate::nil.into(), err);
        }
        register_subfs_impls();
        return (
            Arc::new(subFS {
                fsys: self.fsys.clone(),
                dir: full,
            }),
            errors::nil,
        );
    }

    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
//     registries for `subFS`, which is unexported and so only
//     nameable here. Go's linker builds the equivalent itabs.
fn register_subfs_impls() {
    __goish_register_ReadDirFS_impl::<subFS>();
    __goish_register_ReadFileFS_impl::<subFS>();
    __goish_register_StatFS_impl::<subFS>();
    __goish_register_ReadLinkFS_impl::<subFS>();
    __goish_register_GlobFS_impl::<subFS>();
    __goish_register_SubFS_impl::<subFS>();
}
