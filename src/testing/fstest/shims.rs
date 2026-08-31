// go: none — goish idiom: `openMapFile` and `mapFileInfo` are
//     unexported in Go and stay unexported here, so their methods
//     cannot be reached from an example, which is a separate crate.
//     These shims give the smoke tests a way in without widening the
//     real API. Go's tests live inside the package and need none of
//     this.
//
// shims.rs — goish-only. No Go counterpart, hence no `// go: file`.

use super::mapfs::*;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs;
use crate::types::{byte, int};

// ─── test shims ──────────────────────────────────────────────────────────────
//
// `openMapFile` is unexported in Go and stays unexported here, so its
// `Seek`/`ReadAt` cannot be reached from an example (a separate crate).
// These shims give the smoke test a way in without widening the real
// API, following the pattern used elsewhere in the tree for testing
// unexported Go declarations.

// go: none — goish-only: test shim for the unexported openMapFile.Seek.
#[doc(hidden)]
pub fn __shim_open_seek(
    fsys: &MapFS,
    path: impl Into<string>,
    offset: crate::types::int64,
    whence: int,
) -> (crate::types::int64, error) {
    let (f, err) = fs::FS::Open(fsys, path.into());
    if err != errors::nil {
        return (0, err);
    }
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (0, errors::New(string::from_static("not an openMapFile"))),
    };
    return match any.downcast_ref::<openMapFile>() {
        Some(o) => o.Seek(offset, whence),
        None => (0, errors::New(string::from_static("not an openMapFile"))),
    };
}

// go: none — goish-only: two seeks on ONE handle, so `whence == 1`
// (seek relative to the current position) can actually be observed.
// A shim that reopens per call always starts at offset 0 and would
// make the relative case indistinguishable from an absolute one.
#[doc(hidden)]
pub fn __shim_open_seek2(
    fsys: &MapFS,
    path: impl Into<string>,
    off1: crate::types::int64,
    whence1: int,
    off2: crate::types::int64,
    whence2: int,
) -> (crate::types::int64, crate::types::int64, error) {
    let (f, err) = fs::FS::Open(fsys, path.into());
    if err != errors::nil {
        return (0, 0, err);
    }
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (0, 0, errors::New(string::from_static("not an openMapFile"))),
    };
    let o = match any.downcast_ref::<openMapFile>() {
        Some(o) => o,
        None => return (0, 0, errors::New(string::from_static("not an openMapFile"))),
    };
    let (a, e1) = o.Seek(off1, whence1);
    if e1 != errors::nil {
        return (a, 0, e1);
    }
    let (b, e2) = o.Seek(off2, whence2);
    return (a, b, e2);
}

// go: none — goish-only: test shim for the unexported openMapFile.ReadAt.
#[doc(hidden)]
pub fn __shim_open_read_at(
    fsys: &MapFS,
    path: impl Into<string>,
    b: &mut slice<byte>,
    offset: crate::types::int64,
) -> (int, error) {
    let (f, err) = fs::FS::Open(fsys, path.into());
    if err != errors::nil {
        return (0, err);
    }
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (0, errors::New(string::from_static("not an openMapFile"))),
    };
    return match any.downcast_ref::<openMapFile>() {
        Some(o) => o.ReadAt(b, offset),
        None => (0, errors::New(string::from_static("not an openMapFile"))),
    };
}

// go: none — goish-only: test shim for the unexported
// `mapFileInfo.String`. Go's is reachable through `%v` on the
// fs.FileInfo interface; goish's FileInfo trait has no Stringer bridge,
// so an example cannot get at it any other way. Builds the info the
// same way `MapFS.Stat` does.
#[doc(hidden)]
pub fn __shim_map_file_info_string(fsys: &MapFS, name: impl Into<string>) -> (string, bool) {
    let name: string = name.into();
    let (f, ok) = fsys.0.Get(name.clone());
    if !ok {
        return (string::from_static(""), false);
    }
    let info = mapFileInfo { name: name, f: f };
    return (info.String(), true);
}
