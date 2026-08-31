// go: file io/ioutil/ioutil.go decls: ReadAll, ReadFile, WriteFile, ReadDir, NopCloser, Discard

use alloc::sync::Arc;

use crate::error;
use crate::errors::nil;
use crate::goslice::slice;
use crate::io::fs::FileInfo;
use crate::types::byte;

// go: sdk 1.25.5 io/ioutil/ioutil.go:29-31 ReadAll
/// Reads from `r` until an error or EOF and returns the data it read.
/// A successful call returns `err == nil`, not `err == EOF`.
///
/// Deprecated: as of Go 1.16, this simply calls [`crate::io::ReadAll`].
#[inline]
pub fn ReadAll(r: &mut dyn crate::io::Reader) -> (slice<byte>, error) {
    return crate::io::ReadAll(r);
}

// go: sdk 1.25.5 io/ioutil/ioutil.go:41-43 ReadFile
/// Reads the named file and returns its contents. A successful call
/// returns `err == nil`, not `err == EOF`.
///
/// Deprecated: as of Go 1.16, this simply calls `os.ReadFile`.
#[inline]
pub fn ReadFile<N: Into<crate::string>>(name: N) -> (slice<byte>, error) {
    return crate::os::ReadFile(name);
}

// go: sdk 1.25.5 io/ioutil/ioutil.go:52-54 WriteFile
/// Writes `data` to the named file, creating it if necessary.
///
/// Deprecated: as of Go 1.16, this simply calls `os.WriteFile`.
#[inline]
pub fn WriteFile<N: Into<crate::string>, M: Into<crate::os::FileMode>>(
    name: N,
    data: slice<byte>,
    perm: M,
) -> error {
    return crate::os::WriteFile(name, data, perm);
}

// go: sdk 1.25.5 io/ioutil/ioutil.go:76-91 ReadDir
/// Reads the directory named by `dirname` and returns a list of
/// directory entries sorted by filename.
///
/// Deprecated: as of Go 1.16, `os.ReadDir` is more efficient — it
/// returns `DirEntry` and does not stat every entry.
pub fn ReadDir<N: Into<crate::string>>(
    dirname: N,
) -> (slice<Arc<dyn FileInfo + Send + Sync>>, error) {
    // Go reaches for `f.Readdir(-1)`, which is the FileInfo-returning
    // half of the same syscall walk `os.ReadDir` does; goish only has
    // the DirEntry half, so the stat happens here instead. Same
    // result, same order — Go sorts by name, and so does this.
    let (entries, err) = crate::os::ReadDir(dirname);
    if !err.IsNil() {
        return (slice::new(), err);
    }
    let mut list: alloc::vec::Vec<Arc<dyn FileInfo + Send + Sync>> = alloc::vec::Vec::new();
    let mut i: crate::types::int = 0;
    while i < entries.Len() {
        let (info, err) = entries[i as usize].Info();
        if !err.IsNil() {
            return (slice::new(), err);
        }
        list.push(info);
        i += 1;
    }
    list.sort_by(|a, b| a.Name().as_bytes().cmp(b.Name().as_bytes()));
    return (slice::__from_vec(list), nil);
}

// go: sdk 1.25.5 io/ioutil/ioutil.go:98-100 NopCloser
/// A `ReadCloser` with a no-op `Close` wrapping `r`.
///
/// Deprecated: as of Go 1.16, this simply calls [`crate::io::NopCloser`].
#[inline]
pub fn NopCloser<R: crate::io::Reader>(r: R) -> crate::io::NopCloserImpl<R> {
    return crate::io::NopCloser(r);
}

// go: sdk 1.25.5 io/ioutil/ioutil.go:106-106 Discard
/// An `io.Writer` on which all Write calls succeed without doing
/// anything.
///
/// Deprecated: as of Go 1.16, this is simply `io.Discard`. Go spells it
/// as a package-level `var`; goish has no interface value to hold in a
/// static, so it is the constructor the rest of goish already uses.
#[inline]
pub fn Discard() -> crate::io::Discard {
    return crate::io::DiscardWriter();
}
