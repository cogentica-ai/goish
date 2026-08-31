// go: file io/fs/format.go decls: FormatFileInfo, FormatDirEntry
//
// format.go — FormatFileInfo and FormatDirEntry.
extern crate alloc;

use crate::gostring::string;
use crate::types::byte;

use super::*;

// go: sdk 1.25.5 io/fs/format.go:17-52 FormatFileInfo
/// Go: "FormatFileInfo returns a formatted version of info for human
/// readability. Implementations of FileInfo can call this from a String
/// method. The output for a file named "hello.go", 100 bytes, mode
/// 0o644, created January 1, 1970 at noon is
///
///	-rw-r--r-- 100 1970-01-01 12:00:00 hello.go"
///
/// **Known divergence, inherited from `time`.** Go's zero `time.Time`
/// is 0001-01-01T00:00:00Z; goish's `Time` stores `sec` as *Unix*
/// seconds, so its zero is 1970-01-01T00:00:00Z. A FileInfo with no
/// ModTime therefore formats as `1970-01-01 00:00:00` here and
/// `0001-01-01 00:00:00` in Go. Every other field matches byte for
/// byte. This is a `time` representation choice, not something this
/// function can correct — see examples/io_fs_format_smoke.rs.
///
/// The size is rendered by hand rather than through strconv, and Go
/// keeps a leading `-` for a negative size instead of refusing it —
/// FileInfo.Size() is system-dependent for non-regular files, so a
/// formatter that panicked on one would be useless exactly where it is
/// most needed.
pub fn FormatFileInfo(info: &(dyn FileInfo + Send + Sync)) -> string {
    let name = info.Name();
    let mut b: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    b.extend_from_slice(info.Mode().String().as_bytes());
    b.push(b' ');

    // Go: if size >= 0 { usize = uint64(size) }
    //     else { b = append(b, '-'); usize = uint64(-size) }
    let size = info.Size();
    let mut usize_: u64;
    if size >= 0 {
        usize_ = crate::uint64(size);
    } else {
        b.push(b'-');
        usize_ = crate::uint64(-size);
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len() - 1;
    while usize_ >= 10 {
        let q = usize_ / 10;
        buf[i] = b'0' + u8::try_from(usize_ - q * 10).unwrap_or(0);
        i -= 1;
        usize_ = q;
    }
    buf[i] = b'0' + u8::try_from(usize_).unwrap_or(0);
    b.extend_from_slice(&buf[i..]);
    b.push(b' ');

    b.extend_from_slice(
        info.ModTime()
            .Format(string::from_static(crate::time::DateTime))
            .as_bytes(),
    );
    b.push(b' ');

    b.extend_from_slice(name.as_bytes());
    if info.IsDir() {
        b.push(b'/');
    }

    return string::from_bytes(&b);
}

// go: sdk 1.25.5 io/fs/format.go:60-76 FormatDirEntry
/// Go: "FormatDirEntry returns a formatted version of dir for human
/// readability. Implementations of DirEntry can call this from a String
/// method. The outputs for a directory named subdir and a file named
/// hello.go are:
///
///	d subdir/
///	- hello.go"
///
/// Note the mode is truncated by exactly nine characters. `Type()`
/// returns only the type bits, so its `String()` still renders the nine
/// permission positions as dashes; Go strips them rather than printing
/// `d--------- subdir/`.
pub fn FormatDirEntry(dir: &(dyn DirEntry + Send + Sync)) -> string {
    let name = dir.Name();
    let mut b: alloc::vec::Vec<byte> = alloc::vec::Vec::new();

    // Go: "The Type method does not return any permission bits, so
    // strip them from the string."
    let mode = dir.Type().String();
    let mb = mode.as_bytes();
    let keep = if mb.len() >= 9 { mb.len() - 9 } else { 0 };
    b.extend_from_slice(&mb[..keep]);
    b.push(b' ');
    b.extend_from_slice(name.as_bytes());
    if dir.IsDir() {
        b.push(b'/');
    }
    return string::from_bytes(&b);
}
