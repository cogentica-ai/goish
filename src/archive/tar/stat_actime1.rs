// go: file archive/tar/stat_actime1.go decls: statAtime, statCtime
//
// Go splits the access/change-time accessors across two files because
// the field names differ by platform: `Atim`/`Ctim` on Linux and most
// of Unix (stat_actime1.go), `Atimespec`/`Ctimespec` on the BSDs and
// Darwin (stat_actime2.go). goish is Linux-amd64 only, so this is the
// only one of the pair, and goish's `syscall::Stat_t` flattens the
// timespec into `st_atime`/`st_atime_nsec` rather than nesting it.

#![allow(non_snake_case)]

use crate::syscall;
use crate::time;

// go: sdk 1.25.5 archive/tar/stat_actime1.go:14-16 statAtime
/// The file's last-access time.
pub(crate) fn statAtime(st: &syscall::Stat_t) -> time::Time {
    return time::Unix(st.st_atime, crate::convert::int(st.st_atime_nsec));
}

// go: sdk 1.25.5 archive/tar/stat_actime1.go:18-20 statCtime
/// The file's status-change time — when the inode last changed, which
/// is not the modification time and has no portable way to be set.
pub(crate) fn statCtime(st: &syscall::Stat_t) -> time::Time {
    return time::Unix(st.st_ctime, crate::convert::int(st.st_ctime_nsec));
}
