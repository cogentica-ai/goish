// go: file archive/tar/stat_unix.go decls: statUnix
//
// The Unix half of FileInfoHeader: everything a header carries that an
// `fs.FileInfo` does not expose through its own methods. Uid, Gid,
// Uname, Gname, AccessTime, ChangeTime, Devmajor and Devminor all come
// from the raw `syscall.Stat_t` behind `fi.Sys()`, and until this file
// existed they all came back zero — a tar built from a file on disk
// had no owner and no times beyond mtime.
//
// goishlint:ignore GOISH018 init - Go's init assigns `sysStat = statUnix`,
//     the function variable that picks a platform implementation.
//     goish builds for linux only, so `FileInfoHeader` calls
//     `statUnix` directly and there is no variable to assign.
// goishlint:ignore GOISH021 userMap, groupMap - Go caches the two
//     lookups in `sync.Map`s keyed by id. goish looks up each time:
//     `os/user` here reads /etc/passwd and /etc/group directly (there
//     is no cgo path to be slow), and a cache shared across goroutines
//     would need the same `sync.Map` this port does not yet have a use
//     for elsewhere. The lookups stay best-effort either way.

#![allow(non_snake_case)]

use crate::gostring::string;
use crate::io::fs;
use crate::errors::{error, nil};
use crate::os::user;
use crate::strconv;
use crate::syscall;
use crate::types::int;

use super::common::Header;
use super::{TypeBlock, TypeChar};
use super::stat_actime1::{statAtime, statCtime};

// go: sdk 1.25.5 archive/tar/stat_unix.go:26-101 statUnix
/// Fill from `fi.Sys()`. Returns nil and changes nothing when the
/// FileInfo did not come from a stat — Go's `fi.Sys().(*syscall.Stat_t)`
/// comma-ok, which is a miss for a synthesised FileInfo.
pub(crate) fn statUnix(fi: &dyn fs::FileInfo, h: &mut Header, doNameLookups: bool) -> error {
    let sys = fi.Sys();
    let st = match sys.downcast_ref::<syscall::Stat_t>() {
        Some(st) => st,
        None => return nil,
    };

    h.Uid = crate::convert::int(st.st_uid);
    h.Gid = crate::convert::int(st.st_gid);
    if doNameLookups {
        // Best effort: Go notes these "may fail for any number of
        // reasons (not implemented on that platform, cgo not enabled,
        // etc)", and a failure leaves the name empty rather than
        // failing the header.
        let (u, err) = user::LookupId(strconv::Itoa(h.Uid));
        if err.IsNil() {
            h.Uname = u.Username.clone();
        }
        let (g, err) = user::LookupGroupId(strconv::Itoa(h.Gid));
        if err.IsNil() {
            h.Gname = g.Name.clone();
        }
    }
    h.AccessTime = statAtime(st);
    h.ChangeTime = statCtime(st);

    // Best effort at populating Devmajor and Devminor. Go switches on
    // GOOS across seven layouts; this is the linux one, copied from
    // golang.org/x/sys/unix/dev_linux.go as Go's comment says.
    if h.Typeflag == TypeChar || h.Typeflag == TypeBlock {
        let dev = st.st_rdev;
        let mut major: u32 = crate::convert::uint32((dev & 0x0000_0000_000f_ff00) >> 8);
        major |= crate::convert::uint32((dev & 0xffff_f000_0000_0000) >> 32);
        let mut minor: u32 = crate::convert::uint32(dev & 0x0000_0000_0000_00ff);
        minor |= crate::convert::uint32((dev & 0x0000_0fff_fff0_0000) >> 12);
        h.Devmajor = crate::convert::int64(major);
        h.Devminor = crate::convert::int64(minor);
    }
    let _ = string::from("");
    return nil;
}
