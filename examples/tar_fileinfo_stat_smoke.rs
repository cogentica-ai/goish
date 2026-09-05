// tar_fileinfo_stat_smoke — what `FileInfoHeader` carries from a real
// file on disk, against a running Go 1.25.5 via scripts/goref.sh.
//
// Six of these ten came back zero. `FileInfoHeader` never called
// `sysStat`, Go's hook into stat_unix.go, so Uid, Gid, Uname, Gname,
// AccessTime and ChangeTime were all left at their zero values — a tar
// built from a file on disk had no owner and no times beyond mtime,
// and nothing said so.
//
// Two things had to change for that to be portable at all:
//
//   * `os.FileInfo`'s `sys` kept only `(dev, ino)`, the pair SameFile
//     needs, on the stated grounds that "the rest of the struct is
//     already unpacked into the fields above". It is not — st_uid,
//     st_gid, st_rdev and the atime/ctime pairs have no field there,
//     and `Sys()` is the only way Go exposes them.
//   * `impl fs::FileInfo for FileInfoData` returned `Arc::new(())`
//     from `Sys()` while the INHERENT `Sys` returned the real stat.
//     Go's callers hold the interface, so they got the empty one.
//
// The test asserts relationships rather than values, because uid, gid
// and the timestamps differ between machines: the uid MATCHES the
// caller's own, the names are non-empty, the times are non-zero. That
// is enough to separate "read from the stat" from "left at zero",
// which is the whole question.
//
// The file is created by the smoke itself so there is nothing to
// install; its mode is 0640 to make the mode line load-bearing.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::archive::tar;
use goish::fmt;
use goish::gostring::string;
use goish::os;
use goish::types::int;

const GO: [&str; 10] = [
    "name             file.txt",
    "size             5",
    "mode             0640",
    "uid-is-mine      true",
    "gid-is-mine      true",
    "uname-nonempty   true",
    "gname-nonempty   true",
    "atime-set        true",
    "ctime-set        true",
    "mtime-matches    true",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    // Named file.txt because the header's Name is its BASE name, and
    // that is what Go's reference line says.
    let dir = os::TempDir() + "/goish_tar_fileinfo_dir";
    let _ = os::MkdirAll(&dir, os::FileMode(0o755));
    let path = dir.clone() + "/file.txt";
    let _ = os::Remove(&path);
    let (f, err) = os::Create(&path);
    if !err.IsNil() {
        fmt::Printf!("[!!] create: %v\n", err);
        return;
    }
    let mut f = f.MustTake();
    let (_, err) = f.Write(goish::convert::bytes(string::from("hello")));
    if !err.IsNil() {
        fmt::Printf!("[!!] write: %v\n", err);
        return;
    }
    let _ = f.Close();
    let _ = os::Chmod(&path, os::FileMode(0o640));

    let (fi, err) = os::Stat(&path);
    if !err.IsNil() {
        fmt::Printf!("[!!] stat: %v\n", err);
        return;
    }
    let (h, err) = tar::FileInfoHeader(&fi, &string::from(""));
    if !err.IsNil() {
        fmt::Printf!("[!!] header: %v\n", err);
        return;
    }

    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "name", h.Name));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "size", h.Size));
    chk(&mut ln, &fmt::Sprintf!("%-16s %04o", "mode", h.Mode));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "uid-is-mine", h.Uid == os::Getuid()));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "gid-is-mine", h.Gid == os::Getgid()));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "uname-nonempty", h.Uname != ""));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "gname-nonempty", h.Gname != ""));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "atime-set", !h.AccessTime.IsZero()));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "ctime-set", !h.ChangeTime.IsZero()));
    chk(&mut ln, &fmt::Sprintf!("%-16s %v", "mtime-matches", h.ModTime.Equal(fi.ModTime())));

    let _ = os::Remove(&path);
    let _ = os::Remove(&dir);
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
