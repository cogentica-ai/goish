// syscall_openat_ref_smoke — Linux openat behavior required by
// typescript-go internal/fswatch/walkdir_unix.go.
//
// Reference: Go 1.25.5 syscall, measured by
// tools/gen_syscall_openat_ref.go on linux/amd64. GO is verbatim output.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::{fmt, int, int32, nil, os, string, strings, syscall};

const GO: &str = include_str!("syscall_openat_ref.txt");

#[goish::main]
fn main() {
    let root = string::from_static("/tmp/goish_openat_ref");
    let _ = os::Remove(root.clone() + "/link");
    let _ = os::RemoveAll(root.clone());
    let setupDirError = os::MkdirAll(root.clone() + "/sub", 0o755);
    let setupFileError = os::WriteFile(root.clone() + "/file", b"x", 0o644);
    // A directory target makes the no-follow row kill a mutation that silently
    // drops O_NOFOLLOW: following this link would otherwise make Openat pass.
    let setupLinkError = os::Symlink("sub", root.clone() + "/link");
    if setupDirError != nil || setupFileError != nil || setupLinkError != nil {
        syscall::Exit(1);
    }

    let flags = int(syscall::O_RDONLY
        | syscall::O_CLOEXEC
        | syscall::O_DIRECTORY
        | syscall::O_NOCTTY
        | syscall::O_NONBLOCK
        | syscall::O_NOFOLLOW);
    let mut out = strings::Builder::new();
    let _ = fmt::Fprintf!(
        &mut out,
        "constants\t%d\t%d\t%d\t%d\t%d\n",
        syscall::O_DIRECTORY,
        syscall::O_NOCTTY,
        syscall::O_NOFOLLOW,
        syscall::O_NONBLOCK,
        syscall::O_CLOEXEC
    );

    let (rootFD, rootError) = syscall::Openat(int(syscall::AT_FDCWD), root.clone(), flags, 0);
    let _ = fmt::Fprintf!(&mut out, "root\t%t\t%t\n", rootFD >= 0, rootError == nil);

    let (childFD, childError) = syscall::Openat(rootFD, "sub", flags, 0);
    let mut stat = syscall::Stat_t::default();
    let statError = syscall::Fstat(int32(childFD), &mut stat);
    let _ = fmt::Fprintf!(
        &mut out,
        "child\t%t\t%t\t%t\n",
        childFD >= 0,
        childError == nil,
        statError == 0 && stat.st_mode & syscall::S_IFMT == syscall::S_IFDIR
    );
    let _ = syscall::Close(int32(childFD));

    let (fileFD, fileError) = syscall::Openat(rootFD, "file", flags, 0);
    let _ = fmt::Fprintf!(
        &mut out,
        "file-directory\t%t\t%t\n",
        fileFD == -1,
        fileError == syscall::ENOTDIR
    );

    let (linkFD, linkError) = syscall::Openat(rootFD, "link", flags, 0);
    let linkErrno = if linkError == syscall::ENOTDIR { 20 } else { 0 };
    let _ = fmt::Fprintf!(
        &mut out,
        "nofollow-directory\t%t\t%d\n",
        linkFD == -1,
        linkErrno
    );

    let (missingFD, missingError) = syscall::Openat(rootFD, "missing", flags, 0);
    let _ = fmt::Fprintf!(
        &mut out,
        "missing\t%t\t%t\n",
        missingFD == -1,
        missingError == syscall::ENOENT
    );

    let (nulFD, nulError) = syscall::Openat(rootFD, "sub\0ignored", flags, 0);
    let _ = fmt::Fprintf!(
        &mut out,
        "embedded-nul\t%t\t%t\n",
        nulFD == 0,
        nulError == syscall::EINVAL
    );

    let _ = syscall::Close(int32(rootFD));
    let (closedFD, closedError) = syscall::Openat(rootFD, "sub", flags, 0);
    let _ = fmt::Fprintf!(
        &mut out,
        "closed-dirfd\t%t\t%t\n",
        closedFD == -1,
        closedError == syscall::Errno(9)
    );

    let (absoluteFD, absoluteError) = syscall::Openat(-1, root.clone() + "/sub", flags, 0);
    let _ = fmt::Fprintf!(
        &mut out,
        "absolute-ignores-dirfd\t%t\t%t\n",
        absoluteFD >= 0,
        absoluteError == nil
    );
    let _ = syscall::Close(int32(absoluteFD));

    let got = out.String();
    let _ = os::Remove(root.clone() + "/link");
    let _ = os::RemoveAll(root);
    if got != GO {
        syscall::Write(
            syscall::STDERR,
            got.as_bytes().as_ptr(),
            got.as_bytes().len(),
        );
        syscall::Exit(1);
    }
    let message = b"SYSCALL_OPENAT_REF_OK Go 1.25.5 transcript matched\n";
    syscall::Write(syscall::STDOUT, message.as_ptr(), message.len());
    syscall::Exit(0);
}
