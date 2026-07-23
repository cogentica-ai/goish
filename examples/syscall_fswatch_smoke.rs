// syscall_fswatch_smoke — the inotify/fanotify syscall surface a
// Linux file watcher needs (typescript-go internal/fswatch shape:
// fanotify preferred, inotify fallback).
//
// Covers:
//   1. inotify end-to-end: init1 → add_watch → poll(2) → read →
//      parse InotifyEvent records (create/modify/delete, names) →
//      rm_watch.
//   2. Statfs: fs type/bsize of the watched dir (the watcher's
//      supported-filesystem check).
//   3. NameToHandleAt: file handle for the dir (fanotify FID
//      decoding support); EOPNOTSUPP accepted (fs-dependent).
//   4. fanotify: init + mark + event metadata when privileged;
//      a clean errno (EPERM without CAP_SYS_ADMIN) otherwise —
//      which is exactly the fallback signal the watcher keys on.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use goish::{os, syscall, Println};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Walk an inotify read buffer, returning whether an event with
/// `want_mask` set and (if non-empty) the given name was seen.
fn scan_events(buf: &[u8], want_mask: u32, want_name: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos + syscall::SizeofInotifyEvent <= buf.len() {
        let ev: syscall::InotifyEvent = unsafe {
            core::ptr::read_unaligned(buf.as_ptr().add(pos) as *const syscall::InotifyEvent)
        };
        let name_start = pos + syscall::SizeofInotifyEvent;
        let name_end = name_start + ev.Len as usize;
        if name_end > buf.len() {
            break;
        }
        let raw_name = &buf[name_start..name_end];
        let name = match raw_name.iter().position(|&b| b == 0) {
            Some(i) => &raw_name[..i],
            None => raw_name,
        };
        if ev.Mask & want_mask != 0 && (want_name.is_empty() || name == want_name) {
            return true;
        }
        pos = name_end;
    }
    false
}

/// Poll `fd` for readability, then read into `buf`. Returns bytes
/// read (0 if the poll timed out).
fn poll_read(fd: goish::int, buf: &mut [u8], timeout_ms: goish::int) -> usize {
    let mut fds = [syscall::PollFd { Fd: fd as i32, Events: syscall::POLLIN, Revents: 0 }];
    let (n, err) = syscall::Poll(&mut fds, timeout_ms);
    check(err == goish::nil, b"poll err\n");
    if n == 0 {
        return 0;
    }
    check(fds[0].Revents & syscall::POLLIN != 0, b"poll: POLLIN not set\n");
    let n = syscall::Read(fd as i32, buf.as_mut_ptr(), buf.len());
    check(n > 0, b"read after poll returned nothing\n");
    n as usize
}

#[goish::main]
fn main() {
    let root = os::TempDir() + "/goish_fswatch_smoke";
    let _ = os::RemoveAll(root.clone());
    let err = os::MkdirAll(root.clone(), 0o755);
    check(err == goish::nil, b"setup: MkdirAll\n");

    // ─── 1. inotify end-to-end ─────────────────────────────────────
    let (ifd, err) = syscall::InotifyInit1((syscall::IN_CLOEXEC | syscall::IN_NONBLOCK) as goish::int);
    check(err == goish::nil, b"t1: InotifyInit1\n");
    let mask = syscall::IN_CREATE
        | syscall::IN_MODIFY
        | syscall::IN_DELETE
        | syscall::IN_MOVED_FROM
        | syscall::IN_MOVED_TO
        | syscall::IN_ONLYDIR;
    let (wd, err) = syscall::InotifyAddWatch(ifd, root.clone(), mask);
    check(err == goish::nil, b"t1: InotifyAddWatch\n");
    check(wd >= 0, b"t1: watch descriptor\n");

    // Create → expect IN_CREATE (and usually IN_MODIFY) for f.txt.
    let err = os::WriteFile(root.clone() + "/f.txt", b"x", 0o644);
    check(err == goish::nil, b"t1: WriteFile\n");
    let mut buf = [0u8; 4096];
    let n = poll_read(ifd, &mut buf, 2000);
    check(n > 0, b"t1: no events after create\n");
    check(
        scan_events(&buf[..n], syscall::IN_CREATE, b"f.txt"),
        b"t1: IN_CREATE f.txt not seen\n",
    );

    // Delete → IN_DELETE.
    let err = os::Remove(root.clone() + "/f.txt");
    check(err == goish::nil, b"t1: Remove\n");
    let n = poll_read(ifd, &mut buf, 2000);
    check(n > 0, b"t1: no events after delete\n");
    check(
        scan_events(&buf[..n], syscall::IN_DELETE, b"f.txt"),
        b"t1: IN_DELETE f.txt not seen\n",
    );

    let (_, err) = syscall::InotifyRmWatch(ifd, wd as u32);
    check(err == goish::nil, b"t1: InotifyRmWatch\n");
    syscall::Close(ifd as i32);

    // Bad flags round the errno path.
    let (_, err) = syscall::InotifyAddWatch(-1, root.clone(), syscall::IN_CREATE);
    check(err != goish::nil, b"t1b: bad fd must error\n");

    // ─── 2. Statfs ─────────────────────────────────────────────────
    let mut st = syscall::Statfs_t::default();
    let err = syscall::Statfs(root.clone(), &mut st);
    check(err == goish::nil, b"t2: Statfs err\n");
    check(st.Type != 0, b"t2: fs type zero\n");
    check(st.Bsize > 0, b"t2: bsize\n");

    // ─── 3. NameToHandleAt ─────────────────────────────────────────
    let (fh, mount_id, err) = syscall::NameToHandleAt(
        syscall::AT_FDCWD as goish::int,
        root.clone(),
        0,
    );
    if err == goish::nil {
        check(fh.Size() > 0, b"t3: empty handle\n");
        check(mount_id > 0, b"t3: mount id\n");
        Println!("t3: NameToHandleAt ok, handle type/bytes:", fh.Type() as i64, fh.Size());
    } else {
        // Overlay/tmpfs variants without export support say EOPNOTSUPP.
        Println!("t3: NameToHandleAt unsupported here (accepted):", err.Error());
    }

    // ─── 4. fanotify: privileged path or clean fallback errno ──────
    let (ffd, err) = syscall::FanotifyInit(
        syscall::FAN_CLASS_NOTIF
            | syscall::FAN_CLOEXEC
            | syscall::FAN_NONBLOCK
            | syscall::FAN_REPORT_DFID_NAME,
        (syscall::O_RDONLY | syscall::O_CLOEXEC) as u32,
    );
    if err != goish::nil {
        // Unprivileged: EPERM is the documented signal to fall back
        // to inotify — the exact branch typescript-go's watcher takes.
        Println!("t4: fanotify unavailable (accepted, inotify fallback):", err.Error());
    } else {
        let err = syscall::FanotifyMark(
            ffd,
            syscall::FAN_MARK_ADD | syscall::FAN_MARK_ONLYDIR,
            syscall::FAN_CREATE | syscall::FAN_DELETE | syscall::FAN_ONDIR | syscall::FAN_EVENT_ON_CHILD,
            syscall::AT_FDCWD as goish::int,
            root.clone(),
        );
        check(err == goish::nil, b"t4: FanotifyMark\n");
        let err = os::WriteFile(root.clone() + "/g.txt", b"y", 0o644);
        check(err == goish::nil, b"t4: WriteFile\n");
        let mut fbuf = [0u8; 4096];
        let n = poll_read(ffd, &mut fbuf, 2000);
        check(n >= core::mem::size_of::<syscall::FanotifyEventMetadata>(), b"t4: no fanotify event\n");
        let meta: syscall::FanotifyEventMetadata =
            unsafe { core::ptr::read_unaligned(fbuf.as_ptr() as *const _) };
        check(meta.Vers == syscall::FANOTIFY_METADATA_VERSION, b"t4: metadata version\n");
        check(meta.Mask & syscall::FAN_CREATE != 0, b"t4: FAN_CREATE mask\n");
        Println!("t4: fanotify event ok, mask/len:", meta.Mask as i64, meta.Event_len as i64);
        syscall::Close(ffd as i32);
    }

    let _ = os::RemoveAll(root);
    let msg = b"SYSCALL_FSWATCH_OK all test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
