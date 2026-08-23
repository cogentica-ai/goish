// os_pipe_smoke — exercise os.Pipe (pipe2_unix.go:13).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::os;
use goish::syscall;
use goish::types::byte;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Pipe + write/read round trip.
    {
        let (mut r, mut w, err) = os::Pipe();
        if !err.IsNil() {
            fmt::Println!("[ 1] Pipe round trip           FAIL pipe-err");
            failed += 1;
        } else {
            let payload = bytes("hello pipe");
            let (n_w, w_err) = w.Write(payload);
            let mut buf: slice<byte> = slice::__from_vec({
                let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(64);
                v.resize(64, 0);
                v
            });
            let (n_r, r_err) = r.Read(&mut buf);
            let _ = r.Close();
            let _ = w.Close();
            if w_err.IsNil() && r_err.IsNil() && n_w == 10 && n_r == 10 {
                fmt::Println!("[ 1] Pipe round trip           PASS");
            } else {
                fmt::Println!("[ 1] Pipe round trip           FAIL n_r=", n_r as i64);
                failed += 1;
            }
        }
    }

    // 2. Pipe succeeds and hands back two distinct fds.
    {
        let (r, w, e) = os::Pipe();
        if e.IsNil() && r.Fd() != w.Fd() {
            fmt::Println!("[ 2] Pipe fds valid            PASS");
        } else {
            fmt::Println!("[ 2] Pipe fds valid            FAIL");
            failed += 1;
        }
        let mut r2 = r;
        let mut w2 = w;
        let _ = r2.Close();
        let _ = w2.Close();
    }

    // 3. Closing read end → writer eventually errors (EPIPE).
    //    Slim: at minimum, Read after both ends close should not deadlock.
    {
        let (mut r, mut w, _) = os::Pipe();
        let _ = w.Write(bytes("partial"));
        let _ = w.Close();
        let mut buf: slice<byte> = slice::__from_vec({
            let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(32);
            v.resize(32, 0);
            v
        });
        // Read what's there.
        let (n, _) = r.Read(&mut buf);
        // Reader closed end of write should yield EOF on next read.
        let mut buf2: slice<byte> = slice::__from_vec({
            let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(32);
            v.resize(32, 0);
            v
        });
        let (n2, e2) = r.Read(&mut buf2);
        let _ = r.Close();
        let _ = e2;
        if n == 7 && n2 == 0 {
            fmt::Println!("[ 3] Pipe EOF after writer     PASS");
        } else {
            fmt::Println!("[ 3] Pipe EOF after writer     FAIL n=", n as i64);
            failed += 1;
        }
        let _ = io::EOF;
    }

    // 4. Names are "|0" and "|1".
    {
        let (r, w, _) = os::Pipe();
        if r.Name() == "|0" && w.Name() == "|1" {
            fmt::Println!("[ 4] Pipe end names            PASS");
        } else {
            fmt::Println!("[ 4] Pipe end names            FAIL");
            failed += 1;
        }
        let mut r2 = r;
        let mut w2 = w;
        let _ = r2.Close();
        let _ = w2.Close();
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
