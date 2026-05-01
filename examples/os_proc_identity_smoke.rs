// os_proc_identity_smoke — exercise os.Getuid / Getgid / Geteuid /
// Getegid / Getpid / Getppid (proc.go:31–55).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::os;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Getuid is non-negative.
    {
        let uid = os::Getuid();
        if uid >= 0 {
            Println!("[ 1] Getuid non-negative       PASS");
        } else {
            Println!("[ 1] Getuid non-negative       FAIL uid=", uid);
            failed += 1;
        }
    }

    // 2. Geteuid is non-negative; equals Getuid in non-suid run.
    {
        let euid = os::Geteuid();
        if euid >= 0 {
            Println!("[ 2] Geteuid non-negative      PASS");
        } else {
            Println!("[ 2] Geteuid non-negative      FAIL");
            failed += 1;
        }
    }

    // 3. Getgid + Getegid non-negative.
    {
        let gid = os::Getgid();
        let egid = os::Getegid();
        if gid >= 0 && egid >= 0 {
            Println!("[ 3] Getgid + Getegid          PASS");
        } else {
            Println!("[ 3] Getgid + Getegid          FAIL");
            failed += 1;
        }
    }

    // 4. Getpid > 1 (PID 1 is init; we definitely aren't init).
    {
        let pid = os::Getpid();
        if pid > 1 {
            Println!("[ 4] Getpid > 1                PASS");
        } else {
            Println!("[ 4] Getpid > 1                FAIL pid=", pid);
            failed += 1;
        }
    }

    // 5. Getppid > 0 (parent exists; might be 1 if reparented to init).
    {
        let ppid = os::Getppid();
        if ppid > 0 {
            Println!("[ 5] Getppid > 0               PASS");
        } else {
            Println!("[ 5] Getppid > 0               FAIL ppid=", ppid);
            failed += 1;
        }
    }

    // 6. Repeated Getpid is stable.
    {
        let p1 = os::Getpid();
        let p2 = os::Getpid();
        if p1 == p2 {
            Println!("[ 6] Getpid stable             PASS");
        } else {
            Println!("[ 6] Getpid stable             FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
