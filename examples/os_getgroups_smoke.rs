// os_getgroups_smoke — exercise os.Getgroups (proc.go:51-58) and the
// underlying syscall.Getgroups (SYS_GETGROUPS=115 on Linux x86_64).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::os;
use goish::types::int;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed: int = 0;

    // 1. Getgroups returns nil error.
    {
        let (groups, err) = os::Getgroups();
        if errors::Is(err, errors::nil) {
            Println!("[ 1] Getgroups no error        PASS count=", groups.Len());
        } else {
            Println!("[ 1] Getgroups no error        FAIL");
            failed += 1;
        }
    }

    // 2. Repeated Getgroups returns the same length.
    {
        let (g1, _) = os::Getgroups();
        let (g2, _) = os::Getgroups();
        if g1.Len() == g2.Len() {
            Println!("[ 2] Getgroups stable          PASS");
        } else {
            Println!("[ 2] Getgroups stable          FAIL");
            failed += 1;
        }
    }

    // 3. Each gid is non-negative (gids fit in i32 on Linux).
    {
        let (groups, _) = os::Getgroups();
        let mut all_ok = true;
        let n = groups.Len();
        let mut i: int = 0;
        while i < n {
            if groups[i] < 0 {
                all_ok = false;
                break;
            }
            i += 1;
        }
        if all_ok {
            Println!("[ 3] All gids non-negative     PASS");
        } else {
            Println!("[ 3] All gids non-negative     FAIL");
            failed += 1;
        }
    }

    // 4. syscall.Getgroups direct probe with size=0 returns count.
    {
        let n = syscall::Getgroups(0, core::ptr::null_mut());
        if n >= 0 {
            Println!("[ 4] syscall probe non-neg     PASS n=", n as int);
        } else {
            Println!("[ 4] syscall probe non-neg     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
