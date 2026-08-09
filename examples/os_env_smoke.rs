// os_env_smoke — exercise os::Getenv / LookupEnv / TempDir / Hostname.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::os;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. PATH should be set in any normal Linux process.
    {
        let p = os::Getenv(string("PATH"));
        if p.Len() > 0 {
            fmt::Println!("[ 1] Getenv(PATH)              PASS");
        } else {
            fmt::Println!("[ 1] Getenv(PATH)              FAIL");
            failed += 1;
        }
    }

    // 2. LookupEnv on a known-missing key returns false.
    {
        let (_v, ok) = os::LookupEnv(string("GOISH_NO_SUCH_VAR_42"));
        if !ok {
            fmt::Println!("[ 2] LookupEnv missing         PASS");
        } else {
            fmt::Println!("[ 2] LookupEnv missing         FAIL");
            failed += 1;
        }
    }

    // 3. TempDir returns a non-empty path.
    {
        let t = os::TempDir();
        if t.Len() > 0 {
            fmt::Println!("[ 3] TempDir                   PASS ({})", t);
        } else {
            fmt::Println!("[ 3] TempDir                   FAIL");
            failed += 1;
        }
    }

    // 4. Hostname is non-empty.
    {
        let (h, err) = os::Hostname();
        if err.IsNil() && h.Len() > 0 {
            fmt::Println!("[ 4] Hostname                  PASS ({})", h);
        } else {
            fmt::Println!("[ 4] Hostname                  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 4", failed);
        syscall::Exit(1);
    }
}
