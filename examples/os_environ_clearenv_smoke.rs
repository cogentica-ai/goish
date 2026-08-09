// os_environ_clearenv_smoke — exercise os.Environ + os.Clearenv
// (env.go:139 + 134).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::os;
use goish::strings;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Environ returns at least PATH (or HOME — pick one likely set).
    {
        let env = os::Environ();
        let mut found_assignment = false;
        let n = env.Len();
        let mut i: i64 = 0;
        while i < n {
            let entry = env[i].clone();
            if strings::Contains(entry, string("=")) {
                found_assignment = true;
                break;
            }
            i += 1;
        }
        if env.Len() > 0 && found_assignment {
            fmt::Println!("[ 1] Environ has KEY=VALUE     PASS");
        } else {
            fmt::Println!("[ 1] Environ has KEY=VALUE     FAIL n=", env.Len() as i64);
            failed += 1;
        }
    }

    // 2. Setenv result appears in Environ.
    {
        let _ = os::Setenv(string("GOISH_ENVIRON_TEST"), string("present"));
        let env = os::Environ();
        let mut found = false;
        let mut i: i64 = 0;
        while i < env.Len() {
            if env[i] == "GOISH_ENVIRON_TEST=present" {
                found = true;
                break;
            }
            i += 1;
        }
        if found {
            fmt::Println!("[ 2] Setenv → Environ          PASS");
        } else {
            fmt::Println!("[ 2] Setenv → Environ          FAIL");
            failed += 1;
        }
    }

    // 3. Unsetenv hides from Environ.
    {
        let _ = os::Unsetenv(string("GOISH_ENVIRON_TEST"));
        let env = os::Environ();
        let mut found = false;
        let mut i: i64 = 0;
        while i < env.Len() {
            if strings::HasPrefix(env[i].clone(), string("GOISH_ENVIRON_TEST=")) {
                found = true;
                break;
            }
            i += 1;
        }
        if !found {
            fmt::Println!("[ 3] Unsetenv hides Environ    PASS");
        } else {
            fmt::Println!("[ 3] Unsetenv hides Environ    FAIL");
            failed += 1;
        }
    }

    // 4. Setenv override beats kernel-supplied value.
    {
        let path_orig = os::Getenv(string("PATH"));
        if path_orig.Len() > 0 {
            let _ = os::Setenv(string("PATH"), string("/overridden"));
            let env = os::Environ();
            let mut count_path = 0;
            let mut i: i64 = 0;
            while i < env.Len() {
                if strings::HasPrefix(env[i].clone(), string("PATH=")) {
                    count_path += 1;
                }
                i += 1;
            }
            // Should appear exactly once with overridden value.
            if count_path == 1 && os::Getenv(string("PATH")) == "/overridden" {
                fmt::Println!("[ 4] Setenv override unique    PASS");
            } else {
                fmt::Println!(
                    "[ 4] Setenv override unique    FAIL count=",
                    count_path as i64
                );
                failed += 1;
            }
            let _ = os::Setenv(string("PATH"), path_orig);
        } else {
            fmt::Println!("[ 4] Setenv override unique    SKIP");
        }
    }

    // 5. Clearenv empties Environ.
    {
        // Save snapshot of current env for restore.
        let saved = os::Environ();
        os::Clearenv();
        let env = os::Environ();
        let cleared = env.Len() == 0;
        // Restore everything.
        let mut i: i64 = 0;
        while i < saved.Len() {
            let entry = saved[i].clone();
            let (k, v, ok) = strings::Cut(entry, string("="));
            if ok {
                let _ = os::Setenv(k, v);
            }
            i += 1;
        }
        if cleared {
            fmt::Println!("[ 5] Clearenv empties          PASS");
        } else {
            fmt::Println!("[ 5] Clearenv empties          FAIL n=", env.Len() as i64);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
