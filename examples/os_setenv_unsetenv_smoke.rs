// os_setenv_unsetenv_smoke — exercise os.Setenv + os.Unsetenv
// (env.go:119 + 128). Goish v1 slim: writes to a process-local
// overlay; not visible to child processes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::os;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Setenv + Getenv round trip.
    {
        let _ = os::Setenv(string("GOISH_TEST_KEY1"), string("value1"));
        let v = os::Getenv(string("GOISH_TEST_KEY1"));
        if v == "value1" {
            Println!("[ 1] Setenv + Getenv           PASS");
        } else {
            Println!("[ 1] Setenv + Getenv           FAIL got=", v);
            failed += 1;
        }
    }

    // 2. Setenv overrides existing overlay.
    {
        let _ = os::Setenv(string("GOISH_TEST_KEY1"), string("value2"));
        let v = os::Getenv(string("GOISH_TEST_KEY1"));
        if v == "value2" {
            Println!("[ 2] Setenv override           PASS");
        } else {
            Println!("[ 2] Setenv override           FAIL got=", v);
            failed += 1;
        }
    }

    // 3. Unsetenv hides overlay value.
    {
        let _ = os::Unsetenv(string("GOISH_TEST_KEY1"));
        let v = os::Getenv(string("GOISH_TEST_KEY1"));
        if v.Len() == 0 {
            Println!("[ 3] Unsetenv hides            PASS");
        } else {
            Println!("[ 3] Unsetenv hides            FAIL got=", v);
            failed += 1;
        }
    }

    // 4. LookupEnv returns false for unset.
    {
        let (_, ok) = os::LookupEnv(string("GOISH_TEST_KEY1"));
        if !ok {
            Println!("[ 4] LookupEnv unset → false   PASS");
        } else {
            Println!("[ 4] LookupEnv unset → false   FAIL");
            failed += 1;
        }
    }

    // 5. Setenv with '=' in key → error.
    {
        let err = os::Setenv(string("BAD=KEY"), string("value"));
        if !err.IsNil() {
            Println!("[ 5] Setenv bad key → err      PASS");
        } else {
            Println!("[ 5] Setenv bad key → err      FAIL");
            failed += 1;
        }
    }

    // 6. Setenv with empty key → error.
    {
        let err = os::Setenv(string(""), string("value"));
        if !err.IsNil() {
            Println!("[ 6] Setenv empty key → err    PASS");
        } else {
            Println!("[ 6] Setenv empty key → err    FAIL");
            failed += 1;
        }
    }

    // 7. Unsetenv tombstone shadows kernel envp.
    {
        // PATH should always be set in any reasonable env.
        let path_before = os::Getenv(string("PATH"));
        let _ = os::Unsetenv(string("PATH"));
        let path_after = os::Getenv(string("PATH"));
        if path_before.Len() > 0 && path_after.Len() == 0 {
            Println!("[ 7] Unsetenv shadows kernel   PASS");
        } else {
            Println!("[ 7] Unsetenv shadows kernel   FAIL");
            failed += 1;
        }
        // Restore visibility (Setenv overrides tombstone).
        let _ = os::Setenv(string("PATH"), path_before);
    }

    // 8. UserCacheDir picks up Setenv'd XDG_CACHE_HOME.
    {
        let _ = os::Setenv(string("XDG_CACHE_HOME"), string("/tmp/xdg-test"));
        let (cache, err) = os::UserCacheDir();
        if err.IsNil() && cache == "/tmp/xdg-test" {
            Println!("[ 8] UserCacheDir XDG abs      PASS");
        } else {
            Println!("[ 8] UserCacheDir XDG abs      FAIL got=", cache);
            failed += 1;
        }
        let _ = os::Unsetenv(string("XDG_CACHE_HOME"));
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
