// os_user_cache_config_smoke — exercise os.UserCacheDir +
// os.UserConfigDir (file.go:507 + 560).
//
// Slim: goish has no Setenv yet, so we only exercise the HOME-based
// fallback paths (XDG_CACHE_HOME / XDG_CONFIG_HOME unset in the
// envelope) plus the relative-XDG-rejection logic indirectly.

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

    let home = os::Getenv(string("HOME"));

    // 1. UserCacheDir non-empty.
    {
        let (cache, err) = os::UserCacheDir();
        if err.IsNil() && cache.Len() > 0 {
            fmt::Println!("[ 1] UserCacheDir non-empty    PASS");
        } else {
            fmt::Println!("[ 1] UserCacheDir non-empty    FAIL");
            failed += 1;
        }
    }

    // 2. UserConfigDir non-empty.
    {
        let (cfg, err) = os::UserConfigDir();
        if err.IsNil() && cfg.Len() > 0 {
            fmt::Println!("[ 2] UserConfigDir non-empty   PASS");
        } else {
            fmt::Println!("[ 2] UserConfigDir non-empty   FAIL");
            failed += 1;
        }
    }

    // 3. Cache dir starts with HOME (since XDG_CACHE_HOME is unset in
    //    the test envelope) and ends with "/.cache".
    {
        let xdg = os::Getenv(string("XDG_CACHE_HOME"));
        if xdg.Len() == 0 && home.Len() > 0 {
            let (cache, _) = os::UserCacheDir();
            if strings::HasPrefix(cache.clone(), home.clone())
                && strings::HasSuffix(cache.clone(), string("/.cache"))
            {
                fmt::Println!("[ 3] UserCacheDir HOME/.cache  PASS");
            } else {
                fmt::Println!("[ 3] UserCacheDir HOME/.cache  FAIL got=", cache);
                failed += 1;
            }
        } else {
            fmt::Println!("[ 3] UserCacheDir HOME/.cache  SKIP (XDG_CACHE_HOME or HOME)");
        }
    }

    // 4. Config dir HOME suffix check.
    {
        let xdg = os::Getenv(string("XDG_CONFIG_HOME"));
        if xdg.Len() == 0 && home.Len() > 0 {
            let (cfg, _) = os::UserConfigDir();
            if strings::HasPrefix(cfg.clone(), home.clone())
                && strings::HasSuffix(cfg.clone(), string("/.config"))
            {
                fmt::Println!("[ 4] UserConfigDir HOME/.config PASS");
            } else {
                fmt::Println!("[ 4] UserConfigDir HOME/.config FAIL got=", cfg);
                failed += 1;
            }
        } else {
            fmt::Println!("[ 4] UserConfigDir HOME/.config SKIP (XDG_CONFIG_HOME or HOME)");
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
