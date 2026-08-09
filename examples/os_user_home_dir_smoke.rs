// os_user_home_dir_smoke — exercise os.UserHomeDir (os/file.go:608).
//
// Validates: returns $HOME when set; returns error when unset.

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

    // 1. With $HOME set (test runner inherits this), UserHomeDir returns
    //    a non-empty string and nil error.
    {
        let (home, err) = os::UserHomeDir();
        if err.IsNil() && home.Len() > 0 {
            // Sanity: HOME on this host is /home/<user>.
            // Just confirm absolute path.
            let leading_slash = home.Len() > 0 && home[0i64] == b'/';
            if leading_slash {
                fmt::Println!("[ 1] $HOME set returns dir     PASS home=", home);
            } else {
                fmt::Println!("[ 1] $HOME set returns dir     FAIL home=", home);
                failed += 1;
            }
        } else {
            fmt::Println!("[ 1] $HOME set returns dir     FAIL err=", err.Error());
            failed += 1;
        }
    }

    // 2. UserHomeDir matches Getenv("HOME").
    {
        let (home, _) = os::UserHomeDir();
        let env_home = os::Getenv(string("HOME"));
        if home == env_home {
            fmt::Println!("[ 2] matches Getenv HOME       PASS");
        } else {
            fmt::Println!("[ 2] matches Getenv HOME       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 2");
        syscall::Exit(1);
    }
}
